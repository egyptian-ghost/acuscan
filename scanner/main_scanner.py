#!/usr/bin/env python3
"""
AcuScan Main Scanner v6.5.4
===========================
Orchestrates all phases, verification engine, OAST, login test,
crawl map, and server info collection.

Changes in v6.5.4:
  - Preserves target URL path (no more normalize_url stripping path)
  - Added debug output for target URL
  - Passes full URL to crawler
  - Login verification integrated before scanning
  - Server info collection integrated
  - Crawl map recording integrated
"""
import os
import time
import uuid
import threading
import traceback
import collections
from collections import defaultdict
from urllib.parse import urlparse

from core.config import VERSION, DEFAULT_DB_PATH
from core.output import OutputFormatter
from http_client.client import HTTPClient
from storage import get_storage

try:
    from verification import VerifierBridge
    HAS_VERIFIER = True
except ImportError:
    HAS_VERIFIER = False
    VerifierBridge = None

try:
    from oast import OASTClient
    HAS_OAST = True
except ImportError:
    HAS_OAST = False
    OASTClient = None

from .finding import Finding
from .crawler import Crawler
from .tech_detect import TechDetector
from .db_loader import load_db
from .detection_patterns import DetectionHelper
from .crawl_map import CrawlMap
from .server_info import ServerInfoCollector
from .plugins.loader import PluginLoader

try:
    from http_client.login_test import LoginTester
    HAS_LOGIN_TEST = True
except ImportError:
    HAS_LOGIN_TEST = False
    LoginTester = None


class Scanner:
    """Main scanner orchestrator."""

    def __init__(self, config):
        self.config = config
        self.out = OutputFormatter(
            no_color=config.get("no_color", False),
            silent=config.get("silent", False)
        )
        config["_out"] = self.out

        # ═══ HTTP Client ═══
        self.http = HTTPClient(config)
        config["_http_client"] = self.http

        # ═══ Storage ═══
        self.storage = None
        self.storage_scan_id = None
        if config.get("enable_storage", True):
            try:
                self.storage = get_storage(config.get("storage_db"))
            except Exception:
                self.storage = None

        # ═══ OAST ═══
        self.oast = None
        if HAS_OAST and config.get("enable_oast", False):
            try:
                oast_config = {
                    "mode": config.get("oast_mode", "local"),
                    "port": config.get("oast_port", 8000),
                    "dns_port": config.get("oast_dns_port", 5353),
                    "domain": config.get("oast_domain", "oast.local"),
                    "public_ip": config.get("oast_public_ip"),
                }
                self.oast = OASTClient(oast_config)
                config["_oast"] = self.oast
                if self.oast.is_available():
                    self.out.info(f"OAST server: {self.oast.get_url('test')}")
                else:
                    self.out.warn("OAST unavailable — continuing without it")
            except Exception as e:
                self.out.warn(f"OAST init failed: {e}")

        # ═══ Verification ═══
        self.verifier_bridge = None
        if HAS_VERIFIER and config.get("enable_verification", True):
            try:
                self.verifier_bridge = VerifierBridge(self.http, config)
                if self.verifier_bridge.is_available():
                    self.out.success("Verification Engine: ENABLED")
                else:
                    self.out.warn("Verification Engine init failed")
            except Exception as e:
                self.out.warn(f"Verification init failed: {e}")

        # ═══ Plugins ═══
        self.plugin_loader = PluginLoader(
            plugins_dir=config.get("plugins_dir"),
            config=config,
        )

        # ═══ State ═══
        self.db = None
        self.detect = None
        self.findings = []
        self.findings_lock = threading.Lock()
        self.stop_event = threading.Event()

        # Crawler state
        self.crawled_urls = set()
        self.crawled_forms = []
        self.crawled_params = defaultdict(set)

        # New: crawl map + server info + login test
        self.crawl_map = None
        self.server_info = None
        self.login_test_result = None
        self.tech_detector = None
        self.crawler = None

        # 404 detection
        self._404_body_cache = {}
        self._404_lock = threading.Lock()

    # ═══════════════════════════════════════════════════════════════════════
    #  Database loading
    # ═══════════════════════════════════════════════════════════════════════

    def load_database(self, db_path=None):
        path = db_path or self.config.get("db_path") or DEFAULT_DB_PATH
        if not os.path.isfile(path):
            self.out.error(f"Database not found: {path}")
            raise FileNotFoundError(path)
        self.db = load_db(path)
        self.detect = DetectionHelper(self.db)
        size_kb = os.path.getsize(path) // 1024
        self.out.info(f"Loaded DB: {os.path.basename(path)} ({size_kb}KB)")

    # ═══════════════════════════════════════════════════════════════════════
    #  Findings management
    # ═══════════════════════════════════════════════════════════════════════

    def add_finding(self, finding):
        with self.findings_lock:
            key = (f"{finding.name}|{finding.url}|"
                   f"{getattr(finding, 'parameter', '')}")
            for existing in self.findings:
                ek = (f"{existing.name}|{existing.url}|"
                     f"{getattr(existing, 'parameter', '')}")
                if ek == key:
                    return
            self.findings.append(finding)

            # Save to SQLite
            if self.storage and self.storage_scan_id:
                try:
                    self.storage.add_finding(
                        self.storage_scan_id,
                        finding.to_storage_dict()
                    )
                except Exception:
                    pass

            # Severity filter
            severity_filter = self.config.get("severity_filter", [])
            if severity_filter and finding.severity not in severity_filter:
                return

            self.out.finding(finding)

    # ═══════════════════════════════════════════════════════════════════════
    #  404 / URL-rewrite detection
    # ═══════════════════════════════════════════════════════════════════════

    def _probe_404(self, probe_base):
        import hashlib
        samples = []
        for suffix in [
            "nonexistent_%s.html" % hashlib.md5(os.urandom(8)).hexdigest()[:10],
            "nx_%s.txt" % hashlib.md5(os.urandom(8)).hexdigest()[:10],
        ]:
            probe_url = probe_base.rstrip('/') + '/' + suffix
            test_resp = self.http.get(probe_url, timeout=8)
            if test_resp:
                body = test_resp.text
                samples.append({
                    "status": test_resp.status_code,
                    "length": len(body),
                    "hash": hashlib.md5(body.encode()).hexdigest(),
                })
        return samples

    def _get_404_samples(self, url):
        parsed = urlparse(url)
        path = parsed.path or '/'
        dir_path = path.rsplit('/', 1)[0] + '/' if '/' in path else '/'
        base = parsed.scheme + '://' + parsed.netloc
        dir_url = base + dir_path

        with self._404_lock:
            if dir_url not in self._404_body_cache:
                self._404_body_cache[dir_url] = self._probe_404(dir_url)
            root_url = base + '/'
            if root_url not in self._404_body_cache:
                self._404_body_cache[root_url] = self._probe_404(root_url)

        samples = list(self._404_body_cache.get(dir_url, []))
        if dir_url != root_url:
            samples.extend(self._404_body_cache.get(root_url, []))
        return samples

    def is_custom_404(self, resp, base_url, url=None):
        import hashlib
        if resp.status_code == 404:
            return True
        if resp.status_code in (301, 302, 303, 307, 308):
            return True

        lookup_url = url or (resp.url if hasattr(resp, 'url') else base_url)
        samples = self._get_404_samples(lookup_url)
        resp_hash = hashlib.md5(resp.text.encode()).hexdigest()
        resp_len = len(resp.text)

        for sample in samples:
            if sample["hash"] == resp_hash:
                return True
            if sample["status"] == resp.status_code and sample["length"] > 0:
                ratio = abs(resp_len - sample["length"]) / max(sample["length"], 1)
                if ratio < 0.15:
                    return True

        body_lower = resp.text.lower()
        indicators = [
            'page not found', '404 not found', '404 error', 'file not found',
            'does not exist', 'resource not found', 'nothing found',
            'not found on this server',
        ]
        if resp_len < 8000:
            for ind in indicators:
                if ind in body_lower:
                    return True
        return False

    def looks_like_rewrite(self, resp, expected_ext):
        import re
        if not expected_ext:
            return False
        ct = resp.headers.get('Content-Type', '').split(';')[0].strip().lower()
        body = resp.text[:2000]
        is_html = bool(re.search(r'<html|<body|<div|<!doctype', body, re.I))
        non_html_exts = {
            '.txt', '.log', '.cfg', '.conf', '.ini', '.bak', '.old',
            '.orig', '.sql', '.db', '.sqlite', '.csv', '.xml', '.json',
            '.yml', '.yaml', '.env', '.key', '.pem',
            '.gz', '.tar', '.zip', '.rar', '.7z',
            '.swp', '.swo', '.save', '.tmp', '.temp', '.dist', '.sample',
        }
        ext_lower = expected_ext.lower()
        if ext_lower in non_html_exts and (is_html or 'text/html' in ct):
            return True
        return False

    # ═══════════════════════════════════════════════════════════════════════
    #  Login verification
    # ═══════════════════════════════════════════════════════════════════════

    def verify_login(self, base_url):
        """Test login credentials before scanning."""
        if not self.config.get("auto_login"):
            return True
        if not self.config.get("login_url"):
            return True

        if not HAS_LOGIN_TEST:
            self.out.warn("Login test module unavailable")
            return True

        self.out.phase("Login Verification", self.config.get("login_url"))

        try:
            tester = LoginTester(self.http, self.config)
            result = tester.test_login()
            self.login_test_result = result.to_dict()

            if result.success:
                self.out.success(
                    f"Login SUCCESS ({result.confidence:.0%}) — {result.reason}"
                )
                if result.cookies_added:
                    self.out.info(
                        f"Cookies obtained: {', '.join(result.cookies_added)}"
                    )
            else:
                self.out.error(
                    f"Login FAILED ({result.confidence:.0%}) — {result.reason}"
                )
                if self.config.get("require_login"):
                    self.out.error("Scan aborted: login required")
                    return False
        except Exception as e:
            self.out.error(f"Login test error: {e}")
            if self.config.get("verbose"):
                traceback.print_exc()
        return True

    # ═══════════════════════════════════════════════════════════════════════
    #  Main scan — THE KEY METHOD
    # ═══════════════════════════════════════════════════════════════════════

    def scan(self, target_url):
        """
        Main scan entry point.

        IMPORTANT: Preserves path in the target URL.
        http://127.0.0.1/3/v3/  → stays as http://127.0.0.1/3/v3
        (Previously was incorrectly normalized to http://127.0.0.1)
        """
        from core.utils import normalize_url

        # ⭐ KEY FIX: preserve path
        base_url = normalize_url(target_url)
        self.config["_target"] = base_url

        # Debug output
        print(f"[scanner] Raw target: {target_url!r}")
        print(f"[scanner] Normalized: {base_url!r}")

        self.out.info(f"Target: {base_url}")

        # ═══ Create storage scan record ═══
        # A Web UI ScanJob creates the canonical SQLite scan record before
        # entering Scanner.scan(). Do NOT create another row here; doing so
        # produced duplicate targets/scan records in the Web UI. Direct CLI
        # use still gets a storage row when storage_scan_id is not already set.
        if self.storage and not self.storage_scan_id:
            try:
                scan_uuid = str(uuid.uuid4())
                self.storage_scan_id = self.storage.create_scan(
                    scan_uuid, [base_url], self.config
                )
            except Exception:
                self.storage_scan_id = None

        # ═══ Status ═══
        if self.http.authenticated:
            self.out.success("Authentication: ACTIVE")
        else:
            self.out.info("Authentication: none")

        if self.oast and self.oast.is_available():
            self.out.success("OAST: ENABLED")

        self.out.info(
            f"Concurrency: {self.config.get('concurrency', 25)}, "
            f"Rate: {self.config.get('rate_limit', 150)} req/s"
        )

        # ═══ Login verification ═══
        if not self.verify_login(base_url):
            return []

        start_time = time.time()

        # ═══ Signal handler ═══
        import signal
        def sig_handler(sig, frame):
            self.out.warn("Ctrl+C — stopping...")
            self.stop_event.set()
        try:
            signal.signal(signal.SIGINT, sig_handler)
        except Exception:
            pass

        try:
            # ═══ Technology detection ═══
            self.tech_detector = TechDetector(self.http, self.config, self.out)
            self.tech_detector.detect(base_url)

            # ═══ Server Info collection ═══
            self.out.phase("Server Information")
            try:
                self.server_info = ServerInfoCollector(
                    self.http, self.config
                ).collect(base_url)
                if self.server_info.server:
                    self.out.info(f"Server: {self.server_info.server}")
                if self.server_info.operating_system:
                    self.out.info(f"OS: {self.server_info.operating_system}")
                if self.server_info.cdn:
                    self.out.info(f"CDN: {self.server_info.cdn}")
                if self.server_info.ssl_enabled:
                    self.out.info(
                        f"SSL: {self.server_info.ssl_protocol} "
                        f"({self.server_info.ssl_issuer})"
                    )
            except Exception as e:
                self.out.warn(f"Server info collection failed: {e}")
                self.server_info = None

            # ═══ Crawl with crawl map ═══
            self.crawl_map = CrawlMap()
            self.crawl_map.set_base(base_url)

            self.crawler = Crawler(self.http, self.config, self.out)
            self.crawler.set_stop_event(self.stop_event)
            self.crawler.set_crawl_map(self.crawl_map)

            # ⭐ Pass FULL URL with path
            self.crawler.crawl(
                base_url,
                max_depth=self.config.get("crawl_depth", 3),
                max_pages=self.config.get("crawl_max_pages", 200),
            )

            self.crawled_urls = self.crawler.crawled_urls
            self.crawled_forms = self.crawler.crawled_forms
            self.crawled_params = self.crawler.crawled_params

            # Save crawl map progress
            self._save_metadata()

            # ═══ Phases ═══
            from .phases import (
                PhasePerServer, PhasePerFolder, PhasePerFile,
                PhasePostCrawl, PhaseWebApps, PhasePostScan,
                PhaseNetwork, PhaseSpecial,BackupDiscoveryPhase,DirectoryBruteForcePhase,
            )

            phases = [
                PhasePerServer(self),
                PhasePerFolder(self),
                PhasePerFile(self),
                PhasePostCrawl(self),
                BackupDiscoveryPhase(self),   # ← جديد
                DirectoryBruteForcePhase(self),  # ← NEW: discovery
                PhaseWebApps(self),
                PhasePostScan(self),
                PhaseNetwork(self),
                PhaseSpecial(self),
            ]

            for phase in phases:
                if self.stop_event.is_set():
                    break
                try:
                    phase.run(base_url)
                except Exception as e:
                    self.out.error(f"Phase {phase.__class__.__name__}: {e}")
                    if self.config.get("verbose"):
                        traceback.print_exc()

            # ═══ Plugins ═══
            if self.config.get("enable_plugins", True):
                self.out.phase("Phase 9: Custom Plugins")
                count = self.plugin_loader.load_all()
                if count > 0:
                    self.out.info(f"Loaded {count} plugins")
                    self.plugin_loader.run_all(base_url, self.http, self)
                    for err in self.plugin_loader.errors[:5]:
                        self.out.warn(f"Plugin error: {err}")
                else:
                    self.out.info("No plugins found")

        except Exception as e:
            self.out.error(f"Scan error: {e}")
            if self.config.get("verbose"):
                traceback.print_exc()

        elapsed = time.time() - start_time

        # ═══ Verification stats ═══
        if self.verifier_bridge and self.verifier_bridge.is_available():
            stats = self.verifier_bridge.get_stats()
            self.out.info(
                f"Verification: {stats.get('confirmed', 0)} confirmed, "
                f"{stats.get('rejected', 0)} rejected as false positives"
            )

        self.out.summary(
            self.findings, elapsed,
            self.http.request_count, self.http.error_count
        )

        # ═══ Save final metadata ═══
        self._save_metadata()

        # ═══ Update storage status ═══
        if self.storage and self.storage_scan_id:
            try:
                totals = {}
                for f in self.findings:
                    totals[f.severity] = totals.get(f.severity, 0) + 1
                totals['total'] = len(self.findings)
                totals['verified'] = sum(
                    1 for f in self.findings if f.verified
                )
                status = ("completed" if not self.stop_event.is_set()
                         else "stopped")
                self.storage.update_scan_status(
                    self.storage_scan_id, status,
                    self.http.request_count, self.http.error_count,
                    totals, elapsed,
                )
            except Exception:
                pass

        # ═══ Stop OAST ═══
        if self.oast:
            try:
                self.oast.stop()
            except Exception:
                pass

        return self.findings

    # ═══════════════════════════════════════════════════════════════════════
    #  Save metadata helper
    # ═══════════════════════════════════════════════════════════════════════

    def _save_metadata(self):
        """Save crawl map, server info, and login test to storage."""
        if not self.storage or not self.storage_scan_id:
            return

        try:
            crawl_nodes = self.crawl_map.get_all() if self.crawl_map else None
            server_data = (self.server_info.to_dict()
                          if self.server_info else None)
            login_data = self.login_test_result

            self.storage.save_scan_metadata(
                self.storage_scan_id,
                crawl_map=crawl_nodes,
                server_info=server_data,
                login_test=login_data,
            )
        except Exception as e:
            if self.config.get("verbose"):
                self.out.warn(f"Metadata save failed: {e}")