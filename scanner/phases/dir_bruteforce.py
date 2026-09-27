#!/usr/bin/env python3
"""
Directory & File Brute Force
============================
Wordlist-based discovery that works even when:
  - The site requires login
  - Links are hidden by JavaScript
  - The homepage has no links

Detects:
  - Common directories (admin, api, uploads, ...)
  - Framework-specific paths (wp-admin, administrator, ...)
  - Backup folders
  - API endpoints
"""
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.utils import safe_url_join
from ..finding import Finding


class DirectoryBruteForcePhase:
    """Discover hidden paths via wordlist."""

    # ═══════════════════════════════════════════════════════════════════════
    #  Priority wordlist — ordered by importance
    # ═══════════════════════════════════════════════════════════════════════
    WORDLIST = [
        # ═══ Critical ═══
        "admin", "administrator", "login", "signin", "logout",
        "dashboard", "panel", "controlpanel", "cpanel",
        "setup", "install", "installer", "config", "configuration",
        "settings", "manage", "management",
        # ═══ APIs ═══
        "api", "api/v1", "api/v2", "api/v3", "rest", "graphql",
        "swagger", "swagger-ui", "swagger-ui.html", "swagger.json",
        "openapi.json", "docs", "documentation", "api-docs",
        # ═══ Common apps ═══
        "wp-admin", "wp-login.php", "wp-content", "wp-includes",
        "administrator", "administrator/index.php",
        "phpmyadmin", "pma", "myadmin", "mysql", "sqladmin",
        "phpinfo.php", "info.php", "test.php",
        "adminer.php", "adminer",
        # ═══ Security / auth ═══
        "security", "auth", "login.php", "logout.php",
        "register", "signup", "sign-up",
        "password", "forgot", "reset", "recover",
        # ═══ DVWA / training apps (useful for testing) ═══
        "vulnerabilities", "hackable", "uploads",
        "vulnerabilities/sqli", "vulnerabilities/xss_r",
        "vulnerabilities/xss_s", "vulnerabilities/xss_d",
        "vulnerabilities/fi", "vulnerabilities/exec",
        "vulnerabilities/upload", "vulnerabilities/csrf",
        "vulnerabilities/brute", "vulnerabilities/weak_id",
        "instructions.php", "security.php",
        # ═══ Uploads / files ═══
        "uploads", "upload", "files", "download", "downloads",
        "media", "assets", "static", "public", "content",
        "storage", "data", "backup", "backups", "old",
        "archive", "temp", "tmp", "cache",
        # ═══ Version control ═══
        ".git", ".svn", ".hg", ".env",
        # ═══ Web servers ═══
        "server-status", "server-info", "nginx_status",
        "status", "health", "healthz", "ping", "version",
        # ═══ Common frameworks ═══
        "rails/info", "actuator", "actuator/health",
        "console", "jmx-console", "web-console",
        # ═══ Logs ═══
        "logs", "log", "error.log", "access.log", "debug.log",
        # ═══ Documentation ═══
        "README.md", "README.txt", "CHANGELOG.md",
        "LICENSE", "VERSION", "version.txt",
        # ═══ Testing / dev ═══
        "test", "tests", "testing", "dev", "development",
        "staging", "sandbox", "demo", "example", "sample",
    ]

    # ═══════════════════════════════════════════════════════════════════════
    #  Directories to test (prefix for sub-paths)
    # ═══════════════════════════════════════════════════════════════════════
    COMMON_PREFIXES = [
        "/", "/admin/", "/api/", "/v1/", "/v2/",
        "/backup/", "/uploads/", "/static/",
    ]

    def __init__(self, scanner):
        self.scanner = scanner
        self.http = scanner.http
        self.out = scanner.out
        self.config = scanner.config

    def run(self, base_url):
        self.out.phase("Directory Brute Force",
                      f"{len(self.WORDLIST)} paths")

        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        base_prefix = parsed.path.rstrip("/")

        # Build candidate URLs
        candidates = []
        for word in self.WORDLIST:
            # Root path
            candidates.append(safe_url_join(base_url,
                                           "/" + word.lstrip("/")))
            # Under base prefix (if different)
            if base_prefix:
                candidates.append(safe_url_join(base_url,
                                               base_prefix + "/" + word.lstrip("/")))

        # Deduplicate
        seen = set()
        unique = []
        for url in candidates:
            if url not in seen:
                seen.add(url)
                unique.append(url)

        self.out.info(f"Testing {len(unique)} paths...")

        # ═══ Pre-compute 404 fingerprint for each prefix ═══
        # (so we don't flag soft-404s)
        self._probe_404_for(base_url)
        if base_prefix:
            self._probe_404_for(safe_url_join(base_url, base_prefix))

        # ═══ Parallel checks ═══
        total = len(unique)
        checked = [0]
        found = [0]
        lock = __import__("threading").Lock()

        def check_one(url):
            if self.scanner.stop_event.is_set():
                return
            try:
                self._check_url(url, base_url)
            except Exception:
                pass

            with lock:
                checked[0] += 1
                if checked[0] % 25 == 0 or checked[0] >= total:
                    self.out.progress(checked[0], total, "DirBrute")

        workers = min(self.config.get("concurrency", 25), 15)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(check_one, u) for u in unique]
            for f in as_completed(futures):
                if self.scanner.stop_event.is_set():
                    break

        self.out.progress(total, total, "DirBrute")

    # ═══════════════════════════════════════════════════════════════════════
    #  Private
    # ═══════════════════════════════════════════════════════════════════════

    def _probe_404_for(self, url):
        """Probe 404 fingerprint for the base of this URL."""
        # Already handled by scanner._get_404_samples
        pass

    def _check_url(self, url, base_url):
        """Check a single URL."""
        resp = self.http.get(url, timeout=6)
        if not resp:
            return

        # Accept only 200, 301, 302, 401, 403
        if resp.status_code not in (200, 301, 302, 303, 307, 308, 401, 403):
            return

        # ═══ Filter: custom 404 ═══
        if self.scanner.is_custom_404(resp, base_url, url=url):
            return

        # ═══ Filter: URL rewrite ═══
        if '.' in url.split('?')[0]:
            ext = '.' + url.split('?')[0].rsplit('.', 1)[-1]
            if self.scanner.looks_like_rewrite(resp, ext):
                return

        # ═══ Determine severity ═══
        status = resp.status_code
        severity = "info"

        if status == 200:
            severity = "low"
        elif status == 401:
            severity = "medium"  # Auth-protected
        elif status == 403:
            severity = "medium"  # Forbidden but exists
        elif status in (301, 302, 303, 307, 308):
            severity = "info"  # Redirect

        # ═══ Upgrade severity for interesting paths ═══
        url_lower = url.lower()
        critical_paths = [
            '.git', '.env', '.svn', '.hg',
            'admin', 'administrator', 'phpmyadmin',
            'wp-admin', 'wp-login', 'setup', 'install',
            'backup', 'config', 'console',
        ]
        for kw in critical_paths:
            if kw in url_lower and severity in ("low", "info"):
                severity = "medium"
                break

        # ═══ Extract title if available ═══
        title = ""
        try:
            m = re.search(r'<title[^>]*>(.*?)</title>', resp.text,
                         re.I | re.S)
            if m:
                title = m.group(1).strip()[:100]
        except Exception:
            pass

        # ═══ Build finding ═══
        detail_parts = [f"HTTP {status}", f"{len(resp.content)} bytes"]
        if title:
            detail_parts.append(f"Title: {title}")

        self.scanner.add_finding(Finding(
            name=f"Discovered path: {url.replace(base_url, '/') or '/'}",
            severity=severity, url=url,
            detail=" | ".join(detail_parts),
            category="Discovery",
            check_name="Directory_Brute_Force",
            confidence=0.85,
        ))