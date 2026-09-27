#!/usr/bin/env python3
"""
Verification Engine
===================
Orchestrates all verifiers. Each URL+param goes through every verifier
(or a selected subset), returning VerifiedFinding objects.
"""
import time
import threading
import concurrent.futures
from typing import Optional, List, Dict, Callable

from .models import VerifiedFinding
from .http_client import VerificationHTTPClient
from .verifiers import VERIFIERS


class VerificationEngine:
    """Main orchestration engine for vulnerability verification."""

    def __init__(self, base_http_client, config=None):
        self.config = config or {}
        self.base_client = base_http_client
        self.http = VerificationHTTPClient(base_http_client, config)
        self.stats = {
            "tests_run": 0,
            "confirmed": 0,
            "rejected": 0,
            "extracted_info": 0,
        }
        self._lock = threading.Lock()
        self._verifiers_cache = {}

    # ═══════════════════════════════════════════════════════════════════════
    #  Main API
    # ═══════════════════════════════════════════════════════════════════════

    def verify_url_param(self, url: str, param: str,
                        method: str = "GET",
                        form_data: Dict = None,
                        verifier_names: List[str] = None,
                        progress_cb: Callable = None) -> List[VerifiedFinding]:
        """
        Verify a single URL+param through all (or selected) verifiers.
        """
        verifier_names = verifier_names or list(VERIFIERS.keys())
        names = [n for n in verifier_names if n in VERIFIERS]

        def run_one(name):
            try:
                # Fresh verifier per task: verifier instances keep mutable step state.
                verifier = VERIFIERS[name](self.http, self.config)
                if progress_cb:
                    progress_cb(f"Testing {name} on {param}")
                finding = verifier.verify(url, param, method, form_data)
                with self._lock:
                    self.stats["tests_run"] += 1
                    if finding and finding.verified:
                        self.stats["confirmed"] += 1
                        if finding.extracted_info:
                            self.stats["extracted_info"] += 1
                    else:
                        self.stats["rejected"] += 1
                return finding if finding and finding.verified else None
            except Exception:
                with self._lock:
                    self.stats["tests_run"] += 1
                if self.config.get("verbose"):
                    import traceback; traceback.print_exc()
                return None

        workers = max(1, min(int(self.config.get("verification_workers", 6)), 32))
        if len(names) <= 1:
            out = [run_one(names[0])] if names else []
            return [x for x in out if x]
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(names))) as ex:
            return [x for x in ex.map(run_one, names) if x]

    def verify_url_all_params(self, url: str, params: List[str],
                             method: str = "GET",
                             form_data: Dict = None,
                             max_workers: int = 5) -> List[VerifiedFinding]:
        """
        Verify all parameters of a URL in parallel.
        """
        all_findings = []
        if not params:
            return all_findings

        # Reset baseline cache between URLs
        self.http.clear_baseline_cache()

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_workers) as ex:
            futures = {
                ex.submit(self.verify_url_param, url, p, method, form_data): p
                for p in params
            }
            for future in concurrent.futures.as_completed(futures):
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                except Exception:
                    pass
        return all_findings


    def verify_url_surface(self, url: str) -> List[VerifiedFinding]:
        """Run once-per-URL API/GraphQL/JWT/CORS/security-header checks."""
        try:
            from .surface import SurfaceVerifier
            return SurfaceVerifier(self.http, self.config).scan(url)
        except Exception:
            if self.config.get("verbose"):
                import traceback; traceback.print_exc()
            return []

    # ═══════════════════════════════════════════════════════════════════════
    #  Verifier management
    # ═══════════════════════════════════════════════════════════════════════

    def _get_verifier(self, name: str):
        """Get or create a verifier instance."""
        if name not in self._verifiers_cache:
            cls = VERIFIERS[name]
            self._verifiers_cache[name] = cls(self.http, self.config)
        return self._verifiers_cache[name]

    def get_stats(self) -> Dict:
        with self._lock:
            return dict(self.stats)

    def reset_stats(self):
        with self._lock:
            self.stats = {
                "tests_run": 0,
                "confirmed": 0,
                "rejected": 0,
                "extracted_info": 0,
            }


# ═══════════════════════════════════════════════════════════════════════════════
#  Singleton per scan
# ═══════════════════════════════════════════════════════════════════════════════

_engines: Dict[str, VerificationEngine] = {}
_engines_lock = threading.Lock()


def get_verification_engine(base_http_client, config=None,
                           scan_id: str = None) -> VerificationEngine:
    """Get or create a VerificationEngine for a scan."""
    scan_id = scan_id or "default"
    with _engines_lock:
        if scan_id not in _engines:
            _engines[scan_id] = VerificationEngine(base_http_client, config)
        return _engines[scan_id]


def reset_engine(scan_id: str = None):
    """Reset (or delete) an engine for a scan."""
    scan_id = scan_id or "default"
    with _engines_lock:
        if scan_id in _engines:
            del _engines[scan_id]