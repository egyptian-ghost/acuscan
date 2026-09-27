#!/usr/bin/env python3
"""
Phase 2: PerFolder
==================
Checks directory-level issues:
  - Directory listing
  - Basic auth over HTTP
  - HTTP verb tampering
  - Backup files
"""
import threading
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.utils import safe_url_join
from ..finding import Finding


class PhasePerFolder:
    def __init__(self, scanner):
        self.scanner = scanner
        self.http = scanner.http
        self.db = scanner.db
        self.out = scanner.out
        self.detect = scanner.detect
        self.config = scanner.config

    def run(self, base_url):
        self.out.phase("Phase 2: PerFolder Checks")

        dirs = set(["/"])
        for url in self.scanner.crawled_urls:
            parsed = urlparse(url)
            parts = parsed.path.split('/')
            for i in range(1, len(parts)):
                d = '/'.join(parts[:i]) + '/'
                if d and len(d) < 100:
                    dirs.add(d)
        dirs = sorted(dirs)[:15]

        folder_checks = self.db.folder_checks
        total = 0
        for check in folder_checks:
            files = check.get("files", [])
            if files:
                total += len(dirs) * len(files)
            elif check.get("check"):
                total += len(dirs)
        total = max(total, 1)

        checked = [0]
        lock = threading.Lock()

        def run_check(directory, check):
            if self.scanner.stop_event.is_set():
                return
            check_type = check.get("check", "")
            check_name = check.get("name", "folder_check")
            severity = check.get("severity", "medium")
            patterns = check.get("patterns", [])
            files = check.get("files", [])

            try:
                if check_type == "dirlist":
                    self._check_dirlist(base_url, directory)
                elif check_type == "basic_auth":
                    self._check_basic_auth(base_url, directory)
                elif check_type == "verb_tampering":
                    self._check_verb_tampering(base_url, directory)
                else:
                    self._check_files(base_url, directory, check_type,
                                     check_name, severity, patterns, files)
            except Exception:
                pass

            with lock:
                checked[0] += 1
                if checked[0] % 50 == 0 or checked[0] >= total:
                    self.out.progress(min(checked[0], total), total,
                                     "PerFolder")

        tasks = [(d, c) for d in dirs for c in folder_checks]
        if not tasks:
            self.out.info("No folder checks to run")
            return

        max_workers = self.config.get("concurrency", 25)
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [pool.submit(run_check, d, c) for d, c in tasks]
            for _ in as_completed(futures):
                if self.scanner.stop_event.is_set():
                    break

        self.out.progress(total, total, "PerFolder")

    def _check_dirlist(self, base_url, directory):
        url = safe_url_join(base_url, directory)
        resp = self.http.get(url, timeout=8)
        if resp and resp.status_code == 200:
            try:
                body = resp.text
            except Exception:
                return
            dl = self.detect.detect_dirlist(body)
            if dl:
                self.scanner.add_finding(Finding(
                    name=f"Directory listing enabled: {directory}",
                    severity="medium", url=url,
                    detail=f"Pattern: {dl}",
                    category="PerFolder",
                    check_name="Directory_Listing",
                ))

    def _check_basic_auth(self, base_url, directory):
        url = safe_url_join(base_url, directory)
        resp = self.http.get(url, timeout=8)
        if resp and resp.status_code == 401:
            www_auth = resp.headers.get("WWW-Authenticate", "")
            if "basic" in www_auth.lower():
                parsed = urlparse(base_url)
                if parsed.scheme == "http":
                    self.scanner.add_finding(Finding(
                        name="Basic authentication over HTTP",
                        severity="medium", url=url,
                        detail=f"WWW-Authenticate: {www_auth}",
                        category="PerFolder",
                        check_name="Basic_Auth_Over_HTTP",
                    ))

    def _check_verb_tampering(self, base_url, directory):
        url = safe_url_join(base_url, directory)
        resp_get = self.http.get(url, timeout=8)
        if resp_get and resp_get.status_code in (401, 403):
            for method in ["HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"]:
                try:
                    resp_alt = self.http.session.request(
                        method, url, timeout=8, verify=self.http.session.verify
                    )
                    if resp_alt and resp_alt.status_code == 200:
                        self.scanner.add_finding(Finding(
                            name=f"HTTP verb tampering: {method} on {directory}",
                            severity="high", url=url,
                            detail=f"GET={resp_get.status_code}, {method}=200",
                            category="PerFolder",
                            check_name="Http_Verb_Tampering",
                        ))
                        break
                except Exception:
                    pass

    def _check_files(self, base_url, directory, check_type, check_name,
                    severity, patterns, files):
        for fname in files:
            if self.scanner.stop_event.is_set():
                break
            test_path = directory.rstrip('/') + '/' + fname
            test_url = safe_url_join(base_url, test_path)
            method = "GET"

            if check_type == "binary":
                resp = self.http.get(test_url, timeout=8)
            else:
                resp = self.http.get(test_url, timeout=8)

            if (resp and resp.status_code == 200 and
                not self.scanner.is_custom_404(resp, base_url, url=test_url)):

                try:
                    body = resp.text
                except Exception:
                    body = ""

                verified = False
                detail = ""

                if check_type == "binary":
                    ct = resp.headers.get("Content-Type", "").lower()
                    if "octet-stream" in ct or "application/x-" in ct:
                        verified = len(body) > 50
                        detail = f"Binary ({len(body)} bytes)"
                elif patterns:
                    for p in patterns:
                        if p.lower() in body.lower():
                            verified = True
                            detail = f"Pattern: {p}"
                            break
                else:
                    if len(body) > 100:
                        ext = ''
                        if '.' in test_path.split('/')[-1]:
                            ext = '.' + test_path.split('/')[-1].rsplit('.', 1)[-1]
                        if not self.scanner.looks_like_rewrite(resp, ext):
                            verified = True
                            detail = f"File found ({len(body)} bytes)"

                if verified:
                    self.scanner.add_finding(Finding(
                        name=f"{check_name}: {test_path}",
                        severity=severity, url=test_url,
                        detail=detail,
                        category="PerFolder",
                        check_name=check_name.replace(" ", "_"),
                    ))