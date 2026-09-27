#!/usr/bin/env python3
"""
Phase 1: PerServer
==================
Checks server-level resources (sensitive files, directory listing, etc.)
"""
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from core.utils import safe_url_join, is_clean_path
from core.output import OutputFormatter
from ..finding import Finding


class PhasePerServer:
    def __init__(self, scanner):
        self.scanner = scanner
        self.http = scanner.http
        self.db = scanner.db
        self.out = scanner.out
        self.detect = scanner.detect
        self.config = scanner.config

    def run(self, base_url):
        self.out.phase("Phase 1: PerServer Checks")

        server_urls = [u for u in self.db.server_urls if is_clean_path(u)]
        scripts = self.db.scripts.get("PerServer", [])

        # Build URL -> script mapping
        url_to_script = {}
        for script in scripts:
            for url in script.get("urls", []):
                if is_clean_path(url):
                    url_to_script[url] = script
            for arr_key in ["arr_variants", "arr_urls", "arr_paths",
                           "arr_uris", "arr_files"]:
                for url in script.get(arr_key, []):
                    if is_clean_path(url):
                        url_to_script[url] = script

        all_urls = sorted(set(server_urls) | set(url_to_script.keys()))
        if not all_urls:
            self.out.info("No PerServer URLs to check")
            return

        checked = [0]
        total = len(all_urls)
        lock = threading.Lock()

        def check_url(url_path):
            if self.scanner.stop_event.is_set():
                return
            full_url = safe_url_join(base_url, url_path)
            resp = self.http.get(full_url, timeout=8)

            if (resp and resp.status_code == 200 and
                not self.scanner.is_custom_404(resp, base_url, url=full_url)):

                try:
                    body = resp.text
                except Exception:
                    body = ""

                # URL rewrite check
                ext = ''
                if '.' in url_path.split('/')[-1]:
                    ext = '.' + url_path.split('/')[-1].rsplit('.', 1)[-1]
                if self.scanner.looks_like_rewrite(resp, ext):
                    with lock:
                        checked[0] += 1
                    return

                script = url_to_script.get(url_path, {})
                vuln_refs = script.get("vuln_refs", [])
                check_name = script.get("name", "sensitive_file")
                severity = "medium"
                name = f"Sensitive file found: {url_path}"
                cve = cwe = tags = ""

                # Look up vuln severity in DB
                for vref in vuln_refs:
                    vinfo = self.db.vuln_db.get(vref, {})
                    if vinfo:
                        name = vinfo.get("name", name)
                        severity = vinfo.get("severity", severity)
                        cve = vinfo.get("cve", "")
                        cwe = vinfo.get("cwe", "")
                        tags = vinfo.get("tags", "")
                        break

                detail = ""

                # Content checks
                if script.get("detection_plain"):
                    for dp in script["detection_plain"]:
                        if dp in body:
                            detail = f"Pattern: {dp[:80]}"
                            break

                if self.detect.detect_phpinfo(body):
                    name = "phpinfo() page found"
                    severity = "medium"

                dirlist = self.detect.detect_dirlist(body)
                if dirlist and url_path.endswith('/'):
                    name = f"Directory listing: {url_path}"
                    severity = "medium"
                    detail = f"Pattern: {dirlist}"

                src = self.detect.detect_source_code(body)
                if src:
                    name = f"Source code disclosure: {url_path}"
                    severity = "high"
                    detail = src

                trojan = self.detect.detect_trojan_shell(body)
                if trojan:
                    name = f"Web shell detected: {url_path}"
                    severity = "critical"
                    detail = f"Indicator: {trojan}"

                self.scanner.add_finding(Finding(
                    name=name, severity=severity, url=full_url,
                    detail=detail,
                    vuln_ref=",".join(vuln_refs),
                    cve=cve, cwe=cwe, tags=tags,
                    category="PerServer",
                    check_name=check_name,
                ))

            with lock:
                checked[0] += 1
                if checked[0] % 50 == 0 or checked[0] >= total:
                    self.out.progress(min(checked[0], total), total,
                                     "PerServer")

        max_workers = self.config.get("concurrency", 25)
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [pool.submit(check_url, u) for u in all_urls]
            for _ in as_completed(futures):
                if self.scanner.stop_event.is_set():
                    break

        self.out.progress(total, total, "PerServer")