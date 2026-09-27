#!/usr/bin/env python3
"""
Phase 4: PostCrawl
==================
Text analysis of crawled pages + backup file discovery.
"""
import threading
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.utils import safe_url_join, is_clean_path, truncate
from ..finding import Finding


class PhasePostCrawl:
    def __init__(self, scanner):
        self.scanner = scanner
        self.http = scanner.http
        self.db = scanner.db
        self.out = scanner.out
        self.detect = scanner.detect
        self.config = scanner.config

    def run(self, base_url):
        self.out.phase("Phase 4: PostCrawl Checks")

        # Part A: PostCrawl URLs
        postcrawl_urls = [u for u in self.db.postcrawl_urls
                         if is_clean_path(u)]
        if postcrawl_urls:
            self._check_postcrawl_urls(base_url, postcrawl_urls)

        # Part B: Backup files
        if self.db.backup_variants:
            self._check_backups(base_url)

        # Part C: Text search on crawled pages
        self._text_search()

    def _check_postcrawl_urls(self, base_url, urls):
        self.out.info(f"Checking {len(urls)} postcrawl URLs")
        checked = [0]
        total = len(urls)
        lock = threading.Lock()

        def check(url_path):
            if self.scanner.stop_event.is_set():
                return
            full_url = safe_url_join(base_url, url_path)
            resp = self.http.get(full_url, timeout=8)
            if (resp and resp.status_code == 200 and
                not self.scanner.is_custom_404(resp, base_url,
                                             url=full_url)):
                try:
                    body = resp.text
                except Exception:
                    body = ""

                ext = ''
                if '.' in url_path.split('/')[-1]:
                    ext = '.' + url_path.split('/')[-1].rsplit('.', 1)[-1]
                if self.scanner.looks_like_rewrite(resp, ext):
                    with lock:
                        checked[0] += 1
                    return

                name = f"Sensitive resource: {url_path}"
                severity = "medium"
                detail = ""

                err = self.detect.detect_errors(body)
                if err:
                    name = f"Application error: {url_path}"
                    detail = truncate(err, 80)

                if self.detect.detect_phpinfo(body):
                    name = f"phpinfo() found: {url_path}"

                self.scanner.add_finding(Finding(
                    name=name, severity=severity, url=full_url,
                    detail=detail, category="PostCrawl",
                ))

            with lock:
                checked[0] += 1
                if checked[0] % 50 == 0 or checked[0] >= total:
                    self.out.progress(min(checked[0], total), total,
                                     "PostCrawl")

        max_workers = self.config.get("concurrency", 25)
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [pool.submit(check, u) for u in urls]
            for _ in as_completed(futures):
                if self.scanner.stop_event.is_set():
                    break

        self.out.progress(total, total, "PostCrawl")

    def _check_backups(self, base_url):
        variants = self.db.backup_variants
        mimes = self.db.backup_mime_types or {
            'application/octet-stream', 'application/x-gzip', 'application/zip'
        }

        self.out.info(f"Checking backup variants ({len(variants)})")

        base_files = set()
        for url in self.scanner.crawled_urls:
            p = urlparse(url).path
            if '.' in p.split('/')[-1]:
                base_files.add(p)

        for file_path in base_files:
            if self.scanner.stop_event.is_set():
                break
            parts = file_path.rsplit('/', 1)
            dir_path = parts[0] + '/' if len(parts) > 1 else '/'
            filename = parts[-1]
            name_parts = filename.rsplit('.', 1)
            fname = name_parts[0]
            fext = '.' + name_parts[1] if len(name_parts) > 1 else ''

            for template in variants[:20]:
                if self.scanner.stop_event.is_set():
                    break
                variant = (template.replace("${fileName}", fname)
                          .replace("${fileExt}", fext))
                backup_path = dir_path + variant
                backup_url = safe_url_join(base_url, backup_path)
                resp = self.http.get(backup_url, timeout=8)
                if resp and resp.status_code == 200:
                    ct = (resp.headers.get('Content-Type', '')
                         .split(';')[0].strip())
                    if ct in mimes:
                        if not self.scanner.is_custom_404(resp, base_url,
                                                        url=backup_url):
                            bext = ''
                            if '.' in backup_path.split('/')[-1]:
                                bext = ('.' +
                                       backup_path.split('/')[-1].rsplit('.', 1)[-1])
                            if not self.scanner.looks_like_rewrite(resp, bext):
                                self.scanner.add_finding(Finding(
                                    name=f"Backup file: {backup_path}",
                                    severity="medium", url=backup_url,
                                    detail=f"Content-Type: {ct}",
                                    category="PostCrawl",
                                    check_name="Backup_File",
                                ))

    def _text_search(self):
        self.out.info("Text search on crawled pages")
        urls = list(self.scanner.crawled_urls)[:100]
        for url in urls:
            if self.scanner.stop_event.is_set():
                break
            resp = self.http.get(url, timeout=8)
            if not resp or resp.status_code != 200:
                continue
            try:
                body = resp.text
            except Exception:
                continue

            err = self.detect.detect_errors(body)
            if err:
                self.scanner.add_finding(Finding(
                    name="Application error message",
                    severity="medium", url=url,
                    detail=truncate(err, 100), cwe="CWE-200",
                    tags="info_disclosure",
                    category="PostCrawl",
                    check_name="Error_Message",
                ))

            ip = self.detect.detect_internal_ip(body)
            if ip:
                self.scanner.add_finding(Finding(
                    name="Internal IP disclosure", severity="low", url=url,
                    detail=f"IP: {ip}", cwe="CWE-200",
                    category="PostCrawl", check_name="Internal_IP",
                ))

            emails = self.detect.detect_emails(body)
            if emails:
                self.scanner.add_finding(Finding(
                    name="Email addresses found", severity="info", url=url,
                    detail=", ".join(list(set(emails))[:10]),
                    category="PostCrawl", check_name="Email_Addresses",
                ))

            ccs = self.detect.detect_credit_cards(body)
            if ccs:
                self.scanner.add_finding(Finding(
                    name="Credit card disclosure", severity="high", url=url,
                    detail=f"{len(ccs)} cards", cwe="CWE-200",
                    category="PostCrawl", check_name="Credit_Card",
                ))

            pk = self.detect.detect_private_key(body)
            if pk:
                self.scanner.add_finding(Finding(
                    name="Private key exposed", severity="critical",
                    url=url, detail=pk, cwe="CWE-321",
                    category="PostCrawl", check_name="Private_Key",
                ))

            up = self.detect.detect_path_disclosure_unix(body)
            if up:
                self.scanner.add_finding(Finding(
                    name="Path disclosure (Unix)", severity="low", url=url,
                    detail=up, cwe="CWE-200",
                    category="PostCrawl",
                    check_name="Path_Disclosure_Unix",
                ))

            wp = self.detect.detect_path_disclosure_windows(body)
            if wp:
                self.scanner.add_finding(Finding(
                    name="Path disclosure (Windows)", severity="low",
                    url=url, detail=wp, cwe="CWE-200",
                    category="PostCrawl",
                    check_name="Path_Disclosure_Windows",
                ))

            src = self.detect.detect_source_code(body)
            if src:
                self.scanner.add_finding(Finding(
                    name="Source code disclosure", severity="high",
                    url=url, detail=src, cwe="CWE-540",
                    category="PostCrawl", check_name="Source_Code",
                ))