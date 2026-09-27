#!/usr/bin/env python3
"""
Phase 4: PostCrawl v6.8.0
=========================
- Text analysis of crawled pages
- Backup file discovery
- STRICT filtering — skips static/docs/assets
- Confidence values on all findings
"""
import re
import threading
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.utils import safe_url_join, is_clean_path, truncate
from ..finding import Finding


class PhasePostCrawl:
    """Post-crawl analysis with strict validation."""

    # ═══════════════════════════════════════════════════════════════════════
    #  Files to SKIP (they are not real app pages)
    # ═══════════════════════════════════════════════════════════════════════
    SKIP_EXTS = (
        # Docs
        '.md', '.markdown', '.rst', '.txt', '.pdf', '.rtf', '.doc', '.docx',
        # Source code
        '.py', '.rb', '.go', '.rs', '.java', '.cs', '.c', '.cpp', '.h',
        '.sh', '.bat', '.ps1', '.pl', '.pm',
        # Web assets
        '.css', '.js', '.map', '.min.js', '.min.css',
        # Media
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.mp4', '.mp3', '.avi', '.mov', '.webm', '.wav', '.ogg',
        # Archives
        '.zip', '.gz', '.tar', '.rar', '.7z', '.bz2',
        # Data
        '.json', '.xml', '.yaml', '.yml', '.csv', '.tsv',
        # Misc
        '.exe', '.dll', '.so', '.bin', '.iso',
    )

    SKIP_PATH_PARTS = (
        '/documentation/', '/docs/', '/doc/', '/manual/',
        '/vendor/', '/node_modules/', '/bower_components/',
        '/.git/', '/.svn/', '/.hg/',
        '/examples/', '/samples/', '/demo/',
    )

    def __init__(self, scanner):
        self.scanner = scanner
        self.http = scanner.http
        self.db = scanner.db
        self.out = scanner.out
        self.detect = scanner.detect
        self.config = scanner.config

    # ═══════════════════════════════════════════════════════════════════════
    #  Main
    # ═══════════════════════════════════════════════════════════════════════

    def run(self, base_url):
        self.out.phase("Phase 4: PostCrawl Checks")

        # ─── Part A: PostCrawl URLs ───
        postcrawl_urls = [u for u in self.db.postcrawl_urls
                         if is_clean_path(u)]
        if postcrawl_urls:
            self._check_postcrawl_urls(base_url, postcrawl_urls)

        # ─── Part B: Backup files ───
        if self.db.backup_variants:
            self._check_backups(base_url)

        # ─── Part C: Text search ───
        self._text_search()

    # ═══════════════════════════════════════════════════════════════════════
    #  Part A: PostCrawl URLs
    # ═══════════════════════════════════════════════════════════════════════

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
                if err and self._is_real_error(body, err):
                    name = f"Application error: {url_path}"
                    detail = truncate(err, 80)

                if self.detect.detect_phpinfo(body):
                    name = f"phpinfo() found: {url_path}"

                self.scanner.add_finding(Finding(
                    name=name, severity=severity, url=full_url,
                    detail=detail, category="PostCrawl",
                    confidence=0.75,
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

    # ═══════════════════════════════════════════════════════════════════════
    #  Part B: Backup files
    # ═══════════════════════════════════════════════════════════════════════

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
                                    confidence=0.8,
                                ))

    # ═══════════════════════════════════════════════════════════════════════
    #  Part C: Text search — STRICT
    # ═══════════════════════════════════════════════════════════════════════

    def _text_search(self):
        """Analyze only real HTML/text pages, skip assets/docs."""
        self.out.info("Text search on crawled pages")

        urls = list(self.scanner.crawled_urls)[:200]
        checked = 0
        skipped = 0

        for url in urls:
            if self.scanner.stop_event.is_set():
                break

            url_lower = url.lower().split('?')[0]

            # ─── Skip by extension ───
            if any(url_lower.endswith(ext) for ext in self.SKIP_EXTS):
                skipped += 1
                continue

            # ─── Skip by path ───
            if any(part in url_lower for part in self.SKIP_PATH_PARTS):
                skipped += 1
                continue

            resp = self.http.get(url, timeout=8)
            if not resp or resp.status_code != 200:
                continue

            # ─── Skip by content-type ───
            ct = resp.headers.get("Content-Type", "").lower()
            if not any(t in ct for t in
                      ("text/html", "application/xhtml",
                       "text/plain", "application/xml", "text/xml")):
                skipped += 1
                continue

            try:
                body = resp.text
            except Exception:
                continue

            if len(body) > 3 * 1024 * 1024:  # 3MB max
                skipped += 1
                continue

            # ─── Skip documentation-like pages ───
            if self._looks_like_documentation(body):
                skipped += 1
                continue

            checked += 1

            # ═══ Error messages ═══
            err = self.detect.detect_errors(body)
            if err and self._is_real_error(body, err):
                self.scanner.add_finding(Finding(
                    name="Application error message",
                    severity="medium", url=url,
                    detail=truncate(err, 100), cwe="CWE-200",
                    tags="info_disclosure,error_handling",
                    category="PostCrawl", check_name="Error_Message",
                    confidence=0.75,
                ))

            # ═══ Internal IP ═══
            ip_addr = self.detect.detect_internal_ip(body)
            if ip_addr:
                self.scanner.add_finding(Finding(
                    name="Internal IP disclosure",
                    severity="low", url=url,
                    detail=f"IP: {ip_addr}", cwe="CWE-200",
                    category="PostCrawl", check_name="Internal_IP",
                    confidence=0.85,
                ))

            # ═══ Emails ═══
            emails = self.detect.detect_emails(body)
            if emails:
                unique = list(set(emails))[:10]
                self.scanner.add_finding(Finding(
                    name="Email addresses found",
                    severity="info", url=url,
                    detail=", ".join(unique),
                    category="PostCrawl", check_name="Email_Addresses",
                    confidence=0.9,
                ))

            # ═══ Credit cards ═══
            ccs = self.detect.detect_credit_cards(body)
            if ccs:
                self.scanner.add_finding(Finding(
                    name="Credit card disclosure",
                    severity="high", url=url,
                    detail=f"{len(ccs)} cards", cwe="CWE-200",
                    category="PostCrawl", check_name="Credit_Card",
                    confidence=0.95,
                ))

            # ═══ Private key ═══
            pk = self.detect.detect_private_key(body)
            if pk:
                self.scanner.add_finding(Finding(
                    name="Private key exposed",
                    severity="critical", url=url,
                    detail=pk, cwe="CWE-321",
                    category="PostCrawl", check_name="Private_Key",
                    confidence=0.98,
                ))

            # ═══ Path disclosure ═══
            up = self.detect.detect_path_disclosure_unix(body)
            if up:
                self.scanner.add_finding(Finding(
                    name="Path disclosure (Unix)",
                    severity="low", url=url,
                    detail=up, cwe="CWE-200",
                    category="PostCrawl",
                    check_name="Path_Disclosure_Unix",
                    confidence=0.85,
                ))

            wp = self.detect.detect_path_disclosure_windows(body)
            if wp:
                self.scanner.add_finding(Finding(
                    name="Path disclosure (Windows)",
                    severity="low", url=url,
                    detail=wp, cwe="CWE-200",
                    category="PostCrawl",
                    check_name="Path_Disclosure_Windows",
                    confidence=0.85,
                ))

            # ═══ Source code ═══
            src = self.detect.detect_source_code(body)
            if src:
                self.scanner.add_finding(Finding(
                    name="Source code disclosure",
                    severity="high", url=url,
                    detail=src, cwe="CWE-540",
                    category="PostCrawl", check_name="Source_Code",
                    confidence=0.9,
                ))

            # ═══ Env variables ═══
            env = self.detect.detect_env_variables(body)
            if env:
                self.scanner.add_finding(Finding(
                    name="Env variables disclosure",
                    severity="medium", url=url,
                    detail=env, cwe="CWE-200",
                    category="PostCrawl", check_name="Env_Variables",
                    confidence=0.85,
                ))

        self.out.info(
            f"Text search: {checked} pages analyzed, "
            f"{skipped} static/doc files skipped"
        )

    # ═══════════════════════════════════════════════════════════════════════
    #  Helpers
    # ═══════════════════════════════════════════════════════════════════════

    def _looks_like_documentation(self, body):
        """Detect docs/readme/help pages."""
        body_lower = body.lower()

        doc_indicators = [
            "readme", "documentation", "table of contents",
            "getting started", "installation guide",
            "changelog", "release notes", "user manual",
            "how to use", "tutorial",
        ]
        matches = sum(1 for ind in doc_indicators
                     if ind in body_lower[:3000])

        m = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
        if m:
            title = m.group(1).lower()
            if any(kw in title for kw in
                  ['readme', 'documentation', 'guide', 'manual']):
                return True

        return matches >= 3

    def _is_real_error(self, body, error_pattern):
        """Validate that the error is real (not documentation)."""
        error_lower = error_pattern.lower()

        idx = body.lower().find(error_lower)
        if idx == -1:
            return True

        context = body[max(0, idx - 200):min(len(body), idx + 200)]
        context_lower = context.lower()

        # ─── Reject if quoted (mentioned in docs) ───
        doc_quotes = [
            f'"{error_lower}', f"'{error_lower}",
            'for example', 'such as', 'like when',
            'if you see', 'if you get', 'error looks like',
            'you might see', 'documented',
        ]
        for q in doc_quotes:
            if q in context_lower:
                return False

        # ─── Require line number or stack trace ───
        if 'on line' in error_lower or 'at line' in error_lower:
            return True
        if 'stack trace' in error_lower or 'traceback' in error_lower:
            return True

        # ─── Generic warnings need line number nearby ───
        stripped = error_lower.strip()
        if stripped in ('fatal error:', 'warning:', 'notice:'):
            if not re.search(r'line \d+', context, re.I):
                return False

        return True