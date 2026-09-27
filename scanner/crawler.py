#!/usr/bin/env python3
"""
Web Crawler v6.9.0
==================
- Discovers URLs, forms, parameters
- Records everything into a CrawlMap
- Progress logging every 10 seconds
- Global time limit awareness
- Handles slow sites gracefully
"""
import re
import time
import warnings
from urllib.parse import urlparse, urljoin, parse_qs
from collections import defaultdict

try:
    from bs4 import BeautifulSoup
    try:
        from bs4 import XMLParsedAsHTMLWarning
    except ImportError:
        XMLParsedAsHTMLWarning = Warning
    HAS_BS4 = True
except ImportError:
    BeautifulSoup = None
    XMLParsedAsHTMLWarning = Warning
    HAS_BS4 = False

from .crawl_map import CrawlNode


class Crawler:
    """Breadth-first crawler with progress logging."""

    def __init__(self, http_client, config, out):
        self.http = http_client
        self.config = config
        self.out = out
        self.crawl_map = None
        self._stop_event = None

        self.crawled_urls = set()
        self.crawled_forms = []
        self.crawled_params = defaultdict(set)

    def set_stop_event(self, event):
        self._stop_event = event

    def set_crawl_map(self, crawl_map):
        self.crawl_map = crawl_map

    # ═══════════════════════════════════════════════════════════════════════
    #  Main crawl
    # ═══════════════════════════════════════════════════════════════════════

    def crawl(self, base_url, max_depth=3, max_pages=200):
        self.out.phase("Crawl",
                      f"max_depth={max_depth}, max_pages={max_pages}")
        self.out.info(f"Starting crawl from: {base_url}")

        visited = set()
        queue = [(base_url, 0, "")]
        parsed_base = urlparse(base_url)
        base_netloc = parsed_base.netloc

        # ═══ Progress tracking ═══
        start_time = time.time()
        last_log = start_time
        consecutive_failures = 0

        while queue and len(visited) < max_pages:
            if self._stop_event and self._stop_event.is_set():
                break

            url, depth, parent_url = queue.pop(0)
            if url in visited or depth > max_depth:
                continue

            visited.add(url)

            # ═══ Fetch with timing ═══
            fetch_start = time.time()
            resp = self.http.get(url, timeout=self.config.get("timeout", 10))
            elapsed_ms = (time.time() - fetch_start) * 1000

            if not resp:
                consecutive_failures += 1

                if self.crawl_map:
                    self.crawl_map.record(CrawlNode(
                        url=url, method="GET", depth=depth,
                        parent_url=parent_url,
                        response_time_ms=elapsed_ms,
                        error="Connection failed/timeout",
                    ))

                # ─── Stop after too many consecutive failures ───
                if consecutive_failures >= 15:
                    self.out.warn(
                        f"Crawl: 15 consecutive failures — "
                        f"target may be unreachable. Stopping."
                    )
                    break

                # ─── Progress log ───
                self._maybe_log_progress(
                    start_time, last_log, len(visited),
                    len(queue), depth
                )
                if time.time() - last_log >= 10:
                    last_log = time.time()
                continue

            consecutive_failures = 0
            self.crawled_urls.add(url)

            try:
                body = resp.text
            except Exception:
                body = ""

            # ═══ Record in crawl map ═══
            content_type = resp.headers.get('Content-Type', '')
            params = parse_qs(urlparse(url).query)

            # Title
            title = ""
            if HAS_BS4:
                try:
                    m = re.search(r'<title[^>]*>(.*?)</title>',
                                 body, re.I | re.S)
                    if m:
                        title = m.group(1).strip()[:200]
                except Exception:
                    pass

            params_for_node = list(params.keys())
            for pname in params:
                self.crawled_params[url].add(pname)

            # Parse links
            links_count = 0
            forms_found = []

            if HAS_BS4:
                try:
                    # XHTML/XML responses should not be fed to the HTML parser.
                    # Use lxml-xml when available; otherwise suppress only the
                    # specific BeautifulSoup warning and keep scanning.
                    ctype = content_type.lower()
                    looks_xml = (
                        'application/xml' in ctype or
                        'text/xml' in ctype or
                        'application/xhtml+xml' in ctype or
                        body.lstrip().startswith('<?xml')
                    )
                    if looks_xml:
                        try:
                            soup = BeautifulSoup(body, 'xml')
                        except Exception:
                            with warnings.catch_warnings():
                                warnings.simplefilter('ignore', XMLParsedAsHTMLWarning)
                                soup = BeautifulSoup(body, 'html.parser')
                    else:
                        soup = BeautifulSoup(body, 'html.parser')

                    for tag in soup.find_all(['a', 'link', 'area'], href=True):
                        link = tag['href']
                        if not link or link.startswith(('javascript:',
                                                       'mailto:',
                                                       'tel:', '#')):
                            continue
                        abs_url = urljoin(url, link)
                        p = urlparse(abs_url)
                        if p.netloc == base_netloc:
                            links_count += 1
                            if abs_url not in visited:
                                queue.append((abs_url, depth + 1, url))
                        else:
                            if self.crawl_map:
                                self.crawl_map.record(CrawlNode(
                                    url=abs_url,
                                    depth=depth + 1,
                                    parent_url=url,
                                ))

                    for tag in soup.find_all(['script', 'img', 'iframe'],
                                            src=True):
                        try:
                            abs_url = urljoin(url, tag['src'])
                            self.crawled_urls.add(abs_url)
                        except Exception:
                            pass

                    for form in soup.find_all('form'):
                        action = form.get('action', '')
                        method = form.get('method', 'GET').upper()
                        abs_action = urljoin(url, action) if action else url

                        inputs = []
                        for inp in form.find_all(['input', 'textarea',
                                                 'select']):
                            inp_name = inp.get('name', '')
                            if inp_name:
                                inputs.append({
                                    "name": inp_name,
                                    "type": inp.get('type', 'text'),
                                    "value": inp.get('value', ''),
                                })
                                self.crawled_params[abs_action].add(inp_name)

                        if inputs:
                            form_record = {
                                "action": abs_action,
                                "method": method,
                                "inputs": inputs,
                                "source": url,
                            }
                            self.crawled_forms.append(form_record)
                            forms_found.append({
                                "action": abs_action,
                                "method": method,
                                "fields": [i["name"] for i in inputs],
                            })

                except Exception as e:
                    if self.config.get("verbose"):
                        self.out.warn(f"Parse error on {url}: {e}")
            else:
                for m in re.finditer(r'href=["\'](.*?)["\']', body, re.I):
                    link = m.group(1)
                    abs_url = urljoin(url, link)
                    p = urlparse(abs_url)
                    if p.netloc == base_netloc:
                        links_count += 1
                        if abs_url not in visited:
                            queue.append((abs_url, depth + 1, url))

            # ═══ Record node ═══
            if self.crawl_map:
                self.crawl_map.record(CrawlNode(
                    url=url,
                    status=resp.status_code,
                    content_type=content_type,
                    content_length=len(resp.content),
                    method="GET",
                    depth=depth,
                    parent_url=parent_url,
                    title=title,
                    forms=forms_found,
                    parameters=params_for_node,
                    links_found=links_count,
                    response_time_ms=elapsed_ms,
                ))

            # ═══ Progress log every 10 seconds ═══
            if time.time() - last_log >= 10:
                self._log_progress(start_time, len(visited), len(queue), depth)
                last_log = time.time()

        # ═══ Summary ═══
        elapsed = time.time() - start_time
        total_params = sum(len(v) for v in self.crawled_params.values())

        self.out.success(
            f"Crawl complete in {elapsed:.1f}s — "
            f"{len(self.crawled_urls)} URLs, "
            f"{len(self.crawled_forms)} forms, "
            f"{total_params} params"
        )

        if self.crawl_map:
            stats = self.crawl_map.get_stats()
            self.out.info(
                f"Crawl map: {stats.get('internal', 0)} internal, "
                f"{stats.get('external', 0)} external"
            )

    def _log_progress(self, start_time, checked, queued, depth):
        """Log current progress."""
        elapsed = time.time() - start_time
        rate = checked / elapsed if elapsed > 0 else 0
        self.out.info(
            f"Crawl: {checked} checked, "
            f"{queued} queued, "
            f"{rate:.1f} URLs/s, "
            f"depth={depth}, "
            f"elapsed={int(elapsed)}s"
        )

    def _maybe_log_progress(self, start_time, last_log, checked, queued, depth):
        """Log progress on failure path (throttled)."""
        if time.time() - last_log >= 10:
            self._log_progress(start_time, checked, queued, depth)