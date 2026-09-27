#!/usr/bin/env python3
"""
HTTP Client v6.5.4
==================
Thread-safe HTTP client with rate limiting, auth, session, proxy.
"""
import time
import threading
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from core.rate_limiter import AdaptiveRateLimiter
from core.config import DEFAULT_UA
from .session_manager import SessionManager
from .proxy_chain import build_proxies, get_proxy_tags

# Disable warnings
try:
    import urllib3
    # Do not hide TLS warnings unless the user explicitly selected
    # --insecure-tls. Normal scans should validate certificates.
except Exception:
    urllib3 = None


class HTTPClient:
    def __init__(self, config):
        self.config = config
        self.rate_limiter = AdaptiveRateLimiter(
            config.get("rate_limit", 150)
        )
        self.request_count = 0
        self.error_count = 0
        self.lock = threading.Lock()
        self.session_mgr = SessionManager(config)
        self.authenticated = False
        self._log_file = config.get("request_log_file")
        self._log_fh = None
        if self._log_file:
            try:
                self._log_fh = open(self._log_file, 'a', encoding='utf-8')
            except Exception:
                self._log_fh = None
        self._build_session()
        if not self.config.get("verify_ssl", True) and urllib3 is not None:
            urllib3.disable_warnings()
        self._setup_auth()

    def _build_session(self):
        self.session = Session()
        self.session.verify = self.config.get("verify_ssl", True)
        self.session.headers.update({
            "User-Agent": self.config.get("user_agent", DEFAULT_UA),
            "Accept": ("text/html,application/xhtml+xml,application/xml;"
                      "q=0.9,*/*;q=0.8"),
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })

        retry = Retry(total=2, backoff_factor=0.3,
                     status_forcelist=[502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry,
                             pool_connections=100, pool_maxsize=100)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        # Custom headers
        for h in self.config.get("headers", []):
            if ':' in h:
                k, v = h.split(':', 1)
                self.session.headers[k.strip()] = v.strip()

        headers_file = self.config.get("headers_file")
        if headers_file:
            for k, v in self.session_mgr.load_headers_from_file(
                headers_file
            ).items():
                self.session.headers[k] = v

        # ═══ Cookies — main path ═══
        cookie_str = self.config.get("cookie")
        if cookie_str:
            parsed = self.session_mgr.parse_cookie_string(cookie_str)
            for k, v in parsed.items():
                self.session.cookies.set(k, v)
            print(f"[http_client] Loaded {len(parsed)} cookie(s) from "
                  f"config: {list(parsed.keys())}")

        cookie_file = self.config.get("cookie_file")
        if cookie_file:
            for k, v in self.session_mgr.load_cookies_from_file(
                cookie_file
            ).items():
                self.session.cookies.set(k, v)

        self.session_mgr.load_session(self.session)

        # Proxy chain
        proxies = build_proxies(self.config)
        if proxies:
            self.session.proxies = proxies
        for k, v in get_proxy_tags(self.config).items():
            self.session.headers[k] = v

    def _setup_auth(self):
        if self.config.get("auth"):
            user, _, pw = self.config["auth"].partition(':')
            self.session.auth = (user, pw)
            self.authenticated = True

        if self.config.get("bearer"):
            self.session.headers["Authorization"] = (
                f"Bearer {self.config['bearer']}"
            )
            self.authenticated = True

        if self.config.get("api_key"):
            header = self.config.get("api_key_header", "X-API-Key")
            self.session.headers[header] = self.config["api_key"]
            self.authenticated = True

        if self.config.get("auth_header"):
            k, _, v = self.config["auth_header"].partition(':')
            self.session.headers[k.strip()] = v.strip()
            self.authenticated = True

        if self.config.get("auto_login"):
            success = False
            if self.config.get("login_steps"):
                success = self.session_mgr.perform_multi_step_login(self.session)
            else:
                success = self.session_mgr.perform_login(self.session)
            if success:
                self.authenticated = True
                if self.config.get("session_file"):
                    self.session_mgr.save_session(self.session)

    def _log_request(self, method, url, resp):
        if not self._log_fh:
            return
        try:
            import json
            from datetime import datetime
            entry = {
                "ts": datetime.utcnow().isoformat(),
                "method": method,
                "url": url,
                "status": resp.status_code if resp else None,
                "len": len(resp.content) if resp else 0,
            }
            self._log_fh.write(json.dumps(entry) + "\n")
            self._log_fh.flush()
        except Exception:
            pass

    def request(self, method, url, **kwargs):
        self.rate_limiter.acquire()
        if (self.config.get("auto_login") and
            self.config.get("refresh_interval")):
            self.session_mgr.maybe_refresh(self.session)

        timeout = kwargs.pop('timeout', self.config.get("timeout", 10))
        allow_redirects = kwargs.pop('allow_redirects',
                                     self.config.get("follow_redirects", True))
        max_redirects = self.config.get("max_redirects", 10)

        if self.config.get("disable_redirects", False):
            allow_redirects = False

        try:
            kwargs.setdefault('verify', self.config.get('verify_ssl', True))
            kwargs.setdefault('timeout', timeout)
            kwargs.setdefault('allow_redirects', allow_redirects)
            if allow_redirects and max_redirects:
                self.session.max_redirects = max_redirects

            resp = self.session.request(method, url, **kwargs)
            with self.lock:
                self.request_count += 1
            if resp is not None:
                self.rate_limiter.report_response(resp.status_code)
            self._log_request(method, url, resp)
            return resp
        except Exception:
            with self.lock:
                self.error_count += 1
            return None

    def get(self, url, **kwargs):
        return self.request('GET', url, **kwargs)

    def post(self, url, **kwargs):
        return self.request('POST', url, **kwargs)

    def head(self, url, **kwargs):
        return self.request('HEAD', url, **kwargs)

    def options(self, url, **kwargs):
        return self.request('OPTIONS', url, **kwargs)

    def put(self, url, **kwargs):
        return self.request('PUT', url, **kwargs)