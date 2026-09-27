#!/usr/bin/env python3
"""
HTTP Client for Verification
=============================
Wraps a base HTTP client to provide HTTPExchange objects with full
raw request/response capture, timing measurement, and differential analysis.

Important: Uses a FRESH session per request to avoid cookie state affecting
boolean/time-based tests.
"""
import time
import hashlib
from typing import Optional, Dict, List, Tuple
from urllib.parse import urlparse, parse_qs, urlencode
import requests

from .models import HTTPExchange


class VerificationHTTPClient:
    """
    HTTP client wrapper that produces HTTPExchange objects for verification.
    """

    def __init__(self, base_client, config=None):
        """
        Args:
            base_client: HTTPClient from scanner (for auth reuse)
            config: Optional verification config
        """
        self.base_client = base_client
        self.config = config or {}
        self.timeout = self.config.get("timeout", 15)
        self._baseline_cache = {}

    # ═══════════════════════════════════════════════════════════════════════
    #  Session management
    # ═══════════════════════════════════════════════════════════════════════

    def _new_session(self, use_auth=True) -> requests.Session:
        """
        Create a fresh session, copying auth context from base client.
        """
        s = requests.Session()
        s.verify = False
        s.max_redirects = 10

        if use_auth and self.base_client:
            try:
                # Copy headers (except ones that vary per-request)
                for k, v in self.base_client.session.headers.items():
                    if k.lower() not in ('host', 'content-length'):
                        s.headers[k] = v
                # Copy cookies
                for c in self.base_client.session.cookies:
                    s.cookies.set(c.name, c.value)
                # Copy auth
                if self.base_client.session.auth:
                    s.auth = self.base_client.session.auth
                # Copy proxies
                if self.base_client.session.proxies:
                    s.proxies = dict(self.base_client.session.proxies)
            except Exception:
                pass
        return s

    # ═══════════════════════════════════════════════════════════════════════
    #  Core request method
    # ═══════════════════════════════════════════════════════════════════════

    def request(self, method, url, use_auth=True, **kwargs) -> HTTPExchange:
        """
        Perform an HTTP request and return HTTPExchange with full metadata.
        """
        session = self._new_session(use_auth=use_auth)
        kwargs.setdefault('verify', False)
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('allow_redirects',
                         self.config.get('follow_redirects', True))

        start = time.time()
        try:
            resp = session.request(method, url, **kwargs)
            elapsed_ms = (time.time() - start) * 1000
        except requests.exceptions.Timeout:
            elapsed_ms = (time.time() - start) * 1000
            return HTTPExchange(
                method=method, url=url,
                response_status=0,
                response_time_ms=elapsed_ms,
            )
        except Exception:
            elapsed_ms = (time.time() - start) * 1000
            return HTTPExchange(
                method=method, url=url,
                response_status=0,
                response_time_ms=elapsed_ms,
            )
        finally:
            try:
                session.close()
            except Exception:
                pass

        # Build request metadata
        req_headers = {}
        req_body = ""
        try:
            req_headers = dict(resp.request.headers)
            if resp.request.body:
                body = resp.request.body
                if isinstance(body, bytes):
                    try:
                        body = body.decode('utf-8', 'ignore')
                    except Exception:
                        body = str(body)
                req_body = str(body)
        except Exception:
            pass

        # Build response
        try:
            resp_text = resp.text
        except Exception:
            try:
                resp_text = resp.content.decode('utf-8', 'ignore')
            except Exception:
                resp_text = ""

        return HTTPExchange(
            method=method,
            url=resp.url if resp.url else url,
            request_headers=req_headers,
            request_body=req_body,
            response_status=resp.status_code,
            response_headers=dict(resp.headers),
            response_body=resp_text,
            response_time_ms=elapsed_ms,
        )

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def head(self, url, **kwargs):
        return self.request("HEAD", url, **kwargs)

    def options(self, url, **kwargs):
        return self.request("OPTIONS", url, **kwargs)

    # ═══════════════════════════════════════════════════════════════════════
    #  Injection helpers
    # ═══════════════════════════════════════════════════════════════════════

    def inject_get(self, url, param, payload, extra_params=None) -> HTTPExchange:
        """Inject a payload into a GET parameter."""
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            if extra_params:
                for k, v in extra_params.items():
                    qs[k] = [v]
            qs[param] = [payload]
            new_query = urlencode(qs, doseq=True)
            new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            return self.get(new_url)
        except Exception:
            return HTTPExchange(method="GET", url=url, response_status=0)

    def inject_post(self, url, param, payload, form_data=None,
                   method="POST", content_type=None) -> HTTPExchange:
        """Inject a payload into a POST parameter."""
        try:
            data = dict(form_data or {})
            data[param] = payload
            kwargs = {"data": data}
            if content_type:
                kwargs["headers"] = {"Content-Type": content_type}
            if method.upper() == "POST":
                return self.post(url, **kwargs)
            return self.request(method, url, **kwargs)
        except Exception:
            return HTTPExchange(method=method, url=url, response_status=0)

    # ═══════════════════════════════════════════════════════════════════════
    #  Baseline / differential analysis
    # ═══════════════════════════════════════════════════════════════════════

    def capture_baseline(self, url, param, method="GET", form_data=None,
                        samples=3) -> List[HTTPExchange]:
        """
        Capture baseline responses for differential comparison.
        Uses neutral value "1" so that injections can be compared.
        """
        key = f"{method}:{url}:{param}"
        if key in self._baseline_cache:
            return self._baseline_cache[key]

        exchanges = []
        for _ in range(samples):
            if method.upper() == "GET":
                ex = self.inject_get(url, param, "1")
            else:
                ex = self.inject_post(url, param, "1", form_data)
            exchanges.append(ex)

        self._baseline_cache[key] = exchanges
        return exchanges

    def similarity(self, a: HTTPExchange, b: HTTPExchange) -> float:
        """Compute similarity score 0.0-1.0 between two exchanges."""
        if not a or not b:
            return 0.0
        if a.response_status != b.response_status:
            return 0.0

        ha = hashlib.md5((a.response_body or "").encode()).hexdigest()
        hb = hashlib.md5((b.response_body or "").encode()).hexdigest()
        if ha == hb:
            return 1.0

        la = len(a.response_body or "")
        lb = len(b.response_body or "")
        if la == 0 and lb == 0:
            return 1.0
        maxlen = max(la, lb)
        if maxlen == 0:
            return 1.0
        return 1.0 - (abs(la - lb) / maxlen)

    def clear_baseline_cache(self):
        """Clear cached baselines (call between different URLs)."""
        self._baseline_cache = {}