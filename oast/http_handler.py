#!/usr/bin/env python3
"""
OAST HTTP Handler
=================
Captures incoming HTTP requests and extracts correlation tokens
from either the hostname (subdomain) or the path.
"""
import re
from http.server import BaseHTTPRequestHandler
from typing import Optional, Dict


class OASTRouter:
    """
    Extracts tokens from HTTP requests and records interactions.
    Separated from the handler so it can be shared with the DNS resolver.
    """

    # Token format: 32+ hex characters (from secrets.token_hex(16))
    TOKEN_PATTERN = re.compile(r"([a-f0-9]{16,64})", re.I)

    def __init__(self, store, base_domain: str = "oast.local"):
        self.store = store
        self.base_domain = base_domain

    def extract_token(self, host: str, path: str) -> Optional[str]:
        """
        Extract a token from the request.

        Priority:
          1. Subdomain matching pattern (e.g. abc123.oast.local)
          2. First subdomain regardless of base_domain
          3. Token anywhere in path
        """
        # From host
        if host:
            host_clean = host.split(':')[0]  # strip port

            # If we know our base domain, extract subdomain
            if self.base_domain and host_clean.endswith(self.base_domain):
                sub = host_clean[:-len(self.base_domain)].rstrip('.')
                if sub:
                    # Sub might be "abc123" or "abc123.extra"
                    parts = sub.split('.')
                    for part in parts:
                        m = self.TOKEN_PATTERN.match(part)
                        if m:
                            return m.group(1)

            # Fallback: any subdomain
            first = host_clean.split('.')[0]
            m = self.TOKEN_PATTERN.match(first)
            if m:
                return m.group(1)

        # From path
        if path:
            m = self.TOKEN_PATTERN.search(path)
            if m:
                return m.group(1)

        return None

    def record(self, token: str, source_ip: str, method: str, path: str,
              headers: Dict, body: str, protocol: str = "http",
              host: str = "") -> None:
        """Record an interaction (if token is valid)."""
        if not token:
            return
        import time
        from datetime import datetime, timezone

        # Truncate large bodies
        body_truncated = (body or "")[:4000]

        # Extract useful headers
        user_agent = ""
        referer = ""
        content_type = ""
        try:
            headers_lower = {k.lower(): v for k, v in (headers or {}).items()}
            user_agent = headers_lower.get("user-agent", "")
            referer = headers_lower.get("referer", "")
            content_type = headers_lower.get("content-type", "")
        except Exception:
            pass

        interaction = {
            "timestamp": time.time(),
            "datetime": datetime.now(timezone.utc).isoformat(),
            "token": token,
            "source_ip": source_ip,
            "method": method,
            "path": path,
            "host": host,
            "protocol": protocol,
            "user_agent": user_agent,
            "referer": referer,
            "content_type": content_type,
            "headers": dict(headers or {}),
            "body": body_truncated,
        }
        self.store.add(token, interaction)


class OASTHTTPHandler(BaseHTTPRequestHandler):
    """HTTP handler for OAST server."""

    router: Optional[OASTRouter] = None
    server_version = "AcuScan-OAST/6.0"

    def log_message(self, fmt, *args):
        # Silence default HTTP logs
        pass

    def _handle(self, method: str):
        try:
            host = self.headers.get('Host', '')
            path = self.path or '/'

            # Read body
            body = ""
            if method in ('POST', 'PUT', 'PATCH'):
                try:
                    length = int(self.headers.get('Content-Length', 0) or 0)
                    if length > 0:
                        raw = self.rfile.read(min(length, 65536))
                        try:
                            body = raw.decode('utf-8', 'ignore')
                        except Exception:
                            body = str(raw[:2000])
                except Exception:
                    pass

            token = None
            source_ip = "unknown"
            try:
                source_ip = self.client_address[0]
            except Exception:
                pass

            if self.router:
                token = self.router.extract_token(host, path)
                if token:
                    self.router.record(
                        token, source_ip, method, path,
                        dict(self.headers), body,
                        protocol="http", host=host,
                    )

            # Send plausible response
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Server', 'nginx/1.24.0')
            self.send_header('X-OAST', 'AcuScan')
            self.send_header('Connection', 'close')
            self.end_headers()

            # If it's a metadata endpoint probe, respond with fake data
            response_text = "OK"
            if "metadata" in path.lower() or "169.254" in host:
                response_text = (
                    "ami-id: ami-acuscan-probe\n"
                    "instance-id: i-acuscan-probe\n"
                    "hostname: acuscan.local\n"
                )
            elif "user-data" in path.lower():
                response_text = "#cloud-config\nacuscan: probe\n"

            try:
                self.wfile.write(response_text.encode())
            except Exception:
                pass
        except Exception:
            pass

    def do_GET(self):     self._handle('GET')
    def do_POST(self):    self._handle('POST')
    def do_PUT(self):     self._handle('PUT')
    def do_HEAD(self):    self._handle('HEAD')
    def do_OPTIONS(self): self._handle('OPTIONS')
    def do_DELETE(self):  self._handle('DELETE')
    def do_PATCH(self):   self._handle('PATCH')