#!/usr/bin/env python3
"""
OAST Client v6.9.0
==================
- Auto-finds available port
- SILENT fallback — no spam when port blocked
- Works even if OAST can't start
"""
import time
import socket
import secrets
import threading
from typing import Dict, List, Optional


class OASTClient:
    """Client for OAST interactions."""

    def __init__(self, config: Optional[Dict] = None):
        config = config or {}
        self.config = config
        self.mode = config.get("mode", "local")
        self.tokens: Dict[str, float] = {}
        self.lock = threading.Lock()

        self._server = None
        self.store = None
        self._available = False

        self.base_domain = config.get("domain", "oast.local")
        self.http_port = int(config.get("port", 8000))
        self.dns_port = int(config.get("dns_port", 5353))
        self.public_ip = config.get("public_ip")
        self.base_url = config.get("base_url")
        self.interactsh_url = config.get("interactsh_url",
                                        "https://interact.sh")

        if self.mode == "local":
            self._start_local_server()

    # ═══════════════════════════════════════════════════════════════════════
    #  Server lifecycle
    # ═══════════════════════════════════════════════════════════════════════

    def _find_available_port(self, start_port: int, max_attempts: int = 20) -> int:
        for offset in range(max_attempts):
            port = start_port + offset
            if self._is_port_available(port):
                return port
        return 0

    def _is_port_available(self, port: int) -> bool:
        """Check the same bind address used by OASTServer."""
        host = self.config.get("host", "0.0.0.0")
        # 0.0.0.0 is more conservative for Windows: a port can be free on
        # 127.0.0.1 but still unavailable for a wildcard bind.
        bind_host = "0.0.0.0" if host in ("0.0.0.0", "", None) else host
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(0.5)
            s.bind((bind_host, port))
            s.close()
            return True
        except (OSError, socket.error):
            try:
                s.close()
            except Exception:
                pass
            return False

    def _start_local_server(self):
        """Start local OAST server — quiet on failure."""
        try:
            from .server import OASTServer
        except ImportError:
            return

        ports_to_try = []
        # Try the requested port first, then a wider range. Windows may have
        # excluded/reserved individual ports that still pass a weak probe.
        for port in [self.http_port] + list(range(self.http_port + 1, self.http_port + 51)):
            if 1 <= port <= 65535 and port not in ports_to_try and self._is_port_available(port):
                ports_to_try.append(port)

        for port in ports_to_try:
            try:
                self._server = OASTServer(
                    host=self.config.get("host", "0.0.0.0"),
                    http_port=port,
                    dns_port=self.dns_port,
                    base_domain=self.base_domain,
                    public_ip=self.public_ip,
                    ttl_seconds=self.config.get("ttl", 3600),
                )
                self._server.verbose = bool(self.config.get("verbose"))
                self._server.start()

                if self._server.is_http_running():
                    self.store = self._server.store
                    self.public_ip = self._server.public_ip
                    self.http_port = port
                    self._available = True

                    # Silent success message — only show if verbose
                    if self.config.get("verbose"):
                        print(f"[OAST] Server running on port {port}")
                    return
                else:
                    try:
                        self._server.stop()
                    except Exception:
                        pass
                    self._server = None

            except OSError:
                continue
            except Exception:
                self._server = None
                return

        # All attempts failed — silent
        self._server = None
        self._available = False

    def stop(self):
        if self._server:
            try:
                self._server.stop()
            except Exception:
                pass
            self._server = None
        self._available = False

    def is_available(self) -> bool:
        return self._available

    # ═══════════════════════════════════════════════════════════════════════
    #  Tokens
    # ═══════════════════════════════════════════════════════════════════════

    def generate_token(self) -> str:
        if not self._available:
            return ""
        token = secrets.token_hex(16)
        with self.lock:
            self.tokens[token] = time.time()
        if self.store:
            self.store.register_token(token)
        return token

    # ═══════════════════════════════════════════════════════════════════════
    #  URLs
    # ═══════════════════════════════════════════════════════════════════════

    def get_url(self, token: str, path: str = "") -> str:
        if not token:
            return ""
        if self.mode == "local":
            base = f"http://{token}.{self.base_domain}:{self.http_port}/"
        elif self.mode == "remote" and self.base_url:
            base = f"{self.base_url.rstrip('/')}/{token}"
        elif self.mode == "interactsh":
            domain = (self.interactsh_url
                     .replace("https://", "")
                     .replace("http://", "")
                     .rstrip("/"))
            base = f"http://{token}.{domain}"
        else:
            base = f"http://{token}.{self.base_domain}:{self.http_port}/"

        if path:
            base = base.rstrip("/") + "/" + path.lstrip("/")
        return base

    def get_dns(self, token: str) -> str:
        if not token:
            return ""
        return f"{token}.{self.base_domain}"

    # ═══════════════════════════════════════════════════════════════════════
    #  Interactions
    # ═══════════════════════════════════════════════════════════════════════

    def get_interactions(self, token: str) -> List[Dict]:
        if not self._available or not self.store:
            return []
        return self.store.get(token)

    def has_interactions(self, token: str) -> bool:
        return bool(self.get_interactions(token))

    def poll(self, token: str, timeout: int = 10,
            interval: float = 0.5) -> List[Dict]:
        if not self._available:
            return []
        start = time.time()
        while time.time() - start < timeout:
            hits = self.get_interactions(token)
            if hits:
                return hits
            time.sleep(interval)
        return []

    def wait_multi(self, tokens: List[str],
                  timeout: int = 10) -> Dict[str, List[Dict]]:
        if not self._available:
            return {t: [] for t in tokens}
        start = time.time()
        remaining = set(tokens)
        results = {t: [] for t in tokens}
        while time.time() - start < timeout and remaining:
            for token in list(remaining):
                hits = self.get_interactions(token)
                if hits:
                    results[token] = hits
                    remaining.discard(token)
            if remaining:
                time.sleep(0.5)
        return results

    # ═══════════════════════════════════════════════════════════════════════
    #  Stats
    # ═══════════════════════════════════════════════════════════════════════

    def get_stats(self) -> Dict:
        if self.store:
            try:
                return self.store.stats()
            except Exception:
                return {}
        return {}

    def info(self) -> Dict:
        info = {
            "mode": self.mode,
            "available": self._available,
            "base_domain": self.base_domain,
            "http_port": self.http_port,
            "dns_port": self.dns_port,
            "public_ip": self.public_ip,
            "tokens_generated": len(self.tokens),
        }
        if self._server:
            try:
                info.update(self._server.info())
            except Exception:
                pass
        return info