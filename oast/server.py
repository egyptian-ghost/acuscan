#!/usr/bin/env python3
"""
OAST Server
===========
Combined HTTP + DNS server for out-of-band interaction capture.

Usage (standalone):
    server = OASTServer(http_port=8000, dns_port=5353, base_domain="oast.local")
    server.start()
    ...
    server.stop()

Usage (integrated):
    The OASTClient in oast/client.py wraps this automatically.
"""
import os
import socket
import threading
from http.server import ThreadingHTTPServer
from typing import Optional

from .store import InteractionStore
from .http_handler import OASTHTTPHandler, OASTRouter
from .dns_handler import OASTDNSResolver, HAS_DNSLIB, DNSServer


class OASTServer:
    """
    Combined HTTP + DNS OAST server.

    Runs in background threads so the main process can continue.
    """

    def __init__(self, host: str = "0.0.0.0",
                 http_port: int = 8000,
                 dns_port: int = 5353,
                 base_domain: str = "oast.local",
                 public_ip: Optional[str] = None,
                 ttl_seconds: int = 3600):
        self.host = host
        self.http_port = http_port
        self.dns_port = dns_port
        self.base_domain = base_domain
        self.public_ip = public_ip or self._detect_local_ip()
        self.ttl_seconds = ttl_seconds
        self.verbose = False

        self.store = InteractionStore(ttl_seconds=ttl_seconds)
        self.router = OASTRouter(self.store, base_domain)

        self.http_server: Optional[ThreadingHTTPServer] = None
        self.dns_server = None
        self._http_thread: Optional[threading.Thread] = None

    # ═══════════════════════════════════════════════════════════════════════
    #  Lifecycle
    # ═══════════════════════════════════════════════════════════════════════

    def start(self):
        """Start HTTP (and optionally DNS) servers.

        Returns True when HTTP OAST is available. Port binding failures are
        normal on developer machines (reserved/occupied Windows ports), so
        callers can fall back without making the scanner look broken.
        """
        verbose = bool(getattr(self, "verbose", False))
        # Start HTTP
        OASTHTTPHandler.router = self.router
        try:
            self.http_server = ThreadingHTTPServer(
                (self.host, self.http_port), OASTHTTPHandler
            )
            self.http_server.daemon_threads = True
            self._http_thread = threading.Thread(
                target=self.http_server.serve_forever,
                daemon=True,
            )
            self._http_thread.start()
        except OSError as e:
            if verbose:
                print(f"[OAST] HTTP server failed on port {self.http_port}: {e}")
            self.http_server = None

        # Start DNS (optional)
        if HAS_DNSLIB:
            try:
                resolver = OASTDNSResolver(self.router, self.public_ip)
                self.dns_server = DNSServer(
                    resolver,
                    port=self.dns_port,
                    address=self.host,
                )
                self.dns_server.start_thread()
            except Exception as e:
                if verbose:
                    print(f"[OAST] DNS server failed on port {self.dns_port}: {e}")
                self.dns_server = None

        return self.http_server is not None

    def stop(self):
        """Stop all servers."""
        if self.http_server:
            try:
                self.http_server.shutdown()
                self.http_server.server_close()
            except Exception:
                pass
        if self.dns_server:
            try:
                self.dns_server.stop()
            except Exception:
                pass
        try:
            self.store.stop()
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════════
    #  Helpers
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def _detect_local_ip() -> str:
        """Detect the local (LAN) IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def is_http_running(self) -> bool:
        return self.http_server is not None

    def is_dns_running(self) -> bool:
        return self.dns_server is not None

    def get_url(self, token: str) -> str:
        """Return the HTTP URL for a token."""
        return f"http://{token}.{self.base_domain}:{self.http_port}/"

    def get_dns_name(self, token: str) -> str:
        """Return the DNS name for a token."""
        return f"{token}.{self.base_domain}"

    def info(self) -> dict:
        """Return server info."""
        return {
            "host": self.host,
            "http_port": self.http_port,
            "dns_port": self.dns_port,
            "base_domain": self.base_domain,
            "public_ip": self.public_ip,
            "http_running": self.is_http_running(),
            "dns_running": self.is_dns_running(),
            "dnslib_available": HAS_DNSLIB,
        }


# ═══════════════════════════════════════════════════════════════════════════════
#  Standalone CLI
# ═══════════════════════════════════════════════════════════════════════════════

def _standalone_main():
    """CLI entry point for running OAST as standalone server."""
    import argparse
    import time

    parser = argparse.ArgumentParser(
        description="AcuScan OAST Server v6.0"
    )
    parser.add_argument("--host", default="0.0.0.0",
                       help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000,
                       help="HTTP port (default: 8000)")
    parser.add_argument("--dns-port", type=int, default=5353,
                       help="DNS port (default: 5353)")
    parser.add_argument("--domain", default="oast.local",
                       help="Base domain (default: oast.local)")
    parser.add_argument("--public-ip",
                       help="Public IP to return in URLs")
    parser.add_argument("--ttl", type=int, default=3600,
                       help="Token TTL in seconds (default: 3600)")
    args = parser.parse_args()

    print("=" * 70)
    print("  AcuScan OAST Server v6.0")
    print("=" * 70)

    server = OASTServer(
        host=args.host,
        http_port=args.port,
        dns_port=args.dns_port,
        base_domain=args.domain,
        public_ip=args.public_ip,
        ttl_seconds=args.ttl,
    )
    server.start()

    info = server.info()
    print(f"  HTTP listening on:  http://{info['public_ip']}:{args.port}")
    if info['dns_running']:
        print(f"  DNS listening on:   {info['public_ip']}:{args.dns_port}")
    elif not info['dnslib_available']:
        print(f"  DNS:                DISABLED (install dnslib)")
    else:
        print(f"  DNS:                FAILED to start")
    print(f"  Base domain:        {args.domain}")
    print(f"  Example URL:        http://<token>.{args.domain}:{args.port}/")
    print()
    print("  Configure DNS: point *.{domain} → {ip}".format(
        domain=args.domain, ip=info['public_ip']))
    print("  Or add to hosts file:")
    print(f"    {info['public_ip']}  test.{args.domain}")
    print()
    print("  Press Ctrl+C to stop.")
    print("=" * 70)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        server.stop()


if __name__ == "__main__":
    _standalone_main()