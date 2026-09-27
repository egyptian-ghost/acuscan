#!/usr/bin/env python3
"""
Server Info Collector v6.5
==========================
Collects detailed server information like Acunetix:
  - Server software & version
  - Operating system hints
  - Hosting / CDN / Reverse proxy
  - Response headers (full list)
  - Security headers (present/missing)
  - Technologies detected
  - SSL/TLS info (issuer, expires, protocol, cipher)
  - IP addresses
"""
import re
import ssl
import time
import socket
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse


@dataclass
class ServerInfo:
    """Detailed server information."""
    # Core
    url: str = ""
    host: str = ""
    ip_addresses: List[str] = field(default_factory=list)
    server: str = ""
    powered_by: str = ""
    aspnet_version: str = ""
    operating_system: str = ""

    # Hosting
    hosting_provider: str = ""
    cdn: str = ""
    reverse_proxy: str = ""

    # Network
    port: int = 0
    protocol: str = "http"
    response_time_ms: float = 0.0

    # Headers
    headers: Dict = field(default_factory=dict)
    security_headers: Dict = field(default_factory=dict)
    missing_security_headers: List[str] = field(default_factory=list)

    # SSL
    ssl_enabled: bool = False
    ssl_issuer: str = ""
    ssl_subject: str = ""
    ssl_expires: str = ""
    ssl_protocol: str = ""
    ssl_cipher: str = ""
    ssl_days_remaining: int = 0

    # Technologies
    technologies: List[Dict] = field(default_factory=list)

    # Timestamps
    scanned_at: str = ""

    # Errors
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "host": self.host,
            "ip_addresses": list(self.ip_addresses),
            "server": self.server,
            "powered_by": self.powered_by,
            "aspnet_version": self.aspnet_version,
            "operating_system": self.operating_system,
            "hosting_provider": self.hosting_provider,
            "cdn": self.cdn,
            "reverse_proxy": self.reverse_proxy,
            "port": self.port,
            "protocol": self.protocol,
            "response_time_ms": round(self.response_time_ms, 2),
            "headers": dict(self.headers),
            "security_headers": dict(self.security_headers),
            "missing_security_headers": list(self.missing_security_headers),
            "ssl_enabled": self.ssl_enabled,
            "ssl_issuer": self.ssl_issuer,
            "ssl_subject": self.ssl_subject,
            "ssl_expires": self.ssl_expires,
            "ssl_protocol": self.ssl_protocol,
            "ssl_cipher": self.ssl_cipher,
            "ssl_days_remaining": self.ssl_days_remaining,
            "technologies": list(self.technologies),
            "scanned_at": self.scanned_at,
            "errors": list(self.errors),
        }


class ServerInfoCollector:
    """Collects detailed server information."""

    # Standard security headers to check
    SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Content-Security-Policy",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Embedder-Policy",
        "Cross-Origin-Resource-Policy",
    ]

    def __init__(self, http_client, config):
        self.http = http_client
        self.config = config

    # ═══════════════════════════════════════════════════════════════════════
    #  Main entry
    # ═══════════════════════════════════════════════════════════════════════

    def collect(self, base_url: str) -> ServerInfo:
        info = ServerInfo()
        info.url = base_url
        info.scanned_at = time.strftime("%Y-%m-%dT%H:%M:%S")

        parsed = urlparse(base_url)
        info.host = parsed.hostname or ""
        info.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        info.protocol = parsed.scheme

        # ═══ DNS resolution ═══
        self._resolve_dns(info)

        # ═══ Fetch headers ═══
        self._fetch_headers(info, base_url)

        # ═══ Hosting / CDN detection ═══
        self._detect_hosting(info)

        # ═══ OS detection ═══
        self._detect_os(info)

        # ═══ Security headers check ═══
        self._check_security_headers(info)

        # ═══ Technologies (basic fingerprinting) ═══
        self._detect_technologies(info)

        # ═══ SSL/TLS ═══
        if parsed.scheme == "https":
            self._collect_ssl(info)

        return info

    # ═══════════════════════════════════════════════════════════════════════
    #  DNS
    # ═══════════════════════════════════════════════════════════════════════

    def _resolve_dns(self, info: ServerInfo):
        try:
            addrs = socket.getaddrinfo(info.host, info.port)
            info.ip_addresses = sorted(set(a[4][0] for a in addrs))
        except Exception as e:
            info.errors.append(f"DNS resolution failed: {e}")

    # ═══════════════════════════════════════════════════════════════════════
    #  Headers
    # ═══════════════════════════════════════════════════════════════════════

    def _fetch_headers(self, info: ServerInfo, base_url: str):
        try:
            start = time.time()
            resp = self.http.get(base_url, timeout=15)
            info.response_time_ms = (time.time() - start) * 1000

            if not resp:
                info.errors.append("No response")
                return

            info.headers = dict(resp.headers)
            info.server = resp.headers.get("Server", "")
            info.powered_by = resp.headers.get("X-Powered-By", "")
            info.aspnet_version = resp.headers.get("X-AspNet-Version", "")

            # Store all security headers present
            for h in self.SECURITY_HEADERS:
                if h in resp.headers:
                    info.security_headers[h] = resp.headers[h]
        except Exception as e:
            info.errors.append(f"Header fetch failed: {e}")

    def _check_security_headers(self, info: ServerInfo):
        for h in self.SECURITY_HEADERS:
            if h not in info.headers:
                info.missing_security_headers.append(h)

    # ═══════════════════════════════════════════════════════════════════════
    #  Hosting detection
    # ═══════════════════════════════════════════════════════════════════════

    def _detect_hosting(self, info: ServerInfo):
        headers_lower = " ".join(
            f"{k.lower()}:{v}".lower() for k, v in info.headers.items()
        )
        server = (info.server or "").lower()

        # ═══ CDN detection ═══
        if "cf-ray" in info.headers or "cloudflare" in headers_lower:
            info.cdn = "Cloudflare"
        elif "x-amz-cf-id" in headers_lower or "cloudfront" in headers_lower:
            info.cdn = "AWS CloudFront"
        elif "x-azure-ref" in headers_lower or "azurefd" in headers_lower:
            info.cdn = "Azure Front Door"
        elif "akamai" in headers_lower or "x-akamai" in headers_lower:
            info.cdn = "Akamai"
        elif "x-sucuri-id" in info.headers or "sucuri" in headers_lower:
            info.cdn = "Sucuri"
        elif "x-fastly" in headers_lower or "fastly" in headers_lower:
            info.cdn = "Fastly"
        elif "via" in info.headers and "varnish" in info.headers.get(
            "Via", ""
        ).lower():
            info.cdn = "Varnish (proxy)"

        # ═══ Reverse proxy detection ═══
        proxy_hints = []
        if "x-forwarded-for" in headers_lower:
            proxy_hints.append("X-Forwarded-For")
        if "x-forwarded-proto" in headers_lower:
            proxy_hints.append("X-Forwarded-Proto")
        if "x-real-ip" in headers_lower:
            proxy_hints.append("X-Real-IP")
        if proxy_hints:
            info.reverse_proxy = f"Detected ({', '.join(proxy_hints)})"

        # ═══ Hosting provider guess ═══
        if "nginx" in server:
            info.hosting_provider = "Linux / nginx"
        elif "apache" in server:
            info.hosting_provider = "Apache"
        elif "litespeed" in server:
            info.hosting_provider = "LiteSpeed"
        elif "iis" in server or "microsoft" in server:
            info.hosting_provider = "Windows / IIS"
        elif "cloudflare" in server:
            info.hosting_provider = "Cloudflare"

    # ═══════════════════════════════════════════════════════════════════════
    #  OS detection
    # ═══════════════════════════════════════════════════════════════════════

    def _detect_os(self, info: ServerInfo):
        server = (info.server or "").lower()
        powered = (info.powered_by or "").lower()

        if "ubuntu" in server:
            info.operating_system = "Ubuntu Linux"
        elif "debian" in server:
            info.operating_system = "Debian Linux"
        elif "centos" in server:
            info.operating_system = "CentOS Linux"
        elif "red hat" in server or "rhel" in server:
            info.operating_system = "Red Hat Enterprise Linux"
        elif "fedora" in server:
            info.operating_system = "Fedora Linux"
        elif "alpine" in server:
            info.operating_system = "Alpine Linux"
        elif "win" in server or "iis" in server or "microsoft" in server:
            info.operating_system = "Windows"
        elif "asp.net" in powered:
            info.operating_system = "Windows (ASP.NET)"
        elif "unix" in server:
            info.operating_system = "Unix"
        elif "linux" in server:
            info.operating_system = "Linux"
        elif "freebsd" in server:
            info.operating_system = "FreeBSD"
        else:
            info.operating_system = "Unknown"

    # ═══════════════════════════════════════════════════════════════════════
    #  Technology fingerprinting
    # ═══════════════════════════════════════════════════════════════════════

    def _detect_technologies(self, info: ServerInfo):
        """Basic tech detection from headers + cookies."""
        techs = []

        # Server
        if info.server:
            techs.append({
                "name": info.server,
                "category": "Server",
                "source": "Server header",
            })

        # Language hints
        if info.powered_by:
            techs.append({
                "name": info.powered_by,
                "category": "Language/Framework",
                "source": "X-Powered-By header",
            })

        if info.aspnet_version:
            techs.append({
                "name": f"ASP.NET {info.aspnet_version}",
                "category": "Framework",
                "source": "X-AspNet-Version header",
            })

        # Cookies -> language detection
        try:
            cookies_header = info.headers.get("Set-Cookie", "")
            if "PHPSESSID" in cookies_header:
                techs.append({
                    "name": "PHP",
                    "category": "Language",
                    "source": "Set-Cookie (PHPSESSID)",
                })
            if "ASP.NET_SessionId" in cookies_header:
                techs.append({
                    "name": "ASP.NET",
                    "category": "Framework",
                    "source": "Set-Cookie (ASP.NET_SessionId)",
                })
            if "JSESSIONID" in cookies_header:
                techs.append({
                    "name": "Java (Servlet)",
                    "category": "Language",
                    "source": "Set-Cookie (JSESSIONID)",
                })
            if "csrftoken" in cookies_header:
                techs.append({
                    "name": "Django",
                    "category": "Framework",
                    "source": "Set-Cookie (csrftoken)",
                })
            if "_rails" in cookies_header:
                techs.append({
                    "name": "Ruby on Rails",
                    "category": "Framework",
                    "source": "Set-Cookie (_rails)",
                })
        except Exception:
            pass

        # CDN
        if info.cdn:
            techs.append({
                "name": info.cdn,
                "category": "CDN",
                "source": "Headers analysis",
            })

        info.technologies = techs

    # ═══════════════════════════════════════════════════════════════════════
    #  SSL/TLS
    # ═══════════════════════════════════════════════════════════════════════

    def _collect_ssl(self, info: ServerInfo):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (info.host, info.port), timeout=15
            ) as sock:
                with ctx.wrap_socket(sock,
                                    server_hostname=info.host) as ssock:
                    info.ssl_enabled = True
                    info.ssl_protocol = ssock.version() or ""

                    cipher = ssock.cipher()
                    if cipher:
                        info.ssl_cipher = cipher[0]

                    cert = ssock.getpeercert()
                    if cert:
                        # Issuer
                        issuer_parts = dict(
                            x[0] for x in cert.get("issuer", [])
                        )
                        info.ssl_issuer = (
                            issuer_parts.get("organizationName", "")
                            or issuer_parts.get("commonName", "")
                        )

                        # Subject
                        subject_parts = dict(
                            x[0] for x in cert.get("subject", [])
                        )
                        info.ssl_subject = subject_parts.get(
                            "commonName", ""
                        )

                        # Expiry
                        not_after = cert.get("notAfter", "")
                        info.ssl_expires = not_after
                        if not_after:
                            try:
                                from datetime import datetime
                                from email.utils import parsedate_to_datetime
                                expiry = parsedate_to_datetime(not_after)
                                now = datetime.now(expiry.tzinfo)
                                info.ssl_days_remaining = (expiry - now).days
                            except Exception:
                                pass
        except ssl.SSLError as e:
            info.errors.append(f"SSL error: {e}")
        except Exception as e:
            info.errors.append(f"SSL collection failed: {e}")