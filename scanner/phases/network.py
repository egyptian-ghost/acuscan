#!/usr/bin/env python3
"""
Phase 7: Network
================
SSL/TLS checks (weak protocols, cert issues).
"""
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime

from ..finding import Finding


class PhaseNetwork:
    def __init__(self, scanner):
        self.scanner = scanner
        self.out = scanner.out

    def run(self, base_url):
        self.out.phase("Phase 7: Network & SSL")

        parsed = urlparse(base_url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)

        if parsed.scheme == 'https':
            self._check_ssl(base_url, host, port)

    def _check_ssl(self, base_url, host, port):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    protocol = ssock.version()
                    cipher = ssock.cipher()

                    self.out.info(f"SSL/TLS: {protocol}, "
                                 f"Cipher: {cipher[0] if cipher else '?'}")

                    if protocol in ('SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'):
                        self.scanner.add_finding(Finding(
                            name=f"Weak SSL/TLS protocol: {protocol}",
                            severity="medium", url=base_url,
                            detail=f"Server supports deprecated {protocol}",
                            cwe="CWE-326",
                            tags="ssl,tls",
                            category="Network",
                            check_name="Weak_TLS",
                        ))

                    cert = ssock.getpeercert(binary_form=False)
                    if cert:
                        self._check_cert(base_url, cert)
        except Exception as e:
            self.out.info(f"SSL check error: {str(e)[:60]}")

    def _check_cert(self, base_url, cert):
        not_after = cert.get('notAfter', '')
        if not not_after:
            return
        try:
            from email.utils import parsedate_to_datetime
            expiry = parsedate_to_datetime(not_after)
            now = datetime.now(expiry.tzinfo)
            if expiry < now:
                self.scanner.add_finding(Finding(
                    name="SSL certificate expired",
                    severity="high", url=base_url,
                    detail=f"Expired: {not_after}",
                    category="Network",
                    check_name="SSL_Expired",
                ))
            elif (expiry - now).days < 30:
                self.scanner.add_finding(Finding(
                    name="SSL certificate expiring soon",
                    severity="low", url=base_url,
                    detail=f"Expires: {not_after}",
                    category="Network",
                    check_name="SSL_Expiring",
                ))
        except Exception:
            pass