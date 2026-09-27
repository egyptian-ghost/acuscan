#!/usr/bin/env python3
"""
Phase 6: PostScan
=================
Security headers, CORS, cookies, misconfigurations.
"""
import re
from core.utils import safe_url_join
from ..finding import Finding


class PhasePostScan:
    def __init__(self, scanner):
        self.scanner = scanner
        self.http = scanner.http
        self.out = scanner.out

    def run(self, base_url):
        self.out.phase("Phase 6: PostScan & Security Headers")

        resp = self.http.get(base_url)
        if not resp:
            return

        headers = resp.headers

        # ── Missing security headers ──
        security_headers = {
            "X-Frame-Options":
                ("Clickjacking: X-Frame-Options header missing",
                 "medium", "CWE-1021"),
            "X-Content-Type-Options":
                ("X-Content-Type-Options header missing",
                 "low", "CWE-16"),
            "Content-Security-Policy":
                ("Content-Security-Policy header missing",
                 "medium", "CWE-16"),
            "Strict-Transport-Security":
                ("HSTS header missing", "low", "CWE-319"),
            "X-XSS-Protection":
                ("X-XSS-Protection header missing",
                 "low", "CWE-79"),
            "Referrer-Policy":
                ("Referrer-Policy header missing",
                 "info", "CWE-200"),
        }

        for hdr, (name, sev, cwe) in security_headers.items():
            if hdr not in headers:
                self.scanner.add_finding(Finding(
                    name=name, severity=sev, url=base_url,
                    detail=f"{hdr} not set", cwe=cwe,
                    tags="security_headers",
                    category="PostScan",
                    check_name=f"Missing_{hdr}",
                ))

        # ── Server banner ──
        server = headers.get("Server", "")
        if server and any(v in server for v in ['/', '.']):
            self.scanner.add_finding(Finding(
                name="Server version disclosure",
                severity="info", url=base_url,
                detail=f"Server: {server}",
                tags="info_disclosure",
                category="PostScan",
                check_name="Server_Banner",
            ))

        # ── X-Powered-By ──
        xpb = headers.get("X-Powered-By", "")
        if xpb:
            self.scanner.add_finding(Finding(
                name="X-Powered-By header present",
                severity="info", url=base_url,
                detail=f"X-Powered-By: {xpb}",
                tags="info_disclosure",
                category="PostScan",
                check_name="X_Powered_By",
            ))

        # ── Cookies ──
        set_cookie = headers.get("Set-Cookie", "")
        if set_cookie:
            if 'httponly' not in set_cookie.lower():
                self.scanner.add_finding(Finding(
                    name="Cookie without HttpOnly flag",
                    severity="low", url=base_url,
                    detail="Session cookie missing HttpOnly",
                    cwe="CWE-1004",
                    category="PostScan",
                    check_name="Cookie_HttpOnly",
                ))
            if ('secure' not in set_cookie.lower() and
                base_url.startswith('https')):
                self.scanner.add_finding(Finding(
                    name="Cookie without Secure flag",
                    severity="low", url=base_url,
                    detail="Cookie missing Secure over HTTPS",
                    cwe="CWE-614",
                    category="PostScan",
                    check_name="Cookie_Secure",
                ))

        # ── CORS ──
        cors_resp = self.http.get(base_url,
                                 headers={"Origin": "https://evil.com"})
        if cors_resp:
            acao = cors_resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                self.scanner.add_finding(Finding(
                    name="CORS wildcard origin",
                    severity="medium", url=base_url,
                    detail="Access-Control-Allow-Origin: *",
                    cwe="CWE-942",
                    category="PostScan",
                    check_name="CORS_Wildcard",
                ))
            elif "evil.com" in acao:
                self.scanner.add_finding(Finding(
                    name="CORS origin reflection",
                    severity="high", url=base_url,
                    detail=f"ACAO: {acao}",
                    cwe="CWE-942",
                    category="PostScan",
                    check_name="CORS_Reflection",
                ))

        # ── .git exposure ──
        git_resp = self.http.get(safe_url_join(base_url, "/.git/config"),
                                timeout=8)
        if (git_resp and git_resp.status_code == 200 and
            '[core]' in git_resp.text):
            self.scanner.add_finding(Finding(
                name="Git repository exposed",
                severity="high",
                url=safe_url_join(base_url, "/.git/config"),
                detail="Git config is publicly accessible",
                cwe="CWE-538",
                category="PostScan",
                check_name="Git_Exposed",
            ))

        # ── .env exposure ──
        env_resp = self.http.get(safe_url_join(base_url, "/.env"), timeout=8)
        if env_resp and env_resp.status_code == 200:
            if re.search(r'(DB_|APP_|SECRET|KEY|PASSWORD|TOKEN)[\w]*\s*=',
                        env_resp.text):
                self.scanner.add_finding(Finding(
                    name=".env file exposed",
                    severity="critical",
                    url=safe_url_join(base_url, "/.env"),
                    detail="Environment secrets accessible",
                    cwe="CWE-538",
                    category="PostScan",
                    check_name="Env_File",
                ))