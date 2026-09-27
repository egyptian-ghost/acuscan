#!/usr/bin/env python3
"""
Phase 8: Special
================
Shellshock, Host header injection, HTTP verb tampering.
"""
from core.utils import safe_url_join
from ..finding import Finding


class PhaseSpecial:
    def __init__(self, scanner):
        self.scanner = scanner
        self.http = scanner.http
        self.out = scanner.out

    def run(self, base_url):
        self.out.phase("Phase 8: Special Checks")

        self._shellshock(base_url)
        self._host_header_injection(base_url)

    def _shellshock(self, base_url):
        payload = ('() { :; }; echo Content-Type: text/plain; echo; '
                  'echo acunetixshellshock')
        magic = 'acunetixshellshock'
        for path in ["/", "/cgi-bin/", "/cgi-bin/test.cgi"]:
            if self.scanner.stop_event.is_set():
                break
            url = safe_url_join(base_url, path)
            resp = self.http.get(url, headers={
                "Referer": payload,
                "User-Agent": payload,
            }, timeout=10)
            if resp and magic in resp.text:
                self.scanner.add_finding(Finding(
                    name="Shellshock (CVE-2014-6271)",
                    severity="critical", url=url,
                    detail="Bash RCE via CGI environment",
                    evidence=magic,
                    cve="CVE-2014-6271", cwe="CWE-78",
                    category="PerServer",
                    check_name="Shellshock",
                ))
                break

    def _host_header_injection(self, base_url):
        resp = self.http.get(base_url, headers={"Host": "evil.com"},
                            timeout=8)
        if resp and 'evil.com' in resp.text:
            self.scanner.add_finding(Finding(
                name="Host header injection",
                severity="medium", url=base_url,
                detail="Host header is reflected in response body",
                cwe="CWE-644",
                category="PerServer",
                check_name="Host_Header_Injection",
            ))