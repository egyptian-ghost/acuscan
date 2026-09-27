#!/usr/bin/env python3
"""
Technology Detection
====================
Detects server, framework, CMS, and language from headers + body.
"""
import re


class TechDetector:
    """Detect web technologies."""

    def __init__(self, http_client, config, out):
        self.http = http_client
        self.config = config
        self.out = out
        self.tech_stack = {}

    def detect(self, base_url):
        self.out.phase("Technology Detection")
        resp = self.http.get(base_url)
        if not resp:
            return self.tech_stack

        headers = resp.headers
        try:
            body = resp.text
        except Exception:
            body = ""

        # Server
        server = headers.get('Server', '')
        if server:
            self.tech_stack['server'] = server
            self.out.info(f"Server: {server}")

        # X-Powered-By
        xpb = headers.get('X-Powered-By', '')
        if xpb:
            self.tech_stack['powered_by'] = xpb
            self.out.info(f"X-Powered-By: {xpb}")

        # ASP.NET
        aspnet = headers.get('X-AspNet-Version', '')
        if aspnet:
            self.tech_stack['aspnet'] = aspnet
            self.out.info(f"ASP.NET: {aspnet}")

        # Generator (meta tag)
        gen = headers.get('X-Generator', '')
        if not gen and body:
            m = re.search(
                r'<meta\s+name=["\']generator["\']\s+content=["\'](.*?)["\']',
                body, re.I
            )
            if m:
                gen = m.group(1)
        if gen:
            self.tech_stack['generator'] = gen
            self.out.info(f"Generator: {gen}")

        # Cookies -> language hints
        cookies = resp.headers.get('Set-Cookie', '')
        if 'PHPSESSID' in cookies:
            self.tech_stack['php'] = True
            self.out.info("PHP detected (PHPSESSID)")
        if 'ASP.NET_SessionId' in cookies:
            self.tech_stack['aspnet_session'] = True
            self.out.info("ASP.NET detected (session cookie)")
        if 'JSESSIONID' in cookies:
            self.tech_stack['java'] = True
            self.out.info("Java detected (JSESSIONID)")
        if 'csrftoken' in cookies:
            self.tech_stack['django_possible'] = True
            self.out.info("Django likely detected (csrftoken)")

        # Security headers
        for hdr in ['X-Frame-Options', 'X-Content-Type-Options',
                    'Content-Security-Policy', 'Strict-Transport-Security',
                    'X-XSS-Protection', 'Referrer-Policy',
                    'Permissions-Policy', 'Cross-Origin-Opener-Policy']:
            val = headers.get(hdr, '')
            if val:
                self.tech_stack[f'header_{hdr}'] = val

        return self.tech_stack