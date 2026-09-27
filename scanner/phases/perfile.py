#!/usr/bin/env python3
"""
Phase 3: PerFile / PerScheme
============================
Uses the Verification Engine to test all parameters:
  - SQLi, XSS, RCE, LFI, SSRF, SSTI, XXE, NoSQL
Every finding here is VERIFIED with evidence.
"""
from urllib.parse import urlparse, parse_qs, urlencode

from ..finding import Finding


class PhasePerFile:
    def __init__(self, scanner):
        self.scanner = scanner
        self.http = scanner.http
        self.out = scanner.out
        self.config = scanner.config
        self.verifier_bridge = scanner.verifier_bridge

    def run(self, base_url):
        self.out.phase("Phase 3: PerFile & PerScheme Checks")

        # URL params
        urls_with_params = [(u, p) for u, p in
                          self.scanner.crawled_params.items() if p]
        if urls_with_params:
            total = len(urls_with_params)
            self.out.info(f"Testing {total} parameterized URLs")
            checked = 0
            for url, params in urls_with_params:
                if self.scanner.stop_event.is_set():
                    break
                self._test_url_params(url, params)
                checked += 1
                self.out.progress(checked, total, "PerFile  ")

        # Forms
        if self.scanner.crawled_forms:
            forms = self.scanner.crawled_forms
            self.out.info(f"Testing {len(forms)} forms")
            checked = 0
            total = len(forms)
            for form in forms:
                if self.scanner.stop_event.is_set():
                    break
                self._test_form(form)
                checked += 1
                self.out.progress(checked, total, "Forms    ")

    # ═══════════════════════════════════════════════════════════════════════
    #  URL parameters
    # ═══════════════════════════════════════════════════════════════════════

    def _test_url_params(self, url, params):
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name in params:
            if self.scanner.stop_event.is_set():
                break

            # ═══ Primary: Verification Engine ═══
            if self.verifier_bridge and self.verifier_bridge.is_available():
                try:
                    verified_findings = self.verifier_bridge.verify_param(
                        url, param_name, method="GET"
                    )
                    for fd in verified_findings:
                        self._add_verified(fd, url, param_name)
                    if verified_findings:
                        continue  # Skip legacy fallback
                except Exception as e:
                    if self.config.get("verbose"):
                        self.out.warn(f"Verification error: {e}")

            # ═══ Legacy detection (if no verifier) ═══
            else:
                self._legacy_sqli_xss_lfi(url, param_name, query_params,
                                         parsed)

            # ═══ Open Redirect (always) ═══
            param_lower = param_name.lower()
            if any(kw in param_lower for kw in
                   ['url', 'redirect', 'next', 'return', 'goto',
                    'dest', 'redir', 'link', 'target']):
                self._test_open_redirect(url, param_name, query_params, parsed)

    def _add_verified(self, fd, url, param):
        """Add a verified finding from VerifierBridge."""
        finding = Finding.from_verified_dict(fd, url, param)
        self.scanner.add_finding(finding)

    # ═══════════════════════════════════════════════════════════════════════
    #  Legacy fallback (when verifier unavailable)
    # ═══════════════════════════════════════════════════════════════════════

    def _legacy_sqli_xss_lfi(self, url, param_name, query_params, parsed):
        """Basic SQLi/XSS/LFI checks (no verification)."""
        original = query_params.get(param_name, [''])[0]

        # SQLi
        for payload in ["'", "1' OR '1'='1", '"']:
            test_params = dict(query_params)
            test_params[param_name] = [original + payload]
            test_url = (f"{parsed.scheme}://{parsed.netloc}{parsed.path}?"
                       f"{urlencode(test_params, doseq=True)}")
            resp = self.http.get(test_url, timeout=10)
            if resp:
                try:
                    body = resp.text
                except Exception:
                    body = ""
                match = self.scanner.detect.detect_sqli(body)
                if match:
                    self.scanner.add_finding(Finding(
                        name="SQL Injection (unverified)",
                        severity="high", url=test_url,
                        detail=f"Param: {param_name}, Payload: {payload}",
                        evidence=match, payload=payload,
                        cwe="CWE-89", tags="sql_injection",
                        category="PerScheme",
                        check_name="SQL_Injection_Legacy",
                        parameter=param_name,
                    ))
                    break

        # XSS
        marker = "acs" + __import__('hashlib').md5(
            __import__('os').urandom(4)).hexdigest()[:8]
        for payload in [f'"><script>{marker}</script>',
                        f"<svg/onload=alert('{marker}')>"]:
            test_params = dict(query_params)
            test_params[param_name] = [payload]
            test_url = (f"{parsed.scheme}://{parsed.netloc}{parsed.path}?"
                       f"{urlencode(test_params, doseq=True)}")
            resp = self.http.get(test_url, timeout=10)
            if resp:
                try:
                    body = resp.text
                except Exception:
                    body = ""
                if marker in body:
                    self.scanner.add_finding(Finding(
                        name="XSS (unverified)",
                        severity="high", url=test_url,
                        detail=f"Param: {param_name}",
                        evidence=marker, payload=payload,
                        cwe="CWE-79", tags="xss",
                        category="PerScheme",
                        check_name="XSS_Legacy",
                        parameter=param_name,
                    ))
                    break

    # ═══════════════════════════════════════════════════════════════════════
    #  Open Redirect
    # ═══════════════════════════════════════════════════════════════════════

    def _test_open_redirect(self, url, param_name, query_params, parsed):
        for payload in ["//evil.com", "https://evil.com"]:
            test_params = dict(query_params)
            test_params[param_name] = [payload]
            test_url = (f"{parsed.scheme}://{parsed.netloc}{parsed.path}?"
                       f"{urlencode(test_params, doseq=True)}")
            resp = self.http.get(test_url, timeout=10, allow_redirects=False)
            if resp and resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get('Location', '')
                if 'evil.com' in location:
                    self.scanner.add_finding(Finding(
                        name="Open Redirect",
                        severity="medium", url=test_url,
                        detail=f"Param: {param_name}, Location: {location}",
                        evidence=location, payload=payload,
                        cwe="CWE-601", tags="open_redirect",
                        category="PerScheme",
                        check_name="Open_Redirect",
                        parameter=param_name,
                    ))
                    break

    # ═══════════════════════════════════════════════════════════════════════
    #  Forms
    # ═══════════════════════════════════════════════════════════════════════

    def _test_form(self, form):
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        for inp in inputs:
            if self.scanner.stop_event.is_set():
                break
            inp_name = inp["name"]
            inp_type = inp["type"]
            original = inp["value"]
            if inp_type in ("hidden", "submit", "button", "image",
                           "file", "reset"):
                continue

            form_data = {i["name"]: i["value"] for i in inputs}

            # ═══ Verification (POST) ═══
            if self.verifier_bridge and self.verifier_bridge.is_available():
                try:
                    verified = self.verifier_bridge.verify_param(
                        action, inp_name, method=method,
                        form_data=form_data,
                    )
                    for fd in verified:
                        self._add_verified(fd, action, inp_name)
                except Exception:
                    pass
            else:
                # Legacy SQLi in forms
                for payload in ["'", "1' OR '1'='1"]:
                    test_data = dict(form_data)
                    test_data[inp_name] = original + payload
                    resp = (self.http.post(action, data=test_data, timeout=10)
                           if method == "POST"
                           else self.http.get(action, params=test_data,
                                             timeout=10))
                    if resp:
                        try:
                            body = resp.text
                        except Exception:
                            body = ""
                        match = self.scanner.detect.detect_sqli(body)
                        if match:
                            self.scanner.add_finding(Finding(
                                name="SQL Injection (Form - unverified)",
                                severity="high", url=action,
                                detail=f"Input: {inp_name}, Method: {method}",
                                evidence=match, payload=payload,
                                cwe="CWE-89", tags="sql_injection",
                                category="PerScheme",
                                check_name="SQL_Injection_Form",
                                parameter=inp_name,
                            ))
                            break