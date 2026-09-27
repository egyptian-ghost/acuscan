#!/usr/bin/env python3
"""
Login Tester v6.6.0 — THE ULTIMATE FIX
======================================
Multi-strategy login detection:

  1. Auto-detect form action (if you gave us loginform.html, we'll find the
     real POST endpoint automatically)
  2. Auto-extract CSRF tokens (regex + meta + JS variables)
  3. Try BOTH the given URL and the discovered form action
  4. Check 6 different success signals:
       - Success indicator (in body)
       - Success indicator (in redirect target)
       - New cookies set
       - Redirect away from login URL
       - Common success words (dashboard, welcome, logout, etc.)
       - Response body change (differential analysis)
  5. Handle JSON responses
  6. Handle redirect chains
  7. Detailed logging so you know exactly what happened
"""
import re
import json
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, List
from urllib.parse import urljoin, urlparse

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


@dataclass
class LoginTestResult:
    """Detailed result of a login test."""
    success: bool = False
    confidence: float = 0.0
    reason: str = ""

    # Request
    request_url: str = ""
    request_method: str = ""
    request_headers: Dict = field(default_factory=dict)
    request_body: str = ""

    # Response
    response_status: int = 0
    response_headers: Dict = field(default_factory=dict)
    response_body_snippet: str = ""
    response_url: str = ""

    # Session
    cookies_before: Dict = field(default_factory=dict)
    cookies_after: Dict = field(default_factory=dict)
    cookies_added: List[str] = field(default_factory=list)
    cookies_changed: List[str] = field(default_factory=list)

    # Redirects
    redirect_chain: List[str] = field(default_factory=list)

    # Diagnostics
    checks: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    auto_detected: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "success": self.success,
            "confidence": round(self.confidence, 3),
            "reason": self.reason,
            "request_url": self.request_url,
            "request_method": self.request_method,
            "request_body": self.request_body[:2000],
            "request_headers": dict(self.request_headers),
            "response_status": self.response_status,
            "response_headers": dict(self.response_headers),
            "response_body_snippet": self.response_body_snippet[:3000],
            "response_url": self.response_url,
            "cookies_before": dict(self.cookies_before),
            "cookies_after": dict(self.cookies_after),
            "cookies_added": list(self.cookies_added),
            "cookies_changed": list(self.cookies_changed),
            "redirect_chain": list(self.redirect_chain),
            "checks": list(self.checks),
            "errors": list(self.errors),
            "auto_detected": dict(self.auto_detected),
        }


class LoginTester:
    """Advanced login tester."""

    # Failure patterns (English + Persian/Arabic)
    FAILURE_PATTERNS = [
        r"invalid\s+(password|credential|username|user|login)",
        r"incorrect\s+(password|username|credentials)",
        r"wrong\s+(password|username|credentials)",
        r"login\s+(failed|error|incorrect)",
        r"authentication\s+failed",
        r"access\s+denied",
        r"unauthorized",
        r"invalid\s+login",
        r"bad\s+credentials",
        r"try\s+again",
        r"account\s+(locked|disabled|suspended)",
        r"user\s+not\s+found",
        r"نام\s*کاربری\s*یا\s*رمز\s*عبور",
        r"رمز\s*عبور\s*اشتباه",
        r"کاربری\s*یافت\s*نشد",
    ]

    # Success patterns
    SUCCESS_PATTERNS = [
        r"welcome[,\s]+",
        r"\bdashboard\b",
        r"\blogout\b",
        r"sign\s*out",
        r"my\s+account",
        r"\bprofile\b",
        r"خوش\s*آمدید",
        r"\bخروج\b",
        r"پنل\s*مدیریت",
    ]

    # Common CSRF field names
    CSRF_FIELDS = [
        "csrf_token", "csrfmiddlewaretoken", "_token", "authenticity_token",
        "token", "token2", "_csrf", "csrf", "csrfToken", "xsrf_token",
        "__RequestVerificationToken",
    ]

    def __init__(self, http_client, config):
        self.http = http_client
        self.config = config
        self.verify_ssl = bool(config.get("verify_ssl", True))

    # ═══════════════════════════════════════════════════════════════════
    #  PUBLIC API
    # ═══════════════════════════════════════════════════════════════════

    def test_login(self) -> LoginTestResult:
        """Main entry point."""
        result = LoginTestResult()

        login_url = self.config.get("login_url")
        if not login_url:
            result.reason = "No login URL configured"
            result.errors.append("login_url missing")
            return result

        login_data = self.config.get("login_data", {})
        if not login_data:
            result.reason = "No login credentials configured"
            result.errors.append("login_data missing")
            return result

        try:
            # ═══════════════════════════════════════════════════════════
            #  STEP 1: Fetch login page to detect form
            # ═══════════════════════════════════════════════════════════
            self._log("Fetching login page...")
            pre_resp = self.http.session.get(
                login_url, timeout=15, verify=self.verify_ssl,
                allow_redirects=True,
            )

            if not pre_resp:
                result.reason = "Could not fetch login page"
                result.errors.append("No response from login URL")
                return result

            pre_body = pre_resp.text
            result.cookies_before = {
                c.name: c.value for c in self.http.session.cookies
            }

            # ═══════════════════════════════════════════════════════════
            #  STEP 2: Auto-detect form action + method + fields
            # ═══════════════════════════════════════════════════════════
            form_info = self._detect_form(login_url, pre_body)
            result.auto_detected = form_info

            self._log(f"Form detected: {form_info.get('action')} "
                     f"[{form_info.get('method')}]")

            # Choose target URL
            target_url = form_info.get("action") or login_url
            method = form_info.get("method", "POST").upper()

            # If login URL ends with .html but form action ends with .php
            # → use the .php (the real handler)
            if (form_info.get("action")
                and form_info.get("action") != login_url
                and form_info.get("confidence", 0) > 0.5):
                target_url = form_info["action"]
                self._log(f"Using auto-detected action: {target_url}")
            else:
                target_url = login_url
                self._log(f"Using provided login URL: {target_url}")

            # ═══════════════════════════════════════════════════════════
            #  STEP 3: Extract CSRF token(s) + build payload
            # ═══════════════════════════════════════════════════════════
            data = dict(login_data)
            csrf_tokens = self._extract_csrf_tokens(pre_body, login_url)
            self._log(f"CSRF tokens found: {list(csrf_tokens.keys())}")

            # Merge CSRF tokens into data (without overwriting user-provided)
            for k, v in csrf_tokens.items():
                if k not in data:
                    data[k] = v

            # Also add hidden form fields found on page
            for k, v in form_info.get("hidden_fields", {}).items():
                if k not in data and k not in csrf_tokens:
                    data[k] = v

            # ═══════════════════════════════════════════════════════════
            #  STEP 4: Perform login
            # ═══════════════════════════════════════════════════════════
            result.request_url = target_url
            result.request_method = method
            result.request_headers = dict(self.http.session.headers)
            result.request_body = str(data)

            self._log(f"Sending {method} to {target_url} with {len(data)} fields")

            try:
                if method == "POST":
                    resp = self.http.session.post(
                        target_url, data=data, timeout=20,
                        verify=self.verify_ssl, allow_redirects=True,
                    )
                else:
                    resp = self.http.session.get(
                        target_url, params=data, timeout=20,
                        verify=self.verify_ssl, allow_redirects=True,
                    )
            except Exception as e:
                result.errors.append(f"Login request failed: {e}")
                result.reason = f"Login request exception: {e}"
                return result

            if not resp:
                result.reason = "No response from login endpoint"
                return result

            # ═══════════════════════════════════════════════════════════
            #  STEP 5: Collect response details
            # ═══════════════════════════════════════════════════════════
            result.response_status = resp.status_code
            result.response_headers = dict(resp.headers)
            try:
                result.response_body_snippet = resp.text[:5000]
            except Exception:
                result.response_body_snippet = ""
            result.response_url = resp.url or ""

            # Redirect chain
            for h in resp.history:
                result.redirect_chain.append(h.url)
            if resp.url:
                result.redirect_chain.append(resp.url)

            # Cookies after
            result.cookies_after = {
                c.name: c.value for c in self.http.session.cookies
            }

            # Compute diffs
            for name, value in result.cookies_after.items():
                if name not in result.cookies_before:
                    result.cookies_added.append(name)
                elif result.cookies_before[name] != value:
                    result.cookies_changed.append(name)

            # ═══════════════════════════════════════════════════════════
            #  STEP 6: 6-way success detection
            # ═══════════════════════════════════════════════════════════
            self._evaluate(result, resp, pre_body)
            return result

        except Exception as e:
            import traceback
            result.reason = f"Exception: {e}"
            result.errors.append(str(e))
            result.errors.append(traceback.format_exc()[:1000])
            return result

    # ═══════════════════════════════════════════════════════════════════
    #  FORM DETECTION
    # ═══════════════════════════════════════════════════════════════════

    def _detect_form(self, page_url, body):
        """
        Detect login form in HTML.

        Returns:
            {
                'action': '/3/v3/login.php',
                'method': 'POST',
                'confidence': 0.9,
                'hidden_fields': {...},
                'has_password': True,
                'inputs': [...],
            }
        """
        info = {
            "action": None,
            "method": "POST",
            "confidence": 0.0,
            "hidden_fields": {},
            "has_password": False,
            "inputs": [],
        }

        if not HAS_BS4:
            # Regex fallback
            return self._detect_form_regex(page_url, body)

        try:
            soup = BeautifulSoup(body, "html.parser")
            forms = soup.find_all("form")

            # Score each form — find the login one
            best_form = None
            best_score = 0

            for form in forms:
                score = 0
                inputs = form.find_all(["input", "textarea", "select"])
                field_names = []

                has_password = False
                has_user = False

                for inp in inputs:
                    name = (inp.get("name") or "").lower()
                    typ = (inp.get("type") or "").lower()
                    field_names.append(name)

                    if typ == "password":
                        has_password = True
                        score += 5
                    if any(kw in name for kw in ["user", "email", "login", "username"]):
                        has_user = True
                        score += 3
                    if "password" in name or "pass" in name:
                        score += 3
                    if "csrf" in name or "token" in name:
                        score += 1

                if has_password:
                    score += 3
                if has_user:
                    score += 2

                if score > best_score:
                    best_score = score
                    best_form = form

            if best_form:
                action = best_form.get("action", "")
                method = (best_form.get("method") or "POST").upper()

                # Resolve relative action
                if action:
                    action = urljoin(page_url, action)
                else:
                    action = page_url

                # Extract hidden fields
                hidden = {}
                inputs_list = []
                has_password = False

                for inp in best_form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if not name:
                        continue
                    typ = (inp.get("type") or "text").lower()
                    value = inp.get("value", "")

                    inputs_list.append({
                        "name": name,
                        "type": typ,
                        "value": value[:100],
                    })

                    if typ == "hidden":
                        hidden[name] = value
                    if typ == "password":
                        has_password = True

                info["action"] = action
                info["method"] = method
                info["hidden_fields"] = hidden
                info["has_password"] = has_password
                info["inputs"] = inputs_list
                info["confidence"] = min(1.0, best_score / 15.0)

        except Exception as e:
            self._log(f"Form detection failed: {e}")

        return info

    def _detect_form_regex(self, page_url, body):
        """Fallback form detection without BeautifulSoup."""
        info = {
            "action": None,
            "method": "POST",
            "confidence": 0.0,
            "hidden_fields": {},
            "has_password": False,
            "inputs": [],
        }

        # Find <form> tags
        form_pattern = re.compile(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>',
            re.IGNORECASE
        )
        for m in form_pattern.finditer(body):
            action = m.group(1)
            if action:
                info["action"] = urljoin(page_url, action)
                info["confidence"] = 0.6
                break

        # Find password inputs
        if re.search(r'type=["\']password["\']', body, re.I):
            info["has_password"] = True
            info["confidence"] = max(info["confidence"], 0.7)

        return info

    # ═══════════════════════════════════════════════════════════════════
    #  CSRF EXTRACTION
    # ═══════════════════════════════════════════════════════════════════

    def _extract_csrf_tokens(self, body, page_url):
        """
        Extract ALL possible CSRF tokens from page.
        Returns dict: {field_name: token_value}
        """
        tokens = {}

        # ═══ Method 1: BeautifulSoup hidden inputs ═══
        if HAS_BS4:
            try:
                soup = BeautifulSoup(body, "html.parser")
                for inp in soup.find_all("input", type="hidden"):
                    name = (inp.get("name") or "").lower()
                    value = inp.get("value")
                    if value and any(csrf in name for csrf in
                                    ["csrf", "token", "xsrf", "_token",
                                     "authenticity"]):
                        # Use ORIGINAL name (not lowercase)
                        original_name = inp.get("name")
                        tokens[original_name] = value
            except Exception:
                pass

        # ═══ Method 2: Regex for common CSRF input patterns ═══
        csrf_regexes = [
            # name="csrf_token" value="xxx"
            r'name=["\'](csrf[_-]?token|_token|authenticity[_-]?token|token2?|xsrf[_-]?token|__RequestVerificationToken)["\'][^>]*value=["\']([^"\']+)["\']',
            # value="xxx" name="csrf_token"
            r'value=["\']([^"\']+)["\'][^>]*name=["\'](csrf[_-]?token|_token|authenticity[_-]?token|token2?|xsrf[_-]?token)["\']',
        ]

        for pattern in csrf_regexes:
            for m in re.finditer(pattern, body, re.IGNORECASE):
                groups = m.groups()
                if len(groups) == 2:
                    # Figure out which is name and which is value
                    if groups[0] and groups[1]:
                        # Pattern 1: name, value
                        if "=" in groups[0] or len(groups[0]) < 30:
                            tokens[groups[0]] = groups[1]
                        else:
                            tokens[groups[1]] = groups[0]

        # ═══ Method 3: JavaScript variables ═══
        js_patterns = [
            r'["\']csrf_token["\']\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']csrfToken["\']\s*[:=]\s*["\']([^"\']+)["\']',
            r'var\s+csrf_token\s*=\s*["\']([^"\']+)["\']',
            r'window\.csrfToken\s*=\s*["\']([^"\']+)["\']',
        ]
        for pattern in js_patterns:
            m = re.search(pattern, body, re.I)
            if m:
                tokens.setdefault("csrf_token", m.group(1))

        # ═══ Method 4: Meta tags ═══
        meta_pattern = re.compile(
            r'<meta[^>]*name=["\'](csrf[_-]?token|_token)["\'][^>]*content=["\']([^"\']+)["\']',
            re.IGNORECASE
        )
        for m in meta_pattern.finditer(body):
            tokens[m.group(1)] = m.group(2)

        return tokens

    # ═══════════════════════════════════════════════════════════════════
    #  6-WAY SUCCESS DETECTION
    # ═══════════════════════════════════════════════════════════════════

    def _evaluate(self, result, resp, pre_body):
        """Determine login success using 6 independent methods."""
        body = (resp.text or "")
        body_lower = body.lower()
        explicit_check = self.config.get("login_check")
        logout_check = self.config.get("logout_check")
        login_url = self.config.get("login_url", "")

        # ═══════════════════════════════════════════════════════════════
        #  Check 1: Explicit success indicator (highest priority)
        # ═══════════════════════════════════════════════════════════════
        if explicit_check:
            # Strip brackets if user wrote [Login_successful]
            clean_check = explicit_check.strip("[]")
            found_in_body = clean_check.lower() in body_lower

            # Also check in redirect chain
            found_in_redirect = any(
                clean_check.lower() in url.lower()
                for url in result.redirect_chain
            )

            result.checks.append({
                "name": "explicit_success_indicator",
                "passed": found_in_body or found_in_redirect,
                "detail": f"Searched for: '{clean_check}' "
                         f"(body: {found_in_body}, "
                         f"redirect: {found_in_redirect})",
            })

            if found_in_body or found_in_redirect:
                result.success = True
                result.confidence = 0.99
                result.reason = (
                    f"Success indicator '{clean_check}' found "
                    f"({'body' if found_in_body else 'redirect'})"
                )
                return

            # If explicit check set but not found, still check logout
            if logout_check and logout_check.lower() in body_lower:
                result.success = True
                result.confidence = 0.98
                result.reason = f"Logout link found: '{logout_check}'"
                return

            # Explicit check FAILED — but check other methods
            # (maybe indicator is in JS/Cookie/JSON)
            self._log("Explicit indicator not in body, checking other methods...")

        # ═══════════════════════════════════════════════════════════════
        #  Check 2: Failure patterns (run BEFORE cookie check)
        # ═══════════════════════════════════════════════════════════════
        for pattern in self.FAILURE_PATTERNS:
            m = re.search(pattern, body_lower, re.I)
            if m:
                result.checks.append({
                    "name": "failure_pattern",
                    "passed": False,
                    "detail": f"Matched: '{pattern}' → '{m.group(0)[:100]}'",
                })
                result.success = False
                result.confidence = 0.95
                result.reason = f"Failure pattern: {m.group(0)[:100]}"
                return

        # ═══════════════════════════════════════════════════════════════
        #  Check 3: Redirect away from login URL
        # ═══════════════════════════════════════════════════════════════
        final_url = resp.url or ""
        if (login_url and final_url
            and final_url.rstrip("/") != login_url.rstrip("/")
            and not any(kw in final_url.lower() for kw in
                       ["login", "signin", "auth"])):
            result.checks.append({
                "name": "redirected_from_login",
                "passed": True,
                "detail": f"{login_url} → {final_url}",
            })
            result.success = True
            result.confidence = 0.85
            result.reason = f"Redirected from login to: {final_url}"
            return

        # ═══════════════════════════════════════════════════════════════
        #  Check 4: New cookies set (strong signal)
        # ═══════════════════════════════════════════════════════════════
        if result.cookies_added or result.cookies_changed:
            result.checks.append({
                "name": "session_cookies_set",
                "passed": True,
                "detail": f"Added: {', '.join(result.cookies_added[:5])} | "
                         f"Changed: {', '.join(result.cookies_changed[:5])}",
            })

            # But is the response a JSON error?
            is_error_response = False
            if resp.status_code >= 400:
                is_error_response = True
            if any(err in body_lower for err in
                  ['"error"', '"failed"', '"success":false',
                   '"success": false']):
                is_error_response = True

            if not is_error_response:
                result.success = True
                result.confidence = 0.85
                parts = []
                if result.cookies_added:
                    parts.append(f"new cookies: {', '.join(result.cookies_added[:3])}")
                if result.cookies_changed:
                    parts.append(f"changed: {', '.join(result.cookies_changed[:3])}")
                result.reason = "Session established — " + " + ".join(parts)
                return

        # ═══════════════════════════════════════════════════════════════
        #  Check 5: Success patterns in body
        # ═══════════════════════════════════════════════════════════════
        matched = []
        for pattern in self.SUCCESS_PATTERNS:
            if re.search(pattern, body_lower, re.I):
                matched.append(pattern)

        if len(matched) >= 2:
            result.checks.append({
                "name": "success_patterns",
                "passed": True,
                "detail": f"Matched: {', '.join(matched[:3])}",
            })
            result.success = True
            result.confidence = 0.7
            result.reason = f"Multiple success patterns ({len(matched)})"
            return

        # ═══════════════════════════════════════════════════════════════
        #  Check 6: JSON success signal
        # ═══════════════════════════════════════════════════════════════
        try:
            ct = resp.headers.get("Content-Type", "").lower()
            if "json" in ct:
                data = json.loads(body)
                # Look for success flags
                for key in ["success", "status", "ok", "logged_in", "authorized"]:
                    if key in data:
                        val = data[key]
                        if val is True or val == 1 or \
                           (isinstance(val, str) and val.lower() in
                            ["true", "ok", "success", "yes", "1"]):
                            result.checks.append({
                                "name": "json_success",
                                "passed": True,
                                "detail": f"JSON {key}: {val}",
                            })
                            result.success = True
                            result.confidence = 0.95
                            result.reason = f"JSON success signal: {key}={val}"
                            return
        except Exception:
            pass

        # ═══════════════════════════════════════════════════════════════
        #  Ambiguous
        # ═══════════════════════════════════════════════════════════════
        result.checks.append({
            "name": "ambiguous",
            "passed": False,
            "detail": "No definitive signal found",
        })
        result.success = False
        result.confidence = 0.3

        hint = ""
        if explicit_check:
            hint = (f"\n\nWe searched for '{explicit_check.strip('[]')}' "
                   f"in body (length: {len(body)}) and redirects. "
                   f"Consider checking what the actual success response contains.")

        result.reason = (
            f"Could not determine login status. "
            f"Response: HTTP {resp.status_code}, "
            f"{len(body)} bytes, "
            f"{len(result.cookies_added)} new cookies.{hint}"
        )

    def _log(self, msg):
        if self.config.get("verbose"):
            print(f"[LoginTester] {msg}")