#!/usr/bin/env python3
"""
Session & authentication manager v6.5.4
"""
import os
import re
import json
import time
import threading
from http.cookies import SimpleCookie
from urllib.parse import urljoin

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

from .auth_2fa import TwoFactorAuth


class SessionManager:
    """Handles cookies, headers, form login, CSRF, and 2FA."""

    def __init__(self, config):
        self.config = config
        self.session_file = config.get("session_file")
        self.auto_login = config.get("auto_login", False)
        self.login_url = config.get("login_url")
        self.login_data = config.get("login_data", {})
        self.login_method = config.get("login_method", "POST").upper()
        self.login_check = config.get("login_check")
        self.logout_check = config.get("logout_check")
        self.csrf_config = config.get("csrf", {})
        self.refresh_interval = config.get("refresh_interval", 0)
        self.last_refresh = 0
        self.lock = threading.Lock()
        self.verify_ssl = bool(config.get("verify_ssl", True))
        self.twofa = None
        if config.get("totp_secret") or config.get("totp_code"):
            self.twofa = TwoFactorAuth(config)
        self.login_attempts = 0
        self.login_successes = 0

    # ─── Cookie parsing ─────────────────────────────────────────────

    def parse_cookie_string(self, cookie_str):
        """Parse 'name1=value1; name2=value2' into dict."""
        if not cookie_str:
            return {}
        try:
            sc = SimpleCookie()
            sc.load(cookie_str)
            return {k: m.value for k, m in sc.items()}
        except Exception:
            result = {}
            for pair in cookie_str.split(';'):
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    result[k.strip()] = v.strip()
            return result

    def load_cookies_from_file(self, path):
        if not path or not os.path.isfile(path):
            return {}
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
            if content.startswith('{'):
                try:
                    data = json.loads(content)
                    if isinstance(data, dict):
                        return {str(k): str(v) for k, v in data.items()}
                except json.JSONDecodeError:
                    pass
            cookies = {}
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split('\t')
                if len(parts) >= 7:
                    cookies[parts[5]] = parts[6]
            if cookies:
                return cookies
            return self.parse_cookie_string(content)
        except Exception:
            return {}

    def load_headers_from_file(self, path):
        if not path or not os.path.isfile(path):
            return {}
        headers = {}
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and ':' in line:
                        k, v = line.split(':', 1)
                        headers[k.strip()] = v.strip()
        except Exception:
            pass
        return headers

    # ─── Session persistence ────────────────────────────────────────

    def save_session(self, session):
        if not self.session_file:
            return False
        try:
            data = {
                "cookies": {c.name: c.value for c in session.cookies},
                "headers": dict(session.headers),
                "auth": session.auth,
                "saved_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "login_attempts": self.login_attempts,
                "login_successes": self.login_successes,
            }
            # JSON avoids unsafe pickle deserialization. Session files are
            # authentication material and should never execute arbitrary code.
            if isinstance(data.get("auth"), tuple):
                data["auth"] = list(data["auth"])
            with open(self.session_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False)
            # Best-effort owner-only permissions on POSIX systems.
            try:
                os.chmod(self.session_file, 0o600)
            except (OSError, NotImplementedError):
                pass
            return True
        except Exception:
            return False

    def load_session(self, session):
        if not self.session_file or not os.path.isfile(self.session_file):
            return False
        try:
            with open(self.session_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return False
            for k, v in data.get("cookies", {}).items():
                session.cookies.set(k, v)
            for k, v in data.get("headers", {}).items():
                session.headers[k] = v
            if data.get("auth"):
                auth = data["auth"]
                session.auth = tuple(auth) if isinstance(auth, list) else auth
            return True
        except Exception:
            return False

    # ─── CSRF ────────────────────────────────────────────────────────

    def extract_csrf_token(self, session, page_url):
        if not self.csrf_config:
            return None
        try:
            resp = session.get(page_url, timeout=10, verify=self.verify_ssl)
            if not resp or resp.status_code != 200:
                return None
            body = resp.text

            for pattern in self.csrf_config.get("patterns", []):
                m = re.search(pattern, body, re.I | re.S)
                if m:
                    return m.group(1) if m.groups() else m.group(0)

            input_name = self.csrf_config.get("input_name")
            if input_name and HAS_BS4:
                soup = BeautifulSoup(body, 'html.parser')
                inp = soup.find('input', {'name': input_name})
                if inp and inp.get('value'):
                    return inp['value']

            meta_name = self.csrf_config.get("meta_name")
            if meta_name and HAS_BS4:
                soup = BeautifulSoup(body, 'html.parser')
                meta = soup.find('meta', {'name': meta_name})
                if meta and meta.get('content'):
                    return meta['content']

            header_name = self.csrf_config.get("header_name")
            if header_name:
                return resp.headers.get(header_name)
        except Exception:
            pass
        return None

    # ─── Form login ──────────────────────────────────────────────────

    def perform_login(self, session):
        if not self.auto_login or not self.login_url:
            return False
        self.login_attempts += 1
        try:
            pre_resp = session.get(self.login_url, timeout=15, verify=self.verify_ssl)

            data = dict(self.login_data)
            if self.csrf_config and pre_resp:
                token = self.extract_csrf_token(session, self.login_url)
                if token:
                    field_name = (self.csrf_config.get("field_name") or
                                self.csrf_config.get("input_name") or
                                "csrf_token")
                    data[field_name] = token
                    header_name = self.csrf_config.get("header_name")
                    if header_name:
                        session.headers[header_name] = token

            if self.login_method == "POST":
                resp = session.post(self.login_url, data=data, timeout=15,
                                    verify=self.verify_ssl, allow_redirects=True)
            else:
                resp = session.get(self.login_url, params=data, timeout=15,
                                   verify=self.verify_ssl, allow_redirects=True)

            if not resp:
                return False

            if self.twofa and self._requires_2fa(resp):
                if not self._handle_2fa(session, resp):
                    return False
                if self.config.get("login_check_url"):
                    resp = session.get(self.config["login_check_url"],
                                     timeout=15, verify=self.verify_ssl)

            success = self._validate_login(resp)
            if success:
                self.login_successes += 1
            return success
        except Exception:
            return False

    def _requires_2fa(self, resp):
        if not resp:
            return False
        body = resp.text.lower()
        indicators = [
            "two-factor", "2fa", "two factor", "verification code",
            "authenticator", "otp", "totp", "one-time password",
            "enter the code", "6-digit", "6 digit", "google authenticator",
            "auth code", "verification_code", "mfa",
        ]
        return any(ind in body for ind in indicators)

    def _handle_2fa(self, session, resp):
        if not self.twofa:
            return False
        try:
            self.twofa.sync_with_server(
                self.config.get("_target", ""),
                self.config.get("_http_client")
            )
        except Exception:
            pass

        code = self.twofa.generate_code()
        if not code:
            code = self.twofa.get_backup_code()
            if not code:
                return False

        if HAS_BS4:
            soup = BeautifulSoup(resp.text, 'html.parser')
            form = soup.find('form')
            if form:
                action = form.get('action', '')
                method = form.get('method', 'POST').upper()
                url = urljoin(resp.url, action) if action else resp.url

                data = {}
                for inp in form.find_all('input'):
                    name = inp.get('name', '')
                    if name:
                        value = inp.get('value', '')
                        if (inp.get('type') in ('text', 'number', 'tel') or
                            'code' in name.lower() or
                            'otp' in name.lower() or
                            'token' in name.lower()):
                            value = code
                        data[name] = value

                if not any('code' in k.lower() or 'otp' in k.lower()
                          for k in data):
                    data["code"] = code
                    data["otp"] = code

                if method == "POST":
                    verify_resp = session.post(url, data=data, timeout=15,
                                             verify=self.verify_ssl, allow_redirects=True)
                else:
                    verify_resp = session.get(url, params=data, timeout=15,
                                            verify=self.verify_ssl, allow_redirects=True)

                if verify_resp and not self._requires_2fa(verify_resp):
                    return True
        return False

    def _validate_login(self, resp):
        if not resp:
            return False
        body = resp.text
        if self.login_check:
            if self.login_check in body:
                return True
            if self.logout_check and self.logout_check in body:
                return True
            return False

        if self.login_url and resp.url and resp.url != self.login_url:
            if "login" not in resp.url.lower() and "signin" not in resp.url.lower():
                return True

        fail_indicators = [
            "invalid password", "incorrect password",
            "login failed", "authentication failed",
            "wrong credentials", "access denied", "invalid credentials"
        ]
        body_lower = body.lower()
        for ind in fail_indicators:
            if ind in body_lower:
                return False
        return True

    def maybe_refresh(self, session):
        if not self.refresh_interval or not self.auto_login:
            return
        now = time.time()
        with self.lock:
            if now - self.last_refresh < self.refresh_interval:
                return
            self.last_refresh = now
        self.perform_login(session)

    # ─── Multi-step login ────────────────────────────────────────────

    def perform_multi_step_login(self, session):
        steps = self.config.get("login_steps", [])
        if not steps:
            return False
        try:
            vars_ctx = self.config.get("_vars", {})
            for step in steps:
                method = step.get("method", "GET").upper()
                url = step.get("url", "")
                data = step.get("data", {})
                headers = step.get("headers", {})
                json_body = step.get("json")

                for k, v in vars_ctx.items():
                    url = url.replace("{" + k + "}", str(v))
                    data = {dk: str(dv).replace("{" + k + "}", str(v))
                           for dk, dv in data.items()}
                    headers = {hk: str(hv).replace("{" + k + "}", str(v))
                              for hk, hv in headers.items()}

                if self.twofa and "{2fa_code}" in url + json.dumps(data, default=str):
                    code = self.twofa.generate_code() or ""
                    url = url.replace("{2fa_code}", code)
                    data = {dk: str(dv).replace("{2fa_code}", code)
                           for dk, dv in data.items()}

                if method == "POST":
                    resp = session.post(url, data=data, json=json_body,
                                       headers=headers, timeout=15, verify=self.verify_ssl)
                else:
                    resp = session.get(url, params=data, headers=headers,
                                      timeout=15, verify=self.verify_ssl)

                if not resp:
                    return False

                extract = step.get("extract")
                extract_as = step.get("extract_as")
                extract_from = step.get("extract_from", "body")

                if extract and extract_as:
                    source = resp.text
                    if extract_from == "header":
                        source = "\n".join(f"{k}: {v}"
                                          for k, v in resp.headers.items())
                    elif extract_from == "cookie":
                        source = "; ".join(f"{c.name}={c.value}"
                                          for c in resp.cookies)
                    m = re.search(extract, source, re.S)
                    if m:
                        vars_ctx[extract_as] = (m.group(1) if m.groups()
                                               else m.group(0))
                        self.config["_vars"] = vars_ctx

            final_url = self.config.get("login_check_url")
            if final_url:
                final_resp = session.get(final_url, timeout=10, verify=self.verify_ssl)
                return self._validate_login(final_resp)
            return True
        except Exception:
            return False