#!/usr/bin/env python3
"""
Detection Patterns
==================
Reusable detection helpers for LFI, errors, dir listing, etc.
Uses the compiled patterns from DatabaseContext.
"""
import re

from core.utils import luhn_check


class DetectionHelper:
    """Wraps detection logic using compiled DB patterns."""

    def __init__(self, db):
        self.db = db

    # ═══════════════════════════════════════════════════════════════════════
    #  SQL / errors
    # ═══════════════════════════════════════════════════════════════════════

    def detect_sqli(self, text):
        if not text:
            return None
        tl = text.lower()
        for p in self.db.sqli_plain:
            if p in tl:
                return p
        for rx in self.db.sqli_regex:
            m = rx.search(text)
            if m:
                return m.group(0)[:200]
        return None

    def detect_errors(self, text):
        if not text:
            return None
        tl = text.lower()
        for p in self.db.error_plain:
            if p in tl:
                return p
        for rx in self.db.error_regex:
            m = rx.search(text)
            if m:
                return m.group(0)[:200]
        return None

    # ═══════════════════════════════════════════════════════════════════════
    #  LFI / FI / RCE
    # ═══════════════════════════════════════════════════════════════════════

    def detect_lfi(self, text):
        if not text:
            return None
        for p in self.db.lfi_plain:
            if p in text:
                return p
        for rx in self.db.lfi_regex:
            m = rx.search(text)
            if m:
                return m.group(0)[:200]
        return None

    def detect_fi(self, text):
        if not text:
            return None
        for p in self.db.fi_plain:
            if p in text:
                return p
        for rx in self.db.fi_regex:
            m = rx.search(text)
            if m:
                return m.group(0)[:200]
        return None

    def detect_rce(self, text):
        if not text:
            return None
        for rx in self.db.rce_regex:
            m = rx.search(text)
            if m:
                return m.group(0)[:200]
        return None

    def detect_crlf(self, text):
        if not text:
            return None
        for rx in self.db.crlf_regex:
            m = rx.search(text)
            if m:
                return m.group(0)[:200]
        return None

    # ═══════════════════════════════════════════════════════════════════════
    #  Directory listing
    # ═══════════════════════════════════════════════════════════════════════

    def detect_dirlist(self, text):
        if not text:
            return None
        tl = text.lower()
        for p in self.db.dirlist_plain:
            if p in tl:
                return p
        for rx in self.db.dirlist_regex:
            m = rx.search(text)
            if m:
                return m.group(0)[:100]
        return None

    # ═══════════════════════════════════════════════════════════════════════
    #  Content analysis
    # ═══════════════════════════════════════════════════════════════════════

    def _ca_detect(self, name, text):
        if not text:
            return None
        entry = self.db.ca_compiled.get(name, {})
        for p in entry.get("plain", []):
            if p.lower() in text.lower():
                return p
        for rx in entry.get("regex", []):
            m = rx.search(text)
            if m:
                label = entry.get("labels", {}).get(id(rx))
                return label if label else (m.group(0)[:200]
                                           if m.group(0) else True)
        return None

    def _ca_findall(self, name, text):
        if not text:
            return []
        results = []
        entry = self.db.ca_compiled.get(name, {})
        for rx in entry.get("regex", []):
            try:
                results.extend(rx.findall(text))
            except Exception:
                pass
        return results

    def detect_phpinfo(self, text):
        return bool(self._ca_detect("phpinfo", text))

    def detect_internal_ip(self, text):
        result = self._ca_detect("internal_ip", text)
        if result and not str(result).startswith('127.0.'):
            return result
        return None

    def detect_emails(self, text):
        return self._ca_findall("email_addresses", text)

    def detect_credit_cards(self, text):
        if not text:
            return []
        matches = self._ca_findall("credit_cards", text)
        out = []
        for m in matches:
            s = str(m) if not isinstance(m, str) else m
            if luhn_check(s):
                out.append(s)
        return out

    def detect_private_key(self, text):
        return self._ca_detect("private_key", text)

    def detect_source_code(self, text):
        return self._ca_detect("source_code", text)

    def detect_trojan_shell(self, text):
        return self._ca_detect("trojan_shell", text)

    def detect_mysql_dump(self, text):
        return self._ca_detect("mysql_dump", text)

    def detect_env_variables(self, text):
        r = self._ca_detect("env_variables", text)
        return r[:200] if r and isinstance(r, str) else r

    def detect_path_disclosure_unix(self, text):
        if not text:
            return None
        result = self._ca_detect("path_disclosure_unix", text)
        if result and isinstance(result, str):
            if result.rsplit('.', 1)[-1].lower() != 'js':
                return result
        return None

    def detect_path_disclosure_windows(self, text):
        return self._ca_detect("path_disclosure_windows", text)