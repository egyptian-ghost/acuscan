#!/usr/bin/env python3
"""
Database Loader
===============
Loads checks_db.json and pre-compiles all regex patterns for speed.
"""
import os
import json
from typing import Dict, Optional

from core.config import DEFAULT_DB_PATH
from core.utils import compile_regex


class DatabaseContext:
    """Container for loaded database + compiled patterns."""

    def __init__(self, raw: dict):
        self.raw = raw
        self.injection = raw.get("injection_patterns", {})

        # Compiled regex caches
        self.sqli_plain = [p.lower() for p in
                          self.injection.get("sql_injection", {}).get("plain", [])]
        self.sqli_regex = self._compile_list(
            self.injection.get("sql_injection", {}).get("regex", []))

        self.error_plain = [p.lower() for p in
                           self.injection.get("error_messages", {}).get("plain", [])]
        self.error_regex = self._compile_list(
            self.injection.get("error_messages", {}).get("regex", []))

        self.lfi_plain = self.injection.get("directory_traversal", {}).get("plain", [])
        self.lfi_regex = self._compile_list(
            self.injection.get("directory_traversal", {}).get("regex", []))

        self.fi_plain = self.injection.get("file_inclusion", {}).get("plain", [])
        self.fi_regex = self._compile_list(
            self.injection.get("file_inclusion", {}).get("regex", []))

        self.rce_regex = self._compile_list(
            self.injection.get("code_execution", {}).get("regex", []))

        self.crlf_regex = self._compile_list(
            self.injection.get("crlf_injection", {}).get("regex", []))

        self.dirlist_plain = [p.lower() for p in
                             self.injection.get("dir_listing", {}).get("plain", [])]
        self.dirlist_regex = self._compile_list(
            self.injection.get("dir_listing", {}).get("regex", []))

        # Content analysis
        self.ca_compiled = {}
        ca = raw.get("content_analysis", {})
        for name, spec in ca.items():
            entry = {"plain": [], "regex": [], "labels": {}}
            for p in spec.get("plain", []):
                entry["plain"].append(p)
            for r in spec.get("regex", []):
                c = compile_regex(r.get("pattern", ""), r.get("flags", ""))
                if c:
                    entry["regex"].append(c)
                    if r.get("label"):
                        entry["labels"][id(c)] = r["label"]
            self.ca_compiled[name] = entry

    @staticmethod
    def _compile_list(items):
        out = []
        for r in items:
            c = compile_regex(r.get("pattern", ""), r.get("flags", ""))
            if c:
                out.append(c)
        return out

    # Convenience accessors
    @property
    def scripts(self):
        return self.raw.get("scripts", {})

    @property
    def vuln_db(self):
        return self.raw.get("vuln_db", {})

    @property
    def server_urls(self):
        return self.raw.get("server_urls", [])

    @property
    def postcrawl_urls(self):
        return self.raw.get("postcrawl_urls", [])

    @property
    def folder_checks(self):
        return self.raw.get("folder_checks", [])

    @property
    def webapp_patterns(self):
        return self.raw.get("webapp_patterns", {})

    @property
    def backup_variants(self):
        return self.injection.get("backup_variants", [])

    @property
    def backup_mime_types(self):
        return set(self.injection.get("backup_mime_types", []))


def load_db(path: Optional[str] = None) -> DatabaseContext:
    """Load checks_db.json and return a DatabaseContext."""
    path = path or DEFAULT_DB_PATH
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Database not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return DatabaseContext(raw)