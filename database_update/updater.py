#!/usr/bin/env python3
"""DatabaseUpdater — the public interface for all DB update operations."""
import os
import json
import subprocess
import sys
from datetime import datetime

from core.config import DEFAULT_DB_PATH, SCRIPT_DIR
from core.colors import C

from .acunetix_paths import (
    detect_acunetix_version, get_db_version,
    find_best_archive, find_security_bin, find_acunetix_scripts,
)
from .bin_converter import convert_acunetix_bin
from .archive_manager import create_archive, update_from_archive


class DatabaseUpdater:
    """Public interface for DB update operations."""

    def __init__(self, no_color=False):
        self.no_color = no_color

    def _c(self, code, text):
        return text if self.no_color else f"{code}{text}{C.RST}"

    def _banner(self, title):
        print()
        print(self._c(C.CYN, f"  ╔{'═' * 58}╗"))
        print(self._c(C.CYN, f"  ║  {title:<56}║"))
        print(self._c(C.CYN, f"  ╚{'═' * 58}╝"))
        print()

    def _ok(self, msg):
        print(f"  {self._c(C.GRN, '✓')} {msg}")

    def _info(self, msg):
        print(f"  {self._c(C.CYN, 'ℹ')} {msg}")

    def _err(self, msg):
        print(f"  {self._c(C.RED, '✗')} {msg}")

    def _warn(self, msg):
        print(f"  {self._c(C.YLW, '!')} {msg}")

    # ═══════════════════════════════════════════════════════════════════════
    #  Auto-provision
    # ═══════════════════════════════════════════════════════════════════════

    def auto_provision(self):
        """Ensure the DB exists. Try archive → Acunetix → minimal."""
        if os.path.isfile(DEFAULT_DB_PATH):
            return True

        self._banner("Auto-Provisioning Database")
        self._warn("No database found — attempting auto-provision")

        # 1. Try existing archive
        found, ver = find_best_archive()
        if found:
            self._info(f"Found archive: {os.path.basename(found)}")
            if update_from_archive(found) and os.path.isfile(DEFAULT_DB_PATH):
                return True

        # 2. Try Acunetix extraction
        self._info("Trying Acunetix extraction...")
        if self.update_from_acunetix() and os.path.isfile(DEFAULT_DB_PATH):
            create_archive()
            return True

        # 3. Minimal fallback
        self._err("Auto-provisioning failed — creating minimal DB")
        return self._create_minimal_db()

    def _create_minimal_db(self):
        os.makedirs(os.path.dirname(DEFAULT_DB_PATH), exist_ok=True)
        minimal = {
            "_meta": {
                "version": "6.0",
                "generator": "AcuScan minimal fallback",
                "generated_at": datetime.utcnow().isoformat(),
                "acunetix_version": "0",
            },
            "injection_patterns": {
                "sql_injection": {
                    "plain": [
                        "You have an error in your SQL syntax",
                        "mysql_fetch", "ORA-", "SQLSTATE[",
                    ],
                    "regex": [
                        {"pattern": r"SQL syntax.*MySQL", "flags": ""},
                        {"pattern": r"ORA-\d{5}", "flags": ""},
                    ],
                },
                "error_messages": {
                    "plain": ["Fatal error:", "Parse error:", "Warning:"],
                    "regex": [{"pattern": r"on line \d+", "flags": ""}],
                },
                "directory_traversal": {
                    "plain": ["root:x:0:0:"],
                    "regex": [{"pattern": r"root:x:0:0:", "flags": ""}],
                },
                "file_inclusion": {"plain": [], "regex": []},
                "code_execution": {
                    "regex": [{"pattern": r"uid=\d+\(", "flags": ""}],
                },
                "crlf_injection": {"regex": []},
                "dir_listing": {
                    "plain": ["Index of /", "Parent Directory"],
                    "regex": [],
                },
                "backup_variants": [
                    "${fileName}${fileExt}.bak",
                    "${fileName}${fileExt}.old",
                ],
                "backup_mime_types": ["application/octet-stream"],
            },
            "scripts": {
                "PerServer": [], "PerFolder": [], "PerFile": [],
                "PerScheme": [], "PostCrawl": [], "PostScan": [],
                "WebApps": [], "Network": [],
            },
            "vuln_db": {},
            "server_urls": [],
            "postcrawl_urls": [],
            "folder_checks": [],
            "webapp_patterns": {},
            "content_analysis": {},
        }
        with open(DEFAULT_DB_PATH, "w", encoding="utf-8") as f:
            json.dump(minimal, f, indent=2)
        self._ok(f"Created minimal DB: {DEFAULT_DB_PATH}")
        return True

    # ═══════════════════════════════════════════════════════════════════════
    #  -upac: From Acunetix scripts
    # ═══════════════════════════════════════════════════════════════════════

    def update_from_acunetix(self, scripts_dir=None):
        self._banner("Update from Acunetix")
        if not scripts_dir:
            scripts_dir = find_acunetix_scripts()

        if not scripts_dir or not os.path.isdir(scripts_dir):
            self._err("Scripts dir not found")
            return False

        self._ok(f"Scripts: {scripts_dir}")

        updater = os.path.join(SCRIPT_DIR, "updater", "extract_checks.py")
        if not os.path.isfile(updater):
            self._err(f"Extractor not found: {updater}")
            return False

        result = subprocess.run(
            [sys.executable, updater,
             "--acunetix-scripts-dir", scripts_dir,
             "--output", DEFAULT_DB_PATH],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            self._err("Extraction failed")
            if result.stderr:
                print(result.stderr)
            return False

        for line in result.stdout.strip().split("\n"):
            print(f"    {line}")

        version = detect_acunetix_version() or "0"
        with open(DEFAULT_DB_PATH, encoding="utf-8") as f:
            db = json.load(f)
        db["_meta"]["acunetix_version"] = version
        db["_meta"]["generated"] = datetime.utcnow().strftime("%d%m%y%H%M")
        with open(DEFAULT_DB_PATH, "w", encoding="utf-8") as f:
            json.dump(db, f, ensure_ascii=False)
        self._ok("DB updated")
        return True

    # ═══════════════════════════════════════════════════════════════════════
    #  -acuconvupdate: Convert .bin
    # ═══════════════════════════════════════════════════════════════════════

    def convert_bin(self, bin_path=None):
        self._banner("Convert Acunetix .bin")
        if not bin_path:
            bin_path = find_security_bin()
        if not bin_path or not os.path.isfile(bin_path):
            self._err(".bin not found")
            return False

        ok = convert_acunetix_bin(bin_path)
        if ok:
            self.create_archive()
        return ok

    # ═══════════════════════════════════════════════════════════════════════
    #  -cupz / -upuz
    # ═══════════════════════════════════════════════════════════════════════

    def create_archive(self, archive_path=None):
        self._banner("Create Archive")
        if not os.path.isfile(DEFAULT_DB_PATH):
            self._warn("No DB — extracting from Acunetix first...")
            if not self.update_from_acunetix():
                return False
        return create_archive(archive_path)

    def update_from_archive(self, archive_path=None):
        self._banner("Update from Archive")
        return update_from_archive(archive_path)