#!/usr/bin/env python3
"""
Archive Manager
===============
Create/update from updatedbd_VERSION.tgz archives.
"""
import os
import json
import time
import tarfile
import shutil
import hashlib
from datetime import datetime
from io import BytesIO

from core.config import (
    DEFAULT_DB_PATH, DEFAULT_ARCHIVE_PREFIX, SCRIPT_DIR, VERSION,
)


def create_archive(archive_path=None):
    """Create updatedbd_VERSION.tgz from current DB."""
    if not os.path.isfile(DEFAULT_DB_PATH):
        print("  ✗ No DB found")
        return False

    with open(DEFAULT_DB_PATH, encoding="utf-8") as f:
        db = json.load(f)

    meta = db.get("_meta", {})
    ver = meta.get("acunetix_version", "0")

    if not archive_path:
        archive_path = os.path.join(
            SCRIPT_DIR, f"{DEFAULT_ARCHIVE_PREFIX}_{ver}.tgz"
        )

    try:
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(DEFAULT_DB_PATH, arcname="checks_db.json")
            manifest = {
                "format": "acuscan_vuln_db",
                "format_version": 2,
                "scanner_version": VERSION,
                "created": datetime.utcnow().isoformat(),
                "acunetix_version": ver,
                "db_checksum": meta.get("checksum", ""),
            }
            data = json.dumps(manifest, indent=2).encode()
            info = tarfile.TarInfo(name="manifest.json")
            info.size = len(data)
            info.mtime = time.time()
            tar.addfile(info, BytesIO(data))

        size_kb = os.path.getsize(archive_path) // 1024
        print(f"  ✓ Archive: {archive_path} ({size_kb}KB)")
        return True
    except Exception as e:
        print(f"  ✗ Failed to create archive: {e}")
        return False


def update_from_archive(archive_path=None):
    """Update DB from archive."""
    from .acunetix_paths import find_best_archive, get_db_version, \
        parse_version_int

    if not archive_path:
        found, _ = find_best_archive()
        if found:
            archive_path = found

    if not archive_path or not os.path.isfile(archive_path):
        print("  ✗ Archive not found")
        return False

    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            # Safety: no path traversal
            for member in tar.getmembers():
                if member.name.startswith("/") or ".." in member.name:
                    print(f"  ✗ Suspicious path: {member.name}")
                    return False

            names = tar.getnames()
            if "checks_db.json" not in names:
                print("  ✗ Archive does not contain checks_db.json")
                return False

            # Version check
            archive_ver = None
            if "manifest.json" in names:
                try:
                    mf = tar.extractfile("manifest.json")
                    if mf:
                        manifest = json.loads(mf.read().decode())
                        archive_ver = manifest.get("acunetix_version")
                except Exception:
                    pass

            installed_ver = get_db_version()
            if (installed_ver and archive_ver and
                parse_version_int(installed_ver) >=
                parse_version_int(archive_ver)):
                print(f"  ! Installed DB ({installed_ver}) is >= "
                      f"archive ({archive_ver})")
                print("  ! Skipping update")
                return True

            # Backup existing
            if os.path.isfile(DEFAULT_DB_PATH):
                backup = DEFAULT_DB_PATH + ".bak"
                shutil.copy2(DEFAULT_DB_PATH, backup)
                print(f"  ℹ Backup: {os.path.basename(backup)}")

            # Extract
            db_file = tar.extractfile("checks_db.json")
            data = db_file.read()
            json.loads(data)  # validate

            os.makedirs(os.path.dirname(DEFAULT_DB_PATH), exist_ok=True)
            with open(DEFAULT_DB_PATH, "wb") as f:
                f.write(data)

        size_kb = os.path.getsize(DEFAULT_DB_PATH) // 1024
        print(f"  ✓ Updated: {DEFAULT_DB_PATH} ({size_kb}KB)")
        return True
    except Exception as e:
        print(f"  ✗ Update failed: {e}")
        return False