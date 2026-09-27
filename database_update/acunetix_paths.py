#!/usr/bin/env python3
"""Detect Acunetix installation paths and versions."""
import os
import re

from core.config import (
    DEFAULT_DB_PATH, IS_WINDOWS, SCRIPT_DIR,
    detect_acunetix_paths,
)


def detect_acunetix_version():
    """Detect the installed Acunetix version."""
    best_ver = None
    best_int = 0

    # Windows: security_NNNNN.bin
    if IS_WINDOWS:
        pd = os.environ.get("ProgramData", r"C:\ProgramData")
        sec_dirs = [
            os.path.join(pd, "Acunetix", "shared", "security"),
            os.path.join(
                os.environ.get("ProgramFiles", r"C:\Program Files"),
                "Acunetix", "shared", "security",
            ),
        ]
        pat = re.compile(r"^security_(\d+)\.bin$", re.I)
        for d in sec_dirs:
            if not os.path.isdir(d):
                continue
            try:
                for e in os.listdir(d):
                    m = pat.match(e)
                    if m:
                        v = int(m.group(1))
                        if v > best_int:
                            best_int = v
                            best_ver = m.group(1)
            except PermissionError:
                continue

    # Linux: v_NNNNNNNNN directory
    scripts_dir, install_dir = detect_acunetix_paths()
    candidates = []
    if install_dir:
        candidates.append(install_dir)
    if not IS_WINDOWS:
        candidates.extend([
            "/home/acunetix/.acunetix",
            os.path.expanduser("~/.acunetix"),
            "/opt/acunetix",
        ])
    for base in candidates:
        if not base or not os.path.isdir(base):
            continue
        try:
            for entry in os.listdir(base):
                if entry.startswith("v_") and os.path.isdir(
                    os.path.join(base, entry)
                ):
                    ver = entry[2:]
                    if ver.isdigit():
                        v = int(ver)
                        if v > best_int:
                            best_int = v
                            best_ver = ver
        except PermissionError:
            continue

    return best_ver


def get_db_version(db_path=None):
    """Read version from an existing checks_db.json."""
    import json
    path = db_path or DEFAULT_DB_PATH
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            db = json.load(f)
        return db.get("_meta", {}).get("acunetix_version")
    except Exception:
        return None


def parse_version_int(ver_str):
    """Convert version string to int for comparison."""
    if not ver_str:
        return 0
    try:
        return int(ver_str)
    except Exception:
        return 0


def find_best_archive(search_dirs=None):
    """Find updatedbd_*.tgz with the highest version."""
    from core.config import DEFAULT_ARCHIVE_PREFIX
    if search_dirs is None:
        search_dirs = [os.getcwd(), SCRIPT_DIR]

    best_path = None
    best_ver = 0
    best_ver_str = None
    pat = re.compile(rf"^{DEFAULT_ARCHIVE_PREFIX}_(\d+)\.tgz$")

    for d in search_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for fname in os.listdir(d):
                m = pat.match(fname)
                if m:
                    v = int(m.group(1))
                    if v > best_ver:
                        best_ver = v
                        best_ver_str = m.group(1)
                        best_path = os.path.join(d, fname)
        except PermissionError:
            continue

    return best_path, best_ver_str


def find_security_bin():
    """Find security_NNNNN.bin with the highest version."""
    dirs = []
    if IS_WINDOWS:
        pd = os.environ.get("ProgramData", r"C:\ProgramData")
        dirs.append(os.path.join(pd, "Acunetix", "shared", "security"))
    else:
        dirs.extend([
            "/home/acunetix/.acunetix/data/security",
            os.path.expanduser("~/.acunetix/data/security"),
        ])
    dirs.extend([os.getcwd(), SCRIPT_DIR])

    best = None
    best_ver = 0
    pat = re.compile(r"^security_(\d+)\.bin$", re.I)

    for d in dirs:
        if not d or not os.path.isdir(d):
            continue
        try:
            for entry in os.listdir(d):
                m = pat.match(entry)
                if m:
                    v = int(m.group(1))
                    if v > best_ver:
                        best_ver = v
                        best = os.path.join(d, entry)
        except PermissionError:
            continue

    return best


def find_acunetix_scripts():
    """Find decoded Acunetix scripts directory."""
    detected, _ = detect_acunetix_paths()
    if detected:
        return detected
    candidates = [
        os.path.join(SCRIPT_DIR, "acunetix_scripts", "Scripts"),
        os.path.join(SCRIPT_DIR, "Scripts"),
    ]
    if IS_WINDOWS:
        pd = os.environ.get("ProgramData", r"C:\ProgramData")
        candidates.append(os.path.join(pd, "Acunetix", "shared", "Scripts"))
    else:
        candidates.extend([
            "/home/acunetix/.acunetix/data/Scripts",
            os.path.expanduser("~/.acunetix/data/Scripts"),
            "/opt/acunetix/data/Scripts",
        ])
    for p in candidates:
        if os.path.isdir(p):
            if (os.path.isdir(os.path.join(p, "Includes")) or
                os.path.isdir(os.path.join(p, "PerServer"))):
                return p
    return None