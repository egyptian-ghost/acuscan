#!/usr/bin/env python3
"""AcuScan configuration & constants."""
import os
import sys

VERSION = "6.9.0"
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DB_PATH = os.path.join(SCRIPT_DIR, "data", "checks_db.json")
DEFAULT_STORAGE_DB = os.path.join(SCRIPT_DIR, "data", "acuscan.db")
PLUGINS_DIR = os.path.join(SCRIPT_DIR, "scanner", "plugins")

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
DEFAULT_ARCHIVE_PREFIX = "updatedbd"
IS_WINDOWS = (sys.platform == "win32")


def detect_acunetix_paths():
    """Return (scripts_dir, install_dir) based on platform."""
    if IS_WINDOWS:
        pd = os.environ.get("ProgramData", r"C:\ProgramData")
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        script_candidates = [
            os.path.join(SCRIPT_DIR, "acunetix_scripts", "Scripts"),
            os.path.join(SCRIPT_DIR, "Scripts"),
            os.path.join(pd, "Acunetix", "shared", "Scripts"),
            os.path.join(pf, "Acunetix", "data", "Scripts"),
        ]
        install_candidates = [
            os.path.join(pd, "Acunetix"),
            os.path.join(pf, "Acunetix"),
        ]
    else:
        script_candidates = [
            os.path.join(SCRIPT_DIR, "acunetix_scripts", "Scripts"),
            os.path.join(SCRIPT_DIR, "Scripts"),
            "/home/acunetix/.acunetix/data/Scripts",
            os.path.expanduser("~/.acunetix/data/Scripts"),
            "/opt/acunetix/data/Scripts",
        ]
        install_candidates = [
            "/home/acunetix/.acunetix",
            os.path.expanduser("~/.acunetix"),
            "/opt/acunetix",
        ]

    scripts = None
    for p in script_candidates:
        if os.path.isdir(p):
            if (os.path.isdir(os.path.join(p, "Includes")) or
                os.path.isdir(os.path.join(p, "PerServer"))):
                scripts = p
                break

    install = None
    for p in install_candidates:
        if os.path.isdir(p):
            install = p
            break

    return scripts, install


DEFAULT_ACUNETIX_SCRIPTS, ACUNETIX_INSTALL_DIR = detect_acunetix_paths()