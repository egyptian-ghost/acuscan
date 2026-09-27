#!/usr/bin/env python3
"""
Convert Acunetix security_NNNNN.bin → checks_db.json.

The .bin is a SQLite database with tables: chunk, file, vuln, meta.
Data in chunk table is brotli-compressed protobuf or JSON.
"""
import os
import re
import json
import sqlite3
import struct
import hashlib
import traceback
from datetime import datetime

try:
    import brotli
    HAS_BROTLI = True
except ImportError:
    HAS_BROTLI = False

from core.config import DEFAULT_DB_PATH


def _parse_protobuf(data):
    """Minimal protobuf parser for Acunetix vuln chunks."""
    fields = {}
    pos = 0
    while pos < len(data):
        tag = data[pos]
        fnum, wtype = tag >> 3, tag & 0x07
        pos += 1

        if wtype == 0:  # varint
            val, shift = 0, 0
            while pos < len(data):
                b = data[pos]; pos += 1
                val |= (b & 0x7f) << shift
                if not (b & 0x80):
                    break
                shift += 7
            fields[fnum] = val
        elif wtype == 2:  # length-delimited
            length, shift = 0, 0
            while pos < len(data):
                b = data[pos]; pos += 1
                length |= (b & 0x7f) << shift
                if not (b & 0x80):
                    break
                shift += 7
            if pos + length <= len(data):
                try:
                    fields[fnum] = data[pos:pos + length].decode("utf-8")
                except UnicodeDecodeError:
                    fields[fnum] = data[pos:pos + length]
                pos += length
            else:
                break
        else:
            break
    return fields


def _build_default_injection_patterns():
    """Default injection patterns for the scanner."""
    def R(pats):
        return [{"pattern": p, "flags": ""} for p in pats]

    return {
        "sql_injection": {
            "plain": [
                "You have an error in your SQL syntax",
                "mysql_fetch", "ORA-", "SQLSTATE[",
                "Microsoft OLE DB Provider for SQL Server",
                "Unclosed quotation mark",
            ],
            "regex": R([
                r"SQL syntax.*MySQL",
                r"ORA-\d{5}",
                r"PostgreSQL.*ERROR",
                r"System\.Data\.SqlClient\.SqlException",
            ]),
        },
        "error_messages": {
            "plain": ["Fatal error:", "Parse error:", "Warning:",
                     "Traceback (most recent call last)"],
            "regex": R([r"on line \d+"]),
        },
        "directory_traversal": {
            "plain": ["root:x:0:0:"],
            "regex": R([r"root:x:0:0:"]),
        },
        "file_inclusion": {"plain": [], "regex": []},
        "code_execution": {
            "regex": R([r"uid=\d+\(", r"root:x:0:0:"]),
        },
        "crlf_injection": {"regex": []},
        "dir_listing": {
            "plain": ["Index of /", "Parent Directory"],
            "regex": [],
        },
        "backup_variants": [
            "${fileName}${fileExt}.bak",
            "${fileName}${fileExt}.old",
            "${fileName}${fileExt}.orig",
            "${fileName}${fileExt}~",
            "${fileName}.bak",
        ],
        "backup_mime_types": [
            "application/octet-stream",
            "application/x-gzip",
        ],
    }


def convert_acunetix_bin(bin_path):
    """
    Convert security_NNNNN.bin to checks_db.json.
    Returns True on success.
    """
    if not HAS_BROTLI:
        print("  ✗ brotli required: pip install brotli")
        return False

    if not bin_path or not os.path.isfile(bin_path):
        print(f"  ✗ .bin not found: {bin_path}")
        return False

    print(f"  ✓ Source: {bin_path}")
    bin_size = os.path.getsize(bin_path) / (1024 * 1024)
    print(f"  ℹ Size: {bin_size:.1f} MB")

    # Version from filename
    fname = os.path.basename(bin_path)
    m = re.match(r"security_(\d+)\.bin$", fname, re.I)
    version = m.group(1) if m else "0"
    print(f"  ✓ Acunetix version: {version}")

    try:
        conn = sqlite3.connect(bin_path)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]
        print(f"  ✓ Tables: {', '.join(tables)}")

        # Read checks.json
        cur.execute("SELECT data FROM file WHERE name = 'checks.json'")
        row = cur.fetchone()
        if not row:
            print("  ✗ checks.json not in DB")
            conn.close()
            return False

        cur.execute("SELECT data FROM chunk WHERE chunk = ?", (row[0],))
        chunk_row = cur.fetchone()
        if not chunk_row:
            print(f"  ✗ Chunk {row[0]} not found")
            conn.close()
            return False

        checks_data = json.loads(brotli.decompress(chunk_row[0]).decode("utf-8"))

        # Extract scripts by category
        scripts_db = {
            cat: [] for cat in [
                "PerFile", "PerFolder", "PerScheme", "PerServer",
                "PostCrawl", "PostScan", "WebApps", "Network",
            ]
        }
        total_scripts = 0

        for group in checks_data.get("checks", []):
            if group.get("key") == "Scripts":
                for cat_group in group.get("checks", []):
                    cat_key = cat_group.get("key", "")
                    if cat_key not in scripts_db:
                        scripts_db[cat_key] = []
                    for sc in cat_group.get("checks", []):
                        if sc.get("key"):
                            scripts_db[cat_key].append({
                                "name": sc["key"].replace(".script", ""),
                                "file": sc["key"],
                                "title": sc.get("title", ""),
                                "urls": [],
                                "vuln_refs": [],
                            })
                            total_scripts += 1

        # Extract vulnerabilities
        cur.execute(
            "SELECT v.vuln, v.path, c.data FROM vuln v "
            "JOIN chunk c ON v.data = c.chunk"
        )
        vuln_db = {}
        for vid, vpath, cdata in cur.fetchall():
            try:
                f = _parse_protobuf(brotli.decompress(cdata))
                ref = os.path.basename(vpath or vid).replace(".yaml", "")
                sev_int = f.get(4, 0)
                sev_map = {1: "info", 2: "low", 3: "medium",
                          4: "high", 5: "critical"}
                vuln_db[ref] = {
                    "name": f.get(3, ref),
                    "severity": sev_map.get(sev_int, "info"),
                    "cvss_score": str(round(f.get(5, 0), 1)),
                    "description": (f.get(8, "") or "")[:500],
                }
            except Exception:
                continue
        conn.close()

        # Build the final database
        db = {
            "_meta": {
                "version": "6.0",
                "generator": "AcuScan bin converter",
                "generated_at": datetime.utcnow().isoformat(),
                "acunetix_version": version,
                "generated": datetime.utcnow().strftime("%d%m%y%H%M"),
                "stats": {
                    "total_scripts": total_scripts,
                    "vuln_definitions": len(vuln_db),
                },
            },
            "injection_patterns": _build_default_injection_patterns(),
            "scripts": scripts_db,
            "vuln_db": vuln_db,
            "server_urls": [],
            "postcrawl_urls": [],
            "folder_checks": [],
            "webapp_patterns": {},
            "content_analysis": {},
        }

        content = json.dumps(db, sort_keys=True)
        db["_meta"]["checksum"] = hashlib.sha256(
            content.encode()
        ).hexdigest()[:16]

        os.makedirs(os.path.dirname(DEFAULT_DB_PATH), exist_ok=True)
        with open(DEFAULT_DB_PATH, "w", encoding="utf-8") as f:
            json.dump(db, f, ensure_ascii=False)

        size_kb = os.path.getsize(DEFAULT_DB_PATH) // 1024
        print(f"  ✓ DB: {DEFAULT_DB_PATH} ({size_kb}KB)")
        print(f"  ✓ Scripts: {total_scripts}, Vulns: {len(vuln_db)}")
        return True
    except Exception as e:
        print(f"  ✗ Conversion failed: {e}")
        traceback.print_exc()
        return False