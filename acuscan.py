#!/usr/bin/env python3
"""
AcuScan v6.7 — Unified Entry Point
====================================
Usage:
  python acuscan.py -u https://target.com
  python acuscan.py -u https://target.com --verify --oast
  python acuscan.py -l targets.txt -o report.html
  python acuscan.py --web-ui --web-port 8080
  python acuscan.py -upac                 # extract from Acunetix
  python acuscan.py -acuconvupdate file.bin
  python acuscan.py -cupz
  python acuscan.py -upuz
  python acuscan.py --list-plugins
  python acuscan.py --create-example-plugin

Changes in v6.3:
  - Added _cleanup_stuck_scans() — marks old 'running' scans as 'stopped'
  - Improved error handling for missing modules
  - Better DB auto-provisioning
  - Supports all output formats (txt/json/html/md/sarif/csv/pdf)
"""
import os
import sys
import signal
import argparse
import threading
import traceback
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed

# Make project importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import VERSION, DEFAULT_DB_PATH
from core.colors import C
from core.output import OutputFormatter


# ═══════════════════════════════════════════════════════════════════════════════
#  Lazy imports (only load what's needed)
# ═══════════════════════════════════════════════════════════════════════════════

def _import_scanner():
    from scanner import Scanner
    return Scanner


def _import_updater():
    from database_update import DatabaseUpdater
    return DatabaseUpdater


def _import_reports():
    from reports import (
        write_text_report, write_json_report, write_html_report,
        write_csv_report, write_sarif_report, write_markdown_report,
        write_pdf_report,
    )
    return {
        "text": write_text_report,
        "json": write_json_report,
        "html": write_html_report,
        "csv": write_csv_report,
        "sarif": write_sarif_report,
        "markdown": write_markdown_report,
        "pdf": write_pdf_report,
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  Cleanup stuck scans (from previous crashed runs)
# ═══════════════════════════════════════════════════════════════════════════════

def _cleanup_stuck_scans():
    """
    Mark any 'running' or 'pending' scans in SQLite as 'stopped'.
    Called on every startup to prevent ghost scans.
    """
    try:
        from storage import get_storage
        storage = get_storage()
        if not storage:
            return

        with storage._connect() as conn:
            cur = conn.execute(
                "SELECT id, targets, started_at FROM scans "
                "WHERE status IN ('running', 'pending')"
            )
            stuck = cur.fetchall()

            if not stuck:
                return

            print(f"\n  {C.YLW}━━━{C.RST} "
                  f"{C.BLD + C.WHT}Startup Cleanup{C.RST}")
            print(f"  {C.GRY}Found {len(stuck)} stuck scan(s) from previous run:"
                  f"{C.RST}")
            for row in stuck:
                scan_id = row[0]
                targets = row[1]
                started = row[2] or "unknown"
                # Truncate long target list
                t_display = targets
                if len(t_display) > 60:
                    t_display = t_display[:57] + "..."
                print(f"    {C.GRY}→ #{scan_id}: {t_display}{C.RST}")

            conn.execute(
                "UPDATE scans SET status='stopped', "
                "finished_at=CURRENT_TIMESTAMP, "
                "duration_seconds=0 "
                "WHERE status IN ('running', 'pending')"
            )
            # Runtime target locks belong to the previous process. There is
            # no live ScanJob after a fresh process start, so retaining them
            # would make the same target look permanently busy.
            conn.execute("DELETE FROM active_scan_targets")
            print(f"  {C.GRN}✓{C.RST} Marked all stuck scans as "
                  f"{C.YLW}'stopped'{C.RST}")
            print(f"  {C.GRN}✓{C.RST} Cleared stale target locks\n")

    except Exception as e:
        # Silent — this is optional cleanup
        pass


# ═══════════════════════════════════════════════════════════════════════════════
#  CLI Parser
# ═══════════════════════════════════════════════════════════════════════════════

class WideHelpFormatter(argparse.RawDescriptionHelpFormatter):
    def __init__(self, prog, indent_increment=2,
                 max_help_position=70, width=150):
        super().__init__(
            prog, indent_increment=indent_increment,
            max_help_position=max_help_position, width=width,
        )


def _parse_login_data(s):
    """Parse 'k1=v1,k2=v2' or JSON to dict."""
    if not s:
        return {}
    s = s.strip()
    if s.startswith("{"):
        try:
            import json
            return json.loads(s)
        except Exception:
            pass
    result = {}
    for pair in s.split(","):
        if "=" in pair:
            k, v = pair.split("=", 1)
            result[k.strip()] = v.strip()
    return result


def build_parser():
    parser = argparse.ArgumentParser(
        prog="acuscan.py",
        description=f"{C.CYN}AcuScan v{VERSION}{C.RST}",
        formatter_class=WideHelpFormatter,
        epilog=f"""
{C.GRY}EXAMPLES:{C.RST}
  Basic scan:         python acuscan.py -u https://target.com
  With cookies:       python acuscan.py -u https://target.com --cookie "session=abc"
  Basic auth:         python acuscan.py -u https://target.com --auth admin:pass
  Bearer token:       python acuscan.py -u https://target.com --bearer "eyJ..."
  Auto login:         python acuscan.py -u https://t.com --auto-login --login-url https://t.com/login --login-data "u=admin,p=pass" --login-check "Welcome"
  With 2FA:           python acuscan.py -u https://t.com --auto-login ... --totp-secret "JBSWY3DPEHPK3PXP"
  OAST enabled:       python acuscan.py -u https://t.com --oast
  Burp proxy:         python acuscan.py -u https://t.com --burp 127.0.0.1:8080
  Reports:            python acuscan.py -u https://t.com -o report.txt -oh report.html -oj report.json
  {C.CYN}Web UI:{C.RST}             python acuscan.py --web-ui --web-port 8080
  DB from Acunetix:   python acuscan.py -upac
  Convert .bin:       python acuscan.py -acuconvupdate security_123.bin
        """
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"AcuScan v{VERSION}",
        help="Show version and exit",
    )

    # ── TARGET ──
    g = parser.add_argument_group(f"{C.CYN}TARGET{C.RST}")
    g.add_argument("-u", "-target", "--target", dest="targets",
                   action="append", default=[], metavar="URL",
                   help="Target URL (repeatable)")
    g.add_argument("-l", "-list", "--list", dest="list_file",
                   metavar="path", help="File with target URLs")

    # ── OUTPUT ──
    g = parser.add_argument_group(f"{C.CYN}OUTPUT{C.RST}")
    g.add_argument("-o", "--output", dest="output", metavar="path",
                   help="Text report")
    g.add_argument("-oj", "--output-json", dest="output_json",
                   metavar="path", help="JSON report")
    g.add_argument("-oh", "--output-html", dest="output_html",
                   metavar="path", help="HTML report")
    g.add_argument("-omd", "--output-markdown", dest="output_md",
                   metavar="path", help="Markdown report")
    g.add_argument("-osarif", "--output-sarif", dest="output_sarif",
                   metavar="path", help="SARIF report")
    g.add_argument("-ocsv", "--output-csv", dest="output_csv",
                   metavar="path", help="CSV report")
    g.add_argument("-opdf", "--output-pdf", dest="output_pdf",
                   metavar="path", help="PDF report")
    g.add_argument("-ooh", "--output-both", dest="output_both",
                   metavar="prefix",
                   help="Output all formats with prefix")
    g.add_argument("-silent", "--silent", action="store_true",
                   help="Silent mode (only findings)")
    g.add_argument("-nc", "--no-color", dest="no_color",
                   action="store_true", help="Disable colors")
    g.add_argument("-v", "--verbose", action="store_true",
                   help="Verbose output")

    # ── AUTHENTICATION ──
    g = parser.add_argument_group(f"{C.CYN}AUTHENTICATION{C.RST}")
    g.add_argument("-H", "--header", dest="headers", action="append",
                   default=[], metavar="K:V",
                   help="Custom header (repeatable)")
    g.add_argument("--headers-file", dest="headers_file", metavar="path",
                   help="Headers file (K: V per line)")
    g.add_argument("--cookie", dest="cookie", metavar="str",
                   help="Cookie string")
    g.add_argument("--cookie-file", dest="cookie_file", metavar="path",
                   help="Cookie file")
    g.add_argument("--auth", dest="auth", metavar="user:pass",
                   help="HTTP Basic auth")
    g.add_argument("--bearer", dest="bearer", metavar="token",
                   help="Bearer token")
    g.add_argument("--api-key", dest="api_key", metavar="key",
                   help="API key")
    g.add_argument("--api-key-header", dest="api_key_header",
                   metavar="name", default="X-API-Key",
                   help="API key header name")
    g.add_argument("--auth-header", dest="auth_header", metavar="K:V",
                   help="Custom auth header")

    # ── FORM LOGIN ──
    g = parser.add_argument_group(f"{C.CYN}FORM LOGIN{C.RST}")
    g.add_argument("--auto-login", dest="auto_login", action="store_true",
                   help="Enable form auto-login")
    g.add_argument("--login-url", dest="login_url", metavar="URL",
                   help="Login URL")
    g.add_argument("--login-method", dest="login_method",
                   default="POST", choices=["GET", "POST"],
                   help="Login HTTP method")
    g.add_argument("--login-data", dest="login_data",
                   metavar="k=v,k=v", help="Login form data")
    g.add_argument("--login-check", dest="login_check", metavar="str",
                   help="Success indicator string")
    g.add_argument("--logout-check", dest="logout_check", metavar="str",
                   help="Logged-in indicator string")
    g.add_argument("--login-check-url", dest="login_check_url",
                   metavar="URL", help="URL to verify login")
    g.add_argument("--username-field", dest="username_field",
                   default="username", help="Username field name")
    g.add_argument("--password-field", dest="password_field",
                   default="password", help="Password field name")
    g.add_argument("--login-steps", dest="login_steps", metavar="JSON",
                   help="Multi-step login JSON")
    g.add_argument("--login-steps-file", dest="login_steps_file",
                   metavar="path", help="Multi-step login file")

    # ── CSRF ──
    g = parser.add_argument_group(f"{C.CYN}CSRF{C.RST}")
    g.add_argument("--csrf-field", dest="csrf_field", metavar="name",
                   help="CSRF form field")
    g.add_argument("--csrf-pattern", dest="csrf_pattern",
                   action="append", default=[], metavar="regex",
                   help="CSRF extraction regex (repeatable)")
    g.add_argument("--csrf-header", dest="csrf_header", metavar="name",
                   help="CSRF header name")
    g.add_argument("--csrf-meta", dest="csrf_meta", metavar="name",
                   help="CSRF meta tag name")
    g.add_argument("--csrf-input", dest="csrf_input", metavar="name",
                   help="CSRF hidden input name")

    # ── 2FA / TOTP ──
    g = parser.add_argument_group(f"{C.CYN}2FA / TOTP{C.RST}")
    g.add_argument("--totp-secret", dest="totp_secret", metavar="BASE32",
                   help="TOTP secret (base32)")
    g.add_argument("--totp-code", dest="totp_code", metavar="NNNNNN",
                   help="Manual TOTP code")
    g.add_argument("--totp-digits", dest="totp_digits", type=int,
                   default=6, help="TOTP digits")
    g.add_argument("--totp-interval", dest="totp_interval", type=int,
                   default=30, help="TOTP interval (seconds)")
    g.add_argument("--totp-algorithm", dest="totp_algorithm",
                   default="SHA1", help="TOTP algorithm")
    g.add_argument("--totp-backup-codes", dest="totp_backup_codes",
                   metavar="c1,c2", help="Backup codes")
    g.add_argument("--totp-sync-time", dest="totp_sync_time",
                   action="store_true", help="Sync TOTP with server time")

    # ── SESSION ──
    g = parser.add_argument_group(f"{C.CYN}SESSION{C.RST}")
    g.add_argument("--session-file", dest="session_file", metavar="path",
                   help="Save/load session")
    g.add_argument("--save-session-only", dest="save_session_only",
                   action="store_true",
                   help="Login, save session, then exit")
    g.add_argument("--refresh-interval", dest="refresh_interval",
                   type=int, default=0, metavar="sec",
                   help="Re-login every N seconds")

    # ── BRUTE FORCE ──
    g = parser.add_argument_group(f"{C.CYN}BRUTE-FORCE{C.RST}")
    g.add_argument("--brute-force", dest="brute_force",
                   action="store_true", help="Enable login brute-force")
    g.add_argument("--userlist", dest="userlist_file", metavar="path",
                   help="Username wordlist")
    g.add_argument("--passlist", dest="passlist_file", metavar="path",
                   help="Password wordlist")

    # ── VERIFICATION ──
    g = parser.add_argument_group(f"{C.CYN}VERIFICATION{C.RST}")
    g.add_argument("--verify", dest="enable_verification",
                   action="store_true", default=True,
                   help="Enable verification (default: on)")
    g.add_argument("--no-verify", dest="enable_verification",
                   action="store_false",
                   help="Disable verification (faster, more false positives)")

    # ── OAST ──
    g = parser.add_argument_group(f"{C.CYN}OAST (Out-of-Band){C.RST}")
    g.add_argument("--oast", dest="enable_oast", action="store_true",
                   help="Enable OAST server for blind detection")
    g.add_argument("--oast-port", dest="oast_port", type=int, default=8000,
                   help="OAST HTTP port")
    g.add_argument("--oast-dns-port", dest="oast_dns_port", type=int,
                   default=5353, help="OAST DNS port")
    g.add_argument("--oast-domain", dest="oast_domain",
                   default="oast.local", help="OAST base domain")
    g.add_argument("--oast-public-ip", dest="oast_public_ip",
                   help="OAST public IP")
    g.add_argument("--oast-mode", dest="oast_mode", default="local",
                   choices=["local", "remote", "interactsh"],
                   help="OAST mode")

    # ── STORAGE ──
    g = parser.add_argument_group(f"{C.CYN}STORAGE{C.RST}")
    g.add_argument("--no-storage", dest="enable_storage",
                   action="store_false", default=True,
                   help="Disable SQLite persistence")
    g.add_argument("--storage-db", dest="storage_db", metavar="path",
                   help="SQLite database path")

    # ── PROXY CHAIN ──
    g = parser.add_argument_group(f"{C.CYN}PROXY CHAIN{C.RST}")
    g.add_argument("--proxy-chain", dest="proxy_chain", action="append",
                   default=[], metavar="URL",
                   help="Proxy chain (repeatable, in order)")
    g.add_argument("--burp", dest="burp", metavar="host:port",
                   nargs="?", const="127.0.0.1:8080",
                   help="Burp Suite proxy shortcut")
    g.add_argument("--proxy", dest="proxy", metavar="URL",
                   help="Single proxy URL")

    # ── CONFIG ──
    g = parser.add_argument_group(f"{C.CYN}CONFIG{C.RST}")
    g.add_argument("-fr", "--follow-redirects", dest="follow_redirects",
                   action="store_true", default=True)
    g.add_argument("-dr", "--disable-redirects", dest="disable_redirects",
                   action="store_true")
    g.add_argument("-mr", "--max-redirects", dest="max_redirects",
                   type=int, default=10)
    g.add_argument("-severity", "--severity", dest="severity",
                   metavar="list", help="Severity filter (critical,high,...)")
    g.add_argument("-db", "--database", dest="db_path", metavar="path",
                   help="Checks DB path")
    g.add_argument("-ua", "--user-agent", dest="user_agent", metavar="str",
                   help="User-Agent")
    g.add_argument("-crawl-depth", dest="crawl_depth", type=int, default=3,
                   help="Max crawl depth")
    g.add_argument("-crawl-max", dest="crawl_max_pages", type=int,
                   default=200, help="Max pages to crawl")
    g.add_argument("-timeout", dest="timeout", type=int, default=10,
                   help="HTTP timeout (seconds)")
    g.add_argument("--insecure-tls", dest="insecure_tls",
                   action="store_true",
                   help="Disable TLS certificate verification (lab/self-signed targets only)")

    # ── RATE LIMIT ──
    g = parser.add_argument_group(f"{C.CYN}RATE LIMIT{C.RST}")
    g.add_argument("-rl", "--rate-limit", dest="rate_limit", type=int,
                   default=150, help="Global rate limit")
    g.add_argument("-trl", "--target-rate-limit", dest="target_rate_limit",
                   type=int, default=150, help="Per-target rate limit")
    g.add_argument("-c", "--concurrency", dest="concurrency", type=int,
                   default=25, help="HTTP/crawl concurrency")
    g.add_argument("--verification-workers", dest="verification_workers", type=int,
                   default=6, help="Parallel vulnerability verifiers per parameter")
    g.add_argument("--no-browser-xss", dest="no_browser_xss", action="store_true",
                   help="Disable optional browser-based DOM/reflected XSS confirmation")

    # ── PLUGINS ──
    g = parser.add_argument_group(f"{C.CYN}PLUGINS{C.RST}")
    g.add_argument("--plugins", dest="enable_plugins",
                   action="store_true", default=True)
    g.add_argument("--no-plugins", dest="enable_plugins",
                   action="store_false")
    g.add_argument("--plugins-dir", dest="plugins_dir", metavar="path")
    g.add_argument("--list-plugins", dest="list_plugins",
                   action="store_true", help="List available plugins")
    g.add_argument("--create-example-plugin", dest="create_plugin",
                   action="store_true", help="Create example plugin")

    # ── WEB UI ──
    g = parser.add_argument_group(f"{C.CYN}WEB UI{C.RST}")
    g.add_argument("--web-ui", dest="web_ui", action="store_true",
                   help="Launch web UI")
    g.add_argument("--web-port", dest="web_port", type=int, default=8080,
                   help="Web UI port (default: 8080)")
    g.add_argument("--web-host", dest="web_host", default="127.0.0.1",
                   help="Web UI host (default: 127.0.0.1)")

    # ── DB UPDATE ──
    g = parser.add_argument_group(f"{C.CYN}DATABASE UPDATE{C.RST}")
    g.add_argument("-upac", "--update-from-acunetix", dest="upac",
                   nargs="?", const="__auto__", default=None,
                   metavar="path",
                   help="Extract from local Acunetix install")
    g.add_argument("-acuconvupdate", "--acunetix-conv-db",
                   dest="acuconv", nargs="?", const="__auto__",
                   default=None, metavar="BIN",
                   help="Convert Acunetix .bin file")
    g.add_argument("-cupz", "--create-archive", dest="cupz",
                   nargs="?", const="__auto__", default=None,
                   metavar="path", help="Create portable archive")
    g.add_argument("-upuz", "--update-from-archive", dest="upuz",
                   nargs="?", const="__auto__", default=None,
                   metavar="path", help="Update from archive")

    return parser


# ═══════════════════════════════════════════════════════════════════════════════
#  Build config from args
# ═══════════════════════════════════════════════════════════════════════════════

def build_config(args):
    csrf = {}
    if args.csrf_field:
        csrf["field_name"] = args.csrf_field
        csrf["input_name"] = args.csrf_field
    if args.csrf_pattern:
        csrf["patterns"] = args.csrf_pattern
    if args.csrf_header:
        csrf["header_name"] = args.csrf_header
    if args.csrf_meta:
        csrf["meta_name"] = args.csrf_meta
    if args.csrf_input:
        csrf["input_name"] = args.csrf_input

    login_steps = []
    if args.login_steps_file and os.path.isfile(args.login_steps_file):
        try:
            import json
            with open(args.login_steps_file, encoding="utf-8") as f:
                login_steps = json.load(f)
        except Exception:
            pass
    elif args.login_steps:
        try:
            import json
            login_steps = json.loads(args.login_steps)
        except Exception:
            pass

    totp_backup = []
    if args.totp_backup_codes:
        totp_backup = [c.strip() for c in args.totp_backup_codes.split(",")
                      if c.strip()]

    config = {
        "follow_redirects": args.follow_redirects and not args.disable_redirects,
        "max_redirects": args.max_redirects,
        "disable_redirects": args.disable_redirects,
        "rate_limit": args.target_rate_limit,
        "concurrency": args.concurrency,
        "verification_workers": max(1, min(args.verification_workers, 32)),
        "browser_xss": not args.no_browser_xss,
        "no_color": args.no_color,
        "silent": args.silent,
        "verbose": args.verbose,
        "user_agent": args.user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "crawl_depth": args.crawl_depth,
        "crawl_max_pages": args.crawl_max_pages,
        "timeout": args.timeout,
        "verify_ssl": not args.insecure_tls,
        "db_path": args.db_path,
        "proxy": args.proxy,
        "proxy_chain": args.proxy_chain,
        "headers": args.headers,
        "headers_file": args.headers_file,
        "cookie": args.cookie,
        "cookie_file": args.cookie_file,
        "auth": args.auth,
        "bearer": args.bearer,
        "api_key": args.api_key,
        "api_key_header": args.api_key_header,
        "auth_header": args.auth_header,
        "auto_login": args.auto_login,
        "login_url": args.login_url,
        "login_method": args.login_method,
        "login_data": _parse_login_data(args.login_data),
        "login_check": args.login_check,
        "logout_check": args.logout_check,
        "login_check_url": args.login_check_url,
        "login_steps": login_steps,
        "username_field": args.username_field,
        "password_field": args.password_field,
        "csrf": csrf if csrf else None,
        "session_file": args.session_file,
        "refresh_interval": args.refresh_interval,
        "totp_secret": args.totp_secret,
        "totp_code": args.totp_code,
        "totp_digits": args.totp_digits,
        "totp_interval": args.totp_interval,
        "totp_algorithm": args.totp_algorithm,
        "totp_backup_codes": totp_backup,
        "totp_sync_time": args.totp_sync_time,
        "enable_verification": args.enable_verification,
        "enable_oast": args.enable_oast,
        "oast_port": args.oast_port,
        "oast_dns_port": args.oast_dns_port,
        "oast_domain": args.oast_domain,
        "oast_public_ip": args.oast_public_ip,
        "oast_mode": args.oast_mode,
        "enable_storage": args.enable_storage,
        "storage_db": args.storage_db,
        "enable_plugins": args.enable_plugins,
        "plugins_dir": args.plugins_dir,
        "brute_force": args.brute_force,
        "userlist_file": args.userlist_file,
        "passlist_file": args.passlist_file,
        "severity_filter": [],
        "_vars": {},
    }

    if args.severity:
        config["severity_filter"] = [
            s.strip().lower() for s in args.severity.split(",") if s.strip()
        ]

    if args.burp:
        config["proxy"] = f"http://{args.burp}"

    return config


# ═══════════════════════════════════════════════════════════════════════════════
#  Reports
# ═══════════════════════════════════════════════════════════════════════════════

def _write_reports(args, targets, findings, out):
    """Write all requested reports."""
    try:
        reports = _import_reports()
    except Exception as e:
        out.error(f"Reports module failed: {e}")
        return

    if args.output_both:
        base = args.output_both
        for ext in (".txt", ".json", ".html", ".md", ".sarif", ".csv", ".pdf"):
            if base.lower().endswith(ext):
                base = base[:-len(ext)]
                break
        try:
            reports["text"](base + ".txt", targets, findings)
            reports["json"](base + ".json", targets, findings)
            reports["html"](base + ".html", targets, findings)
            reports["markdown"](base + ".md", targets, findings)
            out.info(f"Reports written: {base}.{{txt,json,html,md}}")
        except Exception as e:
            out.error(f"Report write failed: {e}")
        return

    # Individual reports
    if args.output:
        path = (args.output if args.output.endswith(".txt")
               else args.output + ".txt")
        try:
            reports["text"](path, targets, findings)
            out.info(f"Text: {path}")
        except Exception as e:
            out.error(f"Text report failed: {e}")

    if args.output_json:
        try:
            reports["json"](args.output_json, targets, findings)
            out.info(f"JSON: {args.output_json}")
        except Exception as e:
            out.error(f"JSON report failed: {e}")

    if args.output_html:
        path = (args.output_html if args.output_html.endswith(".html")
               else args.output_html + ".html")
        try:
            reports["html"](path, targets, findings)
            out.info(f"HTML: {path}")
        except Exception as e:
            out.error(f"HTML report failed: {e}")

    if args.output_md:
        try:
            reports["markdown"](args.output_md, targets, findings)
            out.info(f"Markdown: {args.output_md}")
        except Exception as e:
            out.error(f"Markdown report failed: {e}")

    if args.output_sarif:
        try:
            reports["sarif"](args.output_sarif, findings)
            out.info(f"SARIF: {args.output_sarif}")
        except Exception as e:
            out.error(f"SARIF report failed: {e}")

    if args.output_csv:
        try:
            reports["csv"](args.output_csv, findings)
            out.info(f"CSV: {args.output_csv}")
        except Exception as e:
            out.error(f"CSV report failed: {e}")

    if args.output_pdf:
        try:
            ok = reports["pdf"](args.output_pdf, targets, findings)
            if ok:
                out.info(f"PDF: {args.output_pdf}")
            else:
                out.warn("PDF failed — install weasyprint or reportlab")
        except Exception as e:
            out.error(f"PDF report failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = build_parser()
    args = parser.parse_args()

    no_color = args.no_color

    # ═══════════════════════════════════════════════════════════════
    #  DB update operations (standalone, no scanner needed)
    # ═══════════════════════════════════════════════════════════════
    try:
        DatabaseUpdater = _import_updater()
    except ImportError as e:
        print(f"{C.RED}[!] Failed to import DatabaseUpdater: {e}{C.RST}")
        DatabaseUpdater = None

    if args.upac is not None and DatabaseUpdater:
        updater = DatabaseUpdater(no_color=no_color)
        path = None if args.upac == "__auto__" else args.upac
        sys.exit(0 if updater.update_from_acunetix(path) else 1)

    if args.acuconv is not None and DatabaseUpdater:
        updater = DatabaseUpdater(no_color=no_color)
        path = None if args.acuconv == "__auto__" else args.acuconv
        sys.exit(0 if updater.convert_bin(path) else 1)

    if args.cupz is not None and DatabaseUpdater:
        updater = DatabaseUpdater(no_color=no_color)
        path = None if args.cupz == "__auto__" else args.cupz
        sys.exit(0 if updater.create_archive(path) else 1)

    if args.upuz is not None and DatabaseUpdater:
        updater = DatabaseUpdater(no_color=no_color)
        path = None if args.upuz == "__auto__" else args.upuz
        sys.exit(0 if updater.update_from_archive(path) else 1)

    # ═══════════════════════════════════════════════════════════════
    #  Plugin helpers
    # ═══════════════════════════════════════════════════════════════
    if args.create_plugin:
        try:
            from scanner.plugins.examples import create_example_plugin
            path = create_example_plugin()
            print(f"  {C.GRN}✓{C.RST} Example plugin created: {path}")
            sys.exit(0)
        except Exception as e:
            print(f"  {C.RED}✗{C.RST} Failed: {e}")
            sys.exit(1)

    if args.list_plugins:
        try:
            from scanner.plugins.loader import PluginLoader
            loader = PluginLoader(plugins_dir=args.plugins_dir)
            count = loader.load_all()
            print(f"\n  Loaded {count} plugin(s):\n")
            for meta in loader.list_plugins():
                print(f"    {C.CYN}•{C.RST} {meta['name']}: "
                      f"{meta['description']} "
                      f"[{C.YLW}{meta['severity']}{C.RST}]")
            if loader.errors:
                print(f"\n  {C.RED}Errors:{C.RST}")
                for err in loader.errors:
                    print(f"    ! {err}")
            print()
            sys.exit(0)
        except Exception as e:
            print(f"{C.RED}[!] {e}{C.RST}")
            sys.exit(1)

    # ═══════════════════════════════════════════════════════════════
    #  Cleanup stuck scans (from previous crashed runs)
    # ═══════════════════════════════════════════════════════════════
    _cleanup_stuck_scans()

    # ═══════════════════════════════════════════════════════════════
    #  Web UI
    # ═══════════════════════════════════════════════════════════════
    if args.web_ui:
        try:
            from webui import run_web_ui
            run_web_ui(host=args.web_host, port=args.web_port)
            sys.exit(0)
        except ImportError as e:
            print(f"{C.RED}[!] Web UI failed to load: {e}{C.RST}")
            traceback.print_exc()
            sys.exit(1)

    # ═══════════════════════════════════════════════════════════════
    #  Auto-provision DB
    # ═══════════════════════════════════════════════════════════════
    if DatabaseUpdater:
        updater = DatabaseUpdater(no_color=no_color)
        if not updater.auto_provision():
            sys.exit(1)

    # ═══════════════════════════════════════════════════════════════
    #  Build config
    # ═══════════════════════════════════════════════════════════════
    config = build_config(args)
    out = OutputFormatter(no_color=no_color, silent=args.silent)
    out.banner()

    # ═══════════════════════════════════════════════════════════════
    #  Collect targets
    # ═══════════════════════════════════════════════════════════════
    targets = list(args.targets)
    if args.list_file:
        try:
            with open(args.list_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except FileNotFoundError:
            out.error(f"Target list not found: {args.list_file}")
            sys.exit(1)

    # ═══════════════════════════════════════════════════════════════
    #  --save-session-only
    # ═══════════════════════════════════════════════════════════════
    if args.save_session_only:
        if not args.auto_login or not args.login_url:
            out.error("--save-session-only requires --auto-login and --login-url")
            sys.exit(1)
        out.info("Performing login...")
        try:
            from http_client import HTTPClient
            client = HTTPClient(config)
            if client.authenticated and client.session_mgr.save_session(
                client.session
            ):
                out.success(f"Session saved: {args.session_file}")
                sys.exit(0)
            else:
                out.error("Login failed")
                sys.exit(1)
        except Exception as e:
            out.error(f"Failed: {e}")
            sys.exit(1)

    # ═══════════════════════════════════════════════════════════════
    #  Brute-force mode
    # ═══════════════════════════════════════════════════════════════
    if args.brute_force:
        if not args.login_url:
            out.error("--brute-force requires --login-url")
            sys.exit(1)
        out.info("Starting login brute-force...")
        try:
            from http_client import HTTPClient
            from scanner.brute_force import LoginBruteForcer
            client = HTTPClient(config)
            bf = LoginBruteForcer(client, config, out)
            result = bf.run()
            if result and args.session_file:
                config["login_data"] = {
                    args.username_field: result["username"],
                    args.password_field: result["password"],
                }
                config["auto_login"] = True
                client2 = HTTPClient(config)
                if client2.authenticated:
                    client2.session_mgr.save_session(client2.session)
                    out.success(f"Session saved: {args.session_file}")
            sys.exit(0 if result else 1)
        except Exception as e:
            out.error(f"Brute-force failed: {e}")
            sys.exit(1)

    # ═══════════════════════════════════════════════════════════════
    #  Check we have targets
    # ═══════════════════════════════════════════════════════════════
    if not targets:
        parser.print_help()
        print(f"\n  {C.RED}Error: No targets specified. Use -u or -l.{C.RST}\n")
        sys.exit(1)

    targets = list(OrderedDict.fromkeys(targets))  # dedupe
    out.info(f"Targets: {len(targets)}")

    # ═══════════════════════════════════════════════════════════════
    #  Load Scanner and run
    # ═══════════════════════════════════════════════════════════════
    try:
        Scanner = _import_scanner()
    except ImportError as e:
        out.error(f"Scanner module failed: {e}")
        traceback.print_exc()
        sys.exit(1)

    all_findings = []
    try:
        scanner = Scanner(config)
        scanner.load_database()
    except Exception as e:
        out.error(f"Scanner init failed: {e}")
        traceback.print_exc()
        sys.exit(1)

    for i, target in enumerate(targets, 1):
        if len(targets) > 1:
            out.info(f"\n{'=' * 60}")
            out.info(f"[{i}/{len(targets)}] Scanning: {target}")
            out.info(f"{'=' * 60}")
        else:
            out.info(f"\n{'=' * 60}")
            out.info(f"Scanning: {target}")
            out.info(f"{'=' * 60}")

        # Reset per-target state
        scanner.findings = []
        scanner.crawled_urls = set()
        scanner.crawled_forms = []
        import collections
        scanner.crawled_params = collections.defaultdict(set)
        scanner.tech_stack = {}
        scanner.stop_event = threading.Event()
        scanner._404_body_cache = {}
        scanner.storage_scan_id = None

        try:
            findings = scanner.scan(target)
            all_findings.extend(findings)
        except KeyboardInterrupt:
            out.warn("Interrupted by user")
            break
        except Exception as e:
            out.error(f"Scan failed: {e}")
            if args.verbose:
                traceback.print_exc()

    # ═══════════════════════════════════════════════════════════════
    #  Write reports
    # ═══════════════════════════════════════════════════════════════
    _write_reports(args, targets, all_findings, out)

    # ═══════════════════════════════════════════════════════════════
    #  Final summary
    # ═══════════════════════════════════════════════════════════════
    out.info(f"Total findings: {len(all_findings)}")

    # Exit code: 0 if no findings, 1 if findings found (useful for CI/CD)
    if all_findings:
        sys.exit(0)  # Change to sys.exit(1) if you want non-zero on findings


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.YLW}[!] Interrupted by user{C.RST}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{C.RED}[!] Fatal error: {e}{C.RST}")
        traceback.print_exc()
        sys.exit(1)