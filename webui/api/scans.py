#!/usr/bin/env python3
"""
Scans API v6.9.0
================
- Preserves target URL path
- Scan scope: path | domain | both
- ATOMIC duplicate prevention via DB unique index
- Auto-release locks on scan completion
- Resume endpoint
"""
import json
import queue
import uuid
import threading
from flask import (
    Blueprint, render_template, request, jsonify, Response,
)

from ..auth import login_required
from ..jobs import start_scan, get_scan, list_scans
from storage import get_storage


scans_bp = Blueprint("scans", __name__)

# Fallback in-memory lock (if storage fails)
_SCAN_START_LOCK = threading.Lock()


# ═══════════════════════════════════════════════════════════════════════════════
#  Pages
# ═══════════════════════════════════════════════════════════════════════════════

@scans_bp.route("/")
@login_required
def dashboard_page():
    try:
        return render_template("dashboard.html")
    except Exception as e:
        return f"<h1>Dashboard</h1><pre>{e}</pre>", 500


@scans_bp.route("/scans")
@login_required
def scans_page():
    try:
        return render_template("scans.html")
    except Exception as e:
        return f"<h1>Scans</h1><pre>{e}</pre>", 500


@scans_bp.route("/scan/<scan_id>")
@login_required
def scan_detail_page(scan_id):
    try:
        return render_template("scan_detail_v2.html", scan_id=scan_id)
    except Exception:
        try:
            return render_template("scan_detail.html", scan_id=scan_id)
        except Exception:
            import traceback
            return f"<h1>Scan</h1><pre>{traceback.format_exc()}</pre>", 500


# ═══════════════════════════════════════════════════════════════════════════════
#  API — Start scan (ATOMIC via DB lock)
# ═══════════════════════════════════════════════════════════════════════════════

@scans_bp.route("/api/scan", methods=["POST"])
def api_start_scan():
    """Start a new scan — atomic duplicate prevention."""
    data = request.get_json() or {}
    targets = data.get("targets", [])
    if not targets:
        return jsonify({"error": "no targets provided"}), 400
    if not isinstance(targets, list):
        return jsonify({"error": "targets must be a list"}), 400

    # Normalize the input list before expansion. This prevents the same URL
    # pasted twice (or with a trailing slash/case difference) from appearing
    # twice in a single scan.
    cleaned = []
    seen_input = set()
    for raw in targets:
        if raw is None:
            continue
        raw = str(raw).strip()
        if not raw:
            continue
        key = raw.rstrip('/').lower()
        if key not in seen_input:
            seen_input.add(key)
            cleaned.append(raw)
    targets = cleaned
    if not targets:
        return jsonify({"error": "no valid targets provided"}), 400

    # ═══ Scan scope ═══
    scan_scope = data.get("scan_scope", "path").lower()
    if scan_scope not in ("path", "domain", "both"):
        scan_scope = "path"

    # ═══ Expand based on scope ═══
    from core.utils import expand_scan_targets, normalize_url
    expanded = []
    for t in targets:
        for expanded_url in expand_scan_targets(t, scan_scope):
            if expanded_url not in expanded:
                expanded.append(expanded_url)

    if not expanded:
        return jsonify({"error": "no valid targets after expansion"}), 400

    # ═══ Normalize ═══
    deduplicated = []
    for t in expanded:
        nt = normalize_url(t)
        if nt not in deduplicated:
            deduplicated.append(nt)

    if not deduplicated:
        return jsonify({"error": "no valid targets after normalization"}), 400

    # ═══════════════════════════════════════════════════════════════════════
    #  ATOMIC: DB-level lock
    # ═══════════════════════════════════════════════════════════════════════
    storage = get_storage()

    with _SCAN_START_LOCK:
        locked = []
        failed = []
        scan_uuid = str(uuid.uuid4())

        for t in deduplicated:
            key = _normalize_target(t)
            if storage:
                # Try DB-level lock
                if storage.lock_target(key, scan_uuid):
                    locked.append(t)
                else:
                    failed.append(t)
            else:
                # Fallback: memory check
                active = set()
                for s in list_scans():
                    if s.get("status") in ("running", "pending"):
                        for tgt in s.get("targets", []):
                            active.add(_normalize_target(tgt))
                if key in active:
                    failed.append(t)
                else:
                    locked.append(t)

        if not locked:
            return jsonify({
                "error": (
                    f"Scan already running for: {', '.join(failed)}. "
                    f"Stop the existing scan first or wait for it to finish."
                ),
                "duplicates": failed,
            }), 409

        # ═══ Start scan ═══
        config = _build_scan_config(data)
        config["_scan_scope"] = scan_scope
        config["_locked_targets"] = [_normalize_target(t) for t in locked]

        try:
            scan_id = start_scan(config, locked, scan_id=scan_uuid)
        except Exception as e:
            # Rollback locks
            if storage:
                storage.unlock_targets([_normalize_target(t) for t in locked])
            return jsonify({"error": f"Failed to start scan: {e}"}), 500

    result = {
        "scan_id": scan_id,
        "ok": True,
        "scope": scan_scope,
        "targets_expanded": locked,
    }
    if failed:
        result["skipped"] = failed
        result["message"] = f"Skipped (already running): {', '.join(failed)}"

    return jsonify(result)


# ═══════════════════════════════════════════════════════════════════════════════
#  API — List / Info
# ═══════════════════════════════════════════════════════════════════════════════

@scans_bp.route("/api/scans")
def api_list_scans():
    scans = list_scans()
    for scan in scans:
        targets = scan.get("targets") or []
        unique = []
        seen = set()
        for target in targets:
            target = str(target).strip()
            key = target.rstrip('/').lower()
            if target and key not in seen:
                seen.add(key)
                unique.append(target)
        scan["targets"] = unique
    return jsonify({"scans": scans[:100], "total": len(scans)})


@scans_bp.route("/api/scan/<scan_id>")
def api_scan_info(scan_id):
    job = get_scan(scan_id)
    if job:
        return jsonify(job.to_dict())

    try:
        storage = get_storage()
        if storage:
            try:
                sid = int(scan_id)
                scan = storage.get_scan(sid)
                if scan:
                    return jsonify({
                        "scan_id": scan.get("scan_uuid"),
                        "status": scan.get("status"),
                        "targets": scan.get("targets", []),
                        "findings_count": scan.get("total_findings", 0),
                        "duration": scan.get("duration_seconds"),
                        "started_at": scan.get("started_at"),
                    })
            except ValueError:
                scan = storage.get_scan_by_uuid(scan_id)
                if scan:
                    return jsonify({
                        "scan_id": scan.get("scan_uuid"),
                        "status": scan.get("status"),
                        "targets": scan.get("targets", []),
                        "findings_count": scan.get("total_findings", 0),
                    })
    except Exception:
        pass

    return jsonify({"error": "not found"}), 404


# ═══════════════════════════════════════════════════════════════════════════════
#  API — SSE stream
# ═══════════════════════════════════════════════════════════════════════════════

@scans_bp.route("/api/scan/<scan_id>/stream")
def api_stream(scan_id):
    job = get_scan(scan_id)
    if not job:
        return jsonify({"error": "not found"}), 404

    def event_stream():
        yield "data: " + json.dumps({
            "type": "status",
            "data": {"status": job.status, "targets": job.targets},
        }) + "\n\n"
        for f in job.findings:
            yield "data: " + json.dumps({
                "type": "finding", "data": f.to_dict()
            }, default=str) + "\n\n"
        while True:
            try:
                event = job.events.get(timeout=30)
                yield "data: " + json.dumps(event, default=str) + "\n\n"
                if (event["type"] == "status" and
                    event["data"].get("status") in
                    ("completed", "failed", "stopped")):
                    break
            except queue.Empty:
                yield ": heartbeat\n\n"
                if job.status in ("completed", "failed", "stopped"):
                    break

    return Response(
        event_stream(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  API — Stop / Delete / Resume
# ═══════════════════════════════════════════════════════════════════════════════

@scans_bp.route("/api/scan/<scan_id>/stop", methods=["POST"])
def api_stop_scan(scan_id):
    job = get_scan(scan_id)
    if job:
        job.stop()
        return jsonify({"status": "stopping", "ok": True})

    try:
        storage = get_storage()
        if storage:
            try:
                sid = int(scan_id)
                storage.update_scan_status(sid, "stopped")
                return jsonify({"status": "stopped", "ok": True})
            except ValueError:
                scan = storage.get_scan_by_uuid(scan_id)
                if scan:
                    storage.update_scan_status(scan["id"], "stopped")
                    return jsonify({"status": "stopped", "ok": True})
    except Exception:
        pass

    return jsonify({"error": "not found"}), 404


@scans_bp.route("/api/scans/stop-all", methods=["POST"])
def api_stop_all():
    count = 0
    for s in list_scans():
        if s.get("status") in ("running", "pending"):
            job = get_scan(s.get("scan_id"))
            if job:
                job.stop()
                count += 1

    # Clean DB
    try:
        storage = get_storage()
        if storage:
            with storage._connect() as conn:
                conn.execute(
                    """UPDATE scans SET status='stopped',
                       finished_at=CURRENT_TIMESTAMP
                       WHERE status IN ('running', 'pending')"""
                )
                # Also clear all target locks
                conn.execute("DELETE FROM active_scan_targets")
    except Exception:
        pass

    return jsonify({"stopped": count, "ok": True})


@scans_bp.route("/api/scans/<scan_id>", methods=["DELETE"])
def api_delete_scan(scan_id):
    try:
        storage = get_storage()
        if not storage:
            return jsonify({"error": "storage disabled"}), 500

        try:
            sid = int(scan_id)
            storage.delete_scan(sid)
            return jsonify({"ok": True})
        except ValueError:
            pass

        scan = storage.get_scan_by_uuid(scan_id)
        if scan:
            storage.delete_scan(scan["id"])
            return jsonify({"ok": True})

        return jsonify({"error": "not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@scans_bp.route("/api/scan/<scan_id>/resume", methods=["POST"])
def api_resume_scan(scan_id):
    """Resume a stopped scan."""
    storage = get_storage()
    if not storage:
        return jsonify({"error": "storage disabled"}), 500

    try:
        sid = int(scan_id)
        scan = storage.get_scan(sid)
    except ValueError:
        scan = storage.get_scan_by_uuid(scan_id)

    if not scan:
        return jsonify({"error": "scan not found"}), 404

    meta = storage.get_scan_metadata(scan["id"])
    visited_urls = [n["url"] for n in meta.get("crawl_map", [])
                   if not n.get("is_external")]

    config = scan.get("config", {})
    config["_resume_from"] = visited_urls
    config["enable_storage"] = True

    new_scan_id = start_scan(config, scan.get("targets", []))
    return jsonify({
        "scan_id": new_scan_id,
        "resumed_from": len(visited_urls),
        "ok": True,
    })


# ═══════════════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _normalize_target(url):
    """Canonical target key shared with the storage lock semantics."""
    try:
        from urllib.parse import urlsplit, urlunsplit
        raw = str(url or '').strip()
        if not raw:
            return ''
        if '://' not in raw:
            raw = 'https://' + raw
        p = urlsplit(raw)
        scheme = (p.scheme or 'https').lower()
        host = (p.hostname or '').lower().rstrip('.')
        port = p.port
        if (scheme == 'https' and port == 443) or (scheme == 'http' and port == 80):
            port = None
        netloc = host if port is None else f'{host}:{port}'
        path = p.path or '/'
        path = '/' if path == '' else path.rstrip('/') or '/'
        return urlunsplit((scheme, netloc, path, p.query, '')).lower()
    except Exception:
        return str(url or '').strip().rstrip('/').lower().split('#', 1)[0]


def _build_scan_config(data):
    """Build full scan config from payload."""
    headers = data.get("headers", [])
    if isinstance(headers, str):
        headers = [h.strip() for h in headers.split("\n") if ":" in h]

    config = {
        "follow_redirects": True,
        "max_redirects": 10,
        "disable_redirects": False,
        "rate_limit": int(data.get("rate_limit", 150)),
        "concurrency": int(data.get("concurrency", 25)),
        "verification_workers": max(1, min(int(data.get("verification_workers", 6)), 32)),
        "browser_xss": bool(data.get("browser_xss", True)),
        "no_color": True,
        "silent": True,
        "verbose": False,
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "crawl_depth": int(data.get("crawl_depth", 3)),
        "crawl_max_pages": int(data.get("crawl_max_pages", 500)),
        "timeout": int(data.get("timeout", 10)),
        "db_path": None,
        "proxy": data.get("proxy") or None,
        "proxy_chain": [],
        "headers": headers,
        "cookie": data.get("cookie") or None,
        "cookie_file": None,
        "auth": data.get("auth") or None,
        "bearer": data.get("bearer") or None,
        "api_key": data.get("api_key") or None,
        "api_key_header": data.get("api_key_header") or "X-API-Key",
        "auth_header": None,
        "auto_login": bool(data.get("login_url")),
        "login_url": data.get("login_url") or None,
        "login_method": "POST",
        "login_data": {},
        "login_check": data.get("login_check") or None,
        "logout_check": None,
        "login_check_url": None,
        "login_steps": [],
        "csrf": None,
        "session_file": None,
        "refresh_interval": 0,
        "auth_compare": False,
        "totp_secret": data.get("totp_secret") or None,
        "totp_code": None,
        "totp_digits": 6,
        "totp_interval": 30,
        "totp_algorithm": "SHA1",
        "totp_backup_codes": [],
        "totp_sync_time": False,
        "brute_force": False,
        "enable_plugins": True,
        "plugins_dir": None,
        "enable_verification": bool(data.get("enable_verification", True)),
        "enable_oast": bool(data.get("enable_oast", False)),
        "oast_port": int(data.get("oast_port", 8000)),
        "oast_dns_port": int(data.get("oast_dns_port", 5353)),
        "oast_domain": data.get("oast_domain", "oast.local"),
        "oast_public_ip": data.get("oast_public_ip"),
        "oast_mode": data.get("oast_mode", "local"),
        "enable_storage": bool(data.get("enable_storage", True)),
        "storage_db": None,
        "severity_filter": [],
        "_vars": {},
    }

    # Login data
    if data.get("login_data"):
        ld = data["login_data"]
        if ld.startswith("{"):
            try:
                config["login_data"] = json.loads(ld)
            except json.JSONDecodeError:
                pass
        else:
            for pair in ld.split(","):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    config["login_data"][k.strip()] = v.strip()

    if data.get("csrf_field"):
        config["csrf"] = {
            "field_name": data["csrf_field"],
            "input_name": data["csrf_field"],
        }

    if data.get("severity"):
        config["severity_filter"] = [
            s.strip().lower() for s in data["severity"].split(",")
            if s.strip()
        ]

    return config