"""Scan routes — v6.4 (Fixed: reads from BOTH memory + SQLite)."""
import json
import queue
from flask import (
    Blueprint, render_template, request, jsonify, Response,
)

from ..auth import login_required
from ..jobs import start_scan, get_scan, list_scans
from storage import get_storage


scans_bp = Blueprint("scans", __name__)


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
        return render_template("scan_detail.html", scan_id=scan_id)
    except Exception as e:
        return f"<h1>Scan</h1><pre>{e}</pre>", 500


# ═══════════════════════════════════════════════════════════════════════════════
#  API — Start scan
# ═══════════════════════════════════════════════════════════════════════════════

@scans_bp.route("/api/scan", methods=["POST"])
def api_start_scan():
    data = request.get_json() or {}
    targets = data.get("targets", [])
    if not targets:
        return jsonify({"error": "no targets"}), 400
    if not isinstance(targets, list):
        return jsonify({"error": "targets must be a list"}), 400

    # ── Duplicate prevention ──
    active_targets = set()
    for s in list_scans():
        if s.get("status") in ("running", "pending"):
            for t in s.get("targets", []):
                active_targets.add(_normalize_target(t))

    normalized = []
    duplicates = []
    for t in targets:
        key = _normalize_target(t)
        if key in active_targets:
            duplicates.append(t)
        else:
            normalized.append(t)

    if not normalized:
        return jsonify({
            "error": f"Scan already running for: {', '.join(duplicates)}",
            "duplicates": duplicates,
        }), 409

    config = _build_scan_config(data)
    scan_id = start_scan(config, normalized)

    result = {"scan_id": scan_id, "ok": True}
    if duplicates:
        result["skipped"] = duplicates
        result["message"] = f"Skipped (already running): {', '.join(duplicates)}"
    return jsonify(result)


# ═══════════════════════════════════════════════════════════════════════════════
#  API — List scans (merges memory + SQLite) ⭐ THE FIX
# ═══════════════════════════════════════════════════════════════════════════════

@scans_bp.route("/api/scans")
def api_list_scans():
    """
    List all scans — merges:
      1. SQLite historical scans (persisted)
      2. In-memory running scans (live)
    """
    scans_by_id = {}

    # ═══ 1. Load from SQLite ═══
    try:
        storage = get_storage()
        if storage:
            db_scans = storage.list_scans(limit=100)
            for s in db_scans:
                scan_key = str(s.get("id", ""))
                if not scan_key:
                    continue
                scans_by_id[scan_key] = {
                    "id": s.get("id"),
                    "scan_uuid": s.get("scan_uuid", ""),
                    "display_id": f"#{s.get('id')}",
                    "targets": s.get("targets", []),
                    "status": s.get("status", "unknown"),
                    "findings_count": s.get("total_findings", 0),
                    "total_findings": s.get("total_findings", 0),
                    "duration": s.get("duration_seconds"),
                    "duration_seconds": s.get("duration_seconds"),
                    "started_at": s.get("started_at"),
                    "finished_at": s.get("finished_at"),
                    "source": "db",
                }
    except Exception as e:
        print(f"[api/scans] SQLite load failed: {e}")

    # ═══ 2. Merge in-memory scans ═══
    try:
        for s in list_scans():
            uuid = s.get("scan_id", "")
            matched_key = None

            # Find matching DB record by scan_uuid
            for key, db_s in scans_by_id.items():
                if db_s.get("scan_uuid") == uuid:
                    matched_key = key
                    break

            if matched_key:
                # Merge (memory wins for live status)
                merged = dict(scans_by_id[matched_key])
                merged.update({
                    "status": s.get("status", merged.get("status")),
                    "findings_count": s.get(
                        "findings_count", merged.get("findings_count", 0)
                    ),
                    "duration": s.get("duration", merged.get("duration")),
                    "start_time": s.get("start_time"),
                    "scan_uuid": uuid,
                    "live": True,
                })
                scans_by_id[matched_key] = merged
            else:
                # New live scan not yet in DB
                new_key = f"live_{uuid[:8]}"
                scans_by_id[new_key] = {
                    "id": None,
                    "scan_uuid": uuid,
                    "display_id": uuid[:8] if uuid else "?",
                    "targets": s.get("targets", []),
                    "status": s.get("status", "pending"),
                    "findings_count": s.get("findings_count", 0),
                    "total_findings": s.get("findings_count", 0),
                    "duration": s.get("duration"),
                    "duration_seconds": s.get("duration"),
                    "start_time": s.get("start_time"),
                    "started_at": None,
                    "live": True,
                    "source": "memory",
                }
    except Exception as e:
        print(f"[api/scans] Memory merge failed: {e}")

    # ═══ 3. Sort by id/start_time desc ═══
    def sort_key(s):
        if s.get("id"):
            return -s["id"]
        if s.get("start_time"):
            return -int(s["start_time"])
        return 0

    result = sorted(scans_by_id.values(), key=sort_key)

    return jsonify({"scans": result[:100], "total": len(result)})


@scans_bp.route("/api/scan/<scan_id>")
def api_scan_info(scan_id):
    """Get scan info — memory first, then SQLite."""
    job = get_scan(scan_id)
    if job:
        return jsonify(job.to_dict())

    try:
        storage = get_storage()
        if storage:
            try:
                scan_id_int = int(scan_id)
                scan = storage.get_scan(scan_id_int)
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
#  API — Stop / Delete
# ═══════════════════════════════════════════════════════════════════════════════

@scans_bp.route("/api/scan/<scan_id>/stop", methods=["POST"])
def api_stop_scan(scan_id):
    job = get_scan(scan_id)
    if job:
        job.stop()
        return jsonify({"status": "stopping", "ok": True})

    # Try SQLite update
    try:
        storage = get_storage()
        if storage:
            try:
                sid = int(scan_id)
                storage.update_scan_status(sid, "stopped")
                return jsonify({"status": "stopped", "ok": True})
            except ValueError:
                pass
    except Exception:
        pass

    return jsonify({"error": "not found"}), 404


@scans_bp.route("/api/scans/stop-all", methods=["POST"])
def api_stop_all():
    count = 0
    for s in list_scans():
        if s.get("status") in ("running", "pending"):
            job = get_scan(s["scan_id"])
            if job:
                job.stop()
                count += 1
    return jsonify({"stopped": count, "ok": True})


@scans_bp.route("/api/scans/<scan_id>", methods=["DELETE"])
def api_delete_scan(scan_id):
    """Delete scan by ID or UUID."""
    try:
        storage = get_storage()
        if not storage:
            return jsonify({"error": "storage disabled"}), 500

        # Try numeric ID
        try:
            sid = int(scan_id)
            storage.delete_scan(sid)
            return jsonify({"ok": True})
        except ValueError:
            pass

        # Try UUID
        scan = storage.get_scan_by_uuid(scan_id)
        if scan:
            storage.delete_scan(scan["id"])
            return jsonify({"ok": True})

        return jsonify({"error": "not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _normalize_target(url):
    if not url:
        return ""
    t = url.strip().rstrip("/")
    if "://" in t:
        t = t.split("://", 1)[1]
    return t.lower()


def _build_scan_config(data):
    headers = data.get("headers", [])
    if isinstance(headers, str):
        headers = [h.strip() for h in headers.split("\n") if ":" in h]

    config = {
        "follow_redirects": True,
        "max_redirects": 10,
        "disable_redirects": False,
        "rate_limit": int(data.get("rate_limit", 150)),
        "concurrency": int(data.get("concurrency", 25)),
        "no_color": True,
        "silent": True,
        "verbose": False,
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "crawl_depth": int(data.get("crawl_depth", 3)),
        "crawl_max_pages": int(data.get("crawl_max_pages", 200)),
        "timeout": 10,
        "db_path": None,
        "proxy": data.get("proxy") or None,
        "proxy_chain": [],
        "headers": headers,
        "cookie": data.get("cookie") or None,
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
        "oast_port": 8000,
        "oast_dns_port": 5353,
        "oast_domain": "oast.local",
        "oast_public_ip": None,
        "oast_mode": "local",
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

    # CSRF
    if data.get("csrf_field"):
        config["csrf"] = {
            "field_name": data["csrf_field"],
            "input_name": data["csrf_field"],
        }

    # Severity filter
    if data.get("severity"):
        config["severity_filter"] = [
            s.strip().lower() for s in data["severity"].split(",")
            if s.strip()
        ]

    return config