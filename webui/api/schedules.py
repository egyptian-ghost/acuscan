#!/usr/bin/env python3
"""
Schedules API
=============
Endpoints:
  GET    /schedules
  GET    /api/v1/schedules
  POST   /api/v1/schedules
  PATCH  /api/v1/schedules/<id>
  DELETE /api/v1/schedules/<id>
  POST   /api/v1/schedules/<id>/run
"""
from flask import Blueprint, render_template, request, jsonify

from ..auth import login_required


schedules_bp = Blueprint("schedules", __name__)


@schedules_bp.route("/schedules")
@login_required
def schedules_page():
    try:
        return render_template("schedules.html")
    except Exception as e:
        return f"<h1>Schedules</h1><pre>{e}</pre>", 500


@schedules_bp.route("/api/v1/schedules", methods=["GET", "POST"])
def api_schedules():
    from storage import get_storage
    storage = get_storage()
    if not storage:
        return jsonify({"schedules": []})

    if request.method == "GET":
        return jsonify({"schedules": storage.list_schedules()})

    # POST: create schedule
    data = request.get_json() or {}
    name = (data.get("name") or "Untitled").strip()
    cron = (data.get("cron") or data.get("cron_expression") or "0 2 * * *").strip()
    targets = data.get("targets") or []
    config = data.get("config") or {}

    if not targets:
        return jsonify({"error": "at least one target required"}), 400

    # Validate cron
    if not _validate_cron(cron):
        return jsonify({"error": "invalid cron expression"}), 400

    sid = storage.add_schedule(name, cron, targets, config)
    return jsonify({"id": sid, "ok": True})


@schedules_bp.route("/api/v1/schedules/<int:sid>",
                   methods=["GET", "PATCH", "DELETE"])
def api_schedule_ops(sid):
    from storage import get_storage
    storage = get_storage()
    if not storage:
        return jsonify({"error": "storage disabled"}), 500

    if request.method == "GET":
        schedules = storage.list_schedules()
        sched = next((s for s in schedules if s["id"] == sid), None)
        if not sched:
            return jsonify({"error": "not found"}), 404
        return jsonify(sched)

    if request.method == "DELETE":
        storage.delete_schedule(sid)
        return jsonify({"ok": True})

    # PATCH
    data = request.get_json() or {}
    if "enabled" in data:
        storage.toggle_schedule(sid, bool(data["enabled"]))
    return jsonify({"ok": True})


@schedules_bp.route("/api/v1/schedules/<int:sid>/run", methods=["POST"])
def api_run_schedule(sid):
    """Trigger a scheduled scan immediately."""
    from storage import get_storage
    from ..jobs import start_scan
    storage = get_storage()
    if not storage:
        return jsonify({"error": "storage disabled"}), 500

    schedules = storage.list_schedules()
    sched = next((s for s in schedules if s["id"] == sid), None)
    if not sched:
        return jsonify({"error": "not found"}), 404

    config = _scheduled_config(sched.get("config", {}))
    scan_id = start_scan(config, sched["targets"])
    storage.update_schedule_run(sid)

    return jsonify({"scan_id": scan_id, "ok": True})


# ═══════════════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _validate_cron(expr):
    try:
        from croniter import croniter
        return croniter.is_valid(expr)
    except ImportError:
        # Basic check: 5 fields
        return len(expr.split()) == 5
    except Exception:
        return False


def _scheduled_config(config):
    """Fill in defaults for scheduled scans."""
    full_config = dict(config or {})
    for k, v in {
        "follow_redirects": True,
        "max_redirects": 10,
        "disable_redirects": False,
        "rate_limit": 150,
        "concurrency": 25,
        "no_color": True,
        "silent": True,
        "verbose": False,
        "crawl_depth": 3,
        "crawl_max_pages": 200,
        "timeout": 10,
        "enable_verification": True,
        "enable_oast": False,
        "enable_storage": True,
        "enable_plugins": True,
        "headers": [],
        "severity_filter": [],
        "_vars": {},
    }.items():
        full_config.setdefault(k, v)
    return full_config