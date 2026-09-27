"""Schedules routes."""
from flask import Blueprint, render_template, request, jsonify

from ..auth import login_required
from storage import get_storage


schedules_bp = Blueprint("schedules", __name__)


@schedules_bp.route("/schedules")
@login_required
def schedules_page():
    return render_template("schedules.html")


@schedules_bp.route("/api/v1/schedules", methods=["GET", "POST"])
def api_schedules():
    storage = get_storage()
    if not storage:
        return jsonify({"schedules": []})

    if request.method == "GET":
        return jsonify({"schedules": storage.list_schedules()})

    data = request.get_json() or {}
    sid = storage.add_schedule(
        data.get("name", "Untitled"),
        data.get("cron", "0 0 * * *"),
        data.get("targets", []),
        data.get("config", {}),
    )
    return jsonify({"id": sid, "ok": True})


@schedules_bp.route("/api/v1/schedules/<int:sid>",
                   methods=["DELETE", "PATCH"])
def api_schedule_ops(sid):
    storage = get_storage()
    if not storage:
        return jsonify({"error": "storage disabled"}), 500

    if request.method == "DELETE":
        storage.delete_schedule(sid)
        return jsonify({"ok": True})

    data = request.get_json() or {}
    if "enabled" in data:
        storage.toggle_schedule(sid, bool(data["enabled"]))
    return jsonify({"ok": True})