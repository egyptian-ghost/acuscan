"""Dashboard API routes."""
from flask import Blueprint, jsonify

from storage import get_storage


dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/api/v1/dashboard")
def api_dashboard():
    storage = get_storage()
    if not storage:
        # Fallback to in-memory scans
        from ..jobs import list_scans
        scans = list_scans()
        stats = {"total_findings": 0, "total_scans": len(scans)}
        scans_status = {}
        for s in scans:
            scans_status[s["status"]] = scans_status.get(s["status"], 0) + 1
            stats["total_findings"] += s.get("findings_count", 0)
        return jsonify({
            "stats": stats,
            "timeline": [],
            "top_vulns": [],
            "scans_status": scans_status,
            "recent_scans": scans[:10],
        })

    stats = storage.get_stats()
    with storage._connect() as conn:
        rows = conn.execute(
            "SELECT status, COUNT(*) as c FROM scans GROUP BY status"
        ).fetchall()
        scans_status = {r["status"]: r["c"] for r in rows}

    return jsonify({
        "stats": stats,
        "timeline": storage.get_severity_timeline(30),
        "top_vulns": storage.get_top_vulns(10),
        "scans_status": scans_status,
        "recent_scans": storage.list_scans(10),
    })