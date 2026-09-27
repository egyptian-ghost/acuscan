#!/usr/bin/env python3
"""
Dashboard API
=============
Endpoints:
  GET /api/v1/dashboard
"""
from flask import Blueprint, jsonify

from ..auth import login_required


dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/api/v1/dashboard")
@login_required
def api_dashboard():
    """
    Returns:
      - stats: aggregate severity counts
      - timeline: findings by day for last 30 days
      - top_vulns: top 10 vuln types
      - scans_status: counts by scan status
      - recent_scans: last 10 scans
      - verification: verification statistics
    """
    from storage import get_storage
    storage = get_storage()

    if not storage:
        # Fallback to in-memory scans
        from ..jobs import list_scans
        scans = list_scans()
        stats = {
            "total_findings": 0,
            "total_scans": len(scans),
            "verified": 0,
        }
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
            "verification": {
                "verified": 0,
                "unverified": stats["total_findings"],
                "verified_ratio": 0,
            },
        })

    stats = storage.get_stats()
    with storage._connect() as conn:
        rows = conn.execute(
            "SELECT status, COUNT(*) as c FROM scans GROUP BY status"
        ).fetchall()
        scans_status = {r["status"]: r["c"] for r in rows}

    # Verification stats
    total = stats.get("total_findings", 0)
    verified = stats.get("verified", 0)

    return jsonify({
        "stats": stats,
        "timeline": storage.get_severity_timeline(30),
        "top_vulns": storage.get_top_vulns(10),
        "scans_status": scans_status,
        "recent_scans": storage.list_scans(10),
        "verification": {
            "verified": verified,
            "unverified": max(0, total - verified),
            "verified_ratio": (verified / total) if total else 0,
        },
    })


@dashboard_bp.route("/api/v1/stats")
def api_stats():
    """Simpler stats endpoint for quick queries."""
    from storage import get_storage
    storage = get_storage()
    if not storage:
        return jsonify({})
    return jsonify(storage.get_stats())