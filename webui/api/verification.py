#!/usr/bin/env python3
"""
Verification API
================
Endpoints:
  GET /verification/<id>           (standalone page)
  GET /api/v1/verification/<id>    (JSON)
"""
import json
from flask import Blueprint, render_template, jsonify

from ..auth import login_required
from .findings import build_verification_trace


verification_bp = Blueprint("verification", __name__)


@verification_bp.route("/verification/<int:finding_id>")
@login_required
def verification_page(finding_id):
    from storage import get_storage
    storage = get_storage()
    if not storage:
        return "Storage disabled", 500

    detail = storage.get_finding_detail(finding_id)
    if not detail:
        return "Finding not found", 404

    detail["verification"] = build_verification_trace(detail)

    try:
        return render_template(
            "verification.html",
            finding_id=finding_id,
            finding_json=json.dumps(detail, default=str),
        )
    except Exception as e:
        return f"<h1>Verification</h1><pre>{e}</pre>", 500


@verification_bp.route("/api/v1/verification/<int:finding_id>")
def api_verification(finding_id):
    """Return the verification trace as JSON."""
    from storage import get_storage
    storage = get_storage()
    if not storage:
        return jsonify({"error": "storage disabled"}), 500

    detail = storage.get_finding_detail(finding_id)
    if not detail:
        return jsonify({"error": "not found"}), 404

    verification = build_verification_trace(detail)

    return jsonify({
        "finding_id": finding_id,
        "verified": bool(detail.get("verified")),
        "confidence": detail.get("confidence", 0.0),
        "methods": detail.get("verification_methods", []),
        "extracted_info": detail.get("extracted_info", {}),
        "verification": verification,
    })


@verification_bp.route("/api/v1/verification/stats")
def api_verification_stats():
    """Global verification statistics."""
    from storage import get_storage
    storage = get_storage()
    if not storage:
        return jsonify({"stats": {}})

    stats = storage.get_stats()
    total = stats.get("total_findings", 0)
    verified = stats.get("verified", 0)
    rejected = max(0, total - verified)

    return jsonify({
        "total_findings": total,
        "verified": verified,
        "unverified": rejected,
        "verified_ratio": (verified / total) if total else 0,
    })