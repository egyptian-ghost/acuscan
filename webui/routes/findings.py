"""
Findings routes — v6.5.4 (UUID-aware)
=====================================
Handles:
  - /findings                            (page)
  - /findings/<int:finding_id>           (detail page)
  - /api/v1/findings                     (all findings)
  - /api/v1/findings/<int:finding_id>    (single)
  - /api/v1/scans/<scan_id>/findings     ← accepts numeric OR UUID
"""
import json
import base64
from flask import Blueprint, render_template, jsonify, request

from ..auth import login_required
from storage import get_storage


findings_bp = Blueprint("findings", __name__)


# ═══════════════════════════════════════════════════════════════════════════════
#  Helper: resolve scan identifier (numeric OR UUID) → numeric ID
# ═══════════════════════════════════════════════════════════════════════════════

def _resolve_scan_id(scan_id_str):
    """
    Accepts:
      - "123"                                     → returns 123
      - "006d8fce-6fcc-4844-97f0-4e8c9a057f42"   → returns numeric id
    Returns None if not found.
    """
    if not scan_id_str:
        return None

    storage = get_storage()
    if not storage:
        return None

    # Try as integer first
    try:
        sid = int(scan_id_str)
        if storage.get_scan(sid):
            return sid
    except (ValueError, TypeError):
        pass

    # Try as UUID
    try:
        scan = storage.get_scan_by_uuid(scan_id_str)
        if scan:
            return scan.get("id")
    except Exception:
        pass

    return None


# ═══════════════════════════════════════════════════════════════════════════════
#  Pages
# ═══════════════════════════════════════════════════════════════════════════════

@findings_bp.route("/findings")
@login_required
def findings_page():
    try:
        return render_template("findings.html")
    except Exception as e:
        return f"<h1>Findings</h1><pre>{e}</pre>", 500


@findings_bp.route("/findings/<int:finding_id>")
@login_required
def finding_detail_page(finding_id):
    storage = get_storage()
    if not storage:
        return "Storage disabled", 500

    detail = storage.get_finding_detail(finding_id)
    if not detail:
        return "Finding not found", 404

    detail["verification"] = build_verification_trace(detail)

    try:
        json_str = json.dumps(detail, default=str, ensure_ascii=False)
        json_b64 = base64.b64encode(json_str.encode("utf-8")).decode("ascii")
    except Exception as e:
        return f"<h1>JSON Error</h1><pre>{e}</pre>", 500

    try:
        return render_template(
            "finding_detail.html",
            finding_id=finding_id,
            finding_b64=json_b64,
        )
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        return f"<h1>Template Error</h1><pre>{tb}</pre>", 500


# ═══════════════════════════════════════════════════════════════════════════════
#  API: Global findings
# ═══════════════════════════════════════════════════════════════════════════════

@findings_bp.route("/api/v1/findings")
def api_findings():
    """List findings across all scans (or filtered by scan_id)."""
    storage = get_storage()
    if not storage:
        return jsonify({"findings": [], "count": 0})

    scan_id = request.args.get("scan_id", type=int)
    severity = request.args.get("severity")
    verified_only = request.args.get("verified") == "1"
    limit = request.args.get("limit", type=int, default=500)

    if scan_id:
        findings = storage.get_findings(
            scan_id, severity, verified_only=verified_only, limit=limit
        )
    else:
        findings = storage.get_all_findings(limit=limit)
        if severity:
            findings = [f for f in findings if f.get("severity") == severity]
        if verified_only:
            findings = [f for f in findings if f.get("verified")]

    return jsonify({"findings": findings, "count": len(findings)})


@findings_bp.route("/api/v1/findings/<int:finding_id>")
def api_finding_detail(finding_id):
    """Get a single finding with full details."""
    storage = get_storage()
    if not storage:
        return jsonify({"error": "storage disabled"}), 500

    detail = storage.get_finding_detail(finding_id)
    if not detail:
        return jsonify({"error": "not found"}), 404

    detail["verification"] = build_verification_trace(detail)
    return jsonify(detail)


# ═══════════════════════════════════════════════════════════════════════════════
#  API: Per-scan findings  ⭐ THE KEY ENDPOINT (accepts UUID)
# ═══════════════════════════════════════════════════════════════════════════════

@findings_bp.route("/api/v1/scans/<scan_id>/findings")
def api_scan_findings(scan_id):
    """
    Get findings for a specific scan.
    Accepts BOTH numeric ID and UUID in the URL.
    """
    numeric_id = _resolve_scan_id(scan_id)

    if numeric_id is None:
        return jsonify({
            "findings": [],
            "count": 0,
            "error": "scan not found",
        }), 200

    storage = get_storage()
    if not storage:
        return jsonify({"findings": [], "count": 0}), 200

    severity = request.args.get("severity")
    verified_only = request.args.get("verified") == "1"
    limit = request.args.get("limit", type=int, default=2000)

    findings = storage.get_findings(
        numeric_id, severity, verified_only=verified_only, limit=limit
    )

    return jsonify({
        "findings": findings,
        "count": len(findings),
        "scan_id": numeric_id,
    })


# ═══════════════════════════════════════════════════════════════════════════════
#  Verification trace builder
# ═══════════════════════════════════════════════════════════════════════════════

def build_verification_trace(finding):
    """Build a verification trace from finding evidence."""

    try:
        vsteps = finding.get("verification_steps")
        if isinstance(vsteps, str):
            vsteps = json.loads(vsteps)
        if isinstance(vsteps, list) and vsteps:
            return {
                "total_steps": len(vsteps),
                "steps": vsteps,
                "has_trace": True,
            }
    except Exception:
        pass

    evidence_list = finding.get("all_evidence") or []
    if isinstance(evidence_list, str):
        try:
            evidence_list = json.loads(evidence_list)
        except Exception:
            evidence_list = []

    if not evidence_list and finding.get("evidence"):
        evidence_list = [{
            "type": "raw_evidence",
            "data": finding.get("evidence"),
            "confidence": finding.get("confidence", 0.5),
            "title": "Detected",
            "description": finding.get("detail", ""),
            "extracted_data": {},
        }]

    groups = {}
    for ev in evidence_list:
        t = ev.get("type", "unknown")
        groups.setdefault(t, []).append(ev)

    steps = []
    for ev_type, evs in groups.items():
        if ev_type in ("dbms_error", "boolean_differential", "timing_delay",
                       "reflection", "arithmetic_proof", "file_content",
                       "internal_access", "cloud_metadata", "oast_callback",
                       "ssti_arithmetic", "xxe_file_read", "nosql_error",
                       "php_filter"):
            stage = "detection"
        elif ev_type in ("db_extract", "data_extracted", "command_output",
                        "rce_via_ssti", "file_read"):
            stage = "extraction"
        else:
            stage = "confirmation"

        steps.append({
            "name": ev_type,
            "stage": stage,
            "status": "passed",
            "evidence": evs,
            "count": len(evs),
            "duration_ms": 0,
        })

    return {
        "total_steps": len(steps),
        "steps": steps,
        "has_trace": len(steps) > 0,
    }