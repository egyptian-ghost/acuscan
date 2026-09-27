#!/usr/bin/env python3
"""
Scan Detail API v6.5.2
======================
Provides detailed scan information:
  - /api/v1/scans/<id>/crawl-map
  - /api/v1/scans/<id>/crawl-tree
  - /api/v1/scans/<id>/server-info
  - /api/v1/scans/<id>/login-test
  - /api/v1/scans/<id>/statistics
  - /api/v1/scans/<id>/activity

Note: /findings endpoint lives in findings.py to avoid route conflicts.

Accepts BOTH numeric ID and UUID in the URL.
"""
from flask import Blueprint, jsonify, request
from storage import get_storage


scans_detail_bp = Blueprint("scans_detail", __name__)


# ═══════════════════════════════════════════════════════════════════════════════
#  Helper: resolve scan identifier (numeric OR UUID) → numeric ID
# ═══════════════════════════════════════════════════════════════════════════════

def _resolve_scan(scan_id_str):
    """Resolve scan identifier to numeric scan_id. Returns None if not found."""
    if not scan_id_str:
        return None

    storage = get_storage()
    if not storage:
        return None

    # Try as integer
    try:
        sid = int(scan_id_str)
        scan = storage.get_scan(sid)
        if scan:
            return scan.get("id")
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
#  Crawl Map
# ═══════════════════════════════════════════════════════════════════════════════

@scans_detail_bp.route("/api/v1/scans/<scan_id>/crawl-map")
def api_crawl_map(scan_id):
    """Get crawl map with full statistics."""
    numeric_id = _resolve_scan(scan_id)
    if numeric_id is None:
        return jsonify({"crawl_map": [], "stats": {}, "total": 0})

    storage = get_storage()
    meta = storage.get_scan_metadata(numeric_id)
    crawl_map = meta.get("crawl_map", [])

    # Optional filters
    filter_type = request.args.get("type")
    if filter_type == "internal":
        crawl_map = [n for n in crawl_map if not n.get("is_external")]
    elif filter_type == "external":
        crawl_map = [n for n in crawl_map if n.get("is_external")]
    elif filter_type == "with_forms":
        crawl_map = [n for n in crawl_map if n.get("forms")]
    elif filter_type == "with_params":
        crawl_map = [n for n in crawl_map if n.get("parameters")]

    q = request.args.get("q", "").lower()
    if q:
        crawl_map = [
            n for n in crawl_map
            if q in (n.get("url", "") + " " + n.get("title", "")).lower()
        ]

    return jsonify({
        "crawl_map": crawl_map,
        "stats": meta.get("crawl_stats", {}),
        "total": len(crawl_map),
    })


@scans_detail_bp.route("/api/v1/scans/<scan_id>/crawl-tree")
def api_crawl_tree(scan_id):
    """Get crawl map as a hierarchical tree."""
    numeric_id = _resolve_scan(scan_id)
    if numeric_id is None:
        return jsonify({"_children": {}})

    storage = get_storage()
    meta = storage.get_scan_metadata(numeric_id)
    nodes = meta.get("crawl_map", [])

    root = {"_children": {}}
    for node in nodes:
        url = node.get("url", "")
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            path = parsed.path or "/"
            parts = [p for p in path.split("/") if p]

            if not parts:
                root["_node"] = node
                continue

            current = root["_children"]
            current_path = ""

            for i, part in enumerate(parts):
                current_path += "/" + part
                if part not in current:
                    current[part] = {"path": current_path, "_children": {}}
                if i == len(parts) - 1:
                    current[part]["_node"] = node
                    if parsed.query:
                        qs = parse_qs(parsed.query)
                        current[part]["_query_params"] = list(qs.keys())
                current = current[part]["_children"]
        except Exception:
            continue

    return jsonify(root)


# ═══════════════════════════════════════════════════════════════════════════════
#  Server Info
# ═══════════════════════════════════════════════════════════════════════════════

@scans_detail_bp.route("/api/v1/scans/<scan_id>/server-info")
def api_server_info(scan_id):
    """Get server information."""
    numeric_id = _resolve_scan(scan_id)
    if numeric_id is None:
        return jsonify({})

    storage = get_storage()
    meta = storage.get_scan_metadata(numeric_id)
    return jsonify(meta.get("server_info", {}))


# ═══════════════════════════════════════════════════════════════════════════════
#  Login Test
# ═══════════════════════════════════════════════════════════════════════════════

@scans_detail_bp.route("/api/v1/scans/<scan_id>/login-test")
def api_login_test(scan_id):
    """Get login test result."""
    numeric_id = _resolve_scan(scan_id)
    if numeric_id is None:
        return jsonify({})

    storage = get_storage()
    meta = storage.get_scan_metadata(numeric_id)
    return jsonify(meta.get("login_test", {}))


# ═══════════════════════════════════════════════════════════════════════════════
#  Statistics
# ═══════════════════════════════════════════════════════════════════════════════

@scans_detail_bp.route("/api/v1/scans/<scan_id>/statistics")
def api_scan_statistics(scan_id):
    """Aggregate statistics for a scan."""
    numeric_id = _resolve_scan(scan_id)
    if numeric_id is None:
        return jsonify({
            "scan": {},
            "findings": {"total": 0, "verified": 0, "by_severity": {}},
            "crawl": {},
        })

    storage = get_storage()
    scan = storage.get_scan(numeric_id)
    if not scan:
        return jsonify({
            "scan": {},
            "findings": {"total": 0, "verified": 0, "by_severity": {}},
            "crawl": {},
        })

    findings = storage.get_findings(numeric_id)
    sev_counts = {}
    verified_count = 0
    for f in findings:
        s = f.get("severity", "info")
        sev_counts[s] = sev_counts.get(s, 0) + 1
        if f.get("verified"):
            verified_count += 1

    meta = storage.get_scan_metadata(numeric_id)

    duration = scan.get("duration_seconds") or 0
    request_count = scan.get("request_count", 0)
    req_rate = round(request_count / duration, 2) if duration else 0

    return jsonify({
        "scan": {
            "id": scan.get("id"),
            "scan_uuid": scan.get("scan_uuid"),
            "targets": scan.get("targets", []),
            "status": scan.get("status"),
            "started_at": scan.get("started_at"),
            "finished_at": scan.get("finished_at"),
            "duration_seconds": duration,
            "request_count": request_count,
            "error_count": scan.get("error_count", 0),
            "requests_per_second": req_rate,
        },
        "findings": {
            "total": len(findings),
            "verified": verified_count,
            "by_severity": sev_counts,
        },
        "crawl": meta.get("crawl_stats", {}),
    })


# ═══════════════════════════════════════════════════════════════════════════════
#  Activity Timeline
# ═══════════════════════════════════════════════════════════════════════════════

@scans_detail_bp.route("/api/v1/scans/<scan_id>/activity")
def api_scan_activity(scan_id):
    """Timeline of activities for a scan."""
    numeric_id = _resolve_scan(scan_id)
    if numeric_id is None:
        return jsonify({"activities": []})

    storage = get_storage()
    scan = storage.get_scan(numeric_id)
    if not scan:
        return jsonify({"activities": []})

    meta = storage.get_scan_metadata(numeric_id)
    activities = []

    started = scan.get("started_at") or ""
    finished = scan.get("finished_at") or ""

    # 1. Scan started
    if started:
        activities.append({
            "timestamp": started,
            "type": "scan_started",
            "icon": "▶",
            "title": "Scan Started",
            "description": f"Target(s): {', '.join(scan.get('targets', []))}",
        })

    # 2. Login test
    lt = meta.get("login_test", {})
    if lt:
        success = bool(lt.get("success"))
        activities.append({
            "timestamp": started,
            "type": "login_test",
            "icon": "🔐" if success else "❌",
            "title": f"Login Test — {'Success' if success else 'Failed'}",
            "description": lt.get("reason", ""),
            "success": success,
            "confidence": lt.get("confidence", 0),
        })

    # 3. Server detected
    si = meta.get("server_info", {})
    if si:
        parts = []
        if si.get("server"):
            parts.append(si["server"])
        if si.get("operating_system"):
            parts.append(si["operating_system"])
        if si.get("cdn"):
            parts.append(f"CDN: {si['cdn']}")
        activities.append({
            "timestamp": started,
            "type": "server_info",
            "icon": "🖥",
            "title": "Server Detected",
            "description": " • ".join(parts) if parts else "Server info collected",
        })

    # 4. Crawl completed
    crawl_stats = meta.get("crawl_stats", {})
    if crawl_stats.get("total"):
        activities.append({
            "timestamp": finished or started,
            "type": "crawl_completed",
            "icon": "🕷",
            "title": "Crawl Completed",
            "description": (
                f"{crawl_stats['total']} URLs discovered "
                f"({crawl_stats.get('internal', 0)} internal, "
                f"{crawl_stats.get('external', 0)} external)"
            ),
        })

    # 5. Findings
    total_findings = scan.get("total_findings", 0)
    if total_findings:
        activities.append({
            "timestamp": finished or started,
            "type": "findings",
            "icon": "🎯",
            "title": f"{total_findings} Findings",
            "description": (
                f"Critical: {scan.get('critical_count', 0)} • "
                f"High: {scan.get('high_count', 0)} • "
                f"Medium: {scan.get('medium_count', 0)} • "
                f"Low: {scan.get('low_count', 0)} • "
                f"Info: {scan.get('info_count', 0)}"
            ),
        })

    # 6. Scan finished
    if finished:
        status = scan.get("status", "completed").capitalize()
        activities.append({
            "timestamp": finished,
            "type": "scan_finished",
            "icon": "✓" if status == "Completed" else "⏹",
            "title": f"Scan {status}",
            "description": (
                f"{total_findings} findings • "
                f"{scan.get('duration_seconds', 0):.1f}s • "
                f"{scan.get('request_count', 0)} requests"
            ),
        })

    activities.sort(key=lambda a: a.get("timestamp") or "")

    return jsonify({"activities": activities})