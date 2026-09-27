#!/usr/bin/env python3
"""
Upload API
==========
Endpoints:
  GET  /upload              (page)
  POST /api/v1/upload       (parse OpenAPI/Postman)
"""
import json
from flask import Blueprint, render_template, request, jsonify

from ..auth import login_required


upload_bp = Blueprint("upload", __name__)


@upload_bp.route("/upload")
@login_required
def upload_page():
    try:
        return render_template("upload.html")
    except Exception as e:
        return f"<h1>Upload</h1><pre>{e}</pre>", 500


@upload_bp.route("/api/v1/upload", methods=["POST"])
def api_upload():
    """Parse an OpenAPI/Swagger/Postman file and extract endpoints."""
    if "file" not in request.files:
        return jsonify({"error": "no file provided"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "empty filename"}), 400

    # Size check
    try:
        content = f.read().decode("utf-8", "ignore")
    except Exception as e:
        return jsonify({"error": f"could not read file: {e}"}), 400

    if len(content) > 10 * 1024 * 1024:
        return jsonify({"error": "file too large (>10MB)"}), 413

    endpoints = []
    fname_lower = f.filename.lower()
    content_lower = content[:2000].lower()

    # Detect type
    is_openapi = ("openapi" in content_lower or
                  "swagger" in content_lower or
                  fname_lower.endswith((".yaml", ".yml")))
    is_postman = ('"_postman_id"' in content or
                  '"postman"' in content_lower or
                  '"info"' in content[:200] and '"item"' in content)

    if is_openapi:
        endpoints = _parse_openapi(content)
    if not endpoints and is_postman:
        endpoints = _parse_postman(content)
    if not endpoints and fname_lower.endswith(".json"):
        endpoints = _parse_postman(content) or _parse_openapi(content)

    if not endpoints:
        return jsonify({
            "error": "could not parse — not a valid OpenAPI/Swagger/Postman file",
            "filename": f.filename,
            "endpoints_count": 0,
            "endpoints": [],
        }), 400

    return jsonify({
        "filename": f.filename,
        "detected_type": "openapi" if is_openapi else "postman",
        "endpoints_count": len(endpoints),
        "endpoints": endpoints[:500],
    })


# ═══════════════════════════════════════════════════════════════════════════════
#  OpenAPI / Swagger parser
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_openapi(content):
    spec = None
    try:
        import yaml
        spec = yaml.safe_load(content)
    except Exception:
        pass

    if spec is None:
        try:
            spec = json.loads(content)
        except Exception:
            return []

    if not isinstance(spec, dict):
        return []

    endpoints = []
    base_url = ""

    # OpenAPI 3
    if "servers" in spec and spec["servers"]:
        base_url = spec["servers"][0].get("url", "")

    # Swagger 2
    elif "host" in spec:
        scheme = (spec.get("schemes") or ["https"])[0]
        base_url = f"{scheme}://{spec['host']}{spec.get('basePath', '')}"

    for path, methods in spec.get("paths", {}).items():
        if not isinstance(methods, dict):
            continue

        for method, details in methods.items():
            if method.lower() not in (
                "get", "post", "put", "delete", "patch", "options", "head"
            ):
                continue

            if not isinstance(details, dict):
                details = {}

            params = []
            # Parameters
            for p in details.get("parameters", []) or []:
                if isinstance(p, dict) and p.get("in") in (
                    "query", "path", "formData"
                ):
                    params.append(p.get("name", ""))

            # Request body (OpenAPI 3)
            if "requestBody" in details:
                content_types = details["requestBody"].get("content", {})
                for ct, cspec in content_types.items():
                    props = cspec.get("schema", {}).get("properties", {})
                    params.extend(props.keys())

            endpoints.append({
                "url": base_url + path,
                "method": method.upper(),
                "params": [p for p in params if p],
                "summary": details.get("summary", ""),
                "operation_id": details.get("operationId", ""),
                "tags": details.get("tags", []),
            })

    return endpoints


# ═══════════════════════════════════════════════════════════════════════════════
#  Postman parser
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_postman(content):
    try:
        col = json.loads(content)
    except Exception:
        return []

    if not isinstance(col, dict):
        return []

    endpoints = []

    def _walk(items):
        for item in items:
            if not isinstance(item, dict):
                continue
            if "item" in item:
                _walk(item["item"])
            elif "request" in item:
                req = item["request"]
                url = req.get("url", {})
                if isinstance(url, str):
                    raw = url
                else:
                    raw = url.get("raw", "")

                params = []
                # Query params
                if isinstance(url, dict):
                    for q in url.get("query", []):
                        params.append(q.get("key", ""))
                    # Path variables
                    for v in url.get("variable", []):
                        params.append(v.get("key", ""))

                # Body params
                if "body" in req and isinstance(req["body"], dict):
                    mode = req["body"].get("mode")
                    if mode == "urlencoded":
                        for p in req["body"].get("urlencoded", []):
                            params.append(p.get("key", ""))
                    elif mode == "formdata":
                        for p in req["body"].get("formdata", []):
                            params.append(p.get("key", ""))

                endpoints.append({
                    "url": raw,
                    "method": req.get("method", "GET").upper(),
                    "params": [p for p in params if p],
                    "summary": item.get("name", ""),
                })

    _walk(col.get("item", []))
    return endpoints