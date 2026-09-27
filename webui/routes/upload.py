"""Upload routes (OpenAPI / Postman parsing)."""
import json
from flask import Blueprint, render_template, request, jsonify

from ..auth import login_required


upload_bp = Blueprint("upload", __name__)


@upload_bp.route("/upload")
@login_required
def upload_page():
    return render_template("upload.html")


@upload_bp.route("/api/v1/upload", methods=["POST"])
def api_upload():
    if "file" not in request.files:
        return jsonify({"error": "no file"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "empty filename"}), 400

    try:
        content = f.read().decode("utf-8", "ignore")
    except Exception as e:
        return jsonify({"error": f"cannot read: {e}"}), 400

    endpoints = []
    fname_lower = f.filename.lower()
    content_lower = content[:2000].lower()

    if (fname_lower.endswith((".yaml", ".yml")) or
        "openapi" in content_lower or
        "swagger" in content_lower):
        endpoints = _parse_openapi(content)
    if not endpoints and fname_lower.endswith(".json"):
        endpoints = _parse_postman(content)
        if not endpoints:
            endpoints = _parse_openapi(content)

    return jsonify({
        "filename": f.filename,
        "endpoints_count": len(endpoints),
        "endpoints": endpoints[:500],
    })


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
    if "servers" in spec and spec["servers"]:
        base_url = spec["servers"][0].get("url", "")
    elif "host" in spec:
        scheme = (spec.get("schemes") or ["https"])[0]
        base_url = f"{scheme}://{spec['host']}{spec.get('basePath', '')}"

    for path, methods in spec.get("paths", {}).items():
        if not isinstance(methods, dict):
            continue
        for method, details in methods.items():
            if method.lower() not in ("get", "post", "put", "delete",
                                     "patch", "options", "head"):
                continue
            if not isinstance(details, dict):
                details = {}
            params = []
            for p in details.get("parameters", []) or []:
                if isinstance(p, dict) and p.get("in") in (
                    "query", "path", "formData"
                ):
                    params.append(p.get("name", ""))
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
            })
    return endpoints


def _parse_postman(content):
    try:
        col = json.loads(content)
    except Exception:
        return []
    endpoints = []

    def _walk(items):
        for item in items:
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
                if isinstance(url, dict):
                    for q in url.get("query", []):
                        params.append(q.get("key", ""))
                if "body" in req and isinstance(req["body"], dict):
                    if req["body"].get("mode") == "urlencoded":
                        for p in req["body"].get("urlencoded", []):
                            params.append(p.get("key", ""))
                endpoints.append({
                    "url": raw,
                    "method": req.get("method", "GET").upper(),
                    "params": [p for p in params if p],
                    "summary": item.get("name", ""),
                })
    _walk(col.get("item", []))
    return endpoints