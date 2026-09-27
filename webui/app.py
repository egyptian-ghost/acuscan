#!/usr/bin/env python3
"""
AcuScan Web UI — App Factory v6.5.3
===================================
Fixed: Proper blueprint registration with diagnostics.
"""
import os
import sys
import logging
import secrets as _secrets
from datetime import timedelta

from flask import Flask, render_template, Response, jsonify, session, \
    redirect, url_for, request
from werkzeug.exceptions import HTTPException
from functools import wraps

# Make project importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import VERSION

# Storage
try:
    from storage import get_storage
    HAS_STORAGE = True
except ImportError:
    HAS_STORAGE = False
    get_storage = None

# WebSocket
try:
    from flask_sock import Sock
    HAS_SOCK = True
except ImportError:
    HAS_SOCK = False

# Scheduler
try:
    from croniter import croniter
    HAS_CRONITER = True
except ImportError:
    HAS_CRONITER = False


_storage = get_storage() if HAS_STORAGE else None


def create_app(config=None):
    """Create and configure the Flask app."""
    config = config or {}

    base_dir = os.path.dirname(os.path.abspath(__file__))
    app = Flask(
        __name__,
        template_folder=os.path.join(base_dir, "templates"),
        static_folder=os.path.join(base_dir, "static"),
        static_url_path="/static",
    )
    app.config["SECRET_KEY"] = (
        os.environ.get("ACUSCAN_SECRET") or _secrets.token_hex(32)
    )
    app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024
    app.config["AUTH_ENABLED"] = os.environ.get("ACUSCAN_AUTH", "0") == "1"
    app.permanent_session_lifetime = timedelta(days=30)

    @app.errorhandler(404)
    def _handle_not_found(exc):
        path = request.path
        if request.method != "HEAD":
            app.logger.debug("404 %s %s", request.method, path)
        if path.startswith("/api/"):
            return jsonify({"ok": False, "error": "Not found", "path": path}), 404
        return ("<h1>404 - Not Found</h1>", 404)

    @app.errorhandler(405)
    def _handle_method_not_allowed(exc):
        if request.path.startswith("/api/"):
            return jsonify({"ok": False, "error": "Method not allowed", "path": request.path}), 405
        return ("<h1>405 - Method Not Allowed</h1>", 405)

    @app.errorhandler(Exception)
    def _handle_unexpected_error(exc):
        if isinstance(exc, HTTPException):
            return exc
        app.logger.exception("Unhandled AcuScan Web UI error")
        if request.path.startswith("/api/"):
            return jsonify({"ok": False, "error": "Internal server error"}), 500
        return ("<h1>Internal Server Error</h1>", 500)

    # Lightweight browser/system endpoints.
    @app.route("/favicon.ico")
    def _favicon():
        return ("", 204)

    @app.route("/robots.txt")
    def _robots():
        return Response("User-agent: *\nDisallow: /api/\n", mimetype="text/plain")

    @app.route("/healthz")
    def _healthz():
        return jsonify({"ok": True, "version": VERSION})

    # WebSocket
    if HAS_SOCK:
        app.config["SOCK"] = Sock(app)

    # ═══════════════════════════════════════════════════════════════════
    #  Register blueprints — internal routes
    # ═══════════════════════════════════════════════════════════════════

    from .routes import (
        auth_bp, findings_bp, verification_bp,
        upload_bp, dashboard_bp, schedules_bp,
    )
    # Use the maintained scans API implementation. The old routes/scans.py
    # was kept for compatibility but caused the Web UI to run an older
    # duplicate-prevention/listing implementation.
    from .api.scans import scans_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(findings_bp)
    app.register_blueprint(verification_bp)
    app.register_blueprint(upload_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(schedules_bp)

    # scans_detail is part of webui.api; import it explicitly so startup
    # never attempts the non-existent top-level ``api`` package first.
    try:
        from .api.scans_detail import scans_detail_bp
        app.register_blueprint(scans_detail_bp)
        print("[webui] ✓ Registered scans_detail_bp")
    except Exception as e:
        print(f"[webui] ✗ scans_detail registration failed: {e}")
        scans_detail_bp = None

    # Findings API is already exposed by webui.routes.findings. Avoid the
    # old top-level ``api.findings`` probe, which produced a misleading
    # import error on every startup.

    # ═══════════════════════════════════════════════════════════════════
    #  WebSocket routes
    # ═══════════════════════════════════════════════════════════════════

    if HAS_SOCK:
        try:
            from .jobs import register_websocket_routes
            register_websocket_routes(app)
            print("[webui] ✓ Registered WebSocket routes")
        except Exception as e:
            print(f"[webui] ✗ WebSocket registration failed: {e}")

    # ═══════════════════════════════════════════════════════════════════
    #  Diagnostics: print all API routes
    # ═══════════════════════════════════════════════════════════════════

    print("\n[webui] Registered API routes:")
    api_routes = []
    for rule in app.url_map.iter_rules():
        rule_str = str(rule)
        if "/api/" in rule_str:
            methods = sorted(rule.methods - {"HEAD", "OPTIONS"})
            api_routes.append((rule_str, methods))

    for rule_str, methods in sorted(api_routes):
        methods_str = ",".join(methods)
        print(f"  {methods_str:12s} {rule_str}")
    print()

    return app


def run_web_ui(host="127.0.0.1", port=8080):
    """Start the Web UI server."""
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    app = create_app()

    # First-run admin setup
    if _storage:
        try:
            if _storage.user_count() == 0:
                from .auth import hash_password
                default_pass = _secrets.token_urlsafe(12)
                _storage.create_user("admin", hash_password(default_pass),
                                    "admin")
                print("\n" + "=" * 60)
                print("  FIRST-RUN SETUP")
                print("=" * 60)
                print(f"  Username: admin")
                print(f"  Password: {default_pass}")
                print("  (Save this! Change it after login.)")
                print("=" * 60 + "\n")
        except Exception as e:
            print(f"[Auth] Setup skipped: {e}")

    # Start scheduler
    try:
        from .scheduler import scheduler
        if scheduler:
            scheduler.start()
    except Exception:
        pass

    print(f"\n  " + "=" * 60)
    print(f"  AcuScan Web UI v{VERSION}")
    print(f"  " + "=" * 60)
    print(f"\n  Open in browser: http://{host}:{port}")
    if app.config["AUTH_ENABLED"]:
        print(f"  Auth:            ENABLED — login at /login")
    else:
        print(f"  Auth:            DISABLED (set ACUSCAN_AUTH=1)")
    print()

    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    run_web_ui()