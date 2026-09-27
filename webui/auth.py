#!/usr/bin/env python3
"""Authentication utilities (JWT + password hashing)."""
import os
import time
import hmac
import json
import base64
import hashlib
import secrets as _secrets
from functools import wraps

from flask import request, jsonify, session, redirect, url_for


JWT_SECRET = (os.environ.get("ACUSCAN_JWT_SECRET") or
             _secrets.token_hex(32))


# ═══════════════════════════════════════════════════════════════════════════════
#  Password hashing (PBKDF2)
# ═══════════════════════════════════════════════════════════════════════════════

def hash_password(password, salt=None):
    salt = salt or _secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 100000
    )
    return f"{salt}${h.hex()}"


def verify_password(password, stored):
    try:
        salt, expected = stored.split("$", 1)
        h = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), 100000
        )
        return hmac.compare_digest(h.hex(), expected)
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════════════════════
#  JWT (simple HS256)
# ═══════════════════════════════════════════════════════════════════════════════

def _b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(data):
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


def make_jwt(payload, expires_in=86400):
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}))
    payload = dict(payload)
    payload["exp"] = int(time.time()) + expires_in
    payload["iat"] = int(time.time())
    body = _b64url_encode(json.dumps(payload))
    signing_input = f"{header}.{body}"
    sig = _b64url_encode(
        hmac.new(JWT_SECRET.encode(), signing_input.encode(),
                hashlib.sha256).digest()
    )
    return f"{signing_input}.{sig}"


def verify_jwt(token):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, body, sig = parts
        signing_input = f"{header}.{body}"
        expected = _b64url_encode(
            hmac.new(JWT_SECRET.encode(), signing_input.encode(),
                    hashlib.sha256).digest()
        )
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(_b64url_decode(body))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
#  Decorators
# ═══════════════════════════════════════════════════════════════════════════════

def require_auth_api(f):
    """Decorator for API routes (returns 401 if not authed)."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        from flask import current_app
        if not current_app.config.get("AUTH_ENABLED", False):
            return f(*args, **kwargs)
        token = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
        if not token:
            token = request.args.get("token")
        if not token:
            return jsonify({"error": "unauthorized"}), 401
        payload = verify_jwt(token)
        if not payload:
            return jsonify({"error": "invalid or expired token"}), 401
        request.user = payload
        return f(*args, **kwargs)
    return wrapper


def login_required(f):
    """Decorator for HTML pages (redirects to /login if not authed)."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        from flask import current_app
        if not current_app.config.get("AUTH_ENABLED", False):
            return f(*args, **kwargs)
        if "user_id" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("auth.login_page", next=request.path))
        return f(*args, **kwargs)
    return wrapper