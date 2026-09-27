#!/usr/bin/env python3
"""
Auth API
========
Session-based authentication for Web UI.
Endpoints:
  POST /api/auth/login
  POST /api/auth/logout
  POST /api/auth/register
  GET  /api/auth/me
  GET  /login           (page)
  GET  /register        (page)
"""
import time
import secrets as _secrets
from flask import (
    Blueprint, render_template, request, jsonify, session, redirect,
    url_for,
)

from ..auth import hash_password, verify_password, make_jwt


auth_bp = Blueprint("auth", __name__)


# ═══════════════════════════════════════════════════════════════════════════════
#  Pages
# ═══════════════════════════════════════════════════════════════════════════════

@auth_bp.route("/login")
def login_page():
    """Serve login page."""
    if "user_id" in session:
        return redirect(url_for("scans.dashboard_page"))
    try:
        return render_template("login.html")
    except Exception:
        return _fallback_login(), 200


@auth_bp.route("/register")
def register_page():
    """Serve register page."""
    if "user_id" in session:
        return redirect(url_for("scans.dashboard_page"))
    try:
        return render_template("register.html")
    except Exception:
        return _fallback_register(), 200


@auth_bp.route("/logout")
def logout_page():
    """Clear session and redirect."""
    session.clear()
    return redirect(url_for("auth.login_page"))


# ═══════════════════════════════════════════════════════════════════════════════
#  API
# ═══════════════════════════════════════════════════════════════════════════════

@auth_bp.route("/api/auth/login", methods=["POST"])
def api_login():
    """Session + JWT login."""
    from storage import get_storage
    storage = get_storage()
    if not storage:
        return jsonify({"error": "storage disabled"}), 500

    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    user = storage.get_user(username)
    if not user or not verify_password(password, user["password_hash"]):
        # Slight delay to slow down brute force
        time.sleep(0.5)
        return jsonify({"error": "invalid credentials"}), 401

    # Set session
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    session.permanent = True

    storage.update_last_login(user["id"])

    return jsonify({
        "ok": True,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
        },
        "token": make_jwt({
            "sub": user["id"],
            "username": user["username"],
            "role": user["role"],
        }),
    })


@auth_bp.route("/api/auth/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})


@auth_bp.route("/api/auth/register", methods=["POST"])
def api_register():
    """Register a new user. First user becomes admin."""
    from storage import get_storage
    storage = get_storage()
    if not storage:
        return jsonify({"error": "storage disabled"}), 500

    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    email = (data.get("email") or "").strip() or None

    # Validation
    if len(username) < 3:
        return jsonify({"error": "username must be at least 3 characters"}), 400
    if len(username) > 50:
        return jsonify({"error": "username too long"}), 400
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400
    if not username.replace("_", "").replace("-", "").isalnum():
        return jsonify({"error": "username must be alphanumeric"}), 400

    if storage.get_user(username):
        return jsonify({"error": "username already taken"}), 409

    # First user is admin
    stats = storage.get_stats()
    role = "admin" if stats.get("total_scans", 0) == 0 and \
                     _count_users(storage) == 0 else "user"

    storage.create_user(username, hash_password(password), role, email)
    return jsonify({
        "ok": True,
        "user": {"username": username, "role": role},
    })


@auth_bp.route("/api/auth/me")
def api_me():
    if "user_id" not in session:
        return jsonify({"authenticated": False})
    return jsonify({
        "authenticated": True,
        "user": {
            "id": session.get("user_id"),
            "username": session.get("username"),
            "role": session.get("role"),
        },
    })


@auth_bp.route("/api/auth/change-password", methods=["POST"])
def api_change_password():
    if "user_id" not in session:
        return jsonify({"error": "unauthorized"}), 401

    from storage import get_storage
    storage = get_storage()
    if not storage:
        return jsonify({"error": "storage disabled"}), 500

    data = request.get_json() or {}
    old_password = data.get("old_password") or ""
    new_password = data.get("new_password") or ""

    if len(new_password) < 8:
        return jsonify({"error": "new password must be at least 8 characters"}), 400

    user = storage.get_user(session.get("username"))
    if not user or not verify_password(old_password, user["password_hash"]):
        return jsonify({"error": "invalid current password"}), 401

    # Update password
    with storage.lock, storage._connect() as conn:
        conn.execute(
            "UPDATE users SET password_hash=? WHERE id=?",
            (hash_password(new_password), user["id"])
        )

    return jsonify({"ok": True})


# ═══════════════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _count_users(storage):
    try:
        return storage.user_count()
    except Exception:
        return 0


def _fallback_login():
    """Fallback login page if template is missing."""
    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Login — AcuScan</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:linear-gradient(135deg,#0a0f1c,#0f172a);color:#f1f5f9;
font-family:system-ui;display:flex;align-items:center;justify-content:center;
min-height:100vh;padding:20px}
.card{background:#0f172a;border:1px solid #1e293b;border-radius:20px;
padding:48px 40px;width:100%;max-width:440px;box-shadow:0 24px 80px rgba(0,0,0,.5)}
.brand{text-align:center;margin-bottom:32px}
.brand-icon{font-size:56px;margin-bottom:12px}
.brand h1{font-size:26px;font-weight:800;color:#38bdf8;letter-spacing:-.5px}
.brand p{color:#64748b;font-size:13px;margin-top:4px}
label{display:block;color:#94a3b8;font-size:12px;font-weight:600;
text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}
input{width:100%;background:#0a0f1c;border:1.5px solid #334155;color:#f1f5f9;
border-radius:10px;padding:14px 16px;font-size:14px;outline:none;
transition:border-color .15s;margin-bottom:18px}
input:focus{border-color:#38bdf8;box-shadow:0 0 0 3px rgba(56,189,248,.15)}
button{width:100%;background:linear-gradient(135deg,#38bdf8,#0ea5e9);
color:#0a0f1c;border:none;border-radius:10px;padding:15px;font-size:15px;
font-weight:700;cursor:pointer;transition:all .15s}
button:hover{transform:translateY(-1px);box-shadow:0 8px 24px rgba(56,189,248,.4)}
.error{background:rgba(220,38,38,.15);border:1px solid #dc2626;color:#f87171;
padding:12px 16px;border-radius:10px;font-size:13px;margin-bottom:16px;display:none}
.error.show{display:block}
.footer{text-align:center;margin-top:24px;color:#64748b;font-size:13px}
.footer a{color:#38bdf8;text-decoration:none;font-weight:600}
</style></head><body>
<div class="card">
<div class="brand">
<div class="brand-icon">&#128270;</div>
<h1>AcuScan</h1>
<p>Professional Web Vulnerability Scanner</p>
</div>
<div class="error" id="err"></div>
<form onsubmit="doLogin(event)">
<label>Username</label>
<input type="text" id="username" required autofocus>
<label>Password</label>
<input type="password" id="password" required>
<button type="submit">Sign In</button>
</form>
<div class="footer">No account? <a href="/register">Create one</a></div>
</div>
<script>
async function doLogin(e){
  e.preventDefault();
  const err=document.getElementById('err');
  err.classList.remove('show');
  const btn=e.target.querySelector('button');
  btn.disabled=true;btn.textContent='Signing in...';
  try{
    const r=await fetch('/api/auth/login',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({
        username:document.getElementById('username').value,
        password:document.getElementById('password').value
      })});
    const d=await r.json();
    if(d.ok)window.location.href='/';
    else{err.textContent=d.error||'Login failed';err.classList.add('show');
         btn.disabled=false;btn.textContent='Sign In'}
  }catch(e){err.textContent='Network error: '+e.message;
             err.classList.add('show');btn.disabled=false;btn.textContent='Sign In'}
}
</script></body></html>"""


def _fallback_register():
    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Register — AcuScan</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:linear-gradient(135deg,#0a0f1c,#0f172a);color:#f1f5f9;
font-family:system-ui;display:flex;align-items:center;justify-content:center;
min-height:100vh;padding:20px}
.card{background:#0f172a;border:1px solid #1e293b;border-radius:20px;
padding:48px 40px;width:100%;max-width:440px;box-shadow:0 24px 80px rgba(0,0,0,.5)}
.brand{text-align:center;margin-bottom:32px}
.brand-icon{font-size:56px;margin-bottom:12px}
.brand h1{font-size:26px;font-weight:800;color:#38bdf8}
.brand p{color:#64748b;font-size:13px;margin-top:4px}
label{display:block;color:#94a3b8;font-size:12px;font-weight:600;
text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}
input{width:100%;background:#0a0f1c;border:1.5px solid #334155;color:#f1f5f9;
border-radius:10px;padding:14px 16px;font-size:14px;outline:none;
transition:border-color .15s;margin-bottom:8px}
input:focus{border-color:#38bdf8;box-shadow:0 0 0 3px rgba(56,189,248,.15)}
.hint{color:#64748b;font-size:11px;margin-bottom:16px}
button{width:100%;background:linear-gradient(135deg,#38bdf8,#0ea5e9);
color:#0a0f1c;border:none;border-radius:10px;padding:15px;font-size:15px;
font-weight:700;cursor:pointer;transition:all .15s;margin-top:8px}
button:hover{transform:translateY(-1px);box-shadow:0 8px 24px rgba(56,189,248,.4)}
.error{background:rgba(220,38,38,.15);border:1px solid #dc2626;color:#f87171;
padding:12px 16px;border-radius:10px;font-size:13px;margin-bottom:16px;display:none}
.error.show{display:block}
.footer{text-align:center;margin-top:24px;color:#64748b;font-size:13px}
.footer a{color:#38bdf8;text-decoration:none;font-weight:600}
</style></head><body>
<div class="card">
<div class="brand">
<div class="brand-icon">&#128270;</div>
<h1>Create Account</h1>
<p>Join AcuScan Security Platform</p>
</div>
<div class="error" id="err"></div>
<form onsubmit="doReg(event)">
<label>Username</label>
<input type="text" id="username" required minlength="3" placeholder="At least 3 characters">
<div class="hint">Letters, numbers, -, _ only</div>
<label>Password</label>
<input type="password" id="password" required minlength="8" placeholder="At least 8 characters">
<div class="hint">Minimum 8 characters</div>
<button type="submit">Create Account</button>
</form>
<div class="footer">Have an account? <a href="/login">Sign In</a></div>
</div>
<script>
async function doReg(e){
  e.preventDefault();
  const err=document.getElementById('err');
  err.classList.remove('show');
  const btn=e.target.querySelector('button');
  btn.disabled=true;btn.textContent='Creating...';
  try{
    const r=await fetch('/api/auth/register',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({
        username:document.getElementById('username').value,
        password:document.getElementById('password').value
      })});
    const d=await r.json();
    if(d.ok){alert('Account created! Please login.');window.location.href='/login'}
    else{err.textContent=d.error||'Registration failed';err.classList.add('show');
         btn.disabled=false;btn.textContent='Create Account'}
  }catch(e){err.textContent='Network error: '+e.message;
             err.classList.add('show');btn.disabled=false;btn.textContent='Create Account'}
}
</script></body></html>"""