"""Auth routes (login/register/logout)."""
import json
from flask import (
    Blueprint, render_template, request, jsonify, session, redirect,
    url_for,
)

from ..auth import hash_password, verify_password, make_jwt
from storage import get_storage


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login")
def login_page():
    if "user_id" in session:
        return redirect(url_for("scans.dashboard_page"))
    try:
        return render_template("login.html")
    except Exception:
        return _inline_login(), 200


@auth_bp.route("/register")
def register_page():
    try:
        return render_template("register.html")
    except Exception:
        return _inline_register(), 200


@auth_bp.route("/api/auth/login", methods=["POST"])
def session_login():
    storage = get_storage()
    if not storage:
        return jsonify({"error": "storage disabled"}), 500

    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    user = storage.get_user(username)
    if not user or not verify_password(password, user["password_hash"]):
        return jsonify({"error": "invalid credentials"}), 401

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    session.permanent = True

    storage.update_last_login(user["id"])

    return jsonify({
        "ok": True,
        "user": {"username": user["username"], "role": user["role"]},
        "token": make_jwt({
            "sub": user["id"],
            "username": user["username"],
            "role": user["role"],
        }),
    })


@auth_bp.route("/api/auth/logout", methods=["POST"])
def session_logout():
    session.clear()
    return jsonify({"ok": True})


@auth_bp.route("/api/auth/register", methods=["POST"])
def session_register():
    storage = get_storage()
    if not storage:
        return jsonify({"error": "storage disabled"}), 500

    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    email = (data.get("email") or "").strip() or None

    if len(username) < 3:
        return jsonify({"error": "username must be at least 3 chars"}), 400
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 chars"}), 400
    if storage.get_user(username):
        return jsonify({"error": "username taken"}), 409

    stats = storage.get_stats()
    role = "admin" if stats.get("total_scans", 0) == 0 else "user"
    storage.create_user(username, hash_password(password), role, email)
    return jsonify({"ok": True})


@auth_bp.route("/api/auth/me")
def session_me():
    if "user_id" not in session:
        return jsonify({"authenticated": False})
    return jsonify({
        "authenticated": True,
        "user": {
            "username": session.get("username"),
            "role": session.get("role"),
        },
    })


def _inline_login():
    return """<!DOCTYPE html>
<html><head><title>Login — AcuScan</title>
<style>
body{background:#0a0f1c;color:#f1f5f9;font-family:system-ui;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{background:#0f172a;border:1px solid #1e293b;border-radius:16px;
padding:40px;width:400px;max-width:90vw;box-shadow:0 24px 80px rgba(0,0,0,.5)}
h1{color:#38bdf8;margin-bottom:20px}
input{width:100%;background:#0a0f1c;border:1px solid #334155;color:#f1f5f9;
border-radius:8px;padding:12px;font-size:14px;margin-bottom:12px;
box-sizing:border-box;outline:none}
input:focus{border-color:#38bdf8}
button{width:100%;background:#38bdf8;color:#0a0f1c;border:none;
border-radius:8px;padding:14px;font-size:14px;font-weight:700;cursor:pointer}
.error{color:#ef4444;font-size:13px;margin-bottom:12px;display:none}
</style></head><body>
<div class="card">
<h1>&#128270; AcuScan Login</h1>
<div class="error" id="err"></div>
<form onsubmit="doLogin(event)">
<input type="text" id="username" placeholder="Username" required>
<input type="password" id="password" placeholder="Password" required>
<button type="submit">Login</button>
</form>
<p style="margin-top:16px;color:#94a3b8;font-size:12px;text-align:center">
No account? <a href="/register" style="color:#38bdf8">Register</a>
</p>
</div>
<script>
async function doLogin(e){
  e.preventDefault();
  const r = await fetch('/api/auth/login',{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({
      username:document.getElementById('username').value,
      password:document.getElementById('password').value
    })});
  const d = await r.json();
  if(d.ok) window.location.href='/';
  else{const e=document.getElementById('err');
       e.textContent=d.error||'Login failed';e.style.display='block';}
}
</script></body></html>"""


def _inline_register():
    return """<!DOCTYPE html>
<html><head><title>Register — AcuScan</title>
<style>
body{background:#0a0f1c;color:#f1f5f9;font-family:system-ui;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{background:#0f172a;border:1px solid #1e293b;border-radius:16px;
padding:40px;width:400px;max-width:90vw}
h1{color:#38bdf8;margin-bottom:20px}
input{width:100%;background:#0a0f1c;border:1px solid #334155;color:#f1f5f9;
border-radius:8px;padding:12px;font-size:14px;margin-bottom:12px;
box-sizing:border-box;outline:none}
input:focus{border-color:#38bdf8}
button{width:100%;background:#38bdf8;color:#0a0f1c;border:none;
border-radius:8px;padding:14px;font-size:14px;font-weight:700;cursor:pointer}
</style></head><body>
<div class="card">
<h1>&#128270; Register</h1>
<form onsubmit="doReg(event)">
<input type="text" id="username" placeholder="Username" required minlength="3">
<input type="password" id="password" placeholder="Password" required minlength="8">
<button type="submit">Create Account</button>
</form>
<p style="margin-top:16px;color:#94a3b8;font-size:12px;text-align:center">
Have an account? <a href="/login" style="color:#38bdf8">Login</a>
</p>
</div>
<script>
async function doReg(e){
  e.preventDefault();
  const r = await fetch('/api/auth/register',{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({
      username:document.getElementById('username').value,
      password:document.getElementById('password').value
    })});
  const d = await r.json();
  if(d.ok){alert('Created! Please login.');window.location.href='/login';}
  else alert(d.error||'Failed');
}
</script></body></html>"""