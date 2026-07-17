"""Authentication for the SecOps-AI console (Phase 4a).

Session-cookie auth against the `users` table: /register and /login are the
only routes an anonymous client can reach; everything else -- the dashboard,
every data endpoint, and (in app_groq) the WebSocket -- requires a logged-in
session. The gate is default-deny by endpoint name rather than a decorator per
route, so a route added tomorrow is born protected instead of born leaking.

Passwords are never stored: werkzeug's generate_password_hash (salted, per
user) goes into the DB, check_password_hash verifies at login. Sessions are
Flask's signed cookies -- the cookie holds only user_id/username and is signed
with SECRET_KEY; cookie flags (HttpOnly, SameSite, Secure) are set in app_groq.

CSRF: the auth forms carry a per-session token (hidden input, constant-time
compared). SameSite=Lax already blocks the classic cross-site POST, the token
covers the rest.
"""
from __future__ import annotations

import re
import secrets
import sqlite3
import threading
import time
from collections import deque

from flask import (Blueprint, flash, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import config

bp = Blueprint("auth", __name__)

# Set by init_app. A zero-arg callable so the connection provider is resolved
# per request -- the tests swap app_groq.get_db_connection for a temp-DB one,
# and a late-bound lambda picks that up where a captured connection would not.
_get_db = None

# Endpoints reachable without a session. Everything else is denied.
PUBLIC_ENDPOINTS = {"auth.login", "auth.register", "static"}

# Endpoints that are HTML pages: an anonymous browser is redirected to the
# login form. Everything not listed is API-shaped and gets a plain 401 JSON.
PAGE_ENDPOINTS = {"home", "report_view"}

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
PASSWORD_MIN_LEN = 8


# --- login brute-force throttle ----------------------------------------------
# Sliding window of failed attempts per remote address, in memory. Enough to
# blunt online guessing on a single-process demo server; a multi-process
# deployment would need shared state (noted in the README's Security section).

_failures: dict[str, deque] = {}
_failures_lock = threading.Lock()


def _login_blocked(ip: str) -> bool:
    now = time.monotonic()
    with _failures_lock:
        window = _failures.get(ip)
        if not window:
            return False
        while window and now - window[0] > config.LOGIN_FAILURE_WINDOW_S:
            window.popleft()
        return len(window) >= config.LOGIN_MAX_FAILURES


def _note_failure(ip: str) -> None:
    with _failures_lock:
        _failures.setdefault(ip, deque()).append(time.monotonic())


def _clear_failures(ip: str) -> None:
    with _failures_lock:
        _failures.pop(ip, None)


def reset_login_limiter() -> None:
    """Tests only: start each test from a clean throttle state."""
    with _failures_lock:
        _failures.clear()


# --- CSRF ---------------------------------------------------------------------

def csrf_token() -> str:
    """The session's CSRF token, minting one on first use. Exposed to templates
    as `csrf_token()` via the context processor registered in init_app."""
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_hex(32)
        session["_csrf_token"] = token
    return token


def _csrf_ok() -> bool:
    sent = request.form.get("csrf_token", "")
    stored = session.get("_csrf_token", "")
    return bool(stored) and secrets.compare_digest(sent, stored)


# --- the gate -------------------------------------------------------------------

def _require_login():
    endpoint = request.endpoint
    if endpoint is None or endpoint in PUBLIC_ENDPOINTS:
        return None
    if session.get("user_id"):
        return None
    if endpoint in PAGE_ENDPOINTS:
        return redirect(url_for("auth.login"))
    return jsonify({"error": "authentication required"}), 401


def init_app(app, get_db) -> None:
    """Wire the blueprint, the default-deny gate, and the template helpers.

    `get_db` is a zero-arg callable returning a row-factory sqlite3 connection
    (app_groq passes `lambda: get_db_connection()`).
    """
    global _get_db
    _get_db = get_db
    app.register_blueprint(bp)
    app.before_request(_require_login)
    app.context_processor(lambda: {"csrf_token": csrf_token})


# --- routes ---------------------------------------------------------------------

@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    if not _csrf_ok():
        return "CSRF validation failed", 400

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    if not USERNAME_RE.match(username):
        flash("Username must be 3-32 characters: letters, digits, . _ -", "error")
        return render_template("register.html"), 400
    if len(password) < PASSWORD_MIN_LEN:
        flash(f"Password must be at least {PASSWORD_MIN_LEN} characters.", "error")
        return render_template("register.html"), 400

    try:
        with _get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password)))
            conn.commit()
    except sqlite3.IntegrityError:
        flash("That username is already taken.", "error")
        return render_template("register.html"), 409

    flash("Account created. Sign in to continue.", "success")
    return redirect(url_for("auth.login"))


@bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("home"))
    if request.method == "GET":
        return render_template("login.html")
    if not _csrf_ok():
        return "CSRF validation failed", 400

    ip = request.remote_addr or "unknown"
    if _login_blocked(ip):
        flash("Too many failed attempts. Try again in a few minutes.", "error")
        return render_template("login.html"), 429

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    with _get_db() as conn:
        row = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,)).fetchone()

    if row is None or not check_password_hash(row["password_hash"], password):
        _note_failure(ip)
        flash("Invalid username or password.", "error")
        return render_template("login.html"), 401

    _clear_failures(ip)
    # Fresh session on privilege change (session-fixation hygiene). Clearing
    # also drops the pre-login CSRF token; a new one is minted on next use.
    session.clear()
    session["user_id"] = row["id"]
    session["username"] = row["username"]
    return redirect(url_for("home"))


@bp.route("/logout", methods=["POST"])
def logout():
    # Behind the gate (an anonymous POST gets 401 before reaching here) and
    # CSRF-checked, so a cross-site request cannot forcibly log the user out.
    if not _csrf_ok():
        return "CSRF validation failed", 400
    session.clear()
    flash("Signed out.", "success")
    return redirect(url_for("auth.login"))
