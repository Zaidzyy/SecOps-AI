"""Phase 4a auth tests: the login gate over HTTP and the WebSocket.

What is pinned here:
  - /register stores a salted hash, never the plaintext password
  - /login sets the session; /logout clears it
  - every data endpoint answers 401 anonymous / 200 authenticated, and the
    dashboard redirects an anonymous browser to /login
  - the auth forms reject a missing/wrong CSRF token
  - repeated login failures trip the brute-force throttle (429)
  - an anonymous WebSocket connect is REJECTED -- the live stream must not
    leak what the HTTP guard protects
"""
import os
import sys

import pytest
from werkzeug.security import check_password_hash

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import (TEST_USER, connect, csrf_token_from, login,  # noqa: E402
                      register, register_and_login)

import app_groq  # noqa: E402  -- conftest points SECOPS_DB at a temp file first
import auth  # noqa: E402
import config  # noqa: E402

# Every JSON/API surface the console reads. All must be closed to anonymous
# clients; /search-logs and /chat are POST-shaped and covered separately.
PROTECTED_GETS = ["/detections", "/threat-map", "/stats", "/telemetry",
                  "/logs", "/network-requests", "/pipeline-stats",
                  "/system-info", "/server-status"]


@pytest.fixture
def client(migrated_db, monkeypatch):
    """Anonymous test client on a temp DB (has the users table via migrate)."""
    monkeypatch.setattr(app_groq, "get_db_connection", lambda: connect(migrated_db))
    app_groq.app.config.update(TESTING=True)
    auth.reset_login_limiter()
    return app_groq.app.test_client()


@pytest.fixture
def logged_in(client):
    return register_and_login(client)


# --- register -----------------------------------------------------------------

def test_register_stores_hash_not_plaintext(client, migrated_db):
    resp = register(client, "alice", "a-long-password-1")
    assert resp.status_code == 302  # -> /login

    row = connect(migrated_db).execute(
        "SELECT password_hash FROM users WHERE username='alice'").fetchone()
    assert row is not None
    assert row["password_hash"] != "a-long-password-1"
    # werkzeug format: "method:params$salt$hash" -- salted, never bare
    assert "$" in row["password_hash"]
    assert check_password_hash(row["password_hash"], "a-long-password-1")


def test_register_rejects_duplicate_username(client):
    register(client, "bob", "a-long-password-1")
    resp = register(client, "bob", "another-password-2")
    assert resp.status_code == 409


def test_register_rejects_weak_or_malformed_input(client):
    assert register(client, "x", "a-long-password-1").status_code == 400
    assert register(client, "carol", "short").status_code == 400


# --- login / logout -----------------------------------------------------------

def test_login_sets_session(client):
    register(client, **TEST_USER)
    resp = login(client, **TEST_USER)
    assert resp.status_code == 302 and resp.headers["Location"] in ("/", "http://localhost/")

    with client.session_transaction() as sess:
        assert sess.get("user_id") is not None
        assert sess.get("username") == TEST_USER["username"]


def test_login_rejects_wrong_password(client):
    register(client, **TEST_USER)
    resp = login(client, TEST_USER["username"], "not-the-password")
    assert resp.status_code == 401
    with client.session_transaction() as sess:
        assert sess.get("user_id") is None


def test_login_requires_csrf_token(client):
    register(client, **TEST_USER)
    resp = client.post("/login", data={**TEST_USER, "csrf_token": "forged"})
    assert resp.status_code == 400


def test_logout_clears_session_and_recloses_the_api(logged_in):
    token = csrf_token_from(logged_in, "/")  # the console's sign-out form
    resp = logged_in.post("/logout", data={"csrf_token": token})
    assert resp.status_code == 302

    with logged_in.session_transaction() as sess:
        assert sess.get("user_id") is None
    assert logged_in.get("/detections").status_code == 401


def test_login_failures_trip_the_throttle(client):
    register(client, **TEST_USER)
    for _ in range(config.LOGIN_MAX_FAILURES):
        assert login(client, TEST_USER["username"], "wrong-guess").status_code == 401
    # Even the CORRECT password is refused while the window is tripped.
    assert login(client, **TEST_USER).status_code == 429


# --- the gate ------------------------------------------------------------------

def test_dashboard_redirects_anonymous_browser_to_login(client):
    resp = client.get("/")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


@pytest.mark.parametrize("path", PROTECTED_GETS)
def test_data_endpoint_is_closed_when_logged_out(client, path):
    resp = client.get(path)
    assert resp.status_code == 401
    assert resp.get_json() == {"error": "authentication required"}


def test_post_endpoints_are_closed_when_logged_out(client):
    assert client.post("/chat", json={"message": "hi"}).status_code == 401
    assert client.post("/search-logs", json={"query": "x"}).status_code == 401


def test_data_endpoints_open_after_login(logged_in):
    # Fast DB-backed reads: these must serve normally once authenticated.
    for path in ["/detections", "/threat-map", "/stats", "/telemetry",
                 "/logs", "/network-requests", "/pipeline-stats"]:
        assert logged_in.get(path).status_code == 200, path
    assert logged_in.get("/").status_code == 200


def test_live_system_endpoints_open_after_login(logged_in):
    # psutil-backed routes; slower (cpu_percent samples for 1s) but real.
    assert logged_in.get("/system-info").status_code == 200
    assert logged_in.get("/server-status").status_code == 200


def test_auth_pages_are_self_contained(client):
    """Same offline rule as the console: no CDN scripts or styles."""
    import re
    for path in ("/login", "/register"):
        html = client.get(path).get_data(as_text=True)
        refs = re.findall(r'(?:src|href)="([^"]+)"', html)
        external = [r for r in refs if r.startswith(("http://", "https://", "//"))]
        assert external == [], f"{path} references external hosts: {external}"


# --- the WebSocket gate ---------------------------------------------------------

def test_anonymous_websocket_is_rejected(client):
    """The critical leak check: without this gate the socket streams every
    metric and verdict to anyone who connects, guard or no guard."""
    sock = app_groq.socketio.test_client(app_groq.app, flask_test_client=client)
    assert not sock.is_connected()


def test_authenticated_websocket_connects(logged_in, monkeypatch):
    # Stop the connect handler from launching the real infinite metrics loop.
    monkeypatch.setattr(app_groq, "send_system_metrics", lambda: None)
    sock = app_groq.socketio.test_client(app_groq.app, flask_test_client=logged_in)
    assert sock.is_connected()
    sock.disconnect()
