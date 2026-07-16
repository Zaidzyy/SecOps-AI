"""Shared test setup.

The SECOPS_DB assignment MUST happen at import time, before any test module
imports config or app_groq: config.DB_PATH is read once at import, and app_groq
runs initialize_database() as an import side effect. Without this, importing
app_groq in a test would migrate the developer's real system_metrics.db.
pytest imports conftest before collecting test modules, which is what makes this
early enough.
"""
import os
import re
import sqlite3
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault(
    "SECOPS_DB", os.path.join(tempfile.mkdtemp(prefix="secops-tests-"), "test.db"))
# Same import-time reasoning as SECOPS_DB: config.SECRET_KEY is read once, and
# sessions/CSRF need a stable signing key for the test client's cookie jar.
os.environ.setdefault("SECOPS_SECRET_KEY", "test-secret-key-not-for-production")

import migrations  # noqa: E402


@pytest.fixture
def migrated_db(tmp_path):
    """Path to an empty database at the current schema."""
    path = str(tmp_path / "secops.db")
    conn = sqlite3.connect(path)
    migrations.migrate(conn)
    conn.close()
    return path


def connect(path) -> sqlite3.Connection:
    """Row-factory connection, matching what the app's routes use."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


# --- auth helpers (Phase 4a) -------------------------------------------------
# The API routes sit behind the login gate, so any test client that wants data
# must authenticate the way a real operator does: register, then log in, with
# the CSRF token each form carries.

TEST_USER = {"username": "operator", "password": "correct-horse-battery"}


def csrf_token_from(client, path):
    """Fetch `path` and pull the CSRF token out of its form."""
    html = client.get(path).get_data(as_text=True)
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, f"no CSRF token found in {path}"
    return m.group(1)


def register(client, username, password):
    token = csrf_token_from(client, "/register")
    return client.post("/register", data={
        "username": username, "password": password, "csrf_token": token})


def login(client, username, password):
    token = csrf_token_from(client, "/login")
    return client.post("/login", data={
        "username": username, "password": password, "csrf_token": token})


def register_and_login(client, username=TEST_USER["username"],
                       password=TEST_USER["password"]):
    register(client, username, password)
    resp = login(client, username, password)
    assert resp.status_code == 302, "test login failed -- fixtures depend on it"
    return client
