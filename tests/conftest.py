"""Shared test setup.

The SECOPS_DB assignment MUST happen at import time, before any test module
imports config or app_groq: config.DB_PATH is read once at import, and app_groq
runs initialize_database() as an import side effect. Without this, importing
app_groq in a test would migrate the developer's real system_metrics.db.
pytest imports conftest before collecting test modules, which is what makes this
early enough.
"""
import os
import sqlite3
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault(
    "SECOPS_DB", os.path.join(tempfile.mkdtemp(prefix="secops-tests-"), "test.db"))

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
