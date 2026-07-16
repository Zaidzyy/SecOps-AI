"""Migration tests.

The 0001 split runs exactly once, against a real database that already holds
~50k rows of someone's captured history. It gets one chance to be right, so the
contract is pinned hard here: every legacy row lands in exactly one table, in the
RIGHT table, with its original timestamp, and re-running changes nothing.
"""
import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import migrations  # noqa: E402

LEGACY_SCHEMA = """
    CREATE TABLE network_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        type TEXT,
        country TEXT,
        summary TEXT,
        blacklisted TEXT,
        attacks INTEGER,
        reports INTEGER,
        cnn_verdict TEXT,
        cnn_confidence REAL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
"""

LEGACY_SCHEMA_NO_VERDICT = """
    CREATE TABLE network_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        type TEXT,
        country TEXT,
        summary TEXT,
        blacklisted TEXT,
        attacks INTEGER,
        reports INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
"""


def _legacy_db(path, schema=LEGACY_SCHEMA):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(schema)
    return conn


@pytest.fixture
def legacy(tmp_path):
    """A pre-split database shaped like the real one: mostly packet telemetry, a
    few flow verdicts, and some type=NULL rows left by the old blacklist 'cache'."""
    conn = _legacy_db(str(tmp_path / "legacy.db"))
    conn.executemany("""
        INSERT INTO network_requests
            (ip, type, country, summary, blacklisted, attacks, reports,
             cnn_verdict, cnn_confidence, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, [
        ("1.1.1.1", "IPv4", "AU, Sydney, NSW", "IP / TCP", "No", 0, 0,
         None, None, "2026-07-01 10:00:00"),
        ("2.2.2.2", "IPv4", "FR, Paris, IDF", "IP / TCP", "Yes", 5, 9,
         None, None, "2026-07-01 10:00:01"),
        ("3.3.3.3", "FLOW", "US, Ashburn, VA", "Flow 3.3.3.3:1 -> 4.4.4.4:80",
         "No", 0, 0, "suspicious", 0.91, "2026-07-01 10:00:02"),
        ("5.5.5.5", "FLOW", "DE, Berlin, BE", "Flow 5.5.5.5:2 -> 4.4.4.4:443",
         "No", 0, 0, "normal", 0.77, "2026-07-01 10:00:03"),
        # The old check_ip_blacklist_cached wrote rows with no type at all.
        ("6.6.6.6", None, "NL, Amsterdam, NH", None, "No", 0, 0,
         None, None, "2026-07-01 10:00:04"),
    ])
    conn.commit()
    return conn


def _count(conn, table):
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_flow_rows_land_in_detections_and_the_rest_in_telemetry(legacy):
    migrations.migrate(legacy)

    assert _count(legacy, "detections") == 2, "type='FLOW' rows belong in detections"
    assert _count(legacy, "telemetry") == 3, \
        "IPv4 rows AND type=NULL rows are telemetry -- neither may be dropped"

    verdicts = {r["src_ip"]: r["cnn_verdict"]
                for r in legacy.execute("SELECT src_ip, cnn_verdict FROM detections")}
    assert verdicts == {"3.3.3.3": "suspicious", "5.5.5.5": "normal"}

    ips = {r["ip"] for r in legacy.execute("SELECT ip FROM telemetry")}
    assert ips == {"1.1.1.1", "2.2.2.2", "6.6.6.6"}


def test_no_row_is_lost_or_duplicated(legacy):
    before = _count(legacy, "network_requests")
    migrations.migrate(legacy)
    after = _count(legacy, "detections") + _count(legacy, "telemetry")
    assert after == before == 5, "every legacy row lands in exactly one table"


def test_migration_preserves_row_content_and_timestamps(legacy):
    migrations.migrate(legacy)

    d = legacy.execute(
        "SELECT * FROM detections WHERE src_ip = '3.3.3.3'").fetchone()
    assert d["cnn_confidence"] == 0.91
    assert d["country"] == "US, Ashburn, VA"
    assert d["summary"] == "Flow 3.3.3.3:1 -> 4.4.4.4:80"
    # History keeps its own timestamps; restamping as "now" would scramble the
    # ordering the feed depends on.
    assert d["timestamp"] == "2026-07-01 10:00:02"
    # The legacy schema never stored coordinates or the 5-tuple. We admit the gap
    # rather than invent values.
    assert d["lat"] is None and d["lon"] is None
    assert d["dst_ip"] is None and d["dst_port"] is None

    t = legacy.execute("SELECT * FROM telemetry WHERE ip = '2.2.2.2'").fetchone()
    assert (t["blacklisted"], t["attacks"], t["reports"]) == ("Yes", 5, 9)
    assert t["timestamp"] == "2026-07-01 10:00:01"


def test_migration_is_idempotent(legacy):
    migrations.migrate(legacy)
    first = (_count(legacy, "detections"), _count(legacy, "telemetry"))

    for _ in range(3):
        migrations.migrate(legacy)

    assert (_count(legacy, "detections"), _count(legacy, "telemetry")) == first, \
        "re-running the migration must not re-copy rows"
    assert migrations.applied(legacy, migrations.SPLIT_MIGRATION)


def test_legacy_table_is_archived_not_dropped(legacy):
    migrations.migrate(legacy)
    assert not migrations._table_exists(legacy, "network_requests")
    assert migrations._table_exists(legacy, "network_requests_legacy")
    assert _count(legacy, "network_requests_legacy") == 5, \
        "the original rows must survive the split untouched"


def test_migrates_older_db_without_verdict_columns(tmp_path):
    """Databases predating the cnn_verdict columns must migrate, not crash."""
    conn = _legacy_db(str(tmp_path / "old.db"), LEGACY_SCHEMA_NO_VERDICT)
    conn.execute("""INSERT INTO network_requests (ip, type, country, summary,
                    blacklisted, attacks, reports)
                    VALUES ('9.9.9.9', 'FLOW', 'CH, Zurich, ZH', 'Flow', 'No', 0, 0)""")
    conn.commit()

    migrations.migrate(conn)

    row = conn.execute("SELECT * FROM detections").fetchone()
    assert row["src_ip"] == "9.9.9.9"
    assert row["cnn_verdict"] is None


def test_fresh_database_gets_full_schema_and_wal(tmp_path):
    path = str(tmp_path / "fresh.db")
    conn = sqlite3.connect(path)
    counts = migrations.migrate(conn)

    for table in ("telemetry", "detections", "logs", "metrics",
                  "schema_migrations"):
        assert migrations._table_exists(conn, table)
    assert counts == {"detections": 0, "telemetry": 0}
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal", \
        "WAL must survive the migration: readers must not block behind the writer"


def test_telemetry_and_detections_have_geo_columns(tmp_path):
    """The map needs coordinates; the split is pointless without them."""
    conn = sqlite3.connect(str(tmp_path / "cols.db"))
    migrations.migrate(conn)
    assert {"lat", "lon"} <= migrations._columns(conn, "telemetry")
    assert {"lat", "lon"} <= migrations._columns(conn, "detections")
    # Flow identity is stored as columns, not buried in a summary string.
    assert {"src_ip", "dst_ip", "src_port", "dst_port", "proto"} <= \
        migrations._columns(conn, "detections")
    assert "type" not in migrations._columns(conn, "telemetry"), \
        "the type discriminator is what the split removes"
