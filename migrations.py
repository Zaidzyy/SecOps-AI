"""Schema creation + versioned migrations.

Why this module exists: `network_requests` mixed two unrelated things in one
table, separated only by a `type` string -- per-packet telemetry (type='IPv4',
tens of thousands of rows) and flow verdicts (type='FLOW', a few thousand). The
detections an operator actually needs to see were buried under ~15x their volume
in routine packet noise, and every query for one had to filter out the other.

They are split into two tables that answer two different questions:

  telemetry  -- "what did we see?"  one row per enriched packet
  detections -- "what is bad?"      one row per classified flow, with the 5-tuple,
                                    the verdict, and the coordinates the map needs

Migration 0001 preserves every existing row: type='FLOW' rows become detections,
everything else (including the ~140 legacy rows with a NULL type, written by the
old blacklist "cache") becomes telemetry. The source table is then renamed to
network_requests_legacy rather than dropped -- nothing here destroys data, and
the rename is also what makes re-running a no-op.

Idempotency is enforced two ways: a `schema_migrations` ledger records what has
been applied, and every statement is CREATE/INSERT-guarded. migrate() is safe to
call on every process start, which is exactly how app_groq uses it.
"""
from __future__ import annotations

import sqlite3

# --- current schema ---------------------------------------------------------

CREATE_TELEMETRY = """
    CREATE TABLE IF NOT EXISTS telemetry (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        country TEXT,
        lat REAL,
        lon REAL,
        summary TEXT,
        blacklisted TEXT,
        attacks INTEGER,
        reports INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
"""

# The 5-tuple is stored as columns rather than parsed back out of `summary`
# whenever someone needs it: this is the table the detection feed, the map, and
# any future correlation query all read from.
CREATE_DETECTIONS = """
    CREATE TABLE IF NOT EXISTS detections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        src_ip TEXT,
        dst_ip TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        proto INTEGER,
        cnn_verdict TEXT,
        cnn_confidence REAL,
        country TEXT,
        lat REAL,
        lon REAL,
        duration_s REAL,
        fwd_packets INTEGER,
        bwd_packets INTEGER,
        fwd_bytes INTEGER,
        bwd_bytes INTEGER,
        summary TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
"""

CREATE_LOGS = """
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        log TEXT
    );
"""

CREATE_METRICS = """
    CREATE TABLE IF NOT EXISTS metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        cpu REAL,
        memory REAL,
        disk REAL,
        network INTEGER
    );
"""

INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_telemetry_timestamp ON telemetry (timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_telemetry_ip ON telemetry (ip)",
    # The feed orders by timestamp DESC and the map filters on verdict; both are
    # the hot read paths, so both get an index.
    "CREATE INDEX IF NOT EXISTS idx_detections_timestamp ON detections (timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_detections_verdict ON detections (cnn_verdict)",
    "CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs (timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics (timestamp)",
]

LEGACY_TABLE = "network_requests"
LEGACY_ARCHIVE = "network_requests_legacy"
SPLIT_MIGRATION = "0001_split_network_requests"


# --- helpers ----------------------------------------------------------------

def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row is not None


def _columns(conn: sqlite3.Connection, table: str) -> set:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def applied(conn: sqlite3.Connection, name: str) -> bool:
    if not _table_exists(conn, "schema_migrations"):
        return False
    return conn.execute("SELECT 1 FROM schema_migrations WHERE name=?",
                        (name,)).fetchone() is not None


def _mark_applied(conn: sqlite3.Connection, name: str) -> None:
    conn.execute("INSERT OR IGNORE INTO schema_migrations (name) VALUES (?)", (name,))


# --- migration 0001 ---------------------------------------------------------

def _split_network_requests(conn: sqlite3.Connection) -> dict:
    """Copy legacy rows into their correct table, then archive the source.

    Returns {"detections": n, "telemetry": n} for logging. Rows keep their
    original `timestamp` -- a migration that silently restamped history as "now"
    would destroy the ordering the feed depends on.

    Legacy detections get NULL for the 5-tuple and NULL coordinates: the old
    schema never stored either (only a human-readable `summary`), and inventing
    values we never captured would be worse than admitting the gap. Their
    `summary` is preserved verbatim, and they simply do not appear as map points.
    """
    counts = {"detections": 0, "telemetry": 0}
    if not _table_exists(conn, LEGACY_TABLE):
        return counts

    cols = _columns(conn, LEGACY_TABLE)
    # Old DBs predate the verdict columns; select a literal NULL where a column
    # does not exist rather than failing on a legitimate older database.
    verdict = "cnn_verdict" if "cnn_verdict" in cols else "NULL"
    confidence = "cnn_confidence" if "cnn_confidence" in cols else "NULL"
    has_type = "type" in cols

    if has_type:
        cur = conn.execute(f"""
            INSERT INTO detections (src_ip, cnn_verdict, cnn_confidence, country,
                                    summary, timestamp)
            SELECT ip, {verdict}, {confidence}, country, summary, timestamp
            FROM {LEGACY_TABLE} WHERE type = 'FLOW'
        """)
        counts["detections"] = cur.rowcount

    # "Everything that is not a flow verdict is telemetry" -- including rows whose
    # type is NULL, which is why this is an inequality rather than type='IPv4'.
    where = "WHERE type IS NULL OR type <> 'FLOW'" if has_type else ""
    cur = conn.execute(f"""
        INSERT INTO telemetry (ip, country, summary, blacklisted, attacks, reports,
                               timestamp)
        SELECT ip, country, summary, blacklisted, attacks, reports, timestamp
        FROM {LEGACY_TABLE} {where}
    """)
    counts["telemetry"] = cur.rowcount

    # Archive rather than drop. If the archive name is somehow taken, the old
    # table stays put: the ledger still records the split, so we never re-copy.
    if not _table_exists(conn, LEGACY_ARCHIVE):
        conn.execute(f"ALTER TABLE {LEGACY_TABLE} RENAME TO {LEGACY_ARCHIVE}")
    return counts


# --- entry point ------------------------------------------------------------

def migrate(conn: sqlite3.Connection, verbose: bool = False) -> dict:
    """Bring `conn`'s database to the current schema. Safe to call repeatedly.

    Returns the row counts moved by any migration that ran this call (all zeros
    when everything was already up to date).
    """
    # WAL is a persistent DB-level setting, but re-asserting it here means a fresh
    # database is in WAL from its first write: dashboard readers never block
    # behind the DB writer.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            name TEXT PRIMARY KEY,
            applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.execute(CREATE_TELEMETRY)
    conn.execute(CREATE_DETECTIONS)
    conn.execute(CREATE_LOGS)
    conn.execute(CREATE_METRICS)
    for stmt in INDEXES:
        conn.execute(stmt)

    counts = {"detections": 0, "telemetry": 0}
    if not applied(conn, SPLIT_MIGRATION):
        counts = _split_network_requests(conn)
        _mark_applied(conn, SPLIT_MIGRATION)
        if verbose and (counts["detections"] or counts["telemetry"]):
            print(f"[OK] Migration {SPLIT_MIGRATION}: moved {counts['detections']} "
                  f"flow verdicts -> detections, {counts['telemetry']} packet rows "
                  f"-> telemetry ({LEGACY_TABLE} archived as {LEGACY_ARCHIVE}).")
    conn.commit()
    return counts
