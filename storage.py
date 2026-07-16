"""The only place that knows which table a row belongs in, and the queries the
read API is built from.

Write side: `write_telemetry()` and `write_detection()` are the routing layer.
Both hand (sql, params) to the ONE BatchedDBWriter, which stays deliberately
generic -- it groups by SQL statement and executemany's each group, so routing by
statement is what lets telemetry and detection rows share a batch without the
writer needing to understand either. Nothing else in the app writes SQLite.

Read side: every query is bounded (paged, or LIMITed), takes a plain
sqlite3.Connection, and returns plain dicts. Keeping them here rather than inline
in Flask routes means they can be tested against a temp DB without a web server,
and the routes stay thin enough to be obviously correct.
"""
from __future__ import annotations

import sqlite3

import config

# --- write side -------------------------------------------------------------

SQL_INSERT_TELEMETRY = """
    INSERT INTO telemetry (ip, country, lat, lon, summary, blacklisted, attacks, reports)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
"""

SQL_INSERT_DETECTION = """
    INSERT INTO detections
        (src_ip, dst_ip, src_port, dst_port, proto, cnn_verdict, cnn_confidence,
         country, lat, lon, duration_s, fwd_packets, bwd_packets, fwd_bytes,
         bwd_bytes, summary)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

# Verdict severity, worst last. The threat map colours a point by the worst
# verdict seen at that location, so "worst" needs a definition in exactly one
# place; adding a verdict means adding it here and nowhere else.
VERDICT_SEVERITY = {"normal": 0, "suspicious": 1}
WORST_VERDICT = "suspicious"
BASE_VERDICT = "normal"


def write_telemetry(writer, *, ip, country, lat, lon, summary, blacklisted,
                    attacks, reports) -> bool:
    """Route one enriched packet to the telemetry table."""
    return writer.submit(SQL_INSERT_TELEMETRY,
                         (ip, country, lat, lon, summary, blacklisted,
                          attacks, reports))


def write_detection(writer, *, src_ip, dst_ip, src_port, dst_port, proto,
                    verdict, confidence, country, lat, lon, duration_s,
                    fwd_packets, bwd_packets, fwd_bytes, bwd_bytes,
                    summary) -> bool:
    """Route one classified flow verdict to the detections table."""
    return writer.submit(SQL_INSERT_DETECTION,
                         (src_ip, dst_ip, src_port, dst_port, proto, verdict,
                          confidence, country, lat, lon, duration_s, fwd_packets,
                          bwd_packets, fwd_bytes, bwd_bytes, summary))


# --- read side --------------------------------------------------------------

def clamp_page_size(value) -> int:
    """Never let a client ask for an unbounded page."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return config.API_PAGE_SIZE_DEFAULT
    return max(1, min(n, config.API_PAGE_SIZE_MAX))


def clamp_page(value) -> int:
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return 1


DETECTION_COLUMNS = """
    id, src_ip, dst_ip, src_port, dst_port, proto, cnn_verdict, cnn_confidence,
    country, lat, lon, duration_s, fwd_packets, bwd_packets, fwd_bytes, bwd_bytes,
    summary, timestamp
"""


def fetch_detections(conn: sqlite3.Connection, page: int = 1,
                     page_size: int = config.API_PAGE_SIZE_DEFAULT,
                     verdict: str | None = None) -> dict:
    """One page of the detection feed, newest first.

    Ties on `timestamp` are broken by id DESC: SQLite's CURRENT_TIMESTAMP has
    one-second resolution, and a replay writes thousands of rows inside one
    second, so ordering on timestamp alone would shuffle rows between pages and
    let the same detection appear twice.
    """
    page = clamp_page(page)
    page_size = clamp_page_size(page_size)
    where, params = "", []
    if verdict:
        where = "WHERE cnn_verdict = ?"
        params.append(verdict)

    total = conn.execute(f"SELECT COUNT(*) FROM detections {where}",
                         params).fetchone()[0]
    rows = conn.execute(f"""
        SELECT {DETECTION_COLUMNS}
        FROM detections {where}
        ORDER BY timestamp DESC, id DESC
        LIMIT ? OFFSET ?
    """, (*params, page_size, (page - 1) * page_size)).fetchall()
    return {
        "page": page,
        "page_size": page_size,
        "total": total,
        "items": [dict(r) for r in rows],
    }


def fetch_telemetry(conn: sqlite3.Connection, page: int = 1,
                    page_size: int = config.API_PAGE_SIZE_DEFAULT) -> dict:
    """One page of raw per-packet telemetry -- queryable, but never mixed into
    the detection feed."""
    page = clamp_page(page)
    page_size = clamp_page_size(page_size)
    total = conn.execute("SELECT COUNT(*) FROM telemetry").fetchone()[0]
    rows = conn.execute("""
        SELECT id, ip, country, lat, lon, summary, blacklisted, attacks, reports,
               timestamp
        FROM telemetry
        ORDER BY timestamp DESC, id DESC
        LIMIT ? OFFSET ?
    """, (page_size, (page - 1) * page_size)).fetchall()
    return {
        "page": page,
        "page_size": page_size,
        "total": total,
        "items": [dict(r) for r in rows],
    }


def fetch_threat_map(conn: sqlite3.Connection,
                     precision: int = config.THREAT_MAP_PRECISION,
                     limit: int = config.THREAT_MAP_MAX_POINTS) -> dict:
    """Detections aggregated into map points.

    Detections with no coordinates are excluded rather than dropped at 0,0: a
    private-range or failed-lookup IP has no location, and plotting it in the
    Gulf of Guinea would be a fabricated point. They stay visible in /detections.

    Grouping is by rounded coordinate, so one busy city is one point instead of
    hundreds of markers stacked on the same pixel.
    """
    rows = conn.execute("""
        SELECT ROUND(lat, ?) AS lat,
               ROUND(lon, ?) AS lon,
               country,
               COUNT(*) AS count,
               SUM(CASE WHEN cnn_verdict = ? THEN 1 ELSE 0 END) AS suspicious_count,
               MAX(timestamp) AS last_seen
        FROM detections
        WHERE lat IS NOT NULL AND lon IS NOT NULL
        GROUP BY ROUND(lat, ?), ROUND(lon, ?), country
        ORDER BY suspicious_count DESC, count DESC
        LIMIT ?
    """, (precision, precision, WORST_VERDICT, precision, precision, limit)).fetchall()

    points = []
    for r in rows:
        suspicious = r["suspicious_count"] or 0
        points.append({
            "lat": r["lat"],
            "lon": r["lon"],
            "country": r["country"],
            "count": r["count"],
            "suspicious_count": suspicious,
            "worst_verdict": WORST_VERDICT if suspicious else BASE_VERDICT,
            "last_seen": r["last_seen"],
        })
    return {"points": points, "total_points": len(points)}


def fetch_counters(conn: sqlite3.Connection) -> dict:
    """Live DB-backed counters for the stat header."""
    def one(sql, params=()):
        return conn.execute(sql, params).fetchone()[0]

    return {
        "telemetry_rows": one("SELECT COUNT(*) FROM telemetry"),
        "unique_ips": one("SELECT COUNT(DISTINCT ip) FROM telemetry"),
        "detections": one("SELECT COUNT(*) FROM detections"),
        "suspicious": one("SELECT COUNT(*) FROM detections WHERE cnn_verdict = ?",
                          (WORST_VERDICT,)),
        "located_detections": one(
            "SELECT COUNT(*) FROM detections WHERE lat IS NOT NULL AND lon IS NOT NULL"),
    }
