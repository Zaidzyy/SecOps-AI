"""Storage tests: write routing and the read queries behind the API.

The split is only real if the writer actually routes: a telemetry row must never
appear in detections and vice versa. These go through the real BatchedDBWriter
against a real (temp) database, because routing-by-SQL-statement is exactly the
thing a mock would paper over.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import storage  # noqa: E402
from conftest import connect  # noqa: E402
from pipeline import BatchedDBWriter  # noqa: E402

TELEMETRY_ROW = dict(ip="8.8.8.8", country="US, Mountain View, CA",
                     lat=37.4, lon=-122.07, summary="IP / TCP 8.8.8.8:53",
                     blacklisted="No", attacks=0, reports=0)

DETECTION_ROW = dict(src_ip="77.88.8.8", dst_ip="93.184.216.34", src_port=44321,
                     dst_port=22, proto=6, verdict="suspicious", confidence=0.93,
                     country="RU, Moscow, MOW", lat=55.75, lon=37.62,
                     duration_s=0.004, fwd_packets=1, bwd_packets=1,
                     fwd_bytes=0, bwd_bytes=0, summary="Flow 77.88.8.8:44321 -> ...")


@pytest.fixture
def writer(migrated_db):
    w = BatchedDBWriter(migrated_db, batch_size=100, flush_interval=0.05)
    w.start()
    yield w
    w.stop()


# --- write routing ----------------------------------------------------------

def test_telemetry_rows_route_to_telemetry_only(writer, migrated_db):
    assert storage.write_telemetry(writer, **TELEMETRY_ROW) is True
    assert writer.drain(timeout=10) is True

    conn = connect(migrated_db)
    rows = conn.execute("SELECT * FROM telemetry").fetchall()
    assert len(rows) == 1
    assert rows[0]["ip"] == "8.8.8.8"
    assert (rows[0]["lat"], rows[0]["lon"]) == (37.4, -122.07)
    assert conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0] == 0, \
        "packet telemetry must never land in the detection feed"


def test_detection_rows_route_to_detections_only(writer, migrated_db):
    assert storage.write_detection(writer, **DETECTION_ROW) is True
    assert writer.drain(timeout=10) is True

    conn = connect(migrated_db)
    rows = conn.execute("SELECT * FROM detections").fetchall()
    assert len(rows) == 1
    r = rows[0]
    assert (r["src_ip"], r["dst_ip"], r["dst_port"], r["proto"]) == \
        ("77.88.8.8", "93.184.216.34", 22, 6)
    assert (r["cnn_verdict"], r["cnn_confidence"]) == ("suspicious", 0.93)
    assert (r["lat"], r["lon"]) == (55.75, 37.62)
    assert conn.execute("SELECT COUNT(*) FROM telemetry").fetchone()[0] == 0


def test_mixed_traffic_is_split_across_tables_in_one_batch(writer, migrated_db):
    """Both row kinds share the writer and the batch; they must not share a table.
    This is the regression the whole split exists to prevent."""
    for i in range(30):
        storage.write_telemetry(writer, **{**TELEMETRY_ROW, "ip": f"8.8.8.{i}"})
    for i in range(4):
        storage.write_detection(writer, **{**DETECTION_ROW, "src_port": 40000 + i})
    assert writer.drain(timeout=10) is True

    conn = connect(migrated_db)
    assert conn.execute("SELECT COUNT(*) FROM telemetry").fetchone()[0] == 30
    assert conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0] == 4
    # Batching is what makes this affordable; 34 rows must not be 34 commits.
    assert writer.stats()["batches"] <= 3
    assert writer.stats()["written"] == 34


def test_writer_keeps_wal_on(writer, migrated_db):
    storage.write_telemetry(writer, **TELEMETRY_ROW)
    writer.drain(timeout=10)
    conn = connect(migrated_db)
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"


# --- read side --------------------------------------------------------------

def _seed(conn, detections=(), telemetry=()):
    for d in detections:
        conn.execute("""
            INSERT INTO detections (src_ip, cnn_verdict, cnn_confidence, country,
                                    lat, lon, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, d)
    for t in telemetry:
        conn.execute("INSERT INTO telemetry (ip, country, lat, lon) VALUES (?,?,?,?)", t)
    conn.commit()


def test_fetch_detections_is_paged_newest_first(migrated_db):
    conn = connect(migrated_db)
    _seed(conn, detections=[
        (f"1.2.3.{i}", "normal", 0.6, "US, X, Y", 1.0, 2.0,
         f"2026-07-01 10:00:{i:02d}") for i in range(10)])

    page1 = storage.fetch_detections(conn, page=1, page_size=4)
    assert page1["total"] == 10
    assert page1["page"] == 1 and page1["page_size"] == 4
    assert len(page1["items"]) == 4
    assert page1["items"][0]["src_ip"] == "1.2.3.9", "newest first"

    page2 = storage.fetch_detections(conn, page=2, page_size=4)
    assert [i["src_ip"] for i in page2["items"]] == ["1.2.3.5", "1.2.3.4",
                                                     "1.2.3.3", "1.2.3.2"]
    assert not ({i["id"] for i in page1["items"]} &
                {i["id"] for i in page2["items"]}), "pages must not overlap"


def test_fetch_detections_orders_stably_within_one_timestamp(migrated_db):
    """SQLite timestamps have 1s resolution and a replay writes thousands of rows
    inside one second; ordering by timestamp alone would let rows swap pages."""
    conn = connect(migrated_db)
    _seed(conn, detections=[(f"9.9.9.{i}", "normal", 0.5, "X", 1.0, 2.0,
                             "2026-07-01 10:00:00") for i in range(20)])

    seen = []
    for page in (1, 2):
        seen += [i["id"] for i in
                 storage.fetch_detections(conn, page=page, page_size=10)["items"]]
    assert len(set(seen)) == 20, "a row appeared twice or vanished across pages"
    assert seen == sorted(seen, reverse=True)


def test_fetch_detections_filters_by_verdict(migrated_db):
    conn = connect(migrated_db)
    _seed(conn, detections=[
        ("1.1.1.1", "suspicious", 0.9, "AU", 1.0, 2.0, "2026-07-01 10:00:00"),
        ("2.2.2.2", "normal", 0.8, "FR", 3.0, 4.0, "2026-07-01 10:00:01"),
    ])
    out = storage.fetch_detections(conn, verdict="suspicious")
    assert out["total"] == 1 and out["items"][0]["src_ip"] == "1.1.1.1"


def test_page_size_is_clamped(migrated_db):
    conn = connect(migrated_db)
    assert storage.fetch_detections(conn, page_size=10_000)["page_size"] == \
        storage.config.API_PAGE_SIZE_MAX, "a client must not be able to ask for everything"
    assert storage.fetch_detections(conn, page_size="junk")["page_size"] == \
        storage.config.API_PAGE_SIZE_DEFAULT
    assert storage.fetch_detections(conn, page=-5)["page"] == 1


def test_threat_map_aggregates_nearby_points(migrated_db):
    conn = connect(migrated_db)
    _seed(conn, detections=[
        # Three detections in ~the same place: ONE point, count 3.
        ("1.1.1.1", "normal", 0.6, "FR, Paris, IDF", 48.85, 2.35, "2026-07-01 10:00:00"),
        ("1.1.1.2", "normal", 0.6, "FR, Paris, IDF", 48.86, 2.36, "2026-07-01 10:00:01"),
        ("1.1.1.3", "suspicious", 0.9, "FR, Paris, IDF", 48.85, 2.35, "2026-07-01 10:00:02"),
        ("2.2.2.1", "normal", 0.7, "JP, Tokyo, 13", 35.68, 139.69, "2026-07-01 10:00:03"),
    ])
    out = storage.fetch_threat_map(conn)
    points = {p["country"]: p for p in out["points"]}

    assert out["total_points"] == 2
    paris = points["FR, Paris, IDF"]
    assert paris["count"] == 3 and paris["suspicious_count"] == 1
    assert paris["worst_verdict"] == "suspicious", \
        "a point is as bad as the worst detection in it"
    assert (paris["lat"], paris["lon"]) == (48.9, 2.4)      # rounded for grouping
    assert points["JP, Tokyo, 13"]["worst_verdict"] == "normal"


def test_threat_map_omits_detections_without_coordinates(migrated_db):
    """No fix means no point. Plotting an unlocated IP at 0,0 would invent a
    threat in the Gulf of Guinea."""
    conn = connect(migrated_db)
    _seed(conn, detections=[
        ("10.0.0.1", "suspicious", 0.9, "Internal/Private Range (Non-Routable)",
         None, None, "2026-07-01 10:00:00"),
        ("1.1.1.1", "normal", 0.6, "AU, Sydney, NSW", -33.86, 151.2,
         "2026-07-01 10:00:01"),
    ])
    out = storage.fetch_threat_map(conn)
    assert out["total_points"] == 1
    assert out["points"][0]["country"] == "AU, Sydney, NSW"
    assert all(p["lat"] is not None and p["lon"] is not None for p in out["points"])
    # ...but it is still visible in the feed.
    assert storage.fetch_detections(conn)["total"] == 2


def test_counters_separate_telemetry_from_detections(migrated_db):
    conn = connect(migrated_db)
    _seed(conn,
          detections=[
              ("1.1.1.1", "suspicious", 0.9, "AU", 1.0, 2.0, "2026-07-01 10:00:00"),
              ("2.2.2.2", "normal", 0.8, "FR", 3.0, 4.0, "2026-07-01 10:00:01"),
              ("3.3.3.3", "suspicious", 0.7, "X", None, None, "2026-07-01 10:00:02"),
          ],
          telemetry=[("8.8.8.8", "US", 1.0, 2.0), ("8.8.8.8", "US", 1.0, 2.0),
                     ("1.1.1.1", "AU", 3.0, 4.0)])

    c = storage.fetch_counters(conn)
    assert c["telemetry_rows"] == 3
    assert c["unique_ips"] == 2, "8.8.8.8 appearing twice is one unique IP"
    assert c["detections"] == 3
    assert c["suspicious"] == 2
    assert c["located_detections"] == 2


def test_fetch_telemetry_is_paged_and_carries_geo(migrated_db):
    conn = connect(migrated_db)
    _seed(conn, telemetry=[(f"8.8.8.{i}", "US, X, Y", 37.4, -122.1)
                           for i in range(5)])
    out = storage.fetch_telemetry(conn, page=1, page_size=2)
    assert out["total"] == 5 and len(out["items"]) == 2
    assert {"ip", "country", "lat", "lon", "timestamp"} <= set(out["items"][0])
