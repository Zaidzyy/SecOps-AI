"""Read-API tests: the JSON shapes the Phase 3b UI will be built against.

These drive the real Flask routes through the test client rather than calling
storage directly, so they cover the wiring too: route -> query -> jsonify. Every
assertion here is a promise to the frontend, so the shapes are pinned explicitly.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import connect  # noqa: E402

import app_groq  # noqa: E402  -- conftest points SECOPS_DB at a temp file first


@pytest.fixture
def client(migrated_db, monkeypatch):
    """Flask test client wired to a temp DB seeded with a realistic mix."""
    conn = connect(migrated_db)
    conn.executemany("""
        INSERT INTO detections (src_ip, dst_ip, src_port, dst_port, proto,
                                cnn_verdict, cnn_confidence, country, lat, lon,
                                duration_s, fwd_packets, bwd_packets, fwd_bytes,
                                bwd_bytes, summary, timestamp)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, [
        ("77.88.8.8", "93.184.216.34", 51000, 22, 6, "suspicious", 0.93,
         "RU, Moscow, MOW", 55.75, 37.62, 0.004, 1, 1, 0, 0, "Flow scan",
         "2026-07-01 10:00:00"),
        ("8.8.8.8", "93.184.216.34", 40001, 80, 6, "normal", 0.88,
         "US, Mountain View, CA", 37.4, -122.07, 0.007, 5, 3, 46, 220, "Flow http",
         "2026-07-01 10:00:01"),
        ("1.1.1.1", "93.184.216.34", 40002, 80, 6, "normal", 0.81,
         "AU, Sydney, NSW", -33.86, 151.2, 0.007, 5, 3, 46, 220, "Flow http",
         "2026-07-01 10:00:02"),
        # No coordinates: belongs in the feed, must not become a map point.
        ("10.0.0.9", "93.184.216.34", 40003, 80, 6, "suspicious", 0.7,
         "Internal/Private Range (Non-Routable)", None, None, 0.1, 2, 0, 0, 0,
         "Flow internal", "2026-07-01 10:00:03"),
    ])
    conn.executemany(
        "INSERT INTO telemetry (ip, country, lat, lon, summary, blacklisted,"
        " attacks, reports) VALUES (?,?,?,?,?,?,?,?)",
        [("77.88.8.8", "RU, Moscow, MOW", 55.75, 37.62, "IP / TCP", "Yes", 4, 8),
         ("8.8.8.8", "US, Mountain View, CA", 37.4, -122.07, "IP / TCP", "No", 0, 0),
         ("8.8.8.8", "US, Mountain View, CA", 37.4, -122.07, "IP / TCP", "No", 0, 0)])
    conn.commit()
    conn.close()

    monkeypatch.setattr(app_groq, "get_db_connection", lambda: connect(migrated_db))
    app_groq.app.config.update(TESTING=True)
    return app_groq.app.test_client()


# --- /detections ------------------------------------------------------------

def test_detections_returns_paged_envelope_newest_first(client):
    body = client.get("/detections").get_json()

    assert set(body) == {"page", "page_size", "total", "items"}
    assert body["total"] == 4
    assert [i["src_ip"] for i in body["items"]] == \
        ["10.0.0.9", "1.1.1.1", "8.8.8.8", "77.88.8.8"]


def test_detection_item_carries_verdict_confidence_and_geo(client):
    item = client.get("/detections").get_json()["items"][-1]

    assert item["src_ip"] == "77.88.8.8"
    assert item["cnn_verdict"] == "suspicious"
    assert item["cnn_confidence"] == 0.93
    assert (item["lat"], item["lon"]) == (55.75, 37.62)
    assert item["country"] == "RU, Moscow, MOW"
    # The 5-tuple is present as fields, not only inside a summary string.
    assert (item["dst_ip"], item["src_port"], item["dst_port"], item["proto"]) == \
        ("93.184.216.34", 51000, 22, 6)
    assert {"duration_s", "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
            "timestamp", "id"} <= set(item)


def test_detections_respects_page_and_verdict_filter(client):
    page = client.get("/detections?page=2&page_size=2").get_json()
    assert page["page"] == 2 and len(page["items"]) == 2
    assert [i["src_ip"] for i in page["items"]] == ["8.8.8.8", "77.88.8.8"]

    only_bad = client.get("/detections?verdict=suspicious").get_json()
    assert only_bad["total"] == 2
    assert all(i["cnn_verdict"] == "suspicious" for i in only_bad["items"])


def test_detections_contains_no_packet_telemetry(client):
    """The point of the split: 46k packet rows must not surface in the feed."""
    body = client.get("/detections").get_json()
    assert all(i["cnn_verdict"] is not None for i in body["items"])
    assert body["total"] == 4, "feed size is detections, not detections + telemetry"


# --- /threat-map ------------------------------------------------------------

def test_threat_map_returns_map_ready_points(client):
    body = client.get("/threat-map").get_json()

    assert set(body) == {"points", "total_points"}
    assert body["total_points"] == 3, "the uncoordinated detection is not a point"
    for p in body["points"]:
        assert set(p) == {"lat", "lon", "country", "count", "suspicious_count",
                          "worst_verdict", "last_seen"}
        assert isinstance(p["lat"], float) and isinstance(p["lon"], float)
        assert p["worst_verdict"] in ("normal", "suspicious")

    moscow = next(p for p in body["points"] if p["country"].startswith("RU"))
    assert moscow["worst_verdict"] == "suspicious"
    assert moscow["count"] == 1


def test_threat_map_never_plots_a_missing_location(client):
    body = client.get("/threat-map").get_json()
    assert not any(p["country"].startswith("Internal") for p in body["points"])
    assert all(p["lat"] is not None and p["lon"] is not None for p in body["points"])


# --- /stats -----------------------------------------------------------------

def test_stats_returns_live_counters(client):
    body = client.get("/stats").get_json()

    assert {"packets_per_sec", "packets_captured", "packets_dropped",
            "unique_ips", "suspicious", "detections", "telemetry_rows",
            "located_detections", "pipeline"} <= set(body)
    assert body["detections"] == 4
    assert body["suspicious"] == 2
    assert body["telemetry_rows"] == 3
    assert body["unique_ips"] == 2, "8.8.8.8 twice is one unique IP"
    assert isinstance(body["packets_per_sec"], (int, float))
    assert isinstance(body["packets_dropped"], int)


def test_stats_embeds_pipeline_health(client):
    """Drops stay visible: a silent drop is indistinguishable from working."""
    pipe = client.get("/stats").get_json()["pipeline"]
    assert {"capture", "db_writer", "enrichment_cache", "open_flows",
            "packets_per_sec"} <= set(pipe)
    assert {"offered", "dropped", "queued"} <= set(pipe["capture"])


def test_pipeline_stats_alias_still_serves_the_existing_dashboard(client):
    body = client.get("/pipeline-stats").get_json()
    assert {"capture", "db_writer", "enrichment_cache", "open_flows"} <= set(body)


# --- telemetry stays queryable, and separate --------------------------------

def test_telemetry_endpoint_is_paged_and_separate(client):
    body = client.get("/telemetry").get_json()
    assert set(body) == {"page", "page_size", "total", "items"}
    assert body["total"] == 3
    assert all("cnn_verdict" not in i for i in body["items"]), \
        "telemetry has no verdicts -- that is what makes it telemetry"
    assert {"ip", "country", "lat", "lon", "blacklisted"} <= set(body["items"][0])


def test_network_requests_stays_backwards_compatible(client):
    """The current dashboard expects a bare list of telemetry rows."""
    body = client.get("/network-requests").get_json()
    assert isinstance(body, list)
    assert len(body) == 3
    assert {"ip", "country", "summary", "timestamp"} <= set(body[0])


def test_console_page_is_self_contained(client):
    """The console must render offline on a fresh clone: every script and
    stylesheet it references is served from /static, never a CDN. (The map's
    no-tile-server rule, applied to the whole page.)"""
    import re
    html = client.get("/").get_data(as_text=True)
    # Every fetched resource (src= / href=) must be local. Raw substring checks
    # would trip on the favicon's data: URI, whose SVG xmlns is an http:// URL
    # that never touches the network.
    refs = re.findall(r'(?:src|href)="([^"]+)"', html)
    external = [r for r in refs if r.startswith(("http://", "https://", "//"))]
    assert external == [], \
        f"console references external hosts -- must be self-contained: {external}"
    for asset in ("static/css/console.css", "static/js/console.js",
                  "static/vendor/chart.umd.min.js", "static/vendor/socket.io.min.js"):
        assert asset in html, f"console page no longer references {asset}"
        assert client.get("/" + asset).status_code == 200, f"{asset} not served"
    # the map's data file is fetched by console.js, not the page -- check it serves
    assert client.get("/static/data/world.geojson").status_code == 200
