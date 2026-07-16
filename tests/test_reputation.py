"""Feature 4: AbuseIPDB reputation.

All HTTP is mocked at enrichment.requests.get (the same seam the existing
enrichment tests use). Pinned here:

  * key present -> AbuseIPDB /check is the source (with the key header and
    the mapped record); key absent -> the blocklist.de path, unchanged;
  * the TTL cache prevents duplicate lookups -- the property that keeps the
    1000/day free tier unreachable by a packet flood;
  * 429 / network errors fall back to blocklist.de, and a total failure is
    marked "unknown" (and cached), never raised into the worker;
  * the score threshold that feeds the pipeline's blacklisted boolean;
  * the score persists through storage into detections/telemetry reads;
  * the triage agent's ip_reputation tool carries the richer record with the
    reputation-vs-verdict honesty note.
"""
import os
import sys

import pytest
from cachetools import TTLCache

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import connect  # noqa: E402

import config  # noqa: E402
import enrichment  # noqa: E402
import storage  # noqa: E402
import triage  # noqa: E402

IP = "93.184.216.34"
IP_2 = "8.8.8.8"


@pytest.fixture
def fresh_caches(monkeypatch):
    monkeypatch.setattr(enrichment, "_rep_cache",
                        TTLCache(maxsize=100, ttl=config.REP_CACHE_TTL_S))
    monkeypatch.setattr(enrichment, "_geo_cache",
                        TTLCache(maxsize=100, ttl=config.GEO_CACHE_TTL_S))
    monkeypatch.setattr(enrichment, "_inflight", {})


class Resp:
    def __init__(self, payload, status=200):
        self._p = payload
        self.status_code = status

    def json(self):
        return self._p


def abuse_payload(score, reports=12, usage="Data Center/Web Hosting/Transit",
                  isp="Example Hosting BV"):
    return {"data": {"abuseConfidenceScore": score, "totalReports": reports,
                     "countryCode": "NL", "usageType": usage, "isp": isp}}


@pytest.fixture
def wire(monkeypatch, fresh_caches):
    """Programmable fake network: counts calls per upstream, scriptable
    responses/exceptions per upstream."""
    state = {
        "abuse_calls": 0, "blocklist_calls": 0, "geo_calls": 0,
        "abuse": Resp(abuse_payload(80)),
        "blocklist": Resp({"attacks": 3, "reports": 7}),
        "abuse_headers": None,
    }

    def fake_get(url, *a, **k):
        if "abuseipdb.com" in url:
            state["abuse_calls"] += 1
            state["abuse_headers"] = k.get("headers")
            r = state["abuse"]
            if isinstance(r, Exception):
                raise r
            return r
        if "blocklist.de" in url:
            state["blocklist_calls"] += 1
            r = state["blocklist"]
            if isinstance(r, Exception):
                raise r
            return r
        state["geo_calls"] += 1
        return Resp({"country_name": "Testland", "city": "T", "state": "S",
                     "latitude": 1.0, "longitude": 2.0})

    monkeypatch.setattr(enrichment.requests, "get", fake_get)
    return state


@pytest.fixture
def with_key(monkeypatch):
    monkeypatch.setenv("SECOPS_ABUSEIPDB_KEY", "test-abuse-key")


@pytest.fixture
def without_key(monkeypatch):
    monkeypatch.delenv("SECOPS_ABUSEIPDB_KEY", raising=False)


# --- source selection ---------------------------------------------------------

def test_key_present_uses_abuseipdb(wire, with_key):
    rep = enrichment.check_ip_reputation(IP)
    assert rep["source"] == "abuseipdb"
    assert rep["abuse_score"] == 80
    assert rep["reports"] == 12
    assert rep["usage_type"].startswith("Data Center")
    assert rep["isp"] == "Example Hosting BV"
    assert rep["blacklisted"] is True          # 80 >= threshold
    assert wire["abuse_calls"] == 1
    assert wire["blocklist_calls"] == 0, "AbuseIPDB answered; no fallback call"
    assert wire["abuse_headers"]["Key"] == "test-abuse-key"


def test_key_absent_falls_back_to_blocklist(wire, without_key):
    rep = enrichment.check_ip_reputation(IP)
    assert rep["source"] == "blocklist.de"
    assert rep["abuse_score"] is None
    assert (rep["blacklisted"], rep["attacks"], rep["reports"]) == (True, 3, 7)
    assert wire["abuse_calls"] == 0, "no key must mean no AbuseIPDB traffic"


def test_flag_threshold_boundary(wire, with_key):
    wire["abuse"] = Resp(abuse_payload(config.ABUSE_SCORE_FLAG_THRESHOLD - 1))
    below = enrichment.check_ip_reputation(IP)
    wire["abuse"] = Resp(abuse_payload(config.ABUSE_SCORE_FLAG_THRESHOLD))
    at = enrichment.check_ip_reputation(IP_2)
    assert below["blacklisted"] is False and below["abuse_score"] is not None
    assert at["blacklisted"] is True


# --- the free-tier guarantee ----------------------------------------------------

def test_cache_prevents_duplicate_abuseipdb_lookups(wire, with_key):
    """One /check per IP per TTL window is what keeps a packet flood from
    burning the 1000/day free tier."""
    for _ in range(50):
        enrichment.check_ip_reputation(IP)
    assert wire["abuse_calls"] == 1
    enrichment.check_ip_reputation(IP_2)
    assert wire["abuse_calls"] == 2, "distinct IPs are separate cache entries"


# --- degradation ----------------------------------------------------------------

def test_429_falls_back_to_blocklist(wire, with_key):
    wire["abuse"] = Resp({"errors": [{"detail": "rate limit"}]}, status=429)
    rep = enrichment.check_ip_reputation(IP)
    assert rep["source"] == "blocklist.de"
    assert rep["blacklisted"] is True          # blocklist still answered
    assert wire["abuse_calls"] == 1 and wire["blocklist_calls"] == 1


def test_total_failure_is_marked_unknown_and_cached(wire, with_key):
    wire["abuse"] = RuntimeError("network down")
    wire["blocklist"] = RuntimeError("network down")
    rep = enrichment.check_ip_reputation(IP)
    assert rep["source"] == "unknown"
    assert rep["blacklisted"] is False and rep["abuse_score"] is None

    # The failure is cached for the TTL window: a failing upstream must not be
    # hammered once per packet.
    enrichment.check_ip_reputation(IP)
    enrichment.check_ip_reputation(IP)
    assert wire["abuse_calls"] == 1 and wire["blocklist_calls"] == 1


def test_worker_never_sees_an_exception(wire, with_key):
    wire["abuse"] = RuntimeError("boom")
    wire["blocklist"] = RuntimeError("boom")
    # No raise = the enrichment worker thread survives.
    assert enrichment.check_ip_reputation(IP)["source"] == "unknown"


def test_private_ips_still_never_touch_any_source(wire, with_key):
    rep = enrichment.check_ip_reputation("10.0.0.5")
    assert rep["source"] == "none"
    assert wire["abuse_calls"] == 0 and wire["blocklist_calls"] == 0


# --- persistence ----------------------------------------------------------------

class DirectWriter:
    """Executes (sql, params) immediately -- storage routing without the
    batched writer thread."""

    def __init__(self, conn):
        self.conn = conn

    def submit(self, sql, params):
        self.conn.execute(sql, params)
        self.conn.commit()
        return True


def test_abuse_score_persists_on_detections(migrated_db):
    conn = connect(migrated_db)
    storage.write_detection(
        DirectWriter(conn), src_ip="93.184.216.34", dst_ip="10.0.0.1",
        src_port=1, dst_port=80, proto=6, verdict="suspicious",
        confidence=0.99, country="NL", lat=None, lon=None, duration_s=1.0,
        fwd_packets=10, bwd_packets=2, fwd_bytes=100, bwd_bytes=20,
        summary="flow", abuse_score=80, rep_reports=12, rep_source="abuseipdb")

    item = storage.fetch_detections(conn)["items"][0]
    assert (item["abuse_score"], item["rep_reports"], item["rep_source"]) == \
        (80, 12, "abuseipdb")
    # ... and stays distinct from the detector's fields.
    assert item["cnn_verdict"] == "suspicious" and item["cnn_confidence"] == 0.99

    by_id = storage.fetch_detection(conn, item["id"])
    conn.close()
    assert by_id["abuse_score"] == 80


def test_abuse_score_persists_on_telemetry(migrated_db):
    conn = connect(migrated_db)
    storage.write_telemetry(
        DirectWriter(conn), ip="93.184.216.34", country="NL", lat=None,
        lon=None, summary="pkt", blacklisted="Yes", attacks=0, reports=12,
        abuse_score=80, rep_source="abuseipdb")
    item = storage.fetch_telemetry(conn)["items"][0]
    conn.close()
    assert (item["abuse_score"], item["rep_source"]) == (80, "abuseipdb")


def test_reputation_migration_is_idempotent(migrated_db):
    import migrations
    conn = connect(migrated_db)
    migrations.migrate(conn)                    # second run: no-op, no error
    cols_d = {r[1] for r in conn.execute("PRAGMA table_info(detections)")}
    cols_t = {r[1] for r in conn.execute("PRAGMA table_info(telemetry)")}
    conn.close()
    assert {"abuse_score", "rep_reports", "rep_source"} <= cols_d
    assert {"abuse_score", "rep_source"} <= cols_t


# --- the triage agent sees the richer record -------------------------------------

def test_triage_ip_reputation_tool_carries_abuse_score(wire, with_key):
    out = triage._tool_ip_reputation(None, {"ip": IP})
    assert out["abuse_score"] == 80
    assert out["source"] == "abuseipdb"
    assert out["isp"] == "Example Hosting BV"
    # The honesty note: reputation signal, never the ML verdict.
    assert "third-party" in out["note"] and "ML verdict" in out["note"]


def test_triage_tool_marks_unknown_reputation_honestly(wire, with_key):
    wire["abuse"] = RuntimeError("down")
    wire["blocklist"] = RuntimeError("down")
    out = triage._tool_ip_reputation(None, {"ip": IP})
    assert out["source"] == "unknown"
    assert "unknown, not clean" in out["note"]
