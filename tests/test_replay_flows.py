"""End-to-end flow-integrity tests: replay a real capture through the real
sharded pipeline and check the flows that come out.

This is the regression test for the fragmentation bug. The shared-tracker design
was thread-safe but not order-preserving: packets of one flow raced across 8
workers, so the demo capture's 48 flows were read as 69-75, ~40% of them
attributed to the wrong endpoint, and the count changed run to run. Unit tests on
the queue cannot catch that -- only driving real packets through the real workers
can, which is what these do.
"""
import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402
import app_groq  # noqa: E402  -- conftest points SECOPS_DB at a temp file first

DEMO_PCAP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "samples", "demo-public-ips.pcap")

# Ground truth, from scripts/make_demo_pcap.py: 14 clients x 2 HTTP flows, plus
# 5 clients x 4 port-scan probes. Every flow is client-initiated.
EXPECTED_FLOWS = 48
EXPECTED_PACKETS = 264
SERVER_IP = "93.184.216.34"


@pytest.fixture
def replay(monkeypatch):
    """Replay the demo capture with the network stubbed out, returning the
    detections it produced."""
    monkeypatch.setattr(app_groq.enrichment, "get_ip_geo",
                        lambda ip: {"country": "Testland", "lat": 1.0, "lon": 2.0})

    def _run():
        conn = sqlite3.connect(config.DB_PATH)
        conn.execute("DELETE FROM detections")      # session DB is shared
        conn.commit()
        conn.close()

        packets = app_groq.replay_pcap(DEMO_PCAP, with_telemetry=False)

        conn = sqlite3.connect(config.DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT src_ip, dst_ip, fwd_packets, bwd_packets, cnn_verdict "
            "FROM detections").fetchall()
        conn.close()
        return packets, [dict(r) for r in rows]

    return _run


def test_replay_yields_exactly_the_flows_in_the_capture(replay):
    packets, flows = replay()
    assert packets == EXPECTED_PACKETS
    assert len(flows) == EXPECTED_FLOWS, (
        f"expected {EXPECTED_FLOWS} flows, got {len(flows)} -- a count above this "
        f"means flows are fragmenting across workers again")


def test_flow_direction_is_never_reversed(replay):
    """Every flow in the capture is client-initiated. The server appearing as an
    initiator means a later packet beat the SYN to the tracker."""
    _, flows = replay()
    misattributed = [f for f in flows if f["src_ip"] == SERVER_IP]
    assert misattributed == [], (
        f"{len(misattributed)} flows attributed to the server: packets of a flow "
        f"reached the tracker out of order")


def test_replay_is_deterministic_across_runs(replay):
    """Three identical replays must agree exactly. Nondeterminism here means
    workers are racing within a flow."""
    runs = [replay() for _ in range(3)]

    counts = [len(flows) for _, flows in runs]
    assert counts == [EXPECTED_FLOWS] * 3, f"flow count varies across runs: {counts}"

    signatures = [sorted((f["src_ip"], f["dst_ip"], f["fwd_packets"],
                          f["bwd_packets"]) for f in flows) for _, flows in runs]
    assert signatures[0] == signatures[1] == signatures[2], \
        "identical replays produced different flows"


def test_flow_features_survive_sharding(replay):
    """Fragmenting split one conversation's packets into several part-flows, so
    the per-flow packet counts came out wrong even when the count looked close.
    The 8-packet HTTP flows must be whole: 5 forward, 3 back."""
    _, flows = replay()
    http = [f for f in flows if f["fwd_packets"] + f["bwd_packets"] == 8]
    assert len(http) == 28, f"expected 28 complete HTTP flows, got {len(http)}"
    assert all(f["fwd_packets"] == 5 and f["bwd_packets"] == 3 for f in http)

    # The port-scan probes: one SYN out, one RST back.
    scans = [f for f in flows if f["fwd_packets"] == 1 and f["bwd_packets"] == 1]
    assert len(scans) == 20, f"expected 20 scan flows, got {len(scans)}"
