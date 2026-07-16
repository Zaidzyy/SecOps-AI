"""Tests for the flow aggregation layer."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flow_tracker import FlowTracker, PacketMeta, PROTO_TCP, PROTO_UDP  # noqa: E402


def _pkt(ts, sip, dip, sp, dp, proto=PROTO_TCP, plen=100,
         syn=False, rst=False, fin=False, ack=False):
    return PacketMeta(ts=ts, src_ip=sip, dst_ip=dip, src_port=sp, dst_port=dp,
                      proto=proto, payload_len=plen,
                      syn=syn, rst=rst, fin=fin, ack=ack)


def test_packets_aggregate_into_one_flow():
    t = FlowTracker(idle_timeout=100, active_timeout=1000)
    # forward, forward, backward -- all the same connection
    t.update(_pkt(1.0, "10.0.0.1", "10.0.0.2", 1111, 80, plen=100, syn=True))
    t.update(_pkt(1.1, "10.0.0.1", "10.0.0.2", 1111, 80, plen=50, ack=True))
    t.update(_pkt(1.2, "10.0.0.2", "10.0.0.1", 80, 1111, plen=200, ack=True))
    assert len(t) == 1
    flow = t.flush()[0]
    assert flow.fwd_packets == 2
    assert flow.bwd_packets == 1
    assert flow.fwd_bytes == 150
    assert flow.bwd_bytes == 200
    assert flow.syn_count == 1
    assert flow.ack_count == 2


def test_reverse_direction_is_same_flow():
    t = FlowTracker(idle_timeout=100, active_timeout=1000)
    t.update(_pkt(1.0, "1.1.1.1", "2.2.2.2", 5000, 443))
    t.update(_pkt(1.0, "2.2.2.2", "1.1.1.1", 443, 5000))  # response
    assert len(t) == 1


def test_distinct_tuples_are_distinct_flows():
    t = FlowTracker(idle_timeout=100, active_timeout=1000)
    t.update(_pkt(1.0, "1.1.1.1", "2.2.2.2", 5000, 443))
    t.update(_pkt(1.0, "1.1.1.1", "2.2.2.2", 5001, 443))  # different src port
    t.update(_pkt(1.0, "1.1.1.1", "3.3.3.3", 5000, 443))  # different dst ip
    assert len(t) == 3


def test_feature_order_and_values():
    import config
    t = FlowTracker(idle_timeout=100, active_timeout=1000)
    t.update(_pkt(10.0, "1.1.1.1", "2.2.2.2", 5000, 80, plen=40, syn=True))
    t.update(_pkt(12.5, "2.2.2.2", "1.1.1.1", 80, 5000, plen=60, ack=True))
    feats = t.flush()[0].to_features()
    # every canonical feature is present
    assert set(feats.keys()) == set(config.FEATURE_ORDER)
    assert feats["duration_s"] == 2.5
    assert feats["protocol"] == float(PROTO_TCP)
    assert feats["fwd_bytes"] == 40
    assert feats["bwd_bytes"] == 60


def test_flags_are_tracked_but_never_fed_to_the_model():
    """The tracker still counts TCP flags -- teardown detection needs them -- but
    they are NOT model input.

    They were dropped from the feature contract for not transferring: CIC-IDS-2017
    labels PortScan rows with every flag zero, while a real scan sets SYN, so a
    model trained on them learns a property of the dataset rather than of the
    attack. Re-adding them to to_features() would silently reintroduce that.
    """
    import config
    t = FlowTracker(idle_timeout=1000, active_timeout=1000)
    t.update(_pkt(1.0, "1.1.1.1", "2.2.2.2", 5000, 80, syn=True, ack=False))
    for i in range(20):  # 20 ACK-bearing packets
        t.update(_pkt(1.0 + i * 0.01, "1.1.1.1", "2.2.2.2", 5000, 80, ack=True))
    flow = t.flush()[0]

    assert flow.syn_count == 1              # raw counts retained on the Flow ...
    assert flow.ack_count == 20

    feats = flow.to_features()              # ... but absent from model input
    for name in ("syn_count", "rst_count", "fin_count", "ack_count"):
        assert name not in feats, f"{name} is not transferable; it must not be a feature"
        assert name not in config.FEATURE_ORDER


def test_idle_timeout_emits_flow():
    t = FlowTracker(idle_timeout=15, active_timeout=1000)
    t.update(_pkt(1.0, "1.1.1.1", "2.2.2.2", 5000, 443, proto=PROTO_UDP))
    assert len(t) == 1
    # a later packet on a different flow pushes the clock forward past the timeout
    completed = t.update(_pkt(20.0, "9.9.9.9", "8.8.8.8", 6000, 53, proto=PROTO_UDP))
    keys = {c.key_tuple()[0] for c in completed}
    assert "1.1.1.1" in keys        # the idle UDP flow was emitted
    assert len(t) == 1              # only the new flow remains


def test_active_timeout_emits_long_flow():
    t = FlowTracker(idle_timeout=1000, active_timeout=120)
    t.update(_pkt(0.0, "1.1.1.1", "2.2.2.2", 5000, 443))
    expired = t.expire(now=200.0)   # 200s > active timeout even though not idle
    assert len(expired) == 1


def test_tcp_rst_closes_flow_immediately():
    t = FlowTracker(idle_timeout=1000, active_timeout=1000)
    t.update(_pkt(1.0, "1.1.1.1", "2.2.2.2", 5000, 80, syn=True))
    completed = t.update(_pkt(1.5, "2.2.2.2", "1.1.1.1", 80, 5000, rst=True))
    assert len(completed) == 1
    assert completed[0].rst_count == 1
    assert len(t) == 0


def test_tcp_fin_both_ways_closes_flow():
    t = FlowTracker(idle_timeout=1000, active_timeout=1000)
    t.update(_pkt(1.0, "1.1.1.1", "2.2.2.2", 5000, 80, syn=True))
    t.update(_pkt(1.5, "1.1.1.1", "2.2.2.2", 5000, 80, fin=True))   # fwd FIN
    completed = t.update(_pkt(1.6, "2.2.2.2", "1.1.1.1", 80, 5000, fin=True))  # bwd FIN
    assert len(completed) == 1
    assert len(t) == 0


def test_udp_flow_not_closed_by_flags():
    t = FlowTracker(idle_timeout=1000, active_timeout=1000)
    completed = t.update(_pkt(1.0, "1.1.1.1", "2.2.2.2", 5000, 53, proto=PROTO_UDP))
    assert completed == []
    assert len(t) == 1
