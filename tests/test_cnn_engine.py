"""Tests for the detection engine: feature extraction shape/order + an
end-to-end classify() smoke test on a synthetic flow.

These require the trained artifacts in models/ (run train_flow_model.py first);
they skip cleanly if the model is absent so the suite still runs on a fresh clone.
"""
import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402
from flow_tracker import FlowTracker, PacketMeta, PROTO_TCP  # noqa: E402

pytestmark = pytest.mark.skipif(
    not os.path.exists(config.FLOW_MODEL_PATH),
    reason="trained model not present; run train_flow_model.py first",
)


def _synthetic_flow():
    t = FlowTracker(idle_timeout=1000, active_timeout=10000)
    t.update(PacketMeta(1.0, "10.0.0.5", "93.184.216.34", 4444, 80,
                        PROTO_TCP, 120, syn=True, ack=False))
    t.update(PacketMeta(1.3, "93.184.216.34", "10.0.0.5", 80, 4444,
                        PROTO_TCP, 300, ack=True))
    t.update(PacketMeta(1.4, "10.0.0.5", "93.184.216.34", 4444, 80,
                        PROTO_TCP, 80, ack=True))
    return t.flush()[0]


def test_extract_features_shape_and_order():
    import cnn_engine
    flow = _synthetic_flow()
    feats = cnn_engine.extract_features(flow)
    # scaled row: shape (1, n_features), finite, correct width
    assert feats.shape == (1, len(config.FEATURE_ORDER))
    assert np.isfinite(feats).all()

    # order matters: build the raw vector by hand in FEATURE_ORDER and confirm
    # extract_features consumed the same order (unscaled identity via inverse).
    raw = flow.to_features()
    _, scaler, _ = cnn_engine.load_model()
    manual = scaler.transform(
        np.array([[raw[n] for n in config.FEATURE_ORDER]], dtype="float32"))
    assert np.allclose(feats, manual, atol=1e-5)


def test_extract_features_accepts_raw_dict():
    import cnn_engine
    d = {name: 0.0 for name in config.FEATURE_ORDER}
    feats = cnn_engine.extract_features(d)
    assert feats.shape == (1, len(config.FEATURE_ORDER))


def test_classify_returns_valid_verdict():
    import cnn_engine
    flow = _synthetic_flow()
    result = cnn_engine.classify_flow(flow)
    assert set(result.keys()) == {"verdict", "confidence"}
    assert result["verdict"] in ("normal", "suspicious")
    assert 0.5 <= result["confidence"] <= 1.0


def test_classify_end_to_end_on_two_different_flows():
    """Smoke test: a quiet flow and a burst flow both return valid, structured
    verdicts through the same code path (we assert validity, not a specific
    label -- the metrics suite covers accuracy)."""
    import cnn_engine

    quiet = _synthetic_flow()

    t = FlowTracker(idle_timeout=1000, active_timeout=10000)
    # many tiny fwd packets to many-ish -- port-scan-ish burst
    for i in range(50):
        t.update(PacketMeta(1.0 + i * 0.001, "10.0.0.5", "10.0.0.9",
                            40000 + i, 80, PROTO_TCP, 0, syn=True))
    burst = t.flush()[0]

    for flow in (quiet, burst):
        r = cnn_engine.classify(cnn_engine.extract_features(flow))
        assert r["verdict"] in ("normal", "suspicious")
        assert 0.5 <= r["confidence"] <= 1.0
