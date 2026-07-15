"""Feature-alignment / loop-closure test.

Takes real CIC-IDS-2017 rows (attack true-positives + benign true-negatives),
reconstructs equivalent synthetic packet sequences, runs them through the LIVE
path (flow_tracker -> cnn_engine), and asserts:

  (a) the features flow_tracker emits reproduce the row's features, and
  (b) the live verdict matches the label, AND the live attack-probability equals
      the offline model's probability on the same row (to 1e-4).

(b) is the loop closure: it proves the deployed serving pipeline (extract_features
+ saved scaler + model) yields the SAME numbers as the offline 0.990 evaluation.

Requires the dataset; set CICIDS_PARQUET to the parquet path. Skips otherwise so
the suite still runs on a fresh clone.
"""
import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402
from flow_tracker import FlowTracker, PacketMeta  # noqa: E402

PARQUET = os.environ.get("CICIDS_PARQUET", "")
pytestmark = pytest.mark.skipif(
    not (PARQUET and os.path.exists(PARQUET) and os.path.exists(config.FLOW_MODEL_PATH)),
    reason="set CICIDS_PARQUET and train models to run the alignment test",
)


def _prepare_rows():
    """Load rows with the SAME preprocessing train_flow_model uses, returning the
    10 raw features + binary label."""
    import pandas as pd
    from train_flow_model import COLUMN_MAP, PROTO_ENCODING, LABEL_COL, BENIGN_LABEL
    df = pd.read_parquet(PARQUET, columns=list(COLUMN_MAP.keys()) + [LABEL_COL])
    df = df.rename(columns=COLUMN_MAP)
    y = (df[LABEL_COL].astype(str).str.upper() != BENIGN_LABEL).astype(int).to_numpy()
    df["protocol"] = (df["protocol"].astype(str).str.lower()
                      .map(PROTO_ENCODING).fillna(0).astype(float))
    df["duration_s"] = (df["duration_s"].astype(float) / 1_000_000.0).clip(lower=0.0)
    X = df[config.FEATURE_ORDER].astype(float)
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0).to_numpy(dtype="float64")
    return X, y


def _reconstructable(raw):
    d = dict(zip(config.FEATURE_ORDER, raw))
    fp, bp = int(round(d["fwd_packets"])), int(round(d["bwd_packets"]))
    total = fp + bp
    if total == 0:
        return False
    if d["fwd_bytes"] > 0 and fp == 0:
        return False
    if d["bwd_bytes"] > 0 and bp == 0:
        return False
    for f in ("syn_count", "rst_count", "fin_count", "ack_count"):
        if int(round(d[f])) > total:
            return False
    return True


def _build_packets(raw):
    """Reconstruct a packet sequence that reproduces `raw` under flow_tracker's
    semantics. Closing flags (RST/FIN) are placed on the final packets so the
    flow closes only at the end (never splitting into two flows)."""
    d = {k: raw[i] for i, k in enumerate(config.FEATURE_ORDER)}
    dur = float(d["duration_s"])
    proto = int(round(d["protocol"]))
    fp, bp = int(round(d["fwd_packets"])), int(round(d["bwd_packets"]))
    fb, bb = int(round(d["fwd_bytes"])), int(round(d["bwd_bytes"]))
    syn, rst = int(round(d["syn_count"])), int(round(d["rst_count"]))
    fin, ack = int(round(d["fin_count"])), int(round(d["ack_count"]))
    total = fp + bp

    # directions in time order: fwd packets, then bwd packets
    dirs = ["f"] * fp + ["b"] * bp
    bytes_ = [0] * total
    if fp:
        bytes_[0] = fb
    if bp:
        bytes_[fp] = bb

    flags = [dict(syn=False, rst=False, fin=False, ack=False) for _ in range(total)]
    for i in range(syn):            # SYN on first packets
        flags[i]["syn"] = True
    for i in range(ack):            # ACK on first packets
        flags[i]["ack"] = True
    for i in range(fin):            # FIN on LAST packets (close only at end)
        flags[total - 1 - i]["fin"] = True
    for i in range(rst):            # RST on LAST packets
        flags[total - 1 - i]["rst"] = True

    sip, dip, sport, dport = "10.0.0.9", "10.0.0.1", 44444, 80
    packets = []
    for i in range(total):
        ts = 0.0 if total == 1 else dur * i / (total - 1)
        if dirs[i] == "f":
            s_ip, d_ip, sp, dp = sip, dip, sport, dport
        else:
            s_ip, d_ip, sp, dp = dip, sip, dport, sport
        packets.append(PacketMeta(ts=ts, src_ip=s_ip, dst_ip=d_ip,
                                  src_port=sp, dst_port=dp, proto=proto,
                                  payload_len=bytes_[i], **flags[i]))
    return packets


def _run_flow(raw):
    t = FlowTracker(idle_timeout=1e9, active_timeout=1e9)
    completed = []
    for p in _build_packets(raw):
        completed.extend(t.update(p))
    completed.extend(t.flush())
    assert len(completed) == 1, f"reconstruction split into {len(completed)} flows"
    return completed[0]


def test_feature_reconstruction_and_loop_closure():
    import cnn_engine
    import joblib
    X, y = _prepare_rows()
    model, scaler, _ = cnn_engine.load_model()

    # offline probabilities on every row, to pick true-positives / true-negatives
    probs = model.predict_proba(scaler.transform(X.astype("float32")))[:, 1]
    preds = (probs >= config.CLASSIFY_THRESHOLD).astype(int)

    rng = np.random.default_rng(0)
    tp = [i for i in rng.permutation(len(X)) if y[i] == 1 and preds[i] == 1
          and _reconstructable(X[i])][:8]
    tn = [i for i in rng.permutation(len(X)) if y[i] == 0 and preds[i] == 0
          and _reconstructable(X[i])][:8]
    assert tp and tn, "could not sample reconstructable TP/TN rows"

    for i in tp + tn:
        raw = X[i]
        flow = _run_flow(raw)
        emitted = flow.to_features()

        # (a) flow_tracker reproduces the row's features
        for j, name in enumerate(config.FEATURE_ORDER):
            if name == "duration_s":
                assert abs(emitted[name] - raw[j]) <= 1e-3, (name, emitted[name], raw[j])
            else:
                assert abs(emitted[name] - raw[j]) <= 0.5, (name, emitted[name], raw[j])

        # (b) live == offline, and verdict matches label
        feats = cnn_engine.extract_features(flow)
        live_prob = float(model.predict_proba(feats)[:, 1][0])
        assert abs(live_prob - probs[i]) < 1e-4, (i, live_prob, probs[i])
        result = cnn_engine.classify(feats)
        expected = "suspicious" if y[i] == 1 else "normal"
        assert result["verdict"] == expected, (i, result, y[i])
