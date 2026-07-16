"""Feature-alignment / loop-closure test -- the decisive classifier check.

Takes real CIC-IDS-2017 rows, reconstructs equivalent synthetic packet sequences,
runs them through the LIVE path (flow_tracker -> cnn_engine), and asserts:

  (a) the features flow_tracker emits reproduce the row's features,
  (b) the live attack-probability equals the offline model's probability on the
      same row (to 1e-4), and the verdict matches the label, and
  (c) real attack flows actually come out "suspicious" through the live path.

(b) is the loop closure: it proves the deployed serving pipeline (extract_features
+ saved scaler + model) yields the SAME numbers as the offline 0.990 evaluation.
(c) is the accuracy question (b) cannot answer on its own, because (b) samples
rows the offline model already gets right. Together they separate the two ways
this can fail: a serving bug (live diverges from offline) versus a model that
never learned the attack (both agree, and both are wrong).

This runs against a committed 452-row stratified fixture by default, so it works
on a fresh clone with no dataset. Point CICIDS_PARQUET at the full parquet to run
it against all 2.8M rows instead. It previously required that env var and so, in
practice, never ran -- which is how "everything classifies normal" went unnoticed.
Regenerate the fixture with scripts/make_alignment_fixture.py.
"""
import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402
from flow_tracker import FlowTracker, PacketMeta  # noqa: E402

PARQUET = os.environ.get("CICIDS_PARQUET", "")
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "fixtures", "cicids_alignment_sample.csv")

pytestmark = pytest.mark.skipif(
    not (os.path.exists(config.FLOW_MODEL_PATH) and
         (os.path.exists(FIXTURE) or (PARQUET and os.path.exists(PARQUET)))),
    reason="train models (and keep tests/fixtures/) to run the alignment test",
)


def _read_source():
    """The raw source rows: the full parquet if CICIDS_PARQUET is set, else the
    committed fixture. Both carry ORIGINAL column names and values, so the
    preprocessing below is the same code path either way."""
    import pandas as pd
    from train_flow_model import COLUMN_MAP, LABEL_COL
    cols = list(COLUMN_MAP.keys()) + [LABEL_COL]
    if PARQUET and os.path.exists(PARQUET):
        return pd.read_parquet(PARQUET, columns=cols)
    return pd.read_csv(FIXTURE, encoding="utf-8")[cols]


def _prepare_rows():
    """Load rows with the SAME preprocessing train_flow_model uses, returning the
    10 raw features + binary label + the original attack-class labels."""
    from train_flow_model import COLUMN_MAP, PROTO_ENCODING, LABEL_COL, BENIGN_LABEL
    df = _read_source().rename(columns=COLUMN_MAP)
    labels = df[LABEL_COL].astype(str).to_numpy()
    y = (df[LABEL_COL].astype(str).str.upper() != BENIGN_LABEL).astype(int).to_numpy()
    df["protocol"] = (df["protocol"].astype(str).str.lower()
                      .map(PROTO_ENCODING).fillna(0).astype(float))
    df["duration_s"] = (df["duration_s"].astype(float) / 1_000_000.0).clip(lower=0.0)
    X = df[config.FEATURE_ORDER].astype(float)
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0).to_numpy(dtype="float64")
    return X, y, labels


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
    X, y, _ = _prepare_rows()
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


def test_live_path_agrees_with_the_offline_model_on_every_row():
    """The serving invariant, checked without pre-selection.

    The loop-closure test above samples rows the offline model already gets right,
    so it cannot distinguish "serving is faithful" from "we only looked at easy
    rows". This runs EVERY fixture row -- attacks the model misses included --
    through flow_tracker -> cnn_engine and demands the live verdict match what the
    offline model says about the same row. Any disagreement is a serving bug
    (scaler drift, feature order, dtype) and is ours to fix. Agreement means the
    deployed path is faithful and any remaining error is the model's, not the
    plumbing's.
    """
    import cnn_engine
    X, y, _ = _prepare_rows()
    model, scaler, _ = cnn_engine.load_model()

    idx = [i for i in range(len(X)) if _reconstructable(X[i])]
    assert len(idx) >= 100, "fixture lost its rows"

    live = [cnn_engine.classify_flow(_run_flow(X[i]))["verdict"] for i in idx]
    offline_probs = model.predict_proba(scaler.transform(X[idx].astype("float32")))[:, 1]
    offline = ["suspicious" if p >= config.CLASSIFY_THRESHOLD else "normal"
               for p in offline_probs]

    disagreements = [(i, a, b) for i, a, b in zip(idx, live, offline) if a != b]
    assert disagreements == [], (
        f"{len(disagreements)} rows where the live path and the offline model "
        f"disagree -- the serving pipeline is not reproducing the evaluation")


# Live recall per attack class, MEASURED on this fixture (equal-weighted, 25 rows
# per class). These are not targets and not aspirations -- they are what the
# shipped model actually does today, pinned so a change shows up as a diff.
#
# Read them next to models/metrics.json's headline 0.985 recall. Both are true:
# that number is weighted by the real class distribution, where DoS Hulk +
# PortScan + DDoS are ~95% of all attack rows and the model scores them ~1.00.
# The classes it is blind to are rare enough to barely move the average. Weight
# every class equally and recall is 0.648. The blind spots below are real,
# unresolved, and a product decision rather than a bug: see the checkpoint report.
#
# NOTE on the Web Attack keys: the dataset spells them with an EN DASH (U+2013),
# and this file is UTF-8, so they are written literally below. Do not retype them
# from a console dump -- a cp1252 terminal prints that dash as a replacement char,
# and keys pasted from what the terminal showed silently match nothing.
BASELINE_RECALL = {
    "Web Attack – XSS": 0.00,
    "Web Attack – Brute Force": 0.04,
    "Web Attack – Sql Injection": 0.28,
    "Bot": 0.32,
    "Infiltration": 0.40,
    "SSH-Patator": 0.56,
    "Heartbleed": 0.63,
    "DoS Hulk": 0.76,
    "PortScan": 1.00,
    "DDoS": 1.00,
    "FTP-Patator": 1.00,
    "DoS Slowhttptest": 1.00,
    "DoS slowloris": 1.00,
    "DoS GoldenEye": 1.00,
}

# The classes the detector can be trusted on today. A regression here is a real
# regression: these are the attacks it is actually shipped to catch.
RELIABLE_CLASSES = ["PortScan", "DDoS", "FTP-Patator", "DoS Slowhttptest",
                    "DoS slowloris", "DoS GoldenEye"]


@pytest.mark.skipif(bool(PARQUET), reason="baseline is measured on the fixture")
def test_per_class_attack_recall_has_not_regressed():
    """Pins per-class live recall so a blind spot cannot silently widen -- or
    silently close without us noticing we fixed it."""
    import cnn_engine
    X, y, labels = _prepare_rows()

    total, hit = {}, {}
    for i in range(len(X)):
        if y[i] != 1 or not _reconstructable(X[i]):
            continue
        label = labels[i]
        total[label] = total.get(label, 0) + 1
        if cnn_engine.classify_flow(_run_flow(X[i]))["verdict"] == "suspicious":
            hit[label] = hit.get(label, 0) + 1

    recalls = {k: hit.get(k, 0) / total[k] for k in total}
    assert set(recalls) == set(BASELINE_RECALL), \
        f"fixture classes changed: {sorted(set(recalls) ^ set(BASELINE_RECALL))}"

    regressed = {k: (v, BASELINE_RECALL[k]) for k, v in recalls.items()
                 if v < BASELINE_RECALL[k] - 0.01}
    assert regressed == {}, f"recall regressed (now, baseline): {regressed}"

    for k in RELIABLE_CLASSES:
        assert recalls[k] == 1.0, f"{k} is a class we rely on; recall fell to {recalls[k]}"


@pytest.mark.skipif(bool(PARQUET), reason="baseline is measured on the fixture")
def test_benign_flows_are_not_flagged():
    """False positives are what makes an operator stop reading the feed."""
    import cnn_engine
    X, y, _ = _prepare_rows()
    benign = [i for i in range(len(X)) if y[i] == 0 and _reconstructable(X[i])]
    verdicts = [cnn_engine.classify_flow(_run_flow(X[i]))["verdict"] for i in benign]
    fpr = verdicts.count("suspicious") / len(verdicts)
    assert fpr <= 0.05, f"live false-positive rate on benign flows is {fpr:.3f}"
