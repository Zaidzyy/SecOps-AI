"""Train SecOps-AI's own flow classifier on CIC-IDS-2017.

Why we train our own instead of using the borrowed SecIDS-CNN.h5: that model's
10-feature training contract (names, order, scaler) was never published, so its
verdicts on our features would be meaningless. These models are ours, trained on
exactly the 10 flow features `flow_tracker` emits, with a scaler we save/reuse.

Primary detector: gradient-boosted trees (GBT). Baseline for comparison: a
compact Conv1D. On 10 low-dimensional tabular flow features the GBT wins clearly
(trees beat CNNs on tabular data); we ship the GBT and keep the CNN documented.

Evaluation honesty (three splits are reported):
  * HEADLINE = DEDUP + stratified. CIC-IDS-2017 contains bursts of near-identical
    flows (a DoS flood is thousands of nearly identical rows); ~36% of our rows
    are exact duplicates. A plain random split scatters identical rows across
    train and test and inflates scores. We drop exact-duplicate feature vectors
    BEFORE splitting so an identical flow can never sit in both sides, then
    stratify. These are the numbers we trust. (Near-duplicates may remain -- this
    reduces leakage, it doesn't claim to eliminate it.)
  * RANDOM stratified is reported as an explicit optimistic upper bound.
  * GROUP-by-source-IP is reported as a DEGENERATE reference: in this dataset a
    single source IP (172.16.0.1) emits 99.6% of all attacks, so holding out
    source IPs holds out entire attack campaigns and the model sees almost no
    attacks in training. We keep it to document why naive host-grouping fails
    here, not because it is a fair measure.
  * A per-feature univariate AUC leakage check flags any single feature that
    alone separates the classes suspiciously well.
The SHIPPED models are exactly the ones trained on the DEDUP-split train set, so
the headline metrics describe the artifacts we deploy (no refit hand-waving).

Dataset: rdpahalavan/CIC-IDS2017, Network-Flows/CICIDS_Flow.parquet.

Run:  venv/Scripts/python.exe train_flow_model.py --parquet <path>
"""
import argparse
import json
import os
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split, GroupShuffleSplit
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix, roc_auc_score)

import config

COLUMN_MAP = {
    "Flow Duration": "duration_s",            # microseconds -> seconds below
    "protocol": "protocol",                   # string tcp/udp/other -> number
    "Total Fwd Packets": "fwd_packets",
    "Total Backward Packets": "bwd_packets",
    "Total Length of Fwd Packets": "fwd_bytes",
    "Total Length of Bwd Packets": "bwd_bytes",
    "SYN Flag Count": "syn_count",
    "RST Flag Count": "rst_count",
    "FIN Flag Count": "fin_count",
    "ACK Flag Count": "ack_count",
}
PROTO_ENCODING = {"tcp": 6, "udp": 17, "other": 0}
LABEL_COL = "attack_label"
GROUP_COL = "source_ip"
BENIGN_LABEL = "BENIGN"


def load_and_prepare(parquet_path, benign_ratio=2.0, seed=42):
    src_cols = list(COLUMN_MAP.keys()) + [LABEL_COL, GROUP_COL]
    df = pd.read_parquet(parquet_path, columns=src_cols).rename(columns=COLUMN_MAP)

    y = (df[LABEL_COL].astype(str).str.upper() != BENIGN_LABEL).astype(int)
    groups = df[GROUP_COL].astype(str)

    df["protocol"] = (df["protocol"].astype(str).str.lower()
                      .map(PROTO_ENCODING).fillna(0).astype(float))
    # Flow Duration is microseconds in CICFlowMeter; flow_tracker emits seconds.
    # Some rows have small negative durations (a known CIC-IDS-2017 artifact) ->
    # clip to 0 rather than invent a value.
    df["duration_s"] = (df["duration_s"].astype(float) / 1_000_000.0).clip(lower=0.0)

    X = df[config.FEATURE_ORDER].astype(float)
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)

    work = X.copy()
    work["_y"] = y.values
    work["_g"] = groups.values
    attacks = work[work["_y"] == 1]
    benign = work[work["_y"] == 0]
    n_benign = min(len(benign), int(len(attacks) * benign_ratio))
    benign = benign.sample(n=n_benign, random_state=seed)
    bal = pd.concat([attacks, benign]).sample(frac=1.0, random_state=seed)
    y_bal = bal.pop("_y").to_numpy()
    g_bal = bal.pop("_g").to_numpy()
    X_bal = bal[config.FEATURE_ORDER].to_numpy(dtype="float32")
    counts = {"total_rows": int(len(df)), "attack_rows": int(len(attacks)),
              "benign_rows_used": int(n_benign)}
    return X_bal, y_bal, g_bal, counts


def build_cnn(n_features):
    import tensorflow as tf
    m = tf.keras.Sequential([
        tf.keras.layers.Input(shape=(n_features, 1)),
        tf.keras.layers.Conv1D(16, 3, activation="relu", padding="same"),
        tf.keras.layers.BatchNormalization(),
        tf.keras.layers.Conv1D(32, 3, activation="relu", padding="same"),
        tf.keras.layers.BatchNormalization(),
        tf.keras.layers.GlobalAveragePooling1D(),
        tf.keras.layers.Dense(32, activation="relu"),
        tf.keras.layers.Dropout(0.3),
        tf.keras.layers.Dense(1, activation="sigmoid"),
    ])
    m.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    return m


def scores(y_true, y_pred, y_prob):
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_true, y_prob)), 4),
    }


def cm_dict(cm):
    return {"tn": int(cm[0, 0]), "fp": int(cm[0, 1]),
            "fn": int(cm[1, 0]), "tp": int(cm[1, 1])}


def train_gbt(Xtr, ytr, Xte, seed):
    gbt = HistGradientBoostingClassifier(max_iter=200, random_state=seed)
    gbt.fit(Xtr, ytr)
    prob = gbt.predict_proba(Xte)[:, 1]
    return gbt, prob


def train_cnn(Xtr, ytr, Xte, n_feat, epochs, seed):
    import tensorflow as tf
    tf.keras.utils.set_random_seed(seed)
    cnn = build_cnn(n_feat)
    classw = {0: 1.0, 1: float((ytr == 0).sum() / max(1, (ytr == 1).sum()))}
    es = tf.keras.callbacks.EarlyStopping(monitor="val_loss", patience=3,
                                          restore_best_weights=True)
    cnn.fit(Xtr.reshape(-1, n_feat, 1), ytr, validation_split=0.1, epochs=epochs,
            batch_size=4096, class_weight=classw, callbacks=[es], verbose=2)
    prob = cnn.predict(Xte.reshape(-1, n_feat, 1), batch_size=8192, verbose=0).ravel()
    return cnn, prob


def evaluate_split(name, note, Xtr, Xte, ytr, yte, n_feat, epochs, seed):
    """Fit scaler + both models on this split's train, eval on test. Returns
    (result_dict, fitted_scaler, fitted_gbt, fitted_cnn, gbt_pred, cnn_pred)."""
    scaler = StandardScaler().fit(Xtr)
    Xtr_s = scaler.transform(Xtr).astype("float32")
    Xte_s = scaler.transform(Xte).astype("float32")

    gbt, gbt_prob = train_gbt(Xtr_s, ytr, Xte_s, seed)
    gbt_pred = (gbt_prob >= config.CLASSIFY_THRESHOLD).astype(int)

    cnn, cnn_prob = train_cnn(Xtr_s, ytr, Xte_s, n_feat, epochs, seed)
    cnn_pred = (cnn_prob >= config.CLASSIFY_THRESHOLD).astype(int)

    result = {
        "note": note,
        "test_size": int(len(yte)),
        "test_positives": int(yte.sum()),
        "gbt": scores(yte, gbt_pred, gbt_prob),
        "cnn": scores(yte, cnn_pred, cnn_prob),
        "gbt_confusion": cm_dict(confusion_matrix(yte, gbt_pred)),
        "cnn_confusion": cm_dict(confusion_matrix(yte, cnn_pred)),
    }
    print(f"  [{name}] GBT: {result['gbt']}")
    print(f"  [{name}] CNN: {result['cnn']}")
    return result, scaler, gbt, cnn, gbt_pred, cnn_pred


def leakage_check(X, y, seed):
    """Per-feature univariate AUC + single-feature decision tree AUC. Flags any
    feature that alone separates the classes with AUC >= 0.98."""
    out = {}
    flagged = []
    for i, name in enumerate(config.FEATURE_ORDER):
        col = X[:, i]
        uni = roc_auc_score(y, col)
        uni = max(uni, 1 - uni)  # direction-agnostic
        stump = DecisionTreeClassifier(max_depth=1, random_state=seed)
        stump.fit(col.reshape(-1, 1), y)
        tree_auc = roc_auc_score(y, stump.predict_proba(col.reshape(-1, 1))[:, 1])
        out[name] = {"univariate_auc": round(float(uni), 4),
                     "stump_auc": round(float(tree_auc), 4)}
        if uni >= 0.98 or tree_auc >= 0.98:
            flagged.append(name)
    return {"per_feature": out, "flagged": flagged,
            "note": "AUC>=0.98 for a single feature suggests possible leakage."}


def save_confusion_png(cm, title, path_png):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(4, 4))
        ax.imshow(cm, cmap="Blues")
        for (i, j), v in np.ndenumerate(cm):
            ax.text(j, i, f"{v}", ha="center", va="center")
        ax.set_xticks([0, 1]); ax.set_xticklabels(["normal", "attack"])
        ax.set_yticks([0, 1]); ax.set_yticklabels(["normal", "attack"])
        ax.set_xlabel("predicted"); ax.set_ylabel("actual")
        ax.set_title(title)
        fig.tight_layout(); fig.savefig(path_png, dpi=120); plt.close(fig)
        return True
    except Exception as e:
        print(f"(skipped {path_png}: {e})")
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--parquet", required=True)
    ap.add_argument("--epochs", type=int, default=20)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    os.makedirs(config.MODEL_DIR, exist_ok=True)
    n_feat = len(config.FEATURE_ORDER)

    print("Loading + preparing data ...")
    X, y, g, counts = load_and_prepare(args.parquet, seed=args.seed)
    print(f"  balanced set: {X.shape}, positives={int(y.sum())}, {counts}")

    # --- Leakage check (on full balanced, unscaled data) ---
    print("Leakage check ...")
    leak = leakage_check(X, y, args.seed)
    print("  flagged:", leak["flagged"] or "none")

    # --- Dedup exact-duplicate feature vectors (keep label) ---
    keyed = np.concatenate([X, y.reshape(-1, 1)], axis=1)
    _, uniq_idx = np.unique(keyed, axis=0, return_index=True)
    uniq_idx.sort()
    Xu, yu, gu = X[uniq_idx], y[uniq_idx], g[uniq_idx]
    dup_stats = {"balanced_rows": int(len(X)), "unique_rows": int(len(Xu)),
                 "duplicate_rate": round(1 - len(Xu) / len(X), 4)}
    print(f"  dedup: {dup_stats}")

    # --- HEADLINE: dedup + stratified split (real numbers, shipped models) ---
    print("Dedup + stratified split -> HEADLINE numbers ...")
    Xtr, Xte, ytr, yte = train_test_split(
        Xu, yu, test_size=0.2, random_state=args.seed, stratify=yu)
    dedup_res, scaler, gbt, cnn, gbt_pred, cnn_pred = evaluate_split(
        "dedup", "Dedup (exact-duplicate feature vectors removed) + stratified. "
        "Identical flows cannot span train/test. Treat as REAL.",
        Xtr, Xte, ytr, yte, n_feat, args.epochs, args.seed)

    # --- Reference: random stratified split (optimistic upper bound) ---
    print("Random stratified split -> optimistic upper bound ...")
    Xtr_r, Xte_r, ytr_r, yte_r = train_test_split(
        X, y, test_size=0.2, random_state=args.seed, stratify=y)
    rnd_res, *_ = evaluate_split(
        "random", "Random stratified split. Optimistic upper bound (duplicate "
        "flow bursts leak across train/test).",
        Xtr_r, Xte_r, ytr_r, yte_r, n_feat, args.epochs, args.seed)

    # --- Reference: group by source IP (DEGENERATE, documented) ---
    print("Group split by source IP -> degenerate reference ...")
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=args.seed)
    gtr, gte = next(gss.split(X, y, groups=g))
    grp_res, *_ = evaluate_split(
        "group", "Group split by source IP. DEGENERATE: one IP emits 99.6% of "
        "attacks, so a held-out IP removes whole campaigns. Documented, not fair.",
        X[gtr], X[gte], y[gtr], y[gte], n_feat, args.epochs, args.seed)

    # --- Ship the DEDUP-split models (headline metrics describe these) ---
    joblib.dump(gbt, config.FLOW_MODEL_PATH)
    cnn.save(config.FLOW_CNN_PATH)
    joblib.dump(scaler, config.FLOW_SCALER_PATH)

    save_confusion_png(confusion_matrix(yte, gbt_pred),
                       "GBT (primary) - dedup split",
                       os.path.join(config.MODEL_DIR, "confusion_gbt.png"))
    save_confusion_png(confusion_matrix(yte, cnn_pred),
                       "Conv1D (baseline) - dedup split",
                       os.path.join(config.MODEL_DIR, "confusion_cnn.png"))

    meta = {
        "primary_model": config.PRIMARY_MODEL_TYPE,
        "feature_order": config.FEATURE_ORDER,
        "protocol_encoding": PROTO_ENCODING,
        "duration_unit": "seconds (CICFlowMeter microseconds / 1e6, clipped >=0)",
        "label_map": {"0": "normal", "1": "suspicious"},
        "threshold": config.CLASSIFY_THRESHOLD,
        "input_shape": [n_feat, 1],
        "dataset": "CIC-IDS-2017 (rdpahalavan/CIC-IDS2017, Network-Flows parquet)",
        "shipped_models": {"gbt": os.path.basename(config.FLOW_MODEL_PATH),
                           "cnn": os.path.basename(config.FLOW_CNN_PATH)},
        "shipped_from_split": "dedup_stratified",
        "dedup_stats": dup_stats,
        "counts": counts,
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(config.FLOW_META_PATH, "w") as f:
        json.dump(meta, f, indent=2)

    metrics = {
        "primary_model": "gbt",
        "baseline_model": "compact Conv1D",
        "headline_split": "dedup_stratified",
        "splits": {"dedup_stratified": dedup_res,
                   "random_stratified": rnd_res,
                   "group_by_source_ip": grp_res},
        "leakage_check": leak,
        "dedup_stats": dup_stats,
        "counts": counts,
    }
    with open(os.path.join(config.MODEL_DIR, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    print("\nDone. Artifacts in", config.MODEL_DIR)
    print(json.dumps({"HEADLINE_dedup_split": dedup_res,
                      "optimistic_random_split": {"gbt": rnd_res["gbt"],
                                                  "cnn": rnd_res["cnn"]},
                      "degenerate_group_split": {"gbt": grp_res["gbt"],
                                                 "cnn": grp_res["cnn"]},
                      "leakage_flagged": leak["flagged"]}, indent=2))


if __name__ == "__main__":
    main()
