"""Train SecOps-AI's own flow classifier on CIC-IDS-2017.

Why we train our own instead of using the borrowed SecIDS-CNN.h5: that model's
10-feature training contract (names, order, scaler) was never published, so its
verdicts on our features would be meaningless. These models are ours, trained on
exactly the flow features `flow_tracker` emits, with a scaler we save/reuse.

Primary detector: gradient-boosted trees (GBT). Baseline for comparison: a
compact Conv1D. On low-dimensional tabular flow features the GBT wins clearly
(trees beat CNNs on tabular data); we ship the GBT and keep the CNN documented.

FEATURES: 6, not the original 10. The four TCP flag features were dropped for not
transferring from the dataset to the wire -- CIC-IDS-2017 PortScan rows have all
flags zero, real scans do not, and the model learned the dataset's artifact rather
than the attack. config.FEATURE_ORDER has the full rationale.

WEIGHTING + OPERATING POINT: chosen from data, not intuition. Per-class sample
weights follow w ~ 1/n^alpha (alpha=0 is exactly unweighted; alpha=1 would be
fully class-balanced). We sweep alpha x decision-threshold on a VALIDATION split
and pick the point that maximises macro attack recall SUBJECT TO a hard budget of
per-flow benign FPR <= 1%. Final numbers are then reported on a held-out TEST
split the selection never saw. History: the unweighted fit reached 0.985 weighted
recall while never detecting a Web Attack, and the fully macro-balanced fit that
answered it bought macro recall by flooding benign flows with false positives.
The frontier makes that trade explicit and picks the defensible point.

FPR is reported PER FLOW, not per shape. The dedup split scores each unique
feature vector once, but benign traffic has natural multiplicity: one common
benign shape can be millions of real flows. A model that misfires on a handful of
common shapes looks fine per-shape and is unusable per-flow (we measured a 12x
gap). Every benign FPR below is therefore weighted by each shape's real
multiplicity in the full dataset; the per-shape number is kept for reference.

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

# Only the transferable features are read from the dataset now. The four flag
# columns (SYN/RST/FIN/ACK Flag Count) are deliberately absent: their meaning in
# CIC-IDS-2017 does not match what a sensor observes on the wire, so a model that
# uses them cannot generalise past the dataset. See config.FEATURE_ORDER.
COLUMN_MAP = {
    "Flow Duration": "duration_s",            # microseconds -> seconds below
    "protocol": "protocol",                   # string tcp/udp/other -> number
    "Total Fwd Packets": "fwd_packets",
    "Total Backward Packets": "bwd_packets",
    "Total Length of Fwd Packets": "fwd_bytes",
    "Total Length of Bwd Packets": "bwd_bytes",
}
PROTO_ENCODING = {"tcp": 6, "udp": 17, "other": 0}
LABEL_COL = "attack_label"
GROUP_COL = "source_ip"
BENIGN_LABEL = "BENIGN"


def load_and_prepare(parquet_path, benign_ratio=2.0, seed=42):
    """Returns (X, y, groups, attack_class_labels, flow_multiplicity, counts).

    `attack_class_labels` rides along so training can weight each attack class
    and evaluation can report recall per class. The binary y is what the model
    predicts; the class label is how we refuse to let DoS Hulk speak for Web
    Attack XSS.

    `flow_multiplicity` is, for every BENIGN row, how many times that exact
    feature vector occurs among ALL benign flows in the dataset (before the 2:1
    subsample, before dedup). It exists so benign FPR can be reported per FLOW:
    after dedup each unique shape is scored once, but a shape that stands for
    600k real flows must count 600k times in a false-positive rate an operator
    will live with. Attack rows carry multiplicity 1 (recall stays per-shape).
    """
    src_cols = list(COLUMN_MAP.keys()) + [LABEL_COL, GROUP_COL]
    df = pd.read_parquet(parquet_path, columns=src_cols).rename(columns=COLUMN_MAP)

    y = (df[LABEL_COL].astype(str).str.upper() != BENIGN_LABEL).astype(int)
    groups = df[GROUP_COL].astype(str)
    classes = df[LABEL_COL].astype(str)

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
    work["_c"] = classes.values
    attacks = work[work["_y"] == 1].copy()
    benign = work[work["_y"] == 0].copy()
    # Natural multiplicity of each benign shape, counted over ALL benign rows --
    # computed BEFORE subsampling so rare-vs-common is measured on the real
    # population, not on the 2:1 sample.
    attacks["_m"] = 1.0
    benign["_m"] = benign.groupby(config.FEATURE_ORDER)["_y"].transform("size").astype(float)
    n_benign = min(len(benign), int(len(attacks) * benign_ratio))
    benign = benign.sample(n=n_benign, random_state=seed)
    bal = pd.concat([attacks, benign]).sample(frac=1.0, random_state=seed)
    y_bal = bal.pop("_y").to_numpy()
    g_bal = bal.pop("_g").to_numpy()
    c_bal = bal.pop("_c").to_numpy()
    m_bal = bal.pop("_m").to_numpy()
    X_bal = bal[config.FEATURE_ORDER].to_numpy(dtype="float32")
    counts = {"total_rows": int(len(df)), "attack_rows": int(len(attacks)),
              "benign_rows_used": int(n_benign)}
    return X_bal, y_bal, g_bal, c_bal, m_bal, counts


def class_weights_alpha(classes: np.ndarray, alpha: float) -> np.ndarray:
    """Per-sample weights w ~ 1/n_class^alpha, benign treated as one class.

    alpha interpolates between the two failures this project has already lived:

      * alpha = 0   -> exactly unweighted. DoS Hulk + PortScan + DDoS are ~95% of
        attack rows, so the model could score 0.985 weighted recall while never
        once detecting a Web Attack.
      * alpha = 1   -> fully class-balanced. The rare classes pull as hard as the
        common ones -- and the fit that tried it bought its macro recall with
        false positives on common benign shapes (12x worse per-flow FPR).

    The shipped alpha is NOT chosen here: train the frontier, measure macro
    recall and per-flow benign FPR on the validation split, and let the FPR
    budget decide (see main). Weights are scaled to mean 1.0, which keeps the
    learners' step sizes sane without changing the ratios; at alpha=0 that makes
    every weight exactly 1.0, i.e. genuinely unweighted.
    """
    cls_arr = np.array([str(c) for c in classes])
    w = np.ones(len(cls_arr), dtype="float64")
    if alpha > 0:
        uniq, counts = np.unique(cls_arr, return_counts=True)
        per_class = {u: n ** (-float(alpha)) for u, n in zip(uniq, counts)}
        w = np.array([per_class[c] for c in cls_arr])
    return w / w.mean()


def benign_fpr(y_true, y_pred, mult) -> dict:
    """Benign false-positive rate, per SHAPE and per FLOW.

    Per-shape: fraction of unique benign feature vectors flagged (what a dedup
    test split naturally measures). Per-flow: the same errors weighted by each
    shape's natural multiplicity in the full dataset -- the rate an operator
    actually experiences, and the HEADLINE FPR of this project. The two diverged
    by 12x on the macro-balanced fit because its false positives landed on
    common shapes; per-shape reporting hid that entirely.
    """
    benign = (y_true == 0)
    fp = benign & (y_pred == 1)
    n_shapes = int(benign.sum())
    flows = float(mult[benign].sum())
    return {
        "per_flow_fpr": round(float(mult[fp].sum() / flows), 6) if flows else 0.0,
        "per_shape_fpr": round(float(fp.sum() / n_shapes), 6) if n_shapes else 0.0,
        "benign_shapes": n_shapes,
        "benign_flows_represented": int(flows),
    }


def per_class_recall(classes, y_true, y_pred) -> dict:
    """Recall for every attack class, plus macro and weighted averages.

    The headline number this project used to quote was the weighted one, which is
    an average dominated by three high-volume classes. Reporting both, next to the
    per-class table, is the difference between a claim and a sales pitch.
    """
    out = {}
    for cls in sorted({str(c) for c in classes}):
        mask = np.array([str(c) == cls for c in classes])
        if str(cls).upper() == BENIGN_LABEL:
            # For benign, "recall" is specificity: correctly left alone.
            out[cls] = {"n": int(mask.sum()),
                        "recall": round(float((y_pred[mask] == 0).mean()), 4)}
            continue
        out[cls] = {"n": int(mask.sum()),
                    "recall": round(float((y_pred[mask] == 1).mean()), 4)}

    attack_only = {k: v for k, v in out.items() if k.upper() != BENIGN_LABEL}
    macro = float(np.mean([v["recall"] for v in attack_only.values()]))
    total = sum(v["n"] for v in attack_only.values())
    weighted = float(sum(v["recall"] * v["n"] for v in attack_only.values()) / total)
    return {"per_class": out,
            "macro_recall": round(macro, 4),
            "weighted_recall": round(weighted, 4),
            "note": "macro = every attack class counts equally. weighted = by row "
                    "count, which this dataset lets 3 high-volume classes dominate."}


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


def train_gbt(Xtr, ytr, Xte, seed, sample_weight=None):
    gbt = HistGradientBoostingClassifier(max_iter=200, random_state=seed)
    gbt.fit(Xtr, ytr, sample_weight=sample_weight)
    prob = gbt.predict_proba(Xte)[:, 1]
    return gbt, prob


def train_cnn(Xtr, ytr, Xte, n_feat, epochs, seed, sample_weight=None):
    import tensorflow as tf
    tf.keras.utils.set_random_seed(seed)
    cnn = build_cnn(n_feat)
    # sample_weight, not class_weight: Keras' class_weight can only balance the
    # binary target, which is the very averaging that hid the blind classes. These
    # weights balance per ATTACK CLASS (see macro_balanced_weights).
    es = tf.keras.callbacks.EarlyStopping(monitor="val_loss", patience=3,
                                          restore_best_weights=True)
    cnn.fit(Xtr.reshape(-1, n_feat, 1), ytr, sample_weight=sample_weight,
            validation_split=0.1, epochs=epochs, batch_size=4096,
            callbacks=[es], verbose=2)
    prob = cnn.predict(Xte.reshape(-1, n_feat, 1), batch_size=8192, verbose=0).ravel()
    return cnn, prob


def evaluate_split(name, note, Xtr, Xte, ytr, yte, ctr, cte, mte, n_feat, epochs,
                   seed, alpha, threshold):
    """Fit scaler + both models on this split's train, eval on test. Returns
    (result_dict, fitted_scaler, fitted_gbt, fitted_cnn, gbt_pred, cnn_pred).

    `ctr`/`cte` are the attack-class labels for train/test: the first drives the
    alpha weighting, the second the per-class recall table. `mte` is the test
    rows' natural flow multiplicity for the per-flow benign FPR. `alpha` and
    `threshold` are the operating point chosen by the frontier sweep in main.
    """
    scaler = StandardScaler().fit(Xtr)
    Xtr_s = scaler.transform(Xtr).astype("float32")
    Xte_s = scaler.transform(Xte).astype("float32")
    w = class_weights_alpha(ctr, alpha)

    gbt, gbt_prob = train_gbt(Xtr_s, ytr, Xte_s, seed, sample_weight=w)
    gbt_pred = (gbt_prob >= threshold).astype(int)

    cnn, cnn_prob = train_cnn(Xtr_s, ytr, Xte_s, n_feat, epochs, seed,
                              sample_weight=w)
    cnn_pred = (cnn_prob >= threshold).astype(int)

    result = {
        "note": note,
        "alpha": alpha,
        "threshold": threshold,
        "test_size": int(len(yte)),
        "test_positives": int(yte.sum()),
        "gbt": scores(yte, gbt_pred, gbt_prob),
        "cnn": scores(yte, cnn_pred, cnn_prob),
        "gbt_benign_fpr": benign_fpr(yte, gbt_pred, mte),
        "cnn_benign_fpr": benign_fpr(yte, cnn_pred, mte),
        "gbt_confusion": cm_dict(confusion_matrix(yte, gbt_pred)),
        "cnn_confusion": cm_dict(confusion_matrix(yte, cnn_pred)),
        "gbt_per_class": per_class_recall(cte, yte, gbt_pred),
        "cnn_per_class": per_class_recall(cte, yte, cnn_pred),
    }
    print(f"  [{name}] GBT: {result['gbt']}")
    print(f"  [{name}] GBT macro recall: {result['gbt_per_class']['macro_recall']} "
          f"| weighted: {result['gbt_per_class']['weighted_recall']} "
          f"| per-flow benign FPR: {result['gbt_benign_fpr']['per_flow_fpr']}")
    print(f"  [{name}] CNN: {result['cnn']}")
    return result, scaler, gbt, cnn, gbt_pred, cnn_pred


# The operating-point grid. Alphas cap at 0.5 because 1.0 (fully balanced) is the
# configuration already shown to blow the FPR budget by 12x; thresholds start at
# 0.5 because below that the FPR only gets worse.
SWEEP_ALPHAS = [0.0, 0.15, 0.25, 0.35, 0.5]
SWEEP_THRESHOLDS = [round(0.5 + 0.05 * i, 2) for i in range(10)]  # 0.5 .. 0.95
FPR_BUDGET = 0.01  # hard ceiling on per-flow benign FPR, tuned on validation


def frontier_sweep(Xtr_s, ytr, ctr, Xva_s, yva, cva, mva, seed):
    """One GBT fit per alpha, one frontier row per (alpha, threshold).

    Every row carries the three numbers the pick is made from -- macro recall,
    per-class recall, per-flow benign FPR -- measured on the VALIDATION split
    only. The held-out test split is not consulted here at all.
    """
    rows = []
    for alpha in SWEEP_ALPHAS:
        w = class_weights_alpha(ctr, alpha)
        _, prob = train_gbt(Xtr_s, ytr, Xva_s, seed, sample_weight=w)
        for thr in SWEEP_THRESHOLDS:
            pred = (prob >= thr).astype(int)
            pc = per_class_recall(cva, yva, pred)
            fpr = benign_fpr(yva, pred, mva)
            rows.append({
                "alpha": alpha,
                "threshold": thr,
                "macro_recall": pc["macro_recall"],
                "weighted_recall": pc["weighted_recall"],
                "per_flow_benign_fpr": fpr["per_flow_fpr"],
                "per_shape_benign_fpr": fpr["per_shape_fpr"],
                "meets_fpr_budget": bool(fpr["per_flow_fpr"] <= FPR_BUDGET),
                "per_class_recall": {k: v["recall"]
                                     for k, v in pc["per_class"].items()
                                     if k.upper() != BENIGN_LABEL},
            })
        best_at_alpha = max((r for r in rows if r["alpha"] == alpha),
                            key=lambda r: r["macro_recall"])
        print(f"  alpha={alpha}: best macro recall {best_at_alpha['macro_recall']} "
              f"@thr={best_at_alpha['threshold']} "
              f"(per-flow FPR {best_at_alpha['per_flow_benign_fpr']})")
    return rows


def choose_operating_point(rows):
    """Max macro recall SUBJECT TO per-flow benign FPR <= FPR_BUDGET, on val.

    Ties go to unweighted@0.5 (the null hypothesis should win draws), then to
    lower FPR, then to the simpler point (lower alpha, lower threshold). If NO
    point fits the budget the sweep failed and we fall back to unweighted@0.5
    explicitly rather than shipping the least-bad violator as if it qualified.
    """
    default = next(r for r in rows
                   if r["alpha"] == 0.0 and r["threshold"] == 0.5)
    feasible = [r for r in rows if r["meets_fpr_budget"]]
    if not feasible:
        return default, ("NO grid point met the per-flow FPR budget of "
                         f"{FPR_BUDGET}; shipping unweighted@0.5 as the "
                         "documented fallback, NOT as a budget-compliant point.")

    def rank(r):
        is_default = r["alpha"] == 0.0 and r["threshold"] == 0.5
        return (-r["macro_recall"], not is_default,
                r["per_flow_benign_fpr"], r["alpha"], r["threshold"])

    best = min(feasible, key=rank)
    if best is default:
        return default, ("No weighted point beat unweighted@0.5 within the "
                         f"per-flow FPR budget of {FPR_BUDGET}; keeping it is "
                         "now a data-driven choice, not a default.")
    return best, (f"Maximises validation macro recall ({best['macro_recall']}) "
                  f"subject to per-flow benign FPR <= {FPR_BUDGET} "
                  f"(achieved {best['per_flow_benign_fpr']}).")


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
    X, y, g, c, m, counts = load_and_prepare(args.parquet, seed=args.seed)
    print(f"  balanced set: {X.shape}, positives={int(y.sum())}, {counts}")
    print(f"  features ({n_feat}): {config.FEATURE_ORDER}")

    # --- Leakage check (on full balanced, unscaled data) ---
    print("Leakage check ...")
    leak = leakage_check(X, y, args.seed)
    print("  flagged:", leak["flagged"] or "none")

    # --- Dedup exact-duplicate feature vectors (keep label) ---
    # The surviving row keeps its shape's FULL-population multiplicity, which is
    # what turns the deduped test split back into a per-flow FPR estimate.
    keyed = np.concatenate([X, y.reshape(-1, 1)], axis=1)
    _, uniq_idx = np.unique(keyed, axis=0, return_index=True)
    uniq_idx.sort()
    Xu, yu, cu, mu = X[uniq_idx], y[uniq_idx], c[uniq_idx], m[uniq_idx]
    dup_stats = {"balanced_rows": int(len(X)), "unique_rows": int(len(Xu)),
                 "duplicate_rate": round(1 - len(Xu) / len(X), 4)}
    print(f"  dedup: {dup_stats}")

    # --- Three-way split: 60 train / 20 validation / 20 test (dedup, stratified)
    # The frontier is tuned on VAL; TEST is opened exactly once, at the end, for
    # the chosen point. Tuning and reporting on the same rows is how operating
    # points flatter themselves.
    Xrest, Xte, yrest, yte, crest, cte, mrest, mte = train_test_split(
        Xu, yu, cu, mu, test_size=0.2, random_state=args.seed, stratify=yu)
    Xtr, Xva, ytr, yva, ctr, cva, mtr, mva = train_test_split(
        Xrest, yrest, crest, mrest, test_size=0.25, random_state=args.seed,
        stratify=yrest)
    print(f"  split: train={len(ytr)} val={len(yva)} test={len(yte)}")

    # --- Frontier sweep: alpha x threshold on the validation split ---
    print("Frontier sweep (alpha x threshold) on validation ...")
    sweep_scaler = StandardScaler().fit(Xtr)
    frontier = frontier_sweep(
        sweep_scaler.transform(Xtr).astype("float32"), ytr, ctr,
        sweep_scaler.transform(Xva).astype("float32"), yva, cva, mva, args.seed)
    chosen, why = choose_operating_point(frontier)
    alpha_star, thr_star = chosen["alpha"], chosen["threshold"]
    print(f"  CHOSEN operating point: alpha={alpha_star} threshold={thr_star}")
    print(f"  {why}")

    # --- HEADLINE: train split -> held-out TEST at the chosen point ---
    # Shipped models are trained on the 60% train split ONLY (not train+val):
    # the GBT below is bit-identical to the one the frontier measured, so the
    # selection evidence describes the exact artifact we deploy.
    print("Held-out test at the chosen operating point -> HEADLINE numbers ...")
    dedup_res, scaler, gbt, cnn, gbt_pred, cnn_pred = evaluate_split(
        "dedup-test", "Dedup + stratified, evaluated on the held-out 20% test "
        "split at the frontier-chosen operating point. Identical flows cannot "
        "span splits; test rows played no part in selection. Treat as REAL.",
        Xtr, Xte, ytr, yte, ctr, cte, mte, n_feat, args.epochs, args.seed,
        alpha_star, thr_star)

    # --- Reference: random stratified split (optimistic upper bound) ---
    print("Random stratified split -> optimistic upper bound ...")
    Xtr_r, Xte_r, ytr_r, yte_r, ctr_r, cte_r, mtr_r, mte_r = train_test_split(
        X, y, c, m, test_size=0.2, random_state=args.seed, stratify=y)
    rnd_res, *_ = evaluate_split(
        "random", "Random stratified split. Optimistic upper bound (duplicate "
        "flow bursts leak across train/test).",
        Xtr_r, Xte_r, ytr_r, yte_r, ctr_r, cte_r, mte_r, n_feat, args.epochs,
        args.seed, alpha_star, thr_star)

    # --- Reference: group by source IP (DEGENERATE, documented) ---
    print("Group split by source IP -> degenerate reference ...")
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=args.seed)
    gtr, gte = next(gss.split(X, y, groups=g))
    grp_res, *_ = evaluate_split(
        "group", "Group split by source IP. DEGENERATE: one IP emits 99.6% of "
        "attacks, so a held-out IP removes whole campaigns. Documented, not fair.",
        X[gtr], X[gte], y[gtr], y[gte], c[gtr], c[gte], m[gte], n_feat,
        args.epochs, args.seed, alpha_star, thr_star)

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
        "dropped_features": {
            "features": ["syn_count", "rst_count", "fin_count", "ack_count"],
            "reason": "Non-transferable. CIC-IDS-2017 PortScan rows carry all TCP "
                      "flags zero, but a real port scan sets SYN, so the model "
                      "learned a dataset artifact that cannot hold at serving "
                      "time: 1.00 recall on dataset PortScan rows, zero detections "
                      "on live scan traffic. Removed 2026-07-16.",
        },
        "protocol_encoding": PROTO_ENCODING,
        "duration_unit": "seconds (CICFlowMeter microseconds / 1e6, clipped >=0)",
        "label_map": {"0": "normal", "1": "suspicious"},
        "threshold": thr_star,
        "threshold_note": "Chosen by the validation frontier sweep; "
                          "config.CLASSIFY_THRESHOLD must be kept equal to this "
                          "value or serving no longer matches the metrics.",
        "input_shape": [n_feat, 1],
        "class_weighting": f"w ~ 1/n^alpha per class (benign is a class), "
                           f"alpha={alpha_star}. alpha and threshold were chosen "
                           f"by maximising validation macro recall subject to "
                           f"per-flow benign FPR <= {FPR_BUDGET}; see "
                           f"metrics.json operating_point/frontier.",
        "operating_point": {"alpha": alpha_star, "threshold": thr_star,
                            "selection": why},
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
        "headline_split": "dedup_stratified_test",
        "operating_point": {
            "alpha": alpha_star,
            "threshold": thr_star,
            "constraint": f"per-flow benign FPR <= {FPR_BUDGET}, on validation",
            "selection": why,
            "validation": chosen,
            "test_gbt_macro_recall": dedup_res["gbt_per_class"]["macro_recall"],
            "test_gbt_weighted_recall":
                dedup_res["gbt_per_class"]["weighted_recall"],
            "test_gbt_benign_fpr": dedup_res["gbt_benign_fpr"],
        },
        "fpr_definition": "per_flow_fpr is the HEADLINE false-positive rate: "
                          "each unique benign shape's error is weighted by how "
                          "many real flows that shape stands for in the full "
                          "dataset. per_shape_fpr counts each unique shape once "
                          "and UNDERSTATES operator pain when errors land on "
                          "common shapes (a 12x gap was measured on the fully "
                          "class-balanced fit). Judge FPR by per_flow_fpr.",
        "feature_order": config.FEATURE_ORDER,
        "dropped_features": meta["dropped_features"],
        "class_weighting": meta["class_weighting"],
        "how_to_read": "Read macro_recall, not recall. The binary `recall` under "
                       "each model, and the weighted_recall in the per-class block, "
                       "are averages over a test set where DoS Hulk + PortScan + "
                       "DDoS are ~95% of attack rows -- they can look excellent "
                       "while a whole attack class is never detected. macro_recall "
                       "counts every attack class once. The per_class table is the "
                       "honest answer and the only basis for a coverage claim. "
                       "For false positives, read gbt_benign_fpr.per_flow_fpr.",
        "frontier": {
            "note": "Validation-split measurements for every (alpha, threshold) "
                    "grid point; the operating point was picked from this table "
                    "and ONLY the chosen point was then scored on test.",
            "alphas": SWEEP_ALPHAS,
            "thresholds": SWEEP_THRESHOLDS,
            "fpr_budget": FPR_BUDGET,
            "rows": frontier,
        },
        "splits": {"dedup_stratified_test": dedup_res,
                   "random_stratified": rnd_res,
                   "group_by_source_ip": grp_res},
        "leakage_check": leak,
        "dedup_stats": dup_stats,
        "counts": counts,
    }
    with open(os.path.join(config.MODEL_DIR, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    print("\nDone. Artifacts in", config.MODEL_DIR)

    print("\nFrontier (validation): alpha  thr  macro  per-flow-FPR  in-budget")
    for r in frontier:
        mark = "*" if r is chosen else " "
        print(f" {mark} {r['alpha']:4.2f}  {r['threshold']:4.2f}  "
              f"{r['macro_recall']:.4f}  {r['per_flow_benign_fpr']:.6f}  "
              f"{'yes' if r['meets_fpr_budget'] else 'NO'}")
    print(f"\nCHOSEN: alpha={alpha_star} threshold={thr_star} -- {why}")

    pc = dedup_res["gbt_per_class"]
    fpr = dedup_res["gbt_benign_fpr"]
    print(f"\nGBT held-out TEST at chosen point -- macro={pc['macro_recall']} "
          f"weighted={pc['weighted_recall']} "
          f"per-flow benign FPR={fpr['per_flow_fpr']} "
          f"(per-shape {fpr['per_shape_fpr']})")
    for cls, v in sorted(pc["per_class"].items(), key=lambda kv: kv[1]["recall"]):
        print(f"  {cls:34s} {v['recall']:.4f}  (n={v['n']})")
    print("\nleakage_flagged:", leak["flagged"] or "none")
    if thr_star != config.CLASSIFY_THRESHOLD:
        print(f"\n!! config.CLASSIFY_THRESHOLD is {config.CLASSIFY_THRESHOLD} but "
              f"the chosen threshold is {thr_star} -- update config.py before "
              f"shipping, or serving will not match these metrics.")


if __name__ == "__main__":
    main()
