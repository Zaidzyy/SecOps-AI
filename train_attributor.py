"""Train the Stage-2 attack-family attributor (MITRE ATT&CK mapping).

Two-stage design, honestly split:

  Stage 1 (existing, UNCHANGED): the binary GBT gate, FPR-tuned on the frontier
    (alpha=0.5, thr=0.95). It answers "is this flow malicious?" and nothing else
    -- a binary detector cannot name a technique.
  Stage 2 (this model): a multi-class GBT that runs ONLY on flows Stage 1
    flagged, predicting the attack FAMILY from the same 6 transferable
    features. The family -> ATT&CK technique lookup is a static curated table
    (attack_mapping.py); the ML never invents a technique ID.

Same methodology as train_flow_model.py, because the leakage risks are the
same dataset's: same 6 features, same column prep, exact-duplicate dedup
BEFORE the split, stratified 60/20/20 train/val/test. Class weighting
(w ~ 1/n^alpha per family) and the serving confidence threshold are chosen on
the VALIDATION split; the confusion matrix and per-family numbers reported at
the end come from the held-out TEST split the selection never saw.

HONESTY RULE built in at training time: the attributor abstains. Predictions
below the confidence threshold -- and predictions of the "other" grab-bag
family (Infiltration + Heartbleed, too rare to learn) -- serve as
"technique unattributed" rather than forcing a wrong technique. The threshold
is picked as: maximise attribution coverage SUBJECT TO accuracy-when-attributed
>= ACCURACY_FLOOR on validation. Coverage is what we give up; accuracy is what
we refuse to give up.

Run:  venv/Scripts/python.exe train_attributor.py --parquet <path>
"""
import argparse
import json
import os
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

import config
from train_flow_model import COLUMN_MAP, PROTO_ENCODING, LABEL_COL, BENIGN_LABEL

# CIC-IDS-2017 label -> attack family. Labels are normalised first (the CSV/
# parquet uses U+2013 en-dashes in the Web Attack labels -- a plain hyphen
# lookup silently misses them, which we learned the hard way).
#
# Families, not raw labels: the four DoS tools are one behaviour to a flow
# sensor, and ATT&CK maps at that granularity anyway. "other" is the explicit
# grab-bag for classes too rare to learn (Infiltration ~36 rows, Heartbleed
# ~11); predicting it serves as "unattributed", never as a technique.
FAMILY_MAP = {
    "PortScan": "port-scan",
    "DoS Hulk": "dos",
    "DoS GoldenEye": "dos",
    "DoS slowloris": "dos",
    "DoS Slowhttptest": "dos",
    "DDoS": "ddos",
    "FTP-Patator": "brute-force",
    "SSH-Patator": "brute-force",
    "Bot": "botnet",
    "Web Attack - Brute Force": "web-attack",
    "Web Attack - XSS": "web-attack",
    "Web Attack - Sql Injection": "web-attack",
    "Infiltration": "other",
    "Heartbleed": "other",
}
ABSTAIN_FAMILY = "other"

# Confidence-threshold selection: maximise coverage subject to this floor on
# accuracy-when-attributed, both measured on validation. Same shape as the
# binary model's FPR budget: the constraint is the promise, coverage is the
# objective.
ACCURACY_FLOOR = 0.95
THRESHOLD_GRID = [round(0.30 + 0.05 * i, 2) for i in range(14)]  # 0.30 .. 0.95

SWEEP_ALPHAS = [0.0, 0.25, 0.5, 0.75, 1.0]


def normalize_label(label: str) -> str:
    """En/em dashes -> hyphen, collapse whitespace. U+2013 in the Web Attack
    labels is a real artifact of this dataset."""
    s = str(label).replace("–", "-").replace("—", "-")
    return " ".join(s.split())


def load_attack_rows(parquet_path):
    """Attack rows only, same feature prep as the binary trainer.
    Returns (X, families, label_counts)."""
    src_cols = list(COLUMN_MAP.keys()) + [LABEL_COL]
    df = pd.read_parquet(parquet_path, columns=src_cols).rename(columns=COLUMN_MAP)
    df = df[df[LABEL_COL].astype(str).str.upper() != BENIGN_LABEL].copy()

    labels = df[LABEL_COL].map(normalize_label)
    unknown = sorted(set(labels) - set(FAMILY_MAP))
    if unknown:
        print(f"  [WARN] unmapped labels -> '{ABSTAIN_FAMILY}': {unknown}")
    families = labels.map(FAMILY_MAP).fillna(ABSTAIN_FAMILY).to_numpy()

    df["protocol"] = (df["protocol"].astype(str).str.lower()
                      .map(PROTO_ENCODING).fillna(0).astype(float))
    df["duration_s"] = (df["duration_s"].astype(float) / 1_000_000.0).clip(lower=0.0)
    X = df[config.FEATURE_ORDER].astype(float)
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0).to_numpy(dtype="float32")

    label_counts = labels.value_counts().to_dict()
    return X, families, label_counts


def family_weights(families: np.ndarray, alpha: float) -> np.ndarray:
    """w ~ 1/n_family^alpha, mean-scaled to 1.0 (alpha=0 -> exactly unweighted).
    Same scheme as the binary trainer's class_weights_alpha."""
    w = np.ones(len(families), dtype="float64")
    if alpha > 0:
        uniq, counts = np.unique(families, return_counts=True)
        per = {u: n ** (-float(alpha)) for u, n in zip(uniq, counts)}
        w = np.array([per[f] for f in families])
    return w / w.mean()


def attribution_report(y_true, proba, classes, threshold) -> dict:
    """Apply the serving rule (abstain below threshold or on ABSTAIN_FAMILY)
    and measure what an operator would see."""
    pred_idx = proba.argmax(axis=1)
    pred = classes[pred_idx]
    conf = proba[np.arange(len(pred_idx)), pred_idx]
    attributed = (conf >= threshold) & (pred != ABSTAIN_FAMILY)
    n = len(y_true)
    n_attr = int(attributed.sum())
    correct = (pred[attributed] == y_true[attributed])
    return {
        "threshold": threshold,
        "coverage": round(n_attr / n, 4) if n else 0.0,
        "accuracy_when_attributed": round(float(correct.mean()), 4) if n_attr else None,
        "attributed": n_attr,
        "total": n,
    }


def choose_threshold(y_val, proba_val, classes):
    """Max coverage s.t. accuracy-when-attributed >= ACCURACY_FLOOR (validation).
    If nothing meets the floor, take the most accurate point and SAY SO."""
    rows = [attribution_report(y_val, proba_val, classes, t) for t in THRESHOLD_GRID]
    feasible = [r for r in rows if r["accuracy_when_attributed"] is not None
                and r["accuracy_when_attributed"] >= ACCURACY_FLOOR]
    if feasible:
        best = max(feasible, key=lambda r: (r["coverage"],
                                            r["accuracy_when_attributed"]))
        why = (f"Maximises validation coverage ({best['coverage']}) subject to "
               f"accuracy-when-attributed >= {ACCURACY_FLOOR} "
               f"(achieved {best['accuracy_when_attributed']}).")
    else:
        best = max((r for r in rows if r["accuracy_when_attributed"] is not None),
                   key=lambda r: r["accuracy_when_attributed"])
        why = (f"NO threshold met the {ACCURACY_FLOOR} accuracy floor on "
               f"validation; shipping the most accurate point "
               f"({best['accuracy_when_attributed']}) as a documented "
               f"compromise, not a floor-compliant one.")
    return best, why, rows


def per_family_table(y_true, proba, classes, threshold) -> dict:
    """For each true family: how often it is attributed, and to what."""
    pred_idx = proba.argmax(axis=1)
    pred = classes[pred_idx]
    conf = proba[np.arange(len(pred_idx)), pred_idx]
    attributed = (conf >= threshold) & (pred != ABSTAIN_FAMILY)
    out = {}
    for fam in sorted(set(y_true)):
        mask = (y_true == fam)
        n = int(mask.sum())
        attr = attributed & mask
        n_attr = int(attr.sum())
        out[fam] = {
            "n": n,
            "attributed_rate": round(n_attr / n, 4),
            "accuracy_when_attributed":
                round(float((pred[attr] == fam).mean()), 4) if n_attr else None,
            "argmax_recall": round(float((pred[mask] == fam).mean()), 4),
        }
    return out


def print_confusion(cm, classes, title):
    width = max(len(c) for c in classes) + 2
    print(f"\n{title}")
    print(" " * width + "".join(f"{c[:10]:>11s}" for c in classes) + "   (predicted)")
    for i, row_label in enumerate(classes):
        print(f"{row_label:<{width}s}" + "".join(f"{v:>11d}" for v in cm[i]))


def save_confusion_png(cm, classes, title, path_png):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(6.5, 6.5))
        ax.imshow(cm, cmap="Blues")
        for (i, j), v in np.ndenumerate(cm):
            ax.text(j, i, f"{v}", ha="center", va="center", fontsize=8)
        ax.set_xticks(range(len(classes)))
        ax.set_xticklabels(classes, rotation=45, ha="right")
        ax.set_yticks(range(len(classes)))
        ax.set_yticklabels(classes)
        ax.set_xlabel("predicted family")
        ax.set_ylabel("actual family")
        ax.set_title(title)
        fig.tight_layout()
        fig.savefig(path_png, dpi=120)
        plt.close(fig)
        return True
    except Exception as e:
        print(f"(skipped {path_png}: {e})")
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--parquet", required=True)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    os.makedirs(config.MODEL_DIR, exist_ok=True)

    print("Loading attack rows ...")
    X, fams, label_counts = load_attack_rows(args.parquet)
    print(f"  attack rows: {len(X)}; label counts: {label_counts}")

    # --- Dedup exact duplicates (feature vector + family) BEFORE splitting ---
    # Same rationale as the binary trainer: a DoS flood is thousands of
    # near-identical rows, and letting one shape sit in both train and test
    # inflates every number that follows.
    fam_codes, fam_uniques = pd.factorize(fams)
    keyed = np.concatenate([X, fam_codes.reshape(-1, 1).astype("float32")], axis=1)
    _, uniq_idx = np.unique(keyed, axis=0, return_index=True)
    uniq_idx.sort()
    Xu, fu = X[uniq_idx], fams[uniq_idx]
    dup_stats = {"attack_rows": int(len(X)), "unique_rows": int(len(Xu)),
                 "duplicate_rate": round(1 - len(Xu) / len(X), 4)}
    print(f"  dedup: {dup_stats}")
    fam_counts = pd.Series(fu).value_counts().to_dict()
    print(f"  family counts (unique shapes): {fam_counts}")

    # --- 60/20/20 stratified by family; val picks alpha + threshold, test is
    # opened once at the end for the reported confusion matrix. ---
    Xrest, Xte, yrest, yte = train_test_split(
        Xu, fu, test_size=0.2, random_state=args.seed, stratify=fu)
    Xtr, Xva, ytr, yva = train_test_split(
        Xrest, yrest, test_size=0.25, random_state=args.seed, stratify=yrest)
    print(f"  split: train={len(ytr)} val={len(yva)} test={len(yte)}")

    scaler = StandardScaler().fit(Xtr)
    Xtr_s = scaler.transform(Xtr).astype("float32")
    Xva_s = scaler.transform(Xva).astype("float32")
    Xte_s = scaler.transform(Xte).astype("float32")

    # --- Alpha sweep on validation: macro-F1 over families ---
    # There is no FPR budget here -- Stage 1 already decided maliciousness;
    # Stage-2 errors are between attack families. Macro-F1 keeps the rare
    # families from being drowned by DoS Hulk's volume.
    print("Alpha sweep (validation macro-F1) ...")
    best_alpha, best_f1, best_model, best_proba = None, -1.0, None, None
    for alpha in SWEEP_ALPHAS:
        model = HistGradientBoostingClassifier(max_iter=300, random_state=args.seed)
        model.fit(Xtr_s, ytr, sample_weight=family_weights(ytr, alpha))
        proba = model.predict_proba(Xva_s)
        f1 = f1_score(yva, model.classes_[proba.argmax(axis=1)],
                      average="macro", zero_division=0)
        print(f"  alpha={alpha:4.2f}: val macro-F1 = {f1:.4f}")
        if f1 > best_f1:
            best_alpha, best_f1, best_model, best_proba = alpha, f1, model, proba
    print(f"  CHOSEN alpha={best_alpha} (val macro-F1 {best_f1:.4f})")

    classes = best_model.classes_

    # --- Confidence threshold: coverage vs accuracy, on validation ---
    print("Confidence-threshold sweep (validation) ...")
    chosen, why, sweep_rows = choose_threshold(yva, best_proba, classes)
    for r in sweep_rows:
        mark = "*" if r is chosen else " "
        print(f" {mark} thr={r['threshold']:.2f}  coverage={r['coverage']:.4f}  "
              f"acc-when-attributed={r['accuracy_when_attributed']}")
    print(f"  CHOSEN threshold={chosen['threshold']} -- {why}")

    # --- Held-out TEST: the numbers that get reported ---
    print("\nHeld-out test ...")
    proba_te = best_model.predict_proba(Xte_s)
    pred_te = classes[proba_te.argmax(axis=1)]
    cm = confusion_matrix(yte, pred_te, labels=list(classes))
    test_attr = attribution_report(yte, proba_te, classes, chosen["threshold"])
    test_macro_f1 = round(float(f1_score(yte, pred_te, average="macro",
                                         zero_division=0)), 4)
    per_family = per_family_table(yte, proba_te, classes, chosen["threshold"])

    print_confusion(cm, list(classes), "TEST confusion matrix (argmax, before "
                                       "the abstain rule):")
    print(f"\nTEST argmax macro-F1: {test_macro_f1}")
    print(f"TEST with abstain rule (thr={chosen['threshold']}, "
          f"'{ABSTAIN_FAMILY}' never attributed):")
    print(f"  coverage={test_attr['coverage']}  "
          f"accuracy-when-attributed={test_attr['accuracy_when_attributed']}  "
          f"({test_attr['attributed']}/{test_attr['total']} attributed)")
    print("\nPer-family (test):")
    print(f"  {'family':<14s} {'n':>6s} {'argmax-recall':>14s} "
          f"{'attributed':>11s} {'acc-when-attr':>14s}")
    for fam, v in sorted(per_family.items()):
        acc = v["accuracy_when_attributed"]
        print(f"  {fam:<14s} {v['n']:>6d} {v['argmax_recall']:>14.4f} "
              f"{v['attributed_rate']:>11.4f} "
              f"{acc if acc is not None else '   --':>14}")

    # --- Ship ---
    joblib.dump(best_model, config.ATTRIBUTOR_MODEL_PATH)
    joblib.dump(scaler, config.ATTRIBUTOR_SCALER_PATH)
    save_confusion_png(cm, list(classes), "Stage-2 attributor - dedup test split",
                       os.path.join(config.MODEL_DIR, "confusion_attributor.png"))

    meta = {
        "role": "Stage-2 attack-family attributor. Runs ONLY on flows the "
                "binary Stage-1 gate flagged suspicious. Family -> ATT&CK "
                "technique lookup is static (attack_mapping.py); this model "
                "never names a technique itself.",
        "feature_order": config.FEATURE_ORDER,
        "families": sorted(set(FAMILY_MAP.values())),
        "family_map": FAMILY_MAP,
        "abstain_family": ABSTAIN_FAMILY,
        "confidence_threshold": chosen["threshold"],
        "threshold_selection": why,
        "accuracy_floor": ACCURACY_FLOOR,
        "alpha": best_alpha,
        "alpha_selection": f"max validation macro-F1 over {SWEEP_ALPHAS}",
        "validation": {"macro_f1": round(best_f1, 4), "attribution": chosen},
        "test": {
            "argmax_macro_f1": test_macro_f1,
            "attribution": test_attr,
            "per_family": per_family,
            "confusion_labels": list(classes),
            "confusion_matrix": cm.tolist(),
        },
        "threshold_sweep_validation": sweep_rows,
        "dedup_stats": dup_stats,
        "family_counts_unique": {k: int(v) for k, v in fam_counts.items()},
        "label_counts_raw": {k: int(v) for k, v in label_counts.items()},
        "dataset": "CIC-IDS-2017 (rdpahalavan/CIC-IDS2017, Network-Flows parquet)",
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(config.ATTRIBUTOR_META_PATH, "w") as f:
        json.dump(meta, f, indent=2)

    print(f"\nDone. Artifacts: {config.ATTRIBUTOR_MODEL_PATH}, "
          f"{config.ATTRIBUTOR_SCALER_PATH}, {config.ATTRIBUTOR_META_PATH}")


if __name__ == "__main__":
    main()
