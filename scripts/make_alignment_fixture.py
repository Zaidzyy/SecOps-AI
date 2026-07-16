"""Sample a small, committable CIC-IDS-2017 fixture for the alignment test.

The alignment test is the only check that answers "do REAL attack flows classify
as suspicious through the live serving path?" -- and it used to skip unless you
had a 370 MB parquet and remembered to set CICIDS_PARQUET, which meant in practice
it never ran. A check that only runs on one machine is not a check. This carves a
few hundred rows out of the dataset so it runs on every clone, for free.

What it writes: verbatim source rows (original column names, original values,
original labels), NOT preprocessed features. The test therefore applies exactly
the same rename/proto-encode/duration-scale path train_flow_model.py does -- a
fixture of pre-cooked features would test the cooking against itself.

Rows are stratified per attack class (not sampled uniformly, which would be ~80%
BENIGN and might contain a couple of dozen attacks total), and filtered to those
the test can reconstruct into a packet sequence, so a fixture row is never a
sample the test has to throw away.

Regenerate (needs the full dataset):

    python scripts/make_alignment_fixture.py
    CICIDS_PARQUET=/path/to/CICIDS_Flow.parquet python scripts/make_alignment_fixture.py
"""
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from train_flow_model import COLUMN_MAP, LABEL_COL, BENIGN_LABEL  # noqa: E402

# Default to the HuggingFace cache location the trainer pulls from.
DEFAULT_PARQUET = os.path.join(
    os.path.expanduser("~"), ".cache", "huggingface", "hub",
    "datasets--rdpahalavan--CIC-IDS2017", "snapshots",
    "eee96b6abc2c4bb621fd67679a4aa24bddc4be6a", "Network-Flows",
    "CICIDS_Flow.parquet")

PARQUET = os.environ.get("CICIDS_PARQUET") or DEFAULT_PARQUET
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "tests", "fixtures", "cicids_alignment_sample.csv")

PER_ATTACK_CLASS = 25
BENIGN_ROWS = 120
SEED = 42


def reconstructable(row) -> bool:
    """Mirrors tests/test_feature_alignment.py::_reconstructable.

    A flow the test cannot rebuild into a packet sequence (bytes with no packets
    to carry them) is not a fixture row worth keeping -- the test would only skip
    over it.
    """
    fp, bp = int(round(row["fwd_packets"])), int(round(row["bwd_packets"]))
    if fp + bp == 0:
        return False
    if row["fwd_bytes"] > 0 and fp == 0:
        return False
    if row["bwd_bytes"] > 0 and bp == 0:
        return False
    return True


def main():
    if not os.path.exists(PARQUET):
        sys.exit(f"dataset not found: {PARQUET}\n"
                 f"set CICIDS_PARQUET to the CICIDS_Flow.parquet path")

    src_cols = list(COLUMN_MAP.keys()) + [LABEL_COL]
    df = pd.read_parquet(PARQUET, columns=src_cols)

    # Filter on renamed copies, but keep and emit the ORIGINAL rows.
    probe = df.rename(columns=COLUMN_MAP)
    for c in ("fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes"):
        probe[c] = pd.to_numeric(probe[c], errors="coerce").fillna(0.0)
    keep = probe.apply(reconstructable, axis=1)
    df = df[keep.to_numpy()]

    chunks = []
    for label, group in df.groupby(LABEL_COL, observed=True):
        n = BENIGN_ROWS if str(label).upper() == BENIGN_LABEL else PER_ATTACK_CLASS
        # Rare classes (Heartbleed has 11 rows total) contribute everything they
        # have rather than being dropped -- they are the most interesting rows here.
        chunks.append(group.sample(n=min(n, len(group)), random_state=SEED))

    out = pd.concat(chunks).sample(frac=1.0, random_state=SEED)  # shuffle
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    out.to_csv(OUT, index=False, encoding="utf-8")

    labels = out[LABEL_COL].value_counts()
    n_attack = int((out[LABEL_COL].astype(str).str.upper() != BENIGN_LABEL).sum())
    print(f"wrote {len(out)} rows -> {OUT} "
          f"({os.path.getsize(OUT) / 1024:.1f} KB)")
    print(f"{n_attack} attack rows across {len(labels) - 1} classes, "
          f"{len(out) - n_attack} benign")
    print(labels.to_string())


if __name__ == "__main__":
    main()
