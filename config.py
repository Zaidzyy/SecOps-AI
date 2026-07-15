"""Central configuration for SecOps-AI's detection engine.

Single source of truth for model paths, the classification threshold, and the
flow-aggregation timing knobs. Nothing detection-related should hardcode these
values elsewhere -- import them from here.
"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Our own trained flow classifier (replaces the borrowed SecIDS-CNN.h5) ---
# We do NOT use SecIDS-CNN.h5 for inference: its 10-feature training contract
# (feature names, order, and scaler) was never published, so its verdicts on
# our features would be meaningless. See README for the full rationale.
#
# Primary detector is a gradient-boosted tree (GBT): on these 10 low-dimensional
# tabular flow features it clearly outperforms the compact Conv1D (trees beat
# CNNs on tabular data). The Conv1D is kept, trained and documented, as the
# benchmarked comparison baseline -- not the live detector.
MODEL_DIR = os.path.join(BASE_DIR, "models")
PRIMARY_MODEL_TYPE = "gbt"                                    # "gbt" | "cnn"
FLOW_MODEL_PATH = os.path.join(MODEL_DIR, "secids_flow_gbt.joblib")   # primary
FLOW_CNN_PATH = os.path.join(MODEL_DIR, "secids_flow_cnn.keras")      # baseline
FLOW_SCALER_PATH = os.path.join(MODEL_DIR, "secids_flow_scaler.joblib")
FLOW_META_PATH = os.path.join(MODEL_DIR, "secids_flow_meta.json")

# Probability of "attack" above this is flagged "suspicious".
CLASSIFY_THRESHOLD = 0.5

# --- Flow aggregation ---
# A flow is emitted for classification when it is idle for this long (no new
# packet) or is explicitly closed (TCP FIN both ways / RST).
FLOW_IDLE_TIMEOUT_S = 15.0
# Hard cap: emit a long-lived flow even if still active, so beaconing/long
# connections still get classified.
FLOW_ACTIVE_TIMEOUT_S = 120.0

# Canonical feature order. This is OUR contract (the upstream model never
# published theirs). flow_tracker emits these names; cnn_engine consumes them
# in exactly this order; the trainer aligns CIC-IDS-2017 columns to them.
FEATURE_ORDER = [
    "duration_s",    # flow wall-clock duration in seconds
    "protocol",      # IP protocol number (6=TCP, 17=UDP, other=proto no.)
    "fwd_packets",   # packets initiator -> responder
    "bwd_packets",   # packets responder -> initiator
    "fwd_bytes",     # payload bytes initiator -> responder
    "bwd_bytes",     # payload bytes responder -> initiator
    "syn_count",     # TCP packets in the flow with SYN set
    "rst_count",     # TCP packets in the flow with RST set
    "fin_count",     # TCP packets in the flow with FIN set
    "ack_count",     # TCP packets in the flow with ACK set
]
