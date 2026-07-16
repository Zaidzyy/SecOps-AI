"""Central configuration for SecOps-AI's detection engine.

Single source of truth for model paths, the classification threshold, and the
flow-aggregation timing knobs. Nothing detection-related should hardcode these
values elsewhere -- import them from here.
"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# The database. Absolute by default so the app opens the SAME file regardless of
# the working directory it was launched from; SECOPS_DB overrides it, which is how
# the tests point the app at a throwaway DB instead of the real one.
DB_PATH = os.getenv("SECOPS_DB", os.path.join(BASE_DIR, "system_metrics.db"))

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
#
# NOTE on the flag features: despite the "_count" names (inherited from
# CICFlowMeter's column titles) these are BINARY PRESENCE indicators, 0.0 or 1.0
# -- that is how CIC-IDS-2017 defines them and how the model was trained. See
# flow_tracker.Flow.to_features().
FEATURE_ORDER = [
    "duration_s",    # flow wall-clock duration in seconds
    "protocol",      # IP protocol number (6=TCP, 17=UDP, other=proto no.)
    "fwd_packets",   # packets initiator -> responder
    "bwd_packets",   # packets responder -> initiator
    "fwd_bytes",     # payload bytes initiator -> responder
    "bwd_bytes",     # payload bytes responder -> initiator
    "syn_count",     # 1.0 if any packet in the flow had SYN set, else 0.0
    "rst_count",     # 1.0 if any packet in the flow had RST set, else 0.0
    "fin_count",     # 1.0 if any packet in the flow had FIN set, else 0.0
    "ack_count",     # 1.0 if any packet in the flow had ACK set, else 0.0
]

# --- Ingestion pipeline (Phase 2) ---
# 3 stages: sniff thread -> capture_queue -> N enrichment workers -> write_queue
# -> ONE batched DB writer. See pipeline.py.

# Bounded so a slow consumer can never grow memory without limit. On overflow we
# DROP and count rather than block: a blocked sniffer stops seeing ALL traffic,
# which is strictly worse than losing some packets. Sized to absorb bursts.
CAPTURE_QUEUE_MAX = 20000

# Enrichment is I/O-bound (geo/reputation HTTP on cache misses), so more threads
# than cores is correct here; they spend most of their time waiting.
ENRICHMENT_WORKERS = 8

# The DB writer is the only thread allowed to write SQLite. SQLite serializes
# writes, so extra writer threads would just trade I/O-blocking for lock-blocking.
WRITE_QUEUE_MAX = 50000
DB_BATCH_SIZE = 200            # flush when this many rows are pending...
DB_FLUSH_INTERVAL_S = 0.5      # ...or this long has passed, whichever is first.

# --- Enrichment caches ---
# Each IP hits the network at most once per TTL window. Geo data is effectively
# static, so it can be cached far longer than reputation, which changes.
GEO_CACHE_TTL_S = 24 * 3600
GEO_CACHE_MAX = 16384
REP_CACHE_TTL_S = 900
REP_CACHE_MAX = 16384
ENRICHMENT_HTTP_TIMEOUT_S = 4.0

# --- Read API (Phase 3) ---
# Paged so a client can never ask the DB for an unbounded result set.
API_PAGE_SIZE_DEFAULT = 50
API_PAGE_SIZE_MAX = 500

# Threat-map aggregation. Coordinates are rounded to this many decimals before
# grouping, so many detections from one city collapse into ONE map point instead
# of a pile of overlapping markers. 1 decimal ~= 11 km.
THREAT_MAP_PRECISION = 1
THREAT_MAP_MAX_POINTS = 500

# Packets/sec is measured from a sampler thread rather than from whoever happens
# to call /stats, so the number does not depend on how often the UI polls.
RATE_SAMPLE_INTERVAL_S = 1.0
RATE_WINDOW_S = 30.0
