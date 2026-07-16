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

# --- Stage 2: attack-family attributor (MITRE ATT&CK mapping) ---
# Multi-class GBT that runs ONLY on flows the binary gate already flagged
# suspicious, predicting the attack FAMILY from the same 6 features. The
# family -> ATT&CK technique lookup is static and curated (attack_mapping.py);
# the ML never invents a technique ID. Trained by train_attributor.py.
ATTRIBUTOR_MODEL_PATH = os.path.join(MODEL_DIR, "secids_attributor.joblib")
ATTRIBUTOR_SCALER_PATH = os.path.join(MODEL_DIR, "secids_attributor_scaler.joblib")
ATTRIBUTOR_META_PATH = os.path.join(MODEL_DIR, "secids_attributor_meta.json")

# Probability of "attack" above this is flagged "suspicious".
#
# 0.95 is not a hunch -- it is the operating point chosen by the frontier sweep
# in train_flow_model.py (alpha=0.5 class weighting x threshold grid, selected on
# a validation split): it maximises macro attack recall subject to a HARD budget
# of per-flow benign FPR <= 1%. The high threshold is what buys back the false
# positives that alpha=0.5's rare-class emphasis would otherwise spray on common
# benign shapes. Must stay equal to models/secids_flow_meta.json's "threshold";
# retrain rather than hand-tune (a new sweep re-derives it from data).
CLASSIFY_THRESHOLD = 0.95

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
# ONLY features whose train-time and serve-time semantics are identical belong
# here. Every one below means the same thing in a CIC-IDS-2017 row as it does in a
# flow flow_tracker built from live packets: a count of packets is a count of
# packets, a byte total is a byte total.
#
# The four TCP flag features (syn/rst/fin/ack) were REMOVED for failing exactly
# that test. CIC-IDS-2017's PortScan rows carry syn=rst=ack=0, while a real port
# scan observed on the wire obviously sets SYN. The model duly learned "PortScan
# means flags are zero" -- true of the dataset, false of the network. It scored
# 1.00 on dataset PortScan rows and never fired on real scan traffic. A feature
# that means different things in training and in production is worse than no
# feature: it teaches the model a rule that cannot hold at serving time. See
# models/metrics.json for what dropping them cost per attack class.
#
# flow_tracker still TRACKS the flags -- TCP teardown detection needs them -- it
# just no longer feeds them to the model.
FEATURE_ORDER = [
    "duration_s",    # flow wall-clock duration in seconds
    "protocol",      # IP protocol number (6=TCP, 17=UDP, other=proto no.)
    "fwd_packets",   # packets initiator -> responder
    "bwd_packets",   # packets responder -> initiator
    "fwd_bytes",     # payload bytes initiator -> responder
    "bwd_bytes",     # payload bytes responder -> initiator
]

# --- Ingestion pipeline (Phase 2) ---
# 3 stages: sniff thread -> shard by flow key -> N enrichment workers (one per
# shard) -> write_queue -> ONE batched DB writer. See pipeline.py.

# TOTAL in-flight packets across all shards (each shard gets
# CAPTURE_QUEUE_MAX // ENRICHMENT_WORKERS). Bounded so a slow consumer can never
# grow memory without limit. On overflow we DROP and count rather than block: a
# blocked sniffer stops seeing ALL traffic, which is strictly worse than losing
# some packets. Sized to absorb bursts.
CAPTURE_QUEUE_MAX = 20000

# Enrichment is I/O-bound (geo/reputation HTTP on cache misses), so more threads
# than cores is correct here; they spend most of their time waiting.
#
# This is ALSO the shard count: one worker per shard, since a shard's FlowTracker
# is owned by exactly one thread. Changing it changes how flows distribute across
# workers, not which worker any given flow's packets agree on.
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

# --- Web app / auth (Phase 4a) ---
# The session-signing key. REQUIRED to start the server: without a stable key,
# every restart would invalidate all sessions, and a guessable default would
# make session forgery trivial. app_groq warns at import (tests/replay still
# work on an ephemeral key) and refuses to start the server if unset.
SECRET_KEY = os.getenv("SECOPS_SECRET_KEY")

HOST = os.getenv("SECOPS_HOST", "127.0.0.1")
PORT = int(os.getenv("SECOPS_PORT", "5000"))

# Socket.IO CORS allowlist. Never "*": the console is same-origin, so the only
# origins that legitimately open the WebSocket are the server's own. Comma-
# separated env override for anything else (e.g. a reverse proxy hostname).
_DEFAULT_ORIGINS = f"http://{HOST}:{PORT},http://localhost:{PORT},http://127.0.0.1:{PORT}"
ALLOWED_ORIGINS = sorted({o.strip() for o in
                          os.getenv("SECOPS_ALLOWED_ORIGINS", _DEFAULT_ORIGINS).split(",")
                          if o.strip()})

# Debug is opt-in, never the default: debug mode ships the Werkzeug debugger,
# which is remote code execution for anyone who can reach the port.
DEBUG = os.getenv("SECOPS_DEBUG", "0").lower() in ("1", "true", "yes")

# Flask-SocketIO refuses to serve on Werkzeug when stdin is not a TTY (its
# production guard). Interactive `python app_groq.py` is unaffected; this
# opt-in exists for non-interactive DEV contexts only (CI smoke tests,
# background runs). A real deployment gets a real WSGI server in Phase 4b.
ALLOW_WERKZEUG = os.getenv("SECOPS_ALLOW_WERKZEUG", "0").lower() in ("1", "true", "yes")

# Session cookie: HttpOnly and SameSite=Lax are unconditional (set in app_groq);
# Secure is opt-in because it requires HTTPS, which a local demo does not have.
SESSION_COOKIE_SECURE = os.getenv("SECOPS_COOKIE_SECURE", "0").lower() in ("1", "true", "yes")

# Login brute-force throttle: after this many failed attempts from one address
# inside the window, /login answers 429 until the window slides past.
LOGIN_MAX_FAILURES = 5
LOGIN_FAILURE_WINDOW_S = 300.0

# --- Serving / container (Phase 4b) ---
# Socket.IO async mode must agree with how the process is served: 'threading'
# for dev (`python app_groq.py` on Werkzeug), 'gevent' in the container where
# gunicorn runs a gevent worker. Env-driven rather than guessed, because the
# same module is imported by both.
SOCKETIO_ASYNC_MODE = os.getenv("SECOPS_SOCKETIO_ASYNC_MODE", "threading")

# Ollama edge-alert service (optional). localhost on bare metal; docker-compose
# points this at its `ollama` service (edge-alerts profile). When nothing is
# listening, notify_ai() degrades gracefully -- alerts are skipped, not fatal.
OLLAMA_URL = os.getenv("SECOPS_OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("SECOPS_OLLAMA_MODEL", "llama3.2")

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
