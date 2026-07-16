"""Detection engine: loads OUR trained flow classifier and scores flows.

All model logic lives here, out of app_groq.py. The primary detector is a
gradient-boosted tree (GBT); a compact Conv1D is kept as a documented baseline.
Paths, the primary-model type, and the decision threshold all come from
config.py (single source of truth).

We deliberately do NOT load the borrowed SecIDS-CNN.h5 here: its feature
contract was never published, so it can't be fed our features honestly. See the
README for the rationale.

Naming note: the module is still called cnn_engine because "CNN" is the
project's detection story; the shipped detector is the better-performing GBT and
the CNN is the benchmarked baseline (see models/metrics.json).
"""
from __future__ import annotations

import json
import threading

import numpy as np

import config

# Primary model + scaler + meta, loaded once and reused. Lock guards first load
# so the sniffer thread and Flask request threads don't race.
_model = None
_scaler = None
_meta = None
_cnn = None
_lock = threading.Lock()


def load_model():
    """Load the primary model + scaler + meta once and cache them.
    Returns (model, scaler, meta)."""
    global _model, _scaler, _meta
    if _model is not None:
        return _model, _scaler, _meta
    with _lock:
        if _model is not None:
            return _model, _scaler, _meta
        import joblib
        model = joblib.load(config.FLOW_MODEL_PATH)   # GBT (sklearn)
        scaler = joblib.load(config.FLOW_SCALER_PATH)
        try:
            with open(config.FLOW_META_PATH) as f:
                meta = json.load(f)
        except FileNotFoundError:
            meta = {"feature_order": config.FEATURE_ORDER,
                    "primary_model": config.PRIMARY_MODEL_TYPE}
        _model, _scaler, _meta = model, scaler, meta
        return _model, _scaler, _meta


def load_cnn_baseline():
    """Load the compact Conv1D baseline (for the comparison writeup / demos)."""
    global _cnn
    if _cnn is None:
        import tensorflow as tf
        _cnn = tf.keras.models.load_model(config.FLOW_CNN_PATH)
    return _cnn


def _feature_dict(flow) -> dict:
    if hasattr(flow, "to_features"):
        return flow.to_features()
    if isinstance(flow, dict):
        return flow
    raise TypeError("extract_features expects a Flow or a feature dict")


def extract_features(flow) -> np.ndarray:
    """Map a Flow (or raw feature dict) to the exact scaled input the model
    expects: shape (1, n_features), features in config.FEATURE_ORDER order,
    transformed by the saved training scaler. (The Conv1D baseline reshapes this
    to (1, n_features, 1) internally.)"""
    _, scaler, _ = load_model()
    feats = _feature_dict(flow)
    row = np.array([[float(feats[name]) for name in config.FEATURE_ORDER]],
                   dtype="float32")
    row = np.nan_to_num(row, nan=0.0, posinf=0.0, neginf=0.0)
    return scaler.transform(row).astype("float32")


def _attack_probability(model, features: np.ndarray) -> float:
    """Attack-class probability, handling both sklearn and Keras models."""
    if hasattr(model, "predict_proba"):                 # sklearn GBT
        return float(model.predict_proba(features)[:, 1][0])
    # Keras Conv1D expects (batch, n_features, 1)
    x = features.reshape(features.shape[0], features.shape[1], 1)
    return float(model.predict(x, verbose=0).ravel()[0])


def classify(features: np.ndarray) -> dict:
    """Run the primary model on an already-extracted feature row.
    Returns {"verdict": "normal"|"suspicious", "confidence": float}.

    Confidence is the model's probability for the *verdict* class. The decision
    threshold is asymmetric (config.CLASSIFY_THRESHOLD, 0.95 -- chosen by the
    training frontier to hold per-flow benign FPR under 1%), so the two verdicts
    have different confidence floors: "suspicious" implies confidence >= 0.95,
    while "normal" can carry confidence as low as 1 - threshold. A low-confidence
    "normal" is a borderline flow the threshold deliberately declined to flag."""
    model, _, _ = load_model()
    attack_prob = _attack_probability(model, features)
    if attack_prob >= config.CLASSIFY_THRESHOLD:
        return {"verdict": "suspicious", "confidence": round(attack_prob, 4)}
    return {"verdict": "normal", "confidence": round(1.0 - attack_prob, 4)}


def classify_flow(flow) -> dict:
    """Convenience one-shot: Flow -> verdict. Single entry point the app uses for
    both live sniffing and (future) pcap replay, so they share one code path."""
    return classify(extract_features(flow))
