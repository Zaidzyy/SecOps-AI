"""Stage-2 MITRE ATT&CK attribution tests.

Pinned here:
  - the static technique lookup carries EXACTLY the verified IDs/names/tactics
    (no LLM anywhere near a technique ID, so this table IS the contract)
  - the shipped attributor's shape: its classes match its meta, and every
    class either maps to a technique or is the abstain family
  - the honesty rule: low confidence -> unattributed; abstain family ->
    unattributed, even at high confidence
  - two-stage wiring: normal flows never carry a technique; suspicious flows do
  - the migration adds the attribution columns
  - /detections items and /attack-coverage carry the attribution fields
"""
import os
import sqlite3
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import connect, register_and_login  # noqa: E402

import app_groq  # noqa: E402  -- conftest points SECOPS_DB at a temp file first
import attack_mapping  # noqa: E402
import auth  # noqa: E402
import cnn_engine  # noqa: E402
import migrations  # noqa: E402


# --- the static lookup is the verified contract --------------------------------

VERIFIED = {
    "port-scan":   ("T1046", "Network Service Discovery", "Discovery"),
    "ddos":        ("T1498", "Network Denial of Service", "Impact"),
    "dos":         ("T1499", "Endpoint Denial of Service", "Impact"),
    "brute-force": ("T1110", "Brute Force", "Credential Access"),
    "botnet":      ("T1071", "Application Layer Protocol", "Command and Control"),
    "web-attack":  ("T1190", "Exploit Public-Facing Application", "Initial Access"),
}


def test_family_lookup_matches_the_verified_mitre_entries():
    assert set(attack_mapping.FAMILY_TO_TECHNIQUE) == set(VERIFIED)
    for family, (tid, name, tactic) in VERIFIED.items():
        entry = attack_mapping.technique_for_family(family)
        assert entry["technique_id"] == tid
        assert entry["technique_name"] == name
        assert entry["tactic"] == tactic


def test_unknown_family_maps_to_unattributed():
    for family in (None, "other", "made-up-family"):
        entry = attack_mapping.technique_for_family(family)
        assert entry["technique_id"] is None
        assert entry["technique_name"] == "technique unattributed"


# --- the shipped attributor artifact --------------------------------------------

def test_attributor_artifacts_load_and_match_their_meta():
    model, scaler, meta = cnn_engine.load_attributor()
    assert model is not None, "attributor artifacts missing from models/"
    classes = {str(c) for c in model.classes_}
    assert classes <= set(meta["families"]), "model predicts unlisted families"
    # Every predictable class either maps to a verified technique or abstains.
    for cls in classes:
        assert cls in attack_mapping.FAMILY_TO_TECHNIQUE or \
            cls == meta["abstain_family"]
    # Shape check: one probability per class, from the same 6 features.
    row = scaler.transform(np.zeros((1, 6), dtype="float32"))
    proba = model.predict_proba(row)
    assert proba.shape == (1, len(model.classes_))
    assert abs(float(proba.sum()) - 1.0) < 1e-6


# --- the honesty rule ------------------------------------------------------------

class _IdentityScaler:
    def transform(self, X):
        return X


class _StubAttributor:
    def __init__(self, classes, proba):
        self.classes_ = np.array(classes)
        self._proba = np.array([proba])

    def predict_proba(self, X):
        return self._proba


@pytest.fixture
def stub_attributor(monkeypatch):
    """Swap in a controllable attributor; threshold fixed at 0.9."""
    def install(classes, proba):
        monkeypatch.setattr(cnn_engine, "_attributor",
                            _StubAttributor(classes, proba))
        monkeypatch.setattr(cnn_engine, "_attributor_scaler", _IdentityScaler())
        monkeypatch.setattr(cnn_engine, "_attributor_meta",
                            {"confidence_threshold": 0.9,
                             "abstain_family": "other"})
        monkeypatch.setattr(cnn_engine, "_attributor_failed", False)
    return install


ROW = np.zeros((1, 6), dtype="float32")


def test_confident_prediction_attributes_the_technique(stub_attributor):
    stub_attributor(["ddos", "dos"], [0.97, 0.03])
    out = cnn_engine.attribute(ROW)
    assert out["technique_id"] == "T1498"
    assert out["attack_family"] == "ddos"
    assert out["attribution_confidence"] == 0.97


def test_low_confidence_is_unattributed_never_forced(stub_attributor):
    stub_attributor(["ddos", "dos"], [0.55, 0.45])  # argmax exists, conf < 0.9
    out = cnn_engine.attribute(ROW)
    assert out["technique_id"] is None
    assert out["attack_family"] is None
    assert out["technique_name"] == "technique unattributed"


def test_abstain_family_is_unattributed_even_when_confident(stub_attributor):
    stub_attributor(["other", "dos"], [0.99, 0.01])
    out = cnn_engine.attribute(ROW)
    assert out["technique_id"] is None


def test_missing_attributor_degrades_to_unattributed(monkeypatch):
    monkeypatch.setattr(cnn_engine, "_attributor", None)
    monkeypatch.setattr(cnn_engine, "_attributor_failed", True)
    out = cnn_engine.attribute(ROW)
    assert out["technique_id"] is None


# --- two-stage wiring -------------------------------------------------------------

def test_normal_flows_never_carry_attribution(monkeypatch):
    monkeypatch.setattr(cnn_engine, "classify",
                        lambda features: {"verdict": "normal", "confidence": 0.98})
    out = cnn_engine.classify_flow({f: 0.0 for f in
                                    ["duration_s", "protocol", "fwd_packets",
                                     "bwd_packets", "fwd_bytes", "bwd_bytes"]})
    assert out["verdict"] == "normal"
    assert "technique_id" not in out, "Stage 2 must not run on normal flows"


def test_suspicious_flows_carry_attribution(monkeypatch, stub_attributor):
    monkeypatch.setattr(cnn_engine, "classify",
                        lambda features: {"verdict": "suspicious",
                                          "confidence": 0.99})
    stub_attributor(["ddos", "dos"], [0.97, 0.03])
    out = cnn_engine.classify_flow({f: 0.0 for f in
                                    ["duration_s", "protocol", "fwd_packets",
                                     "bwd_packets", "fwd_bytes", "bwd_bytes"]})
    assert out["verdict"] == "suspicious"
    assert out["technique_id"] == "T1498"
    assert out["tactic"] == "Impact"


# --- migration --------------------------------------------------------------------

def test_migration_adds_attribution_columns(migrated_db):
    conn = sqlite3.connect(migrated_db)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(detections)")}
    assert {"attack_family", "technique_id", "technique_name", "tactic"} <= cols
    assert migrations.applied(conn, migrations.ATTRIBUTION_MIGRATION)
    conn.close()


# --- API surface ------------------------------------------------------------------

@pytest.fixture
def client(migrated_db, monkeypatch):
    conn = connect(migrated_db)
    conn.executemany("""
        INSERT INTO detections (src_ip, cnn_verdict, cnn_confidence, country,
                                lat, lon, summary, attack_family, technique_id,
                                technique_name, tactic, timestamp)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    """, [
        ("198.51.100.7", "suspicious", 0.99, "US", 37.4, -122.07, "Flow ddos",
         "ddos", "T1498", "Network Denial of Service", "Impact",
         "2026-07-01 10:00:00"),
        ("198.51.100.7", "suspicious", 0.98, "US", 37.4, -122.07, "Flow ddos2",
         "ddos", "T1498", "Network Denial of Service", "Impact",
         "2026-07-01 10:00:01"),
        ("203.0.113.5", "suspicious", 0.97, "DE", 52.5, 13.4, "Flow scan",
         "port-scan", "T1046", "Network Service Discovery", "Discovery",
         "2026-07-01 10:00:02"),
        # Flagged but honestly unattributed: NULL technique fields.
        ("203.0.113.9", "suspicious", 0.96, "FR", 48.8, 2.3, "Flow odd",
         None, None, None, None, "2026-07-01 10:00:03"),
        # Normal flow: no attribution, and must not appear in coverage.
        ("8.8.8.8", "normal", 0.88, "US", 37.4, -122.07, "Flow http",
         None, None, None, None, "2026-07-01 10:00:04"),
    ])
    conn.commit()
    conn.close()
    monkeypatch.setattr(app_groq, "get_db_connection", lambda: connect(migrated_db))
    app_groq.app.config.update(TESTING=True)
    auth.reset_login_limiter()
    return register_and_login(app_groq.app.test_client())


def test_detection_items_carry_the_technique_fields(client):
    items = client.get("/detections").get_json()["items"]
    by_summary = {i["summary"]: i for i in items}
    ddos = by_summary["Flow ddos"]
    assert (ddos["technique_id"], ddos["technique_name"], ddos["tactic"],
            ddos["attack_family"]) == \
        ("T1498", "Network Denial of Service", "Impact", "ddos")
    assert by_summary["Flow odd"]["technique_id"] is None
    assert by_summary["Flow http"]["technique_id"] is None


def test_attack_coverage_aggregates_fired_techniques(client):
    body = client.get("/attack-coverage").get_json()
    assert set(body) == {"techniques", "unattributed", "attributed"}
    by_id = {t["technique_id"]: t for t in body["techniques"]}
    assert by_id["T1498"]["count"] == 2
    assert by_id["T1046"]["count"] == 1
    assert body["attributed"] == 3
    # The honesty counter: 1 suspicious row with NULL technique. The normal
    # row is NOT counted -- attribution never applied to it.
    assert body["unattributed"] == 1


def test_attack_coverage_requires_login(migrated_db, monkeypatch):
    monkeypatch.setattr(app_groq, "get_db_connection", lambda: connect(migrated_db))
    app_groq.app.config.update(TESTING=True)
    auth.reset_login_limiter()
    anon = app_groq.app.test_client()
    assert anon.get("/attack-coverage").status_code == 401
