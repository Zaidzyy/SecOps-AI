"""Feature 5, Part A: incident reports.

Groq is ALWAYS mocked (triage._chat_completion, the shared transport seam).
What these tests pin down:

  * the dossier aggregates REAL rows: detection, attribution, cached triage,
    stored reputation, related flows, and a code-derived timeline + IOCs;
  * grounding: the model's cited detection ids are filtered against the
    dossier in code, its severity is validated, and the factual sections of
    the final report come from the dossier, not from the model;
  * honesty: missing triage/reputation/history is stated in data_gaps;
  * the endpoint sits behind auth, 404s on unknown ids, caches (never
    re-bills), and degrades to 503 when Groq is absent or misbehaves;
  * export: the Markdown download and print HTML view serve ONLY the cache
    (no side effects, no billing), and the view escapes LLM output.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import connect, register_and_login  # noqa: E402

import app_groq  # noqa: E402  -- conftest points SECOPS_DB at a temp file first
import auth  # noqa: E402
import reports  # noqa: E402
import storage  # noqa: E402
import triage  # noqa: E402


FOCAL_ID = 1          # attributed + cached triage + reputation
BARE_ID = 4           # unattributed, no triage, no reputation

CACHED_TRIAGE = {
    "label": "AI-generated triage (advisory)",
    "severity": "high",
    "summary": "Volumetric flood from 203.0.113.7.",
    "likely_intent": "Deny service.",
    "recommended_actions": ["Rate-limit 203.0.113.7 at the edge."],
    "evidence": [{"tool": "detection", "finding": "5200 fwd packets"}],
    "generated_at": "2026-07-10 09:05:00Z",
}


@pytest.fixture
def db(migrated_db):
    """Temp DB: a flagged flow with full Feature 1-4 context, history from the
    same source, and a second flagged flow with none of it (the gaps case)."""
    conn = connect(migrated_db)
    conn.executemany("""
        INSERT INTO detections (src_ip, dst_ip, src_port, dst_port, proto,
                                cnn_verdict, cnn_confidence, country,
                                duration_s, fwd_packets, bwd_packets,
                                fwd_bytes, bwd_bytes, summary, attack_family,
                                technique_id, technique_name, tactic,
                                abuse_score, rep_reports, rep_source, timestamp)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, [
        # id=1: the focal detection (attribution + reputation)
        ("203.0.113.7", "192.0.2.10", 50000, 80, 6, "suspicious", 0.99,
         "NL, Amsterdam, NH", 4.2, 5200, 12, 310000, 800, "Flow flood",
         "ddos", "T1498", "Network Denial of Service", "Impact",
         88, 17, "abuseipdb", "2026-07-10 09:00:00"),
        # id=2: earlier suspicious history from the same source
        ("203.0.113.7", "192.0.2.10", 50001, 443, 6, "suspicious", 0.97,
         "NL, Amsterdam, NH", 3.9, 4100, 9, 250000, 600, "Flow flood 2",
         "ddos", "T1498", "Network Denial of Service", "Impact",
         88, 17, "abuseipdb", "2026-07-10 08:55:00"),
        # id=3: a normal flow from the same source (activity, not history)
        ("203.0.113.7", "192.0.2.10", 50002, 80, 6, "normal", 0.30,
         "NL, Amsterdam, NH", 1.0, 4, 4, 500, 900, "Flow ok",
         None, None, None, None, None, None, None, "2026-07-09 12:00:00"),
        # id=4: flagged but unattributed, no triage, no reputation (gaps case)
        ("198.51.100.9", "192.0.2.20", 41000, 22, 6, "suspicious", 0.96,
         None, 2.0, 60, 3, 4000, 300, "Flow odd",
         None, None, None, None, None, None, None, "2026-07-11 10:00:00"),
    ])
    conn.execute("UPDATE detections SET triage_json = ? WHERE id = ?",
                 (json.dumps(CACHED_TRIAGE), FOCAL_ID))
    conn.commit()
    conn.close()
    return migrated_db


@pytest.fixture
def client(db, monkeypatch):
    monkeypatch.setattr(app_groq, "get_db_connection", lambda: connect(db))
    app_groq.app.config.update(TESTING=True)
    auth.reset_login_limiter()
    return register_and_login(app_groq.app.test_client())


def make_narrative(cited=None, severity="high"):
    return {
        "severity": severity,
        "executive_summary": "Flood from 203.0.113.7 against 192.0.2.10:80.",
        "narrative": "Two suspicious flows were recorded; reputation corroborates.",
        "recommended_actions": ["Engage upstream scrubbing for 192.0.2.10."],
        "cited_detections": cited if cited is not None else [1, 2],
    }


def narrative_message(obj):
    return {"role": "assistant", "content": json.dumps(obj)}


class FakeGroq:
    def __init__(self, message):
        self.message = message
        self.calls = 0
        self.payloads = []

    def __call__(self, payload):
        self.calls += 1
        self.payloads.append(payload)
        return self.message


# --- the dossier aggregates real data -------------------------------------------

def test_dossier_aggregates_features_1_through_4(db):
    conn = connect(db)
    det = storage.fetch_detection(conn, FOCAL_ID)
    dossier = reports.build_dossier(conn, det)
    conn.close()

    # Feature 1: attribution from the stored columns + curated playbook.
    assert dossier["attribution"]["technique_id"] == "T1498"
    assert dossier["attribution"]["playbook"] == triage.PLAYBOOKS["T1498"]
    # Feature 2: the cached triage rides along.
    assert dossier["triage"]["severity"] == "high"
    assert dossier["triage"]["summary"] == CACHED_TRIAGE["summary"]
    # Feature 4: stored reputation, verbatim.
    assert dossier["reputation"] == {"abuse_score": 88, "reports": 17,
                                     "source": "abuseipdb"}
    # Related activity: all three flows, two suspicious.
    assert dossier["activity"]["total_flows"] == 3
    assert dossier["activity"]["suspicious_flows"] == 2
    assert dossier["history"]["total_suspicious"] == 2


def test_timeline_is_chronological_and_marks_focal_detection(db):
    conn = connect(db)
    dossier = reports.build_dossier(conn, storage.fetch_detection(conn, FOCAL_ID))
    conn.close()
    times = [e["timestamp"] for e in dossier["timeline"]]
    assert times == sorted(times)
    focal = [e for e in dossier["timeline"] if e["focal"]]
    assert [e["detection_id"] for e in focal] == [FOCAL_ID]
    assert {e["detection_id"] for e in dossier["timeline"]} == {1, 2}


def test_iocs_only_contain_values_from_the_data(db):
    conn = connect(db)
    dossier = reports.build_dossier(conn, storage.fetch_detection(conn, FOCAL_ID))
    conn.close()
    ip_values = {i["value"] for i in dossier["iocs"] if i["type"] == "ipv4"}
    assert ip_values == {"203.0.113.7", "192.0.2.10"}
    ports = next(i["value"] for i in dossier["iocs"] if i["type"] == "dst_ports")
    assert set(ports) <= {80, 443}


def test_data_gaps_state_whats_missing_instead_of_inventing(db):
    conn = connect(db)
    dossier = reports.build_dossier(conn, storage.fetch_detection(conn, BARE_ID))
    conn.close()
    gaps = " ".join(dossier["data_gaps"])
    assert "no triage" in gaps
    assert "declined to name a technique" in gaps
    assert "no third-party reputation" in gaps
    assert dossier["triage"] is None


# --- grounding on the generated report -------------------------------------------

def test_report_factual_sections_come_from_dossier_not_model(db, monkeypatch):
    """A model that lies about the data cannot inject the lie: the factual
    sections are copied from the dossier in code."""
    lying = make_narrative()
    lying["attack_mapping"] = {"technique_id": "T9999"}   # ignored entirely
    lying["iocs"] = [{"type": "ipv4", "value": "6.6.6.6"}]  # ignored entirely
    monkeypatch.setattr(triage, "_chat_completion",
                        FakeGroq(narrative_message(lying)))
    conn = connect(db)
    report = reports.generate_report(conn, storage.fetch_detection(conn, FOCAL_ID))
    conn.close()
    assert report["attack_mapping"]["technique_id"] == "T1498"
    assert all(i["value"] != "6.6.6.6" for i in report["iocs"])
    assert report["reputation"]["abuse_score"] == 88
    assert report["label"] == "AI-generated incident report (advisory)"


def test_citations_of_rows_not_in_dossier_are_dropped(db, monkeypatch):
    fake = FakeGroq(narrative_message(
        make_narrative(cited=[1, 2, 999999, "junk", 2])))
    monkeypatch.setattr(triage, "_chat_completion", fake)
    conn = connect(db)
    report = reports.generate_report(conn, storage.fetch_detection(conn, FOCAL_ID))
    conn.close()
    assert report["cited_detections"] == [1, 2]  # deduped, fabrication dropped


def test_invalid_severity_is_not_trusted(db, monkeypatch):
    fake = FakeGroq(narrative_message(make_narrative(severity="apocalyptic")))
    monkeypatch.setattr(triage, "_chat_completion", fake)
    conn = connect(db)
    report = reports.generate_report(conn, storage.fetch_detection(conn, FOCAL_ID))
    conn.close()
    assert report["severity"] == "unspecified"


# --- endpoint behaviour -----------------------------------------------------------

def test_report_requires_auth(db, monkeypatch):
    monkeypatch.setattr(app_groq, "get_db_connection", lambda: connect(db))
    app_groq.app.config.update(TESTING=True)
    anon = app_groq.app.test_client()
    assert anon.post(f"/report/{FOCAL_ID}").status_code == 401
    assert anon.get(f"/report/{FOCAL_ID}.md").status_code == 401
    # The view is a page: anonymous access redirects to login, like /.
    assert anon.get(f"/report/{FOCAL_ID}/view").status_code == 302


def test_report_unknown_detection_is_404(client):
    assert client.post("/report/999999").status_code == 404


def test_report_endpoint_returns_and_caches(client, monkeypatch):
    fake = FakeGroq(narrative_message(make_narrative()))
    monkeypatch.setattr(triage, "_chat_completion", fake)

    first = client.post(f"/report/{FOCAL_ID}").get_json()
    calls_after_first = fake.calls
    second = client.post(f"/report/{FOCAL_ID}").get_json()

    assert first["cached"] is False and second["cached"] is True
    assert second["report"] == first["report"]
    assert fake.calls == calls_after_first, "cached report must not call Groq"
    assert first["report"]["executive_summary"].startswith("Flood from")


def test_report_unavailable_without_groq_key(client, monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    resp = client.post(f"/report/{FOCAL_ID}")
    assert resp.status_code == 503
    assert resp.get_json()["error"] == "report unavailable"


def test_report_degrades_when_groq_errors(client, monkeypatch):
    def boom(payload):
        raise triage.TriageUnavailable("Groq returned HTTP 500")
    monkeypatch.setattr(triage, "_chat_completion", boom)
    assert client.post(f"/report/{FOCAL_ID}").status_code == 503


# --- export -----------------------------------------------------------------------

def test_markdown_export_requires_generated_report(client):
    resp = client.get(f"/report/{FOCAL_ID}.md")
    assert resp.status_code == 404
    assert "POST /report" in resp.get_json()["hint"]


def test_markdown_export_serves_cached_report(client, monkeypatch):
    monkeypatch.setattr(triage, "_chat_completion",
                        FakeGroq(narrative_message(make_narrative())))
    client.post(f"/report/{FOCAL_ID}")

    resp = client.get(f"/report/{FOCAL_ID}.md")
    assert resp.status_code == 200
    assert resp.mimetype == "text/markdown"
    assert f"incident-report-{FOCAL_ID}.md" in resp.headers["Content-Disposition"]
    md = resp.get_data(as_text=True)
    assert "T1498" in md and "203.0.113.7" in md
    assert "AI-generated incident report (advisory)" in md
    assert "## Known data gaps" in md


def test_view_serves_print_html_and_escapes_llm_output(client, monkeypatch):
    evil = make_narrative()
    evil["narrative"] = "<script>alert('xss')</script> flood traffic"
    monkeypatch.setattr(triage, "_chat_completion",
                        FakeGroq(narrative_message(evil)))
    client.post(f"/report/{FOCAL_ID}")

    resp = client.get(f"/report/{FOCAL_ID}/view")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "<script>alert" not in html, "LLM output must be escaped"
    assert "&lt;script&gt;" in html
    assert "Print / Save as PDF" in html
    assert f"/report/{FOCAL_ID}.md" in html, "view links the Markdown download"


def test_view_without_report_is_404_page(client):
    resp = client.get(f"/report/{BARE_ID}/view")
    assert resp.status_code == 404
    assert "No report generated" in resp.get_data(as_text=True)


def test_export_get_routes_never_bill_groq(client, monkeypatch):
    fake = FakeGroq(narrative_message(make_narrative()))
    monkeypatch.setattr(triage, "_chat_completion", fake)
    client.get(f"/report/{FOCAL_ID}.md")
    client.get(f"/report/{FOCAL_ID}/view")
    assert fake.calls == 0, "GET export routes serve only the cache"


def test_to_markdown_escapes_pipes_in_values():
    report = {
        "title": "t", "label": "l", "severity": "low",
        "generated_at": "now", "model": "m",
        "executive_summary": "s", "narrative": "n",
        "detection": {"id": 1, "summary": "a|b"},
        "attack_mapping": {}, "reputation": {},
        "iocs": [{"type": "ipv4", "value": "1.2.3.4|x", "role": "r"}],
        "timeline": [], "activity_summary": {}, "triage": None,
        "recommended_actions": [], "cited_detections": [], "data_gaps": [],
    }
    md = reports.to_markdown(report)
    assert "1.2.3.4\\|x" in md
