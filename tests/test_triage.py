"""Feature 2: agentic triage.

Groq is ALWAYS mocked here (monkeypatching triage._chat_completion, the one
transport seam). What these tests pin down:

  * the loop is hard-bounded: a model that calls tools forever still ends
    inside the budget, and the report gets produced anyway;
  * the tools return real rows from the real (temp) DB;
  * the endpoint sits behind auth, 404s on unknown ids, and caches;
  * the output schema, including the advisory label;
  * graceful degradation when GROQ_API_KEY is absent or Groq misbehaves;
  * grounding: evidence citing a tool that never ran is dropped in code.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import connect, register_and_login  # noqa: E402

import app_groq  # noqa: E402  -- conftest points SECOPS_DB at a temp file first
import auth  # noqa: E402
import config  # noqa: E402
import storage  # noqa: E402
import triage  # noqa: E402


SUSPICIOUS_ID = 1  # first seeded row below


@pytest.fixture
def db(migrated_db):
    """Temp DB seeded with a flagged flow plus history for its source IP."""
    conn = connect(migrated_db)
    conn.executemany("""
        INSERT INTO detections (src_ip, dst_ip, src_port, dst_port, proto,
                                cnn_verdict, cnn_confidence, country,
                                duration_s, fwd_packets, bwd_packets,
                                fwd_bytes, bwd_bytes, summary, attack_family,
                                technique_id, technique_name, tactic, timestamp)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, [
        # id=1: the detection under triage
        ("203.0.113.7", "192.0.2.10", 50000, 80, 6, "suspicious", 0.99,
         "NL, Amsterdam, NH", 4.2, 5200, 12, 310000, 800, "Flow flood",
         "ddos", "T1498", "Network Denial of Service", "Impact",
         "2026-07-10 09:00:00"),
        # history from the same source
        ("203.0.113.7", "192.0.2.10", 50001, 443, 6, "suspicious", 0.97,
         "NL, Amsterdam, NH", 3.9, 4100, 9, 250000, 600, "Flow flood 2",
         "ddos", "T1498", "Network Denial of Service", "Impact",
         "2026-07-10 08:55:00"),
        ("203.0.113.7", "192.0.2.10", 50002, 80, 6, "normal", 0.30,
         "NL, Amsterdam, NH", 1.0, 4, 4, 500, 900, "Flow ok",
         None, None, None, None, "2026-07-09 12:00:00"),
    ])
    conn.commit()
    conn.close()
    return migrated_db


@pytest.fixture
def client(db, monkeypatch):
    monkeypatch.setattr(app_groq, "get_db_connection", lambda: connect(db))
    app_groq.app.config.update(TESTING=True)
    auth.reset_login_limiter()
    return register_and_login(app_groq.app.test_client())


def make_report(evidence=None):
    return {
        "severity": "high",
        "summary": "Volumetric flood from 203.0.113.7 against 192.0.2.10:80.",
        "likely_intent": "Deny service on the web endpoint.",
        "recommended_actions": ["Rate-limit 203.0.113.7 at the edge."],
        "evidence": evidence if evidence is not None else
            [{"tool": "detection", "finding": "5200 fwd packets in 4.2s"}],
    }


def final_message(report):
    return {"role": "assistant", "content": json.dumps(report)}


def tool_call_message(name, args, call_id="c1"):
    return {"role": "assistant", "content": None, "tool_calls": [
        {"id": call_id, "type": "function",
         "function": {"name": name, "arguments": json.dumps(args)}}]}


class FakeGroq:
    """Scripted transport: returns each queued message once, then repeats the
    last one forever (which is how we simulate a model that never stops
    calling tools)."""

    def __init__(self, *script):
        self.script = list(script)
        self.calls = 0
        self.payloads = []

    def __call__(self, payload):
        self.payloads.append(payload)
        self.calls += 1
        if len(self.script) > 1:
            return self.script.pop(0)
        return self.script[0]


# --- endpoint behaviour -------------------------------------------------------

def test_triage_requires_auth(db, monkeypatch):
    monkeypatch.setattr(app_groq, "get_db_connection", lambda: connect(db))
    app_groq.app.config.update(TESTING=True)
    resp = app_groq.app.test_client().post(f"/triage/{SUSPICIOUS_ID}")
    assert resp.status_code == 401


def test_triage_unknown_detection_is_404(client):
    resp = client.post("/triage/999999")
    assert resp.status_code == 404
    assert resp.get_json()["error"] == "detection not found"


def test_triage_returns_structured_advisory_report(client, monkeypatch):
    fake = FakeGroq(final_message(make_report()))
    monkeypatch.setattr(triage, "_chat_completion", fake)

    body = client.post(f"/triage/{SUSPICIOUS_ID}").get_json()
    assert body["detection_id"] == SUSPICIOUS_ID
    assert body["cached"] is False
    report = body["triage"]
    assert report["label"] == "AI-generated triage (advisory)"
    assert {"severity", "summary", "likely_intent", "recommended_actions",
            "evidence", "tool_trace", "model", "approach",
            "generated_at"} <= set(report)
    assert report["severity"] == "high"
    assert report["approach"] == "tool-loop"


def test_triage_is_cached_and_never_rebills(client, monkeypatch):
    fake = FakeGroq(final_message(make_report()))
    monkeypatch.setattr(triage, "_chat_completion", fake)

    first = client.post(f"/triage/{SUSPICIOUS_ID}").get_json()
    calls_after_first = fake.calls
    second = client.post(f"/triage/{SUSPICIOUS_ID}").get_json()

    assert first["cached"] is False and second["cached"] is True
    assert second["triage"] == first["triage"]
    assert fake.calls == calls_after_first, "cached triage must not call Groq"


def test_triage_unavailable_without_groq_key(client, monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    resp = client.post(f"/triage/{SUSPICIOUS_ID}")
    assert resp.status_code == 503
    body = resp.get_json()
    assert body["error"] == "triage unavailable"
    assert "GROQ_API_KEY" in body["reason"]


def test_triage_degrades_when_groq_errors(client, monkeypatch):
    def boom(payload):
        raise triage.TriageUnavailable("Groq returned HTTP 500")
    monkeypatch.setattr(triage, "_chat_completion", boom)
    resp = client.post(f"/triage/{SUSPICIOUS_ID}")
    assert resp.status_code == 503
    assert resp.get_json()["error"] == "triage unavailable"


# --- the loop is HARD-bounded ---------------------------------------------------

def test_loop_never_exceeds_tool_budget(db, monkeypatch):
    """A model that calls tools forever: executions stop at the budget, the
    forced-synthesis call still yields a report, and the whole run is bounded
    at max+2 transport rounds."""
    greedy = tool_call_message("related_flows_for_ip", {"ip": "203.0.113.7"})
    fake = FakeGroq(greedy)  # repeats forever

    # The forced final call carries response_format and no tools -- answer it.
    def transport(payload):
        if "tools" not in payload:
            return final_message(make_report())
        return fake(payload)
    monkeypatch.setattr(triage, "_chat_completion", transport)

    conn = connect(db)
    det = storage.fetch_detection(conn, SUSPICIOUS_ID)
    report = triage.run_triage(det, conn)
    conn.close()

    max_calls = config.TRIAGE_MAX_TOOL_CALLS
    assert len(report["tool_trace"]) == max_calls, "tool executions capped"
    assert fake.calls <= max_calls + 2, "transport rounds bounded"
    assert report["summary"], "report still produced after budget exhaustion"


def test_tools_are_withheld_once_budget_is_spent(db, monkeypatch):
    greedy = tool_call_message("ip_reputation", {"ip": "203.0.113.7"})
    seen = []

    def transport(payload):
        seen.append("tools" in payload)
        if "tools" not in payload:
            return final_message(make_report())
        return greedy
    monkeypatch.setattr(triage, "_chat_completion", transport)

    conn = connect(db)
    triage.run_triage(storage.fetch_detection(conn, SUSPICIOUS_ID), conn)
    conn.close()
    assert seen[-1] is False, "final synthesis call must not offer tools"


def test_unknown_tool_and_bad_args_do_not_crash(db, monkeypatch):
    fake = FakeGroq(
        tool_call_message("erase_hard_drive", {"ip": "203.0.113.7"}),
        tool_call_message("ip_reputation", {"ip": "not-an-ip"}),
        final_message(make_report()),
    )
    monkeypatch.setattr(triage, "_chat_completion", fake)

    conn = connect(db)
    report = triage.run_triage(storage.fetch_detection(conn, SUSPICIOUS_ID), conn)
    conn.close()
    assert [t["ok"] for t in report["tool_trace"]] == [False, True]
    assert report["summary"]


def test_non_json_content_gets_one_nudge_then_report(db, monkeypatch):
    fake = FakeGroq(
        {"role": "assistant", "content": "Sure! Here is my analysis..."},
        final_message(make_report()),
    )
    monkeypatch.setattr(triage, "_chat_completion", fake)
    conn = connect(db)
    report = triage.run_triage(storage.fetch_detection(conn, SUSPICIOUS_ID), conn)
    conn.close()
    assert report["severity"] == "high"
    assert fake.calls == 2


# --- grounding ------------------------------------------------------------------

def test_evidence_citing_uncalled_tools_is_dropped(db, monkeypatch):
    evidence = [
        {"tool": "ip_reputation", "finding": "IP blacklisted with 42 attacks"},
        {"tool": "threat_intel_feed", "finding": "APT-999 attribution"},  # never ran
        {"tool": "detection", "finding": "5200 packets in 4.2 seconds"},
    ]
    fake = FakeGroq(
        tool_call_message("ip_reputation", {"ip": "203.0.113.7"}),
        final_message(make_report(evidence)),
    )
    monkeypatch.setattr(triage, "_chat_completion", fake)

    conn = connect(db)
    report = triage.run_triage(storage.fetch_detection(conn, SUSPICIOUS_ID), conn)
    conn.close()

    cited = {e["tool"] for e in report["evidence"]}
    assert cited == {"ip_reputation", "detection"}
    assert not any("APT-999" in e["finding"] for e in report["evidence"])


def test_invalid_severity_is_not_trusted(db, monkeypatch):
    report_in = make_report()
    report_in["severity"] = "apocalyptic"
    fake = FakeGroq(final_message(report_in))
    monkeypatch.setattr(triage, "_chat_completion", fake)
    conn = connect(db)
    report = triage.run_triage(storage.fetch_detection(conn, SUSPICIOUS_ID), conn)
    conn.close()
    assert report["severity"] == "unspecified"


# --- the tools return real data --------------------------------------------------

def test_related_flows_tool_reads_real_rows(db):
    conn = connect(db)
    out = triage._tool_related_flows(conn, {"ip": "203.0.113.7"})
    conn.close()
    assert out["total_flows"] == 3
    assert out["suspicious_flows"] == 2
    assert len(out["flows"]) == 3
    assert out["flows"][0]["src_ip"] == "203.0.113.7"


def test_recent_detections_tool_carries_attribution(db):
    conn = connect(db)
    out = triage._tool_recent_detections(conn, {"ip": "203.0.113.7"})
    conn.close()
    assert out["total_suspicious"] == 2
    assert all(d["technique_id"] == "T1498" for d in out["detections"])


def test_tools_admit_empty_results_instead_of_inventing(db):
    conn = connect(db)
    flows = triage._tool_related_flows(conn, {"ip": "198.51.100.99"})
    history = triage._tool_recent_detections(conn, {"ip": "198.51.100.99"})
    conn.close()
    assert flows["flows"] == [] and "note" in flows
    assert history["detections"] == [] and "note" in history


def test_ip_reputation_tool_says_so_for_private_ips(db):
    conn = connect(db)
    out = triage._tool_ip_reputation(conn, {"ip": "10.0.0.5"})
    conn.close()
    assert out["blacklisted"] is False
    assert "note" in out  # explicitly says no external data exists


def test_technique_info_returns_curated_playbook(db):
    conn = connect(db)
    known = triage._tool_technique_info(conn, {"technique_id": "T1498"})
    unknown = triage._tool_technique_info(conn, {"technique_id": "T9999"})
    conn.close()
    assert known["technique_name"] == "Network Denial of Service"
    assert known["playbook"] == triage.PLAYBOOKS["T1498"]
    assert unknown["playbook"] == triage.GENERIC_PLAYBOOK
    assert "note" in unknown
