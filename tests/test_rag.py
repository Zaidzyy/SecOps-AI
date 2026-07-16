"""Feature 3: RAG chat -- BM25 retrieval over incident history.

The retrieval path runs UNMOCKED: these tests exercise the real tokenizer,
the real BM25 scoring, and the real delta-sync against a real (temp) SQLite
database. Only Groq is mocked, at the same single seam triage uses
(triage._chat_completion). Pinned here:

  * retrieval finds the relevant incidents (technique words, literal IPs)
    and ranks them above unrelated rows;
  * unrelated questions retrieve nothing, and the pipeline says so instead
    of inventing;
  * delta-sync picks up detections written after the initial index build,
    and a swapped/reset database triggers a self-healing rebuild;
  * the answer's citations are filtered against actually-retrieved ids;
  * degradation: Groq down -> clean 503; retrieval broken -> legacy
    last-N-logs fallback, plainly labelled;
  * /chat stays behind the auth gate.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import connect, register_and_login  # noqa: E402

import app_groq  # noqa: E402  -- conftest points SECOPS_DB at a temp file first
import auth  # noqa: E402
import rag  # noqa: E402
import triage  # noqa: E402


def seed(conn, rows):
    conn.executemany("""
        INSERT INTO detections (src_ip, dst_ip, src_port, dst_port, proto,
                                cnn_verdict, cnn_confidence, country,
                                duration_s, fwd_packets, bwd_packets,
                                fwd_bytes, bwd_bytes, summary, attack_family,
                                technique_id, technique_name, tactic, timestamp)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, rows)
    conn.commit()


ROWS = [
    # id=1: port scan from New Zealand
    ("131.203.88.83", "93.184.216.34", 50000, 22, 6, "suspicious", 0.97,
     "New Zealand, Wellington, Wellington", 0.001, 1, 1, 0, 0,
     "Flow scan probe", "port-scan", "T1046", "Network Service Discovery",
     "Discovery", "2026-07-10 09:00:00"),
    # id=2: DoS from China
    ("59.246.32.135", "93.184.216.34", 41000, 80, 6, "suspicious", 1.0,
     "China, Beijing, BJ", 4.0, 5000, 10, 300000, 700,
     "Flow flood high rate", "dos", "T1499", "Endpoint Denial of Service",
     "Impact", "2026-07-10 09:05:00"),
    # id=3: normal web flow from Germany
    ("8.8.8.8", "93.184.216.34", 42000, 443, 6, "normal", 0.2,
     "Germany, Berlin, BE", 0.5, 6, 5, 900, 4000,
     "Flow https ordinary", None, None, None, None, "2026-07-10 09:10:00"),
]


@pytest.fixture
def db(migrated_db):
    conn = connect(migrated_db)
    seed(conn, ROWS)
    conn.close()
    rag.reset()          # module singleton: every test starts unindexed
    return migrated_db


@pytest.fixture
def client(db, monkeypatch):
    monkeypatch.setattr(app_groq, "get_db_connection", lambda: connect(db))
    app_groq.app.config.update(TESTING=True)
    auth.reset_login_limiter()
    return register_and_login(app_groq.app.test_client())


def groq_answer(answer, citations):
    """A scripted Groq reply in the JSON shape the chat prompt demands."""
    def transport(payload):
        transport.payloads.append(payload)
        return {"role": "assistant",
                "content": json.dumps({"answer": answer,
                                       "citations": citations})}
    transport.payloads = []
    return transport


# --- retrieval (real BM25, no mocks) -----------------------------------------

def test_retrieval_finds_technique_words(db):
    conn = connect(db)
    rag.index.sync(conn)
    hits = rag.index.retrieve("any denial of service activity?", k=3)
    conn.close()
    assert hits and hits[0]["id"] == 2
    assert hits[0]["technique_id"] == "T1499"


def test_retrieval_matches_literal_ip_tokens(db):
    """The reason BM25 fits this corpus: a dotted IP is one exact token."""
    conn = connect(db)
    rag.index.sync(conn)
    hits = rag.index.retrieve("what do we know about 131.203.88.83?", k=3)
    conn.close()
    assert hits and hits[0]["id"] == 1
    assert hits[0]["src_ip"] == "131.203.88.83"


def test_retrieval_ranks_scan_question_onto_scan_row(db):
    conn = connect(db)
    rag.index.sync(conn)
    hits = rag.index.retrieve("port scan discovery from new zealand", k=3)
    conn.close()
    assert hits[0]["id"] == 1


def test_unrelated_question_retrieves_nothing(db):
    conn = connect(db)
    rag.index.sync(conn)
    hits = rag.index.retrieve("croissant recipe ingredients butter", k=5)
    conn.close()
    assert hits == []


def test_sync_is_incremental_and_sees_new_rows(db):
    conn = connect(db)
    assert rag.index.sync(conn) == 3
    assert rag.index.sync(conn) == 0          # delta: nothing new

    seed(conn, [("203.0.113.9", "93.184.216.34", 43000, 21, 6, "suspicious",
                 0.9, "France, Paris, IDF", 2.0, 300, 5, 9000, 200,
                 "Flow patator credential guessing", "brute-force", "T1110",
                 "Brute Force", "Credential Access", "2026-07-10 10:00:00")])
    assert rag.index.sync(conn) == 1
    hits = rag.index.retrieve("brute force credential attempts", k=3)
    conn.close()
    assert hits and hits[0]["id"] == 4


def test_swapped_database_triggers_rebuild(db, tmp_path, migrated_db):
    conn = connect(db)
    rag.index.sync(conn)
    conn.close()
    assert len(rag.index) == 3

    # A fresh DB with fewer rows: max(id) < last_id -> self-healing rebuild.
    import migrations, sqlite3
    other = str(tmp_path / "other.db")
    c2 = sqlite3.connect(other)
    migrations.migrate(c2)
    c2.close()
    c2 = connect(other)
    seed(c2, ROWS[:1])
    rag.index.sync(c2)
    c2.close()
    assert len(rag.index) == 1


# --- /chat endpoint -----------------------------------------------------------

def test_chat_requires_auth(db, monkeypatch):
    monkeypatch.setattr(app_groq, "get_db_connection", lambda: connect(db))
    app_groq.app.config.update(TESTING=True)
    resp = app_groq.app.test_client().post("/chat", json={"message": "hi"})
    assert resp.status_code == 401


def test_chat_answers_with_filtered_citations(client, monkeypatch):
    # Model cites id 2 (retrieved) and id 999 (never retrieved): 999 must drop.
    transport = groq_answer("The flood from 59.246.32.135 is the only DoS.",
                            [2, 999])
    monkeypatch.setattr(triage, "_chat_completion", transport)

    body = client.post("/chat", json={
        "message": "any denial of service floods?"}).get_json()

    assert body["label"] == "AI-generated answer (advisory)"
    assert body["retrieval"] == "BM25 over incident history"
    assert [c["id"] for c in body["citations"]] == [2]
    assert body["citations"][0]["technique_id"] == "T1499"
    assert "59.246.32.135" in body["response"]


def test_chat_prompt_carries_only_retrieved_incidents(client, monkeypatch):
    transport = groq_answer("answer", [])
    monkeypatch.setattr(triage, "_chat_completion", transport)

    client.post("/chat", json={"message": "tell me about 131.203.88.83"})

    sent = json.loads(transport.payloads[0]["messages"][1]["content"])
    ids = [i["id"] for i in sent["retrieved_incidents"]]
    assert 1 in ids, "the IP's own detection must be in the prompt"
    assert len(ids) <= app_groq.config.RAG_TOP_K


def test_chat_empty_retrieval_is_stated_not_invented(client, monkeypatch):
    transport = groq_answer("No matching incidents were found for that.", [])
    monkeypatch.setattr(triage, "_chat_completion", transport)

    body = client.post("/chat", json={
        "message": "croissant recipe ingredients butter"}).get_json()

    assert body["retrieved"] == 0
    assert body["citations"] == []
    sent = json.loads(transport.payloads[0]["messages"][1]["content"])
    assert sent["retrieved_incidents"] == []
    assert "note" in sent          # the prompt tells the model to say so


def test_chat_503_when_groq_unavailable(client, monkeypatch):
    def boom(payload):
        raise triage.TriageUnavailable("GROQ_API_KEY is not set")
    monkeypatch.setattr(triage, "_chat_completion", boom)

    resp = client.post("/chat", json={"message": "status?"})
    assert resp.status_code == 503
    assert resp.get_json()["error"] == "chat unavailable"


def test_chat_falls_back_to_logs_when_retrieval_breaks(client, monkeypatch):
    def broken_sync(conn):
        raise RuntimeError("index corrupted")
    monkeypatch.setattr(rag.index, "sync", broken_sync)
    # Legacy path is a plain (non-JSON) completion.
    monkeypatch.setattr(triage, "_chat_completion", lambda p: {
        "role": "assistant", "content": "From recent logs: nothing notable."})

    body = client.post("/chat", json={"message": "anything new?"}).get_json()

    assert body["citations"] == []
    assert body["retrieval"].startswith("unavailable")
    assert body["response"] == "From recent logs: nothing notable."


def test_chat_rejects_empty_message(client):
    assert client.post("/chat", json={}).status_code == 400


# --- unit: tokenizer ----------------------------------------------------------

def test_tokenizer_keeps_ips_whole_and_drops_stopwords():
    tokens = rag.tokenize("What came FROM 131.203.88.83 to port 22?")
    assert "131.203.88.83" in tokens
    assert "from" not in tokens and "what" not in tokens
    assert "port" in tokens and "22" in tokens
