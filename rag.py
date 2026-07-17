"""RAG chat: BM25 retrieval over incident history (Feature 3).

/chat used to paste the last 5 log lines into the prompt. Now it RETRIEVES:
the operator's question is scored against every indexed detection with BM25
(Okapi, k1/b defaults) and the top-k relevant incidents -- not the newest 5
rows -- are handed to Groq, which must answer from them and cite them.

NAMING HONESTY: this is LEXICAL retrieval (BM25 term matching), not vector
search, not semantic embeddings. It is called "BM25 retrieval over incident
history" everywhere on purpose. For this corpus -- short structured rows full
of IPs, ports, T-numbers, and country names -- exact-term matching is the
right tool: an operator asking "what came from 131.203.88.83?" needs that
literal token matched, which small embedding models are famously bad at.
The Retriever interface below is the seam where an embedding/hybrid backend
could slot in later without touching /chat.

Index design: in-process, no separate server, so it runs unchanged in the
unprivileged container; ZERO new dependencies, so retrieval adds nothing to
the image. Persistence rides on SQLite itself rather than a second index file --
at this scale a full rebuild from the detections table costs milliseconds,
and a sidecar file would only add a way to be stale. sync() is a delta
(WHERE id > last_id): called once at startup and again on every /chat, so an
answer always sees detections written up to the moment of the question.

Grounding discipline (same as triage.py): the model answers from ONLY the
retrieved incidents, must say so when nothing relevant was retrieved, and
its citations are filtered IN CODE against the ids actually retrieved --
a citation of a row that was never retrieved is dropped, never trusted.
"""
from __future__ import annotations

import json
import math
import re
import threading
from collections import Counter

import config
import triage  # shared Groq transport (_chat_completion) + TriageUnavailable

ADVISORY_LABEL = "AI-generated answer (advisory)"
RETRIEVAL_METHOD = "BM25 over incident history"

# Okapi BM25 constants (standard defaults).
BM25_K1 = 1.5
BM25_B = 0.75

# Dotted IPv4s must survive tokenization whole: "what came from 131.203.88.83"
# has to match the indexed token "131.203.88.83", not four ambiguous octets.
_TOKEN_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9]+")

# Tiny stopword list so "what happened from the..." doesn't score against
# every document. Domain terms (flow, port, scan...) are deliberately NOT here.
STOPWORDS = frozenset("""
    a an and any are as at been by did do does for from had has have how in is
    it me of on or our show tell that the there this to was we what when which
    who why with you
""".split())


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall(str(text).lower()) if t not in STOPWORDS]


# Columns the index carries per incident: everything the prompt context and
# the citations need, nothing more (these strings go into an LLM prompt).
_INDEX_SQL = """
    SELECT id, src_ip, dst_ip, dst_port, proto, cnn_verdict, cnn_confidence,
           country, attack_family, technique_id, technique_name, tactic,
           summary, timestamp
    FROM detections WHERE id > ? ORDER BY id
"""

_PROTO_NAMES = {6: "tcp", 17: "udp"}


def incident_text(row: dict) -> str:
    """The searchable text for one detection. Field values are concatenated --
    BM25 needs terms, not sentences -- and the technique/tactic names give the
    lexical hooks ("denial of service", "brute force") a question will use."""
    parts = [
        f"detection {row['id']}", row.get("cnn_verdict"),
        row.get("attack_family"), row.get("technique_id"),
        row.get("technique_name"), row.get("tactic"),
        f"src {row.get('src_ip')}", row.get("country"),
        f"dst {row.get('dst_ip')} port {row.get('dst_port')}",
        _PROTO_NAMES.get(row.get("proto"), str(row.get("proto"))),
        row.get("summary"), row.get("timestamp"),
    ]
    return " ".join(str(p) for p in parts if p not in (None, ""))


class Retriever:
    """The one-method contract /chat depends on. Deliberately minimal -- no
    framework: a future embedding or hybrid backend implements retrieve()
    and nothing else changes."""

    def retrieve(self, query: str, k: int) -> list[dict]:
        """Top-k incidents relevant to `query`, best first. Each hit is a dict
        with at least `id` and `score` plus the incident fields. An empty list
        means "nothing relevant" and callers must treat it honestly."""
        raise NotImplementedError


class Bm25Index(Retriever):
    """In-process BM25 index over the detections table.

    Thread-safe: /chat handlers may sync and retrieve concurrently under the
    threaded dev server, so all state mutation happens under one lock.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._reset_locked()

    def _reset_locked(self):
        self._docs: list[dict] = []       # {"id", "tf": Counter, "len", "meta"}
        self._df: Counter = Counter()     # term -> number of docs containing it
        self._total_len = 0
        self._last_id = 0

    def reset(self):
        """Tests and manual reindexing: drop everything; next sync rebuilds."""
        with self._lock:
            self._reset_locked()

    def __len__(self):
        with self._lock:
            return len(self._docs)

    def _add_locked(self, row: dict):
        tokens = tokenize(incident_text(row))
        self._docs.append({"id": row["id"], "tf": Counter(tokens),
                           "len": len(tokens), "meta": row})
        self._df.update(set(tokens))
        self._total_len += len(tokens)

    def sync(self, conn) -> int:
        """Index detections written since the last sync. Called at startup and
        before every retrieval, so answers see rows up to the question moment.

        Self-healing: if the table shrank or its max id went backwards (a
        swapped/reset database -- tests do this constantly), the index is
        rebuilt from scratch rather than trusted. A rebuild is milliseconds.
        Returns the number of rows (re)indexed.
        """
        with self._lock:
            count, max_id = conn.execute(
                "SELECT COUNT(*), MAX(id) FROM detections").fetchone()
            max_id = max_id or 0
            if max_id < self._last_id or count < len(self._docs):
                self._reset_locked()
            added = 0
            for r in conn.execute(_INDEX_SQL, (self._last_id,)):
                self._add_locked(dict(r))
                added += 1
            self._last_id = max_id
            return added

    def retrieve(self, query: str, k: int) -> list[dict]:
        q_tokens = tokenize(query)
        with self._lock:
            n = len(self._docs)
            if not q_tokens or n == 0:
                return []
            avgdl = self._total_len / n if self._total_len else 1.0
            scored = []
            for doc in self._docs:
                score = 0.0
                for t in q_tokens:
                    tf = doc["tf"].get(t)
                    if not tf:
                        continue
                    df = self._df[t]
                    idf = math.log(1.0 + (n - df + 0.5) / (df + 0.5))
                    norm = tf * (BM25_K1 + 1) / (
                        tf + BM25_K1 * (1 - BM25_B + BM25_B * doc["len"] / avgdl))
                    score += idf * norm
                if score > 0.0:
                    scored.append((score, doc))
            scored.sort(key=lambda s: (-s[0], s[1]["id"]))
            return [{"score": round(s, 4), **d["meta"]} for s, d in scored[:k]]


# The module singleton /chat uses. One process, one index.
index = Bm25Index()


def reset():
    index.reset()


# --- grounded answering -----------------------------------------------------

CHAT_SYSTEM_PROMPT = """You are the operator chat assistant inside SecOps-AI, \
a network flow detection console. Each question comes with `retrieved_incidents`: \
the detections most relevant to the question, found by BM25 retrieval over the \
incident history (lexical term matching -- these are real database rows).

HARD RULES:
- Answer using ONLY the retrieved incidents. They are your only source of \
facts about this network's traffic; you have no other knowledge of it.
- If `retrieved_incidents` is empty or none of them actually bear on the \
question, SAY that no matching incidents were found. Never invent detections, \
IPs, counts, or techniques.
- General security knowledge (e.g. what an ATT&CK technique means) is fine, \
but any claim about THIS network must trace to a retrieved incident.
- Keep the answer concise and operational. It is advisory, for a human operator.

Respond with ONLY a JSON object, no prose around it:
{
  "answer": "<the answer>",
  "citations": [<detection id numbers of the incidents your answer relied on>]
}
Cite only ids that appear in retrieved_incidents."""

# What the model sees per incident, and what a citation echoes back to the UI.
_CONTEXT_FIELDS = ("id", "cnn_verdict", "cnn_confidence", "attack_family",
                   "technique_id", "technique_name", "tactic", "src_ip",
                   "dst_ip", "dst_port", "country", "summary", "timestamp")
_CITATION_FIELDS = ("id", "technique_id", "technique_name", "src_ip",
                    "country", "timestamp")


def _parse_answer(content: str) -> dict | None:
    text = (content or "").strip()
    for candidate in (text, text[text.find("{"): text.rfind("}") + 1]):
        if not candidate:
            continue
        try:
            obj = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(obj, dict) and "answer" in obj:
            return obj
    return None


def answer_question(question: str, hits: list[dict]) -> dict:
    """One grounded Groq call over the retrieved incidents. Raises
    triage.TriageUnavailable on any transport/parse failure (the route turns
    that into a clean 503). Citations are filtered against the retrieved ids
    in code -- the model cannot cite a row it was never shown."""
    incidents = [{k: h.get(k) for k in _CONTEXT_FIELDS} for h in hits]
    user_payload = {"question": question, "retrieved_incidents": incidents}
    if not incidents:
        user_payload["note"] = ("retrieval found no incidents matching the "
                                "question; say so if the question is about "
                                "this network's traffic")

    # triage._chat_completion looked up via the module so tests (and both
    # features) share one monkeypatchable Groq seam.
    msg = triage._chat_completion({
        "model": config.RAG_CHAT_MODEL,
        "messages": [{"role": "system", "content": CHAT_SYSTEM_PROMPT},
                     {"role": "user", "content": json.dumps(user_payload,
                                                            default=str)}],
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
    })
    obj = _parse_answer(msg.get("content") or "")
    if obj is None:
        raise triage.TriageUnavailable("model did not produce a valid answer")

    retrieved = {h["id"]: h for h in hits}
    cited_ids, seen = [], set()
    for c in obj.get("citations") or []:
        try:
            cid = int(c)
        except (TypeError, ValueError):
            continue
        if cid in retrieved and cid not in seen:
            seen.add(cid)
            cited_ids.append(cid)

    return {
        "answer": str(obj.get("answer") or "").strip(),
        "citations": [{k: retrieved[cid].get(k) for k in _CITATION_FIELDS}
                      for cid in cited_ids],
        "retrieved": len(hits),
        "retrieval": RETRIEVAL_METHOD,
        "label": ADVISORY_LABEL,
        "model": config.RAG_CHAT_MODEL,
    }


def answer_without_retrieval(question: str, recent_logs: list[str]) -> dict:
    """Degraded mode: retrieval failed (DB error etc). Falls back to the old
    last-N-logs context, plainly labelled so the operator knows the answer is
    NOT grounded in retrieved incidents. Groq failures still raise
    TriageUnavailable for the route to turn into a 503."""
    msg = triage._chat_completion({
        "model": config.RAG_CHAT_MODEL,
        "messages": [{"role": "user", "content":
                      f"Operator question: {question}\n"
                      f"Recent event log lines (retrieval is unavailable; this "
                      f"is the only context): {recent_logs}\n"
                      f"Answer briefly. If the logs do not answer the "
                      f"question, say so."}],
        "temperature": 0.2,
    })
    answer = (msg.get("content") or "").strip()
    if not answer:
        raise triage.TriageUnavailable("model returned an empty answer")
    return {
        "answer": answer,
        "citations": [],
        "retrieved": 0,
        "retrieval": "unavailable (fell back to recent logs)",
        "label": ADVISORY_LABEL,
        "model": config.RAG_CHAT_MODEL,
    }
