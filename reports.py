"""Incident reports (Feature 5, Part A) -- the capstone over Features 1-4.

An operator asks for a report on one suspicious detection; this module
aggregates everything the system ALREADY KNOWS about it -- the detection row,
its MITRE attribution (Feature 1), the cached triage report if one was run
(Feature 2), the third-party reputation stored at classification time
(Feature 4), and the source IP's related flows and suspicious history -- into
a "dossier", then asks Groq to write the SOC narrative OVER that dossier.

Grounding discipline (the same contract as triage.py and rag.py, taken one
step further): the report's factual sections are not merely checked against
the data, they are BUILT from it in code --

  timeline        derived from the dossier's detection timestamps, in code
  iocs            the addresses/ports that actually appear in the dossier
  attack_mapping  copied from the stored attribution + curated table
  reputation      the stored Feature-4 columns, verbatim
  data_gaps       every aggregation source that came back empty, stated

The LLM contributes only the synthesis: executive summary, narrative,
severity, and playbook-based recommended actions. Even there it is fenced in:
its cited detection ids are filtered against the ids actually present in the
dossier (a citation of a row it was never shown is dropped, never trusted),
and its actions start from the curated per-technique playbooks. The label
says what it is: "AI-generated incident report (advisory)".

DEGRADES, NEVER CRASHES: every Groq failure mode raises
triage.TriageUnavailable, which the route turns into a clean 503. Reports are
cached on the detection row (report_json), so re-opening one is a DB read,
never a re-bill.
"""
from __future__ import annotations

import datetime
import json

import attack_mapping
import config
import storage
import triage

ADVISORY_LABEL = "AI-generated incident report (advisory)"

# What the narrative model may see and cite of each related detection row.
# Compact on purpose: the dossier is spliced into an LLM prompt.
_DETECTION_FIELDS = (
    "id", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "cnn_verdict",
    "cnn_confidence", "country", "duration_s", "fwd_packets", "bwd_packets",
    "fwd_bytes", "bwd_bytes", "summary", "attack_family", "technique_id",
    "technique_name", "tactic", "abuse_score", "rep_reports", "rep_source",
    "timestamp",
)

# Triage fields worth carrying into the report (the full cached object also
# holds the tool trace, which is audit detail, not report material).
_TRIAGE_FIELDS = ("severity", "summary", "likely_intent",
                  "recommended_actions", "evidence", "generated_at")


# --- aggregation (all real data, no LLM) --------------------------------------

def build_dossier(conn, detection: dict) -> dict:
    """Everything the system knows about this detection, from Features 1-4.

    Pure aggregation: detections DB + stored attribution + cached triage +
    stored reputation columns. No network calls, no model calls -- a dossier
    is the same every time you build it for the same data.
    """
    det = {k: detection.get(k) for k in _DETECTION_FIELDS}
    src_ip = det["src_ip"]

    # Feature 1: attribution, from the stored columns + curated table.
    technique_id = det.get("technique_id")
    attribution = {
        "technique_id": technique_id,
        "technique_name": det.get("technique_name"),
        "tactic": det.get("tactic"),
        "attack_family": det.get("attack_family"),
        "playbook": triage.PLAYBOOKS.get(technique_id, triage.GENERIC_PLAYBOOK),
    }

    # Feature 2: the cached triage report, if an operator ran one.
    triage_report = None
    if detection.get("triage_json"):
        try:
            cached = json.loads(detection["triage_json"])
            triage_report = {k: cached.get(k) for k in _TRIAGE_FIELDS}
        except ValueError:
            triage_report = None  # a corrupt cache is a gap, not a crash

    # Feature 4: third-party reputation as stored at classification time.
    reputation = {
        "abuse_score": det.get("abuse_score"),
        "reports": det.get("rep_reports"),
        "source": det.get("rep_source"),
    }

    # Related activity for the source IP -- the same bounded queries the
    # triage agent's tools use.
    activity = storage.flows_for_ip(conn, src_ip,
                                    limit=config.REPORT_ROW_LIMIT)
    history = storage.suspicious_history_for_ip(conn, src_ip,
                                                limit=config.REPORT_ROW_LIMIT)

    # Honesty: every aggregation source that has nothing to say, said out loud.
    gaps = []
    if triage_report is None:
        gaps.append("no triage has been run on this detection "
                    "(agentic triage is operator-triggered)")
    if technique_id is None:
        gaps.append("the Stage-2 attributor declined to name a technique "
                    "for this flow (technique unattributed)")
    if reputation["source"] in (None, "unknown"):
        gaps.append("no third-party reputation data was available for the "
                    "source IP at classification time")
    elif reputation["abuse_score"] is None:
        gaps.append(f"reputation source '{reputation['source']}' provides "
                    f"report counts, not a 0-100 abuse confidence score")
    if history["total_suspicious"] <= 1:
        gaps.append("no prior suspicious detections from this source IP "
                    "beyond this one")

    return {
        "detection": det,
        "attribution": attribution,
        "triage": triage_report,
        "reputation": reputation,
        "activity": activity,
        "history": history,
        "timeline": _build_timeline(det, history),
        "iocs": _build_iocs(det, activity, history),
        "data_gaps": gaps,
    }


def _build_timeline(det: dict, history: dict) -> list[dict]:
    """Chronological events, derived in code from real rows. The focal
    detection is included and marked, so the narrative has an anchor."""
    events = []
    for h in history["detections"]:
        events.append({
            "timestamp": h.get("timestamp"),
            "detection_id": h.get("id"),
            "event": f"suspicious flow to {h.get('dst_ip')}:{h.get('dst_port')}"
                     + (f" attributed {h['technique_id']} {h['technique_name']}"
                        if h.get("technique_id") else " (technique unattributed)"),
        })
    if det["id"] not in {e["detection_id"] for e in events}:
        events.append({
            "timestamp": det.get("timestamp"),
            "detection_id": det["id"],
            "event": f"suspicious flow to {det.get('dst_ip')}:{det.get('dst_port')}"
                     + (f" attributed {det['technique_id']} {det['technique_name']}"
                        if det.get("technique_id") else " (technique unattributed)"),
        })
    events.sort(key=lambda e: (str(e["timestamp"]), e["detection_id"]))
    for e in events:
        e["focal"] = e["detection_id"] == det["id"]
    return events


def _build_iocs(det: dict, activity: dict, history: dict) -> list[dict]:
    """Indicators drawn from the aggregated rows -- values that literally
    appear in the data, so an IOC can never be invented."""
    iocs = [{"type": "ipv4", "value": det["src_ip"],
             "role": "source of the flagged flow"}]
    dst_ports = sorted({h.get("dst_port") for h in history["detections"]
                        if h.get("dst_port") is not None}
                       | ({det["dst_port"]} if det.get("dst_port") is not None
                          else set()))
    if det.get("dst_ip"):
        iocs.append({"type": "ipv4", "value": det["dst_ip"],
                     "role": "target of the flagged flow"})
    if dst_ports:
        iocs.append({"type": "dst_ports", "value": dst_ports,
                     "role": "destination ports touched in suspicious flows "
                             "from the source"})
    if activity.get("distinct_dst_ports"):
        iocs.append({"type": "port_spread",
                     "value": activity["distinct_dst_ports"],
                     "role": "distinct destination ports across all recorded "
                             "flows involving the source"})
    return iocs


# --- narrative synthesis (the one LLM call) ------------------------------------

SYSTEM_PROMPT = """You are the incident report writer inside SecOps-AI, a \
network flow detection console. You are given a dossier: REAL aggregated data \
about one suspicious detection -- the detection record, its MITRE ATT&CK \
attribution, a prior AI triage report (if any), third-party IP reputation, \
the source IP's related flows and suspicious history, a derived timeline, \
and indicators. `data_gaps` lists what the system does NOT know.

Write the analytic sections of a SOC incident report.

HARD RULES:
- Every factual claim must come from the dossier. NEVER invent IPs, ports, \
counts, techniques, reputation values, or events. Numbers you state must \
appear in the dossier.
- State the gaps: if data_gaps says something is missing, the narrative must \
say so plainly, never paper over it.
- recommended_actions must start from `attribution.playbook`, adapted to this \
specific detection (its IP, ports, scale). Advisory suggestions for a human \
operator -- not commands.
- cited_detections may contain ONLY detection ids that appear in the dossier.
- Concise, operational, plain language. No dramatization.

Respond with ONLY a JSON object, no prose around it:
{
  "severity": "low" | "medium" | "high" | "critical",
  "executive_summary": "<2-4 sentences: what happened, scale, disposition>",
  "narrative": "<one paragraph telling the story of this incident from the dossier's data, including what is not known>",
  "recommended_actions": ["<playbook step contextualized to this detection>", ...],
  "cited_detections": [<detection id numbers from the dossier your report relies on>]
}"""


def _parse_narrative(content: str) -> dict | None:
    text = (content or "").strip()
    for candidate in (text, text[text.find("{"): text.rfind("}") + 1]):
        if not candidate:
            continue
        try:
            obj = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(obj, dict) and "executive_summary" in obj:
            return obj
    return None


def _dossier_detection_ids(dossier: dict) -> set:
    ids = {dossier["detection"]["id"]}
    ids.update(f["id"] for f in dossier["activity"]["flows"] if f.get("id"))
    ids.update(h["id"] for h in dossier["history"]["detections"] if h.get("id"))
    return ids


def generate_report(conn, detection: dict) -> dict:
    """Build the dossier, make ONE Groq call for the narrative, and assemble
    the final report with the factual sections taken from the dossier itself.
    Raises triage.TriageUnavailable on any transport/parse failure."""
    dossier = build_dossier(conn, detection)

    # triage._chat_completion is the one monkeypatchable Groq seam all three
    # LLM features share (see rag.py for the same pattern).
    msg = triage._chat_completion({
        "model": config.REPORT_MODEL,
        "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                     {"role": "user", "content": json.dumps(dossier,
                                                            default=str)}],
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
    })
    obj = _parse_narrative(msg.get("content") or "")
    if obj is None:
        raise triage.TriageUnavailable("model did not produce a valid report")

    # ENFORCE grounding on the one thing the model asserts about the data:
    # its citations. Ids not present in the dossier are dropped, not trusted.
    allowed = _dossier_detection_ids(dossier)
    cited, seen = [], set()
    for c in obj.get("cited_detections") or []:
        try:
            cid = int(c)
        except (TypeError, ValueError):
            continue
        if cid in allowed and cid not in seen:
            seen.add(cid)
            cited.append(cid)

    severity = str(obj.get("severity") or "").strip().lower()
    if severity not in triage.SEVERITIES:
        severity = "unspecified"

    actions = [str(a).strip() for a in (obj.get("recommended_actions") or [])
               if str(a).strip()]

    det = dossier["detection"]
    return {
        "label": ADVISORY_LABEL,
        "detection_id": det["id"],
        "title": f"Incident report: detection #{det['id']} -- "
                 f"{det.get('technique_name') or 'suspicious flow'} "
                 f"from {det.get('src_ip')}",
        # LLM synthesis (advisory, citation-filtered):
        "severity": severity,
        "executive_summary": str(obj.get("executive_summary") or "").strip(),
        "narrative": str(obj.get("narrative") or "").strip(),
        "recommended_actions": actions,
        "cited_detections": cited,
        # Factual sections BUILT from the dossier, not from the model:
        "detection": det,
        "attack_mapping": dossier["attribution"],
        "reputation": dossier["reputation"],
        "triage": dossier["triage"],
        "activity_summary": {
            "total_flows": dossier["activity"]["total_flows"],
            "suspicious_flows": dossier["activity"]["suspicious_flows"],
            "distinct_dst_ports": dossier["activity"]["distinct_dst_ports"],
            "total_suspicious_detections": dossier["history"]["total_suspicious"],
        },
        "timeline": dossier["timeline"],
        "iocs": dossier["iocs"],
        "data_gaps": dossier["data_gaps"],
        "model": config.REPORT_MODEL,
        "generated_at": datetime.datetime.now(datetime.timezone.utc)
                        .strftime("%Y-%m-%d %H:%M:%SZ"),
    }


# --- Markdown export (zero-dep, the primary format) ----------------------------

def _md_escape(value) -> str:
    """Pipe-escape for table cells. Report values are LLM output and DB
    strings; a stray '|' must not break the table."""
    return str(value if value is not None else "—").replace("|", "\\|")


def to_markdown(report: dict) -> str:
    """Render a generated report as a portable Markdown document. Pure string
    building over the report dict -- no dependency, no template engine."""
    det = report.get("detection") or {}
    amap = report.get("attack_mapping") or {}
    rep = report.get("reputation") or {}
    act = report.get("activity_summary") or {}
    lines = [
        f"# {report.get('title', 'Incident report')}",
        "",
        f"> **{report.get('label', ADVISORY_LABEL)}** · severity: "
        f"**{report.get('severity', 'unspecified')}** · generated "
        f"{report.get('generated_at', '?')} · model `{report.get('model', '?')}`",
        "",
        "## Executive summary",
        "",
        report.get("executive_summary") or "—",
        "",
        "## Narrative",
        "",
        report.get("narrative") or "—",
        "",
        "## Detection",
        "",
        "| Field | Value |",
        "|---|---|",
    ]
    for label, key in (("Detection id", "id"), ("Verdict", "cnn_verdict"),
                       ("Confidence", "cnn_confidence"),
                       ("Source", "src_ip"), ("Destination", "dst_ip"),
                       ("Destination port", "dst_port"), ("Protocol", "proto"),
                       ("Country", "country"), ("Duration (s)", "duration_s"),
                       ("Packets fwd/bwd", None), ("Bytes fwd/bwd", None),
                       ("Timestamp", "timestamp")):
        if label == "Packets fwd/bwd":
            value = f"{det.get('fwd_packets', '—')} / {det.get('bwd_packets', '—')}"
        elif label == "Bytes fwd/bwd":
            value = f"{det.get('fwd_bytes', '—')} / {det.get('bwd_bytes', '—')}"
        else:
            value = det.get(key)
        lines.append(f"| {label} | {_md_escape(value)} |")

    lines += [
        "",
        "## MITRE ATT&CK mapping",
        "",
        f"- **Technique:** {amap.get('technique_id') or 'unattributed'} "
        f"{amap.get('technique_name') or ''}".rstrip(),
        f"- **Tactic:** {amap.get('tactic') or '—'}",
        f"- **Attack family (Stage-2 attributor):** "
        f"{amap.get('attack_family') or 'unattributed'}",
        "",
        "## Indicators (IOCs)",
        "",
        "| Type | Value | Role |",
        "|---|---|---|",
    ]
    for ioc in report.get("iocs") or []:
        value = ioc.get("value")
        if isinstance(value, list):
            value = ", ".join(str(v) for v in value)
        lines.append(f"| {_md_escape(ioc.get('type'))} | {_md_escape(value)} "
                     f"| {_md_escape(ioc.get('role'))} |")

    lines += ["", "## Timeline", "",
              "| Time (UTC) | Detection | Event |", "|---|---|---|"]
    for e in report.get("timeline") or []:
        marker = " **(this report)**" if e.get("focal") else ""
        lines.append(f"| {_md_escape(e.get('timestamp'))} "
                     f"| #{_md_escape(e.get('detection_id'))}{marker} "
                     f"| {_md_escape(e.get('event'))} |")

    lines += [
        "",
        "## Source IP activity",
        "",
        f"- Recorded flows involving the source: {act.get('total_flows', '—')} "
        f"({act.get('suspicious_flows', '—')} suspicious)",
        f"- Distinct destination ports touched: "
        f"{act.get('distinct_dst_ports', '—')}",
        f"- Total suspicious detections from the source: "
        f"{act.get('total_suspicious_detections', '—')}",
        "",
        "## Third-party reputation",
        "",
    ]
    if rep.get("source"):
        lines += [f"- Source: {rep['source']}",
                  f"- Abuse confidence score: "
                  f"{rep['abuse_score'] if rep.get('abuse_score') is not None else '— (source provides report counts only)'}",
                  f"- Reports: {rep['reports'] if rep.get('reports') is not None else '—'}"]
    else:
        lines.append("No third-party reputation data was available for the "
                     "source IP at classification time.")

    triage_rep = report.get("triage")
    lines += ["", "## Prior AI triage", ""]
    if triage_rep:
        lines += [f"- Severity: {triage_rep.get('severity', '—')}",
                  f"- Summary: {triage_rep.get('summary', '—')}",
                  f"- Likely intent: {triage_rep.get('likely_intent', '—')}",
                  f"- Generated: {triage_rep.get('generated_at', '—')}"]
    else:
        lines.append("No triage has been run on this detection.")

    lines += ["", "## Recommended actions (advisory)", ""]
    for i, a in enumerate(report.get("recommended_actions") or [], 1):
        lines.append(f"{i}. {a}")
    if not report.get("recommended_actions"):
        lines.append("—")

    lines += ["", "## Source detections cited", "",
              ", ".join(f"#{c}" for c in report.get("cited_detections") or [])
              or "—"]

    gaps = report.get("data_gaps") or []
    lines += ["", "## Known data gaps", ""]
    lines += [f"- {g}" for g in gaps] if gaps else ["- none"]

    lines += ["", "---",
              f"*{report.get('label', ADVISORY_LABEL)} — synthesized from "
              f"aggregated SecOps-AI data; factual sections are built directly "
              f"from database rows.*", ""]
    return "\n".join(lines)
