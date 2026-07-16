"""Bounded agentic triage for one detection (Feature 2).

An operator triggers POST /triage/<id> on a flagged flow; this module runs a
HARD-BOUNDED Groq tool-use loop that gathers real context and produces a
structured, grounded report. The design constraints, in order of importance:

  GROUNDED -- every tool is a plain function over OUR data: the detections DB
  (storage.flows_for_ip / suspicious_history_for_ip), the existing enrichment
  caches (enrichment.check_ip_reputation / get_ip_geo), and the curated
  attack_mapping table plus its static playbooks below. No tool = no fact.
  The report's evidence list is filtered in code against the tools that
  actually ran -- a citation of a tool that never executed is dropped, so the
  model cannot launder an invented fact through a fabricated citation.

  BOUNDED -- run_triage() is a fixed-range for loop over transport rounds and
  a counted budget of tool executions (config.TRIAGE_MAX_TOOL_CALLS). Once the
  budget is spent, tools are withheld from the request payload entirely and
  the model is forced into JSON synthesis. The loop is provably unable to run
  away: at most MAX+1 transport rounds + 1 forced-synthesis call, at most MAX
  tool executions, no recursion, no while-True.

  DEGRADES, NEVER CRASHES -- no GROQ_API_KEY, Groq unreachable, non-200, or a
  model that never yields parseable JSON all raise TriageUnavailable, which
  the route turns into a clean 503 "triage unavailable" (same posture as
  notify_ai's Ollama guard).

  ADVISORY -- the report is labelled "AI-generated triage (advisory)" and the
  recommended actions start from the static per-technique playbooks below,
  which the LLM contextualizes rather than inventing response steps freely.
"""
from __future__ import annotations

import datetime
import ipaddress
import json
import os

import requests

import attack_mapping
import config
import enrichment
import storage


class TriageUnavailable(Exception):
    """Triage cannot run right now (no key, Groq down, model incoherent).
    Routes catch this and answer 503; it must never escape as a 500."""


GROQ_CHAT_URL = "https://api.groq.com/openai/v1/chat/completions"

SEVERITIES = {"low", "medium", "high", "critical"}
ADVISORY_LABEL = "AI-generated triage (advisory)"

# --- static per-technique playbooks -------------------------------------------
# Curated response steps per ATT&CK technique the attributor can emit (see
# attack_mapping.py). The LLM's job is to CONTEXTUALIZE these for the specific
# detection (which IP, which port, what scale), not to invent incident response
# from scratch -- a hallucinated "step 4: reimage the domain controller" is
# exactly what this table exists to prevent.

PLAYBOOKS = {
    "T1046": [  # Network Service Discovery (port scan)
        "Block or rate-limit the scanning source IP at the perimeter firewall.",
        "Review which of the probed ports expose listening services, and close or filter any that are not required.",
        "Search recent logs for successful connections from the same source after the scan window.",
    ],
    "T1498": [  # Network Denial of Service (volumetric DDoS)
        "Engage upstream provider / DDoS scrubbing for the targeted prefix.",
        "Apply rate limits or ACLs for the offending source addresses at the network edge.",
        "Monitor link saturation and packet-drop counters until traffic returns to baseline.",
    ],
    "T1499": [  # Endpoint Denial of Service (app-layer DoS)
        "Enable per-client connection and request-rate limits on the targeted service.",
        "Tighten slow-request timeouts (slowloris-style floods hold connections open).",
        "Consider a WAF rule or temporary block for the offending source.",
    ],
    "T1110": [  # Brute Force
        "Temporarily block the source IP and review authentication logs for any successful login from it.",
        "Force credential rotation / verify MFA on any account the source attempted.",
        "Add or tighten lockout and rate-limit policy on the targeted service.",
    ],
    "T1071": [  # Application Layer Protocol (C2)
        "Isolate the internal host communicating with the suspected C2 endpoint.",
        "Block the destination address at the egress firewall and search for other hosts contacting it.",
        "Capture and inspect the host's outbound traffic before reimaging decisions.",
    ],
    "T1190": [  # Exploit Public-Facing Application
        "Review web server access and error logs around the detection window for exploitation indicators.",
        "Verify the exposed application is patched; apply virtual patching / WAF rules meanwhile.",
        "Block the source IP and check for follow-on activity (new accounts, webshells, outbound connections).",
    ],
}

# For flagged flows the attributor declined to name -- generic containment.
GENERIC_PLAYBOOK = [
    "Treat as unclassified suspicious activity: review the flow's packet/byte profile and destination service.",
    "Check whether the source IP appears in other recent detections before deciding to block it.",
    "If activity continues, capture traffic from the source for manual analysis.",
]


# --- tools ---------------------------------------------------------------------
# Each takes (conn, args) and returns a JSON-safe dict. An empty result says so
# explicitly ("note": ...) instead of returning bare nothing -- the honesty rule
# lives in the tool output, not just in the prompt.

def _valid_ip(value) -> str | None:
    try:
        ipaddress.ip_address(str(value))
        return str(value)
    except ValueError:
        return None


def _tool_ip_reputation(conn, args) -> dict:
    ip = _valid_ip(args.get("ip"))
    if ip is None:
        return {"error": "invalid or missing 'ip' argument"}
    rep = enrichment.check_ip_reputation(ip)
    geo = enrichment.get_ip_geo(ip)
    out = {"ip": ip, "location": geo["country"], **rep}
    if not enrichment.is_enrichable(ip):
        out["note"] = ("private/non-routable address: no external reputation "
                       "data exists for it")
    elif not rep["blacklisted"]:
        out["note"] = "no blacklist reports found for this IP"
    return out


def _tool_related_flows(conn, args) -> dict:
    ip = _valid_ip(args.get("ip"))
    if ip is None:
        return {"error": "invalid or missing 'ip' argument"}
    result = storage.flows_for_ip(conn, ip, limit=config.TRIAGE_TOOL_ROW_LIMIT)
    if not result["flows"]:
        result["note"] = "no flows recorded for this IP"
    return result


def _tool_recent_detections(conn, args) -> dict:
    ip = _valid_ip(args.get("ip"))
    if ip is None:
        return {"error": "invalid or missing 'ip' argument"}
    result = storage.suspicious_history_for_ip(
        conn, ip, limit=config.TRIAGE_TOOL_ROW_LIMIT)
    if not result["detections"]:
        result["note"] = "no prior suspicious detections from this IP"
    return result


def _tool_technique_info(conn, args) -> dict:
    tid = str(args.get("technique_id") or "").strip().upper()
    for family, info in attack_mapping.FAMILY_TO_TECHNIQUE.items():
        if info["technique_id"] == tid:
            return {**info, "attack_family": family,
                    "playbook": PLAYBOOKS.get(tid, GENERIC_PLAYBOOK)}
    return {"note": f"technique '{tid or 'unattributed'}' is not in the "
                    f"curated mapping; using the generic containment playbook",
            "playbook": GENERIC_PLAYBOOK}


TOOL_IMPLS = {
    "ip_reputation": _tool_ip_reputation,
    "related_flows_for_ip": _tool_related_flows,
    "recent_detections_for_ip": _tool_recent_detections,
    "technique_info": _tool_technique_info,
}

_IP_PARAM = {"type": "object",
             "properties": {"ip": {"type": "string",
                                   "description": "IPv4/IPv6 address"}},
             "required": ["ip"]}

TOOL_SPECS = [
    {"type": "function", "function": {
        "name": "ip_reputation",
        "description": "Blacklist reputation and geolocation for an IP "
                       "(blocklist.de attack/report counts, country/city).",
        "parameters": _IP_PARAM}},
    {"type": "function", "function": {
        "name": "related_flows_for_ip",
        "description": "Recent flows (any verdict) involving an IP, with "
                       "aggregates: total flows, suspicious count, distinct "
                       "destination ports touched.",
        "parameters": _IP_PARAM}},
    {"type": "function", "function": {
        "name": "recent_detections_for_ip",
        "description": "Prior SUSPICIOUS detections from an IP with their "
                       "MITRE ATT&CK attribution.",
        "parameters": _IP_PARAM}},
    {"type": "function", "function": {
        "name": "technique_info",
        "description": "Verified MITRE ATT&CK technique details and the "
                       "curated response playbook for a technique id "
                       "(e.g. T1498).",
        "parameters": {"type": "object",
                       "properties": {"technique_id": {"type": "string"}},
                       "required": ["technique_id"]}}},
]


# --- transport -------------------------------------------------------------------

def _chat_completion(payload: dict) -> dict:
    """One Groq chat round; returns choices[0].message. Every failure mode is
    TriageUnavailable -- the caller degrades, never crashes. Module-level so
    tests can monkeypatch it and drive the loop without a network."""
    key = os.getenv("GROQ_API_KEY")
    if not key:
        raise TriageUnavailable("GROQ_API_KEY is not set")
    try:
        r = requests.post(
            GROQ_CHAT_URL,
            headers={"Authorization": f"Bearer {key}",
                     "Content-Type": "application/json"},
            json=payload, timeout=config.TRIAGE_HTTP_TIMEOUT_S)
    except requests.RequestException as e:
        raise TriageUnavailable(f"Groq unreachable: {e}")
    if r.status_code != 200:
        raise TriageUnavailable(f"Groq returned HTTP {r.status_code}")
    try:
        return r.json()["choices"][0]["message"]
    except (ValueError, KeyError, IndexError, TypeError) as e:
        raise TriageUnavailable(f"malformed Groq response: {e}")


# --- the agent -------------------------------------------------------------------

SYSTEM_PROMPT = """You are the triage analyst inside SecOps-AI, a network flow \
detection console. You are given ONE flagged flow detection (JSON). Use the \
tools to gather real context, then produce a triage report.

HARD RULES:
- Facts come ONLY from the detection record and tool results. If a tool \
returns a 'note' saying data is unavailable or empty, report that honestly; \
NEVER invent reputation, history, or techniques.
- Call technique_info for the detection's technique_id (or 'unattributed') \
and base recommended_actions on the returned playbook, adapted to this \
specific detection. Actions are advisory suggestions for a human operator.
- You have a strict budget of tool calls; be selective.

When done, respond with ONLY a JSON object, no prose around it:
{
  "severity": "low" | "medium" | "high" | "critical",
  "summary": "<one line: what happened>",
  "likely_intent": "<what the actor is probably trying to do>",
  "recommended_actions": ["<playbook step contextualized to this detection>", ...],
  "evidence": [{"tool": "<tool name or 'detection'>", "finding": "<the specific fact that tool result showed>"}, ...]
}
Every evidence item must cite a tool you actually called (or 'detection' for \
the given record) and state only what that result contained."""

# Fields of the detection row the model gets to see. Explicit allowlist: the
# row also carries triage_json (the cache) which must not leak into the prompt.
_CONTEXT_FIELDS = (
    "id", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "cnn_verdict",
    "cnn_confidence", "country", "duration_s", "fwd_packets", "bwd_packets",
    "fwd_bytes", "bwd_bytes", "summary", "attack_family", "technique_id",
    "technique_name", "tactic", "timestamp",
)


def _parse_report(content: str) -> dict | None:
    """Best-effort JSON extraction. None means 'not a report' -- the loop then
    nudges the model once more (still inside the bound)."""
    text = (content or "").strip()
    for candidate in (text, text[text.find("{"): text.rfind("}") + 1]):
        if not candidate:
            continue
        try:
            obj = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(obj, dict) and ("summary" in obj or "severity" in obj):
            return obj
    return None


def _execute_tool(conn, tool_call: dict, trace: list) -> dict:
    """Run one whitelisted tool. Unknown names and bad arguments become error
    results fed back to the model -- never exceptions."""
    fn = tool_call.get("function") or {}
    name = fn.get("name")
    try:
        args = json.loads(fn.get("arguments") or "{}")
    except ValueError:
        args = None

    impl = TOOL_IMPLS.get(name)
    if impl is None:
        result, ok = {"error": f"unknown tool '{name}'"}, False
    elif not isinstance(args, dict):
        result, ok = {"error": "arguments were not a JSON object"}, False
    else:
        try:
            result, ok = impl(conn, args), True
        except Exception as e:                          # tool bug: degrade
            result, ok = {"error": f"tool failed: {e}"}, False
    trace.append({"tool": name, "args": args if isinstance(args, dict) else None,
                  "ok": ok, "result": result})
    return result


def _finalize(report: dict, trace: list) -> dict:
    """Normalize the model's report and ENFORCE grounding: evidence may only
    cite tools that actually executed successfully (or 'detection', the record
    the model was given). Anything else is dropped, not trusted."""
    executed = {t["tool"] for t in trace if t["ok"]} | {"detection"}
    evidence = []
    for item in report.get("evidence") or []:
        if isinstance(item, dict) and item.get("tool") in executed:
            finding = str(item.get("finding") or item.get("detail") or "").strip()
            if finding:
                evidence.append({"tool": item["tool"], "finding": finding})

    severity = str(report.get("severity") or "").strip().lower()
    if severity not in SEVERITIES:
        severity = "unspecified"

    actions = [str(a).strip() for a in (report.get("recommended_actions") or [])
               if str(a).strip()]

    return {
        "label": ADVISORY_LABEL,
        "severity": severity,
        "summary": str(report.get("summary") or "").strip(),
        "likely_intent": str(report.get("likely_intent") or "").strip(),
        "recommended_actions": actions,
        "evidence": evidence,
        # Ground truth of what actually ran, for audit: the UI shows `evidence`,
        # this is the record it can be checked against.
        "tool_trace": [{"tool": t["tool"], "args": t["args"], "ok": t["ok"]}
                       for t in trace],
        "model": config.TRIAGE_MODEL,
        "approach": "tool-loop",
        "generated_at": datetime.datetime.now(datetime.timezone.utc)
                        .strftime("%Y-%m-%d %H:%M:%SZ"),
    }


def run_triage(detection: dict, conn,
               max_tool_calls: int = config.TRIAGE_MAX_TOOL_CALLS) -> dict:
    """The bounded loop. Raises TriageUnavailable on any Groq failure or if the
    model never produces a parseable report.

    Bound, provably: `for _ in range(max_tool_calls + 1)` transport rounds plus
    at most ONE forced-synthesis call after the loop; `calls_used` caps tool
    executions at max_tool_calls. There is no other control flow.
    """
    context = {k: detection.get(k) for k in _CONTEXT_FIELDS}
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "Triage this detection:\n"
                                    + json.dumps(context, default=str)},
    ]
    trace: list = []
    calls_used = 0

    for _ in range(max_tool_calls + 1):
        allow_tools = calls_used < max_tool_calls
        payload = {"model": config.TRIAGE_MODEL, "messages": messages,
                   "temperature": 0.2}
        if allow_tools:
            payload["tools"] = TOOL_SPECS
        else:
            # Budget spent: the model cannot call tools it is not offered.
            payload["response_format"] = {"type": "json_object"}
        msg = _chat_completion(payload)

        tool_calls = msg.get("tool_calls")
        if tool_calls and allow_tools:
            messages.append(msg)
            for tc in tool_calls:
                if calls_used < max_tool_calls:
                    calls_used += 1
                    result = _execute_tool(conn, tc, trace)
                else:
                    result = {"error": "tool budget exhausted; produce the "
                                       "final JSON report now"}
                messages.append({"role": "tool",
                                 "tool_call_id": tc.get("id", ""),
                                 "content": json.dumps(result, default=str)})
            continue

        report = _parse_report(msg.get("content") or "")
        if report is not None:
            return _finalize(report, trace)
        # Content that is not a report: nudge once and keep looping (bounded).
        messages.append({"role": "assistant", "content": msg.get("content") or ""})
        messages.append({"role": "user", "content":
                         "Respond with ONLY the JSON triage object described "
                         "in the system instructions."})

    # Loop exhausted without a report: one final forced-JSON synthesis call.
    messages.append({"role": "user", "content":
                     "Produce the final JSON triage report now, using only the "
                     "tool results above."})
    msg = _chat_completion({"model": config.TRIAGE_MODEL, "messages": messages,
                            "temperature": 0.2,
                            "response_format": {"type": "json_object"}})
    report = _parse_report(msg.get("content") or "")
    if report is None:
        raise TriageUnavailable("model did not produce a valid triage report")
    return _finalize(report, trace)
