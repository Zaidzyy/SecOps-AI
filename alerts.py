"""Outbound webhook alerting on CRITICAL detections (Feature 5, Part B).

One generic webhook: a JSON POST whose payload carries both a `text` field
(Slack incoming webhooks) and a `content` field (Discord), plus the full
structured `alert` object for anything that parses JSON. The URL comes from
SECOPS_ALERT_WEBHOOK, read at CALL time (import-order reasoning as
GROQ_API_KEY in triage.py: this module imports before load_dotenv() runs).

OFF BY DEFAULT: no URL means consider() returns immediately -- no HTTP, no
error, no log spam. Clone-and-run needs no webhook.

What alerts (config.py owns the numbers):
  corroborated   -- suspicious verdict with confidence >= ALERT_CONFIDENCE
                    AND third-party abuse_score >= ALERT_ABUSE_SCORE: our
                    detector and an external reputation source agree.
  new-technique  -- the first time this process observes a given ATT&CK
                    technique. First occurrences are exactly the events an
                    operator wants to hear about once, immediately.

THROTTLED, so a flood can never become an alert storm: at most one alert per
(source IP, technique) per ALERT_THROTTLE_S window. A DDoS producing hundreds
of detections from one source in a minute sends ONE webhook. new-technique is
inherently once-per-technique-per-process on top of that.

FAILURE-SAFE: consider() is called from the enrichment workers, where an
unhandled exception silently shrinks the pipeline (same posture as
notify_ai's Ollama guard). Every failure mode -- bad URL, timeout, non-2xx --
is caught, logged via print, and swallowed. The worker never notices.
"""
from __future__ import annotations

import datetime
import os
import threading
import time

import requests

import config

SEVERITY = "critical"

# Throttle + first-occurrence state. Process-local by design: this is storm
# suppression, not an audit ledger -- a restart re-arming the "first
# occurrence" alert is acceptable, an alert storm is not. One lock: workers
# from every shard call consider() concurrently.
_lock = threading.Lock()
_last_sent: dict = {}       # (src_ip, technique_id) -> monotonic seconds
_seen_techniques: set = set()


def reset():
    """Tests: forget throttle and first-occurrence state."""
    with _lock:
        _last_sent.clear()
        _seen_techniques.clear()


def _trigger(detection: dict) -> str | None:
    """Why this detection is CRITICAL, or None. Pure function of the values
    the pipeline already computed -- no DB, no network."""
    if detection.get("verdict") != "suspicious":
        return None
    technique = detection.get("technique_id")

    confidence = detection.get("confidence")
    abuse = detection.get("abuse_score")
    if (confidence is not None and abuse is not None
            and confidence >= config.ALERT_CONFIDENCE
            and abuse >= config.ALERT_ABUSE_SCORE):
        return "corroborated"

    if technique is not None and technique not in _seen_techniques:
        return "new-technique"
    return None


def _payload(detection: dict, trigger: str) -> dict:
    technique = detection.get("technique_id")
    tech_label = (f"{technique} {detection.get('technique_name')}" if technique
                  else "technique unattributed")
    reason = ("ML verdict corroborated by third-party reputation"
              if trigger == "corroborated"
              else "first occurrence of this ATT&CK technique")
    line = (f"[SecOps-AI] CRITICAL: suspicious flow from "
            f"{detection.get('src_ip')} ({tech_label}) -- {reason}. "
            f"confidence={detection.get('confidence')}, "
            f"abuse_score={detection.get('abuse_score')}")
    return {
        # Slack incoming webhooks render `text`; Discord renders `content`.
        "text": line,
        "content": line,
        "alert": {
            "severity": SEVERITY,
            "trigger": trigger,
            "ip": detection.get("src_ip"),
            "technique_id": technique,
            "technique_name": detection.get("technique_name"),
            "tactic": detection.get("tactic"),
            "confidence": detection.get("confidence"),
            "reputation": {
                "abuse_score": detection.get("abuse_score"),
                "source": detection.get("rep_source"),
            },
            "summary": detection.get("summary"),
            "timestamp": datetime.datetime.now(datetime.timezone.utc)
                         .strftime("%Y-%m-%d %H:%M:%SZ"),
        },
    }


def consider(detection: dict) -> dict | None:
    """Evaluate one classified flow; POST the webhook if it is alert-worthy.

    Returns the payload that was attempted (delivered or not) so the caller
    can log it, or None when nothing fired. NEVER raises -- this runs on the
    enrichment workers.
    """
    try:
        url = os.getenv(config.ALERT_WEBHOOK_ENV)
        if not url:
            return None                      # alerting is off; free no-op

        with _lock:
            trigger = _trigger(detection)
            if trigger is None:
                return None
            key = (detection.get("src_ip"), detection.get("technique_id"))
            now = time.monotonic()
            last = _last_sent.get(key)
            if last is not None and now - last < config.ALERT_THROTTLE_S:
                return None                  # throttled: storm suppression
            # Claim the slot BEFORE the HTTP call: a slow webhook must not
            # let concurrent workers fire duplicates for the same key, and a
            # failed delivery is not retried (throttle logs it; storms are
            # worse than one lost alert).
            _last_sent[key] = now
            technique = detection.get("technique_id")
            if technique is not None:
                _seen_techniques.add(technique)

        payload = _payload(detection, trigger)
        try:
            r = requests.post(url, json=payload,
                              timeout=config.ALERT_HTTP_TIMEOUT_S)
            if not 200 <= r.status_code < 300:
                print(f"[WARN] Alert webhook returned HTTP {r.status_code} "
                      f"(alert logged, not retried)")
        except requests.RequestException as e:
            print(f"[WARN] Alert webhook unreachable (alert logged, not "
                  f"retried): {e}")
        return payload
    except Exception as e:                   # belt and braces: never crash a worker
        print(f"[WARN] Alert evaluation failed (continuing): {e}")
        return None
