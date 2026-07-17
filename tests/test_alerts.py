"""Feature 5, Part B: outbound webhook alerting.

The webhook is ALWAYS mocked (alerts.requests.post). What these tests pin
down:

  * OFF by default: no SECOPS_ALERT_WEBHOOK means no HTTP and no error;
  * the two triggers: corroborated (high confidence + high abuse score) and
    new-technique (first occurrence per process);
  * throttling: one alert per (source IP, technique) per window -- a flood
    of detections produces ONE webhook, and the window slides;
  * payload shape: technique, IP, severity, reputation, timestamp, summary,
    plus Slack (`text`) / Discord (`content`) compatibility;
  * failure-safety: an unreachable webhook or a non-2xx response is logged
    and swallowed -- consider() never raises (it runs on pipeline workers).
"""
import os
import sys

import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import alerts  # noqa: E402
import config  # noqa: E402


WEBHOOK = "https://hooks.example.test/T000/B000/XXX"


def suspicious(**overrides):
    det = {
        "verdict": "suspicious", "confidence": 0.999, "src_ip": "203.0.113.7",
        "technique_id": "T1498", "technique_name": "Network Denial of Service",
        "tactic": "Impact", "abuse_score": 90, "rep_source": "abuseipdb",
        "summary": "Flow 203.0.113.7:1 -> 192.0.2.10:80 proto=6",
    }
    det.update(overrides)
    return det


class FakePost:
    def __init__(self, status=200, exc=None):
        self.calls = []
        self.status = status
        self.exc = exc

    def __call__(self, url, json=None, timeout=None):
        self.calls.append({"url": url, "json": json, "timeout": timeout})
        if self.exc:
            raise self.exc

        class R:
            status_code = self.status
        return R()


@pytest.fixture
def post(monkeypatch):
    fake = FakePost()
    monkeypatch.setattr(alerts.requests, "post", fake)
    alerts.reset()
    yield fake
    alerts.reset()


@pytest.fixture
def webhook_on(monkeypatch):
    monkeypatch.setenv(config.ALERT_WEBHOOK_ENV, WEBHOOK)


# --- off by default ---------------------------------------------------------------

def test_no_webhook_url_means_no_alerting_and_no_error(post, monkeypatch):
    monkeypatch.delenv(config.ALERT_WEBHOOK_ENV, raising=False)
    assert alerts.consider(suspicious()) is None
    assert post.calls == []


# --- triggers ---------------------------------------------------------------------

def test_corroborated_detection_alerts(post, webhook_on):
    payload = alerts.consider(suspicious())
    assert payload is not None
    assert len(post.calls) == 1
    assert post.calls[0]["url"] == WEBHOOK
    assert payload["alert"]["trigger"] in ("corroborated", "new-technique")


def test_normal_verdict_never_alerts(post, webhook_on):
    assert alerts.consider(suspicious(verdict="normal")) is None
    assert post.calls == []


def test_low_confidence_or_low_reputation_does_not_corroborate(post, webhook_on):
    # Isolate the corroborated trigger: pre-mark the technique as seen.
    alerts.consider(suspicious())
    post.calls.clear()

    low_conf = suspicious(src_ip="198.51.100.1", confidence=0.90)
    low_rep = suspicious(src_ip="198.51.100.2", abuse_score=10)
    no_rep = suspicious(src_ip="198.51.100.3", abuse_score=None)
    for det in (low_conf, low_rep, no_rep):
        assert alerts.consider(det) is None
    assert post.calls == []


def test_first_occurrence_of_technique_alerts_once(post, webhook_on):
    # Not corroborated (no abuse score) -- fires only because T1046 is new.
    first = alerts.consider(suspicious(
        src_ip="198.51.100.7", technique_id="T1046",
        technique_name="Network Service Discovery", abuse_score=None))
    assert first is not None
    assert first["alert"]["trigger"] == "new-technique"

    # Same technique from a DIFFERENT ip: not new any more, not corroborated.
    again = alerts.consider(suspicious(
        src_ip="198.51.100.8", technique_id="T1046", abuse_score=None))
    assert again is None
    assert len(post.calls) == 1


def test_unattributed_detections_do_not_fire_new_technique(post, webhook_on):
    det = suspicious(technique_id=None, technique_name=None, abuse_score=None)
    assert alerts.consider(det) is None
    assert post.calls == []


# --- throttling -------------------------------------------------------------------

def test_repeat_detections_are_throttled_to_one_alert(post, webhook_on):
    for _ in range(50):                       # a flood from one source
        alerts.consider(suspicious())
    assert len(post.calls) == 1, "a detection storm must be ONE webhook"


def test_throttle_window_slides(post, webhook_on, monkeypatch):
    t = {"now": 1000.0}
    monkeypatch.setattr(alerts.time, "monotonic", lambda: t["now"])
    alerts.consider(suspicious())
    t["now"] += config.ALERT_THROTTLE_S - 1
    alerts.consider(suspicious())             # still inside the window
    assert len(post.calls) == 1
    t["now"] += 2                             # window has slid past
    alerts.consider(suspicious())
    assert len(post.calls) == 2


def test_different_sources_are_throttled_independently(post, webhook_on):
    alerts.consider(suspicious(src_ip="203.0.113.7"))
    alerts.consider(suspicious(src_ip="203.0.113.8"))
    assert len(post.calls) == 2


# --- payload ----------------------------------------------------------------------

def test_payload_carries_the_specified_fields(post, webhook_on):
    payload = alerts.consider(suspicious())
    alert = payload["alert"]
    assert alert["severity"] == "critical"
    assert alert["ip"] == "203.0.113.7"
    assert alert["technique_id"] == "T1498"
    assert alert["reputation"] == {"abuse_score": 90, "source": "abuseipdb"}
    assert alert["confidence"] == 0.999
    assert alert["summary"].startswith("Flow 203.0.113.7")
    assert alert["timestamp"]
    # Slack renders `text`, Discord renders `content` -- both present, equal.
    assert payload["text"] == payload["content"]
    assert "CRITICAL" in payload["text"] and "203.0.113.7" in payload["text"]
    # And that is exactly what went over the wire.
    assert post.calls[0]["json"] == payload


# --- failure safety ---------------------------------------------------------------

def test_unreachable_webhook_never_raises(webhook_on, monkeypatch):
    fake = FakePost(exc=requests.ConnectionError("refused"))
    monkeypatch.setattr(alerts.requests, "post", fake)
    alerts.reset()
    payload = alerts.consider(suspicious())   # must not raise
    assert payload is not None, "the attempt is still reported for logging"
    assert len(fake.calls) == 1
    alerts.reset()


def test_non_2xx_response_never_raises(webhook_on, monkeypatch):
    fake = FakePost(status=500)
    monkeypatch.setattr(alerts.requests, "post", fake)
    alerts.reset()
    assert alerts.consider(suspicious()) is not None
    alerts.reset()


def test_failed_delivery_is_not_retried_inside_window(webhook_on, monkeypatch):
    fake = FakePost(exc=requests.Timeout("slow"))
    monkeypatch.setattr(alerts.requests, "post", fake)
    alerts.reset()
    alerts.consider(suspicious())
    alerts.consider(suspicious())
    assert len(fake.calls) == 1, "storms are worse than one lost alert"
    alerts.reset()
