"""Static, curated attack-family -> MITRE ATT&CK technique lookup.

This table is the ONLY source of technique IDs in the system. The Stage-2
attributor predicts an attack FAMILY (a string from its training labels); this
module turns that family into a technique. No LLM is involved anywhere in the
chain, so a technique ID can never be hallucinated -- it is either one of the
verified entries below or the explicit "unattributed" sentinel.

Every ID, name, and tactic below was verified against attack.mitre.org on
2026-07-16 (all active, none deprecated/revoked):

  T1046 Network Service Discovery      -- Discovery          (TA0007)
  T1498 Network Denial of Service      -- Impact             (TA0040)
  T1499 Endpoint Denial of Service     -- Impact             (TA0040)
  T1110 Brute Force                    -- Credential Access  (TA0006)
  T1071 Application Layer Protocol     -- Command and Control(TA0011)
  T1190 Exploit Public-Facing Application -- Initial Access  (TA0001)

Mapping rationale (family granularity, not sub-technique -- 6 flow features
cannot distinguish tools, only behaviours):
  * port-scan: CIC-IDS PortScan. Scanning services across ports = T1046.
  * ddos: distributed volumetric flood exhausting network bandwidth = T1498.
  * dos: Hulk/GoldenEye/slowloris/Slowhttptest all exhaust the target
    SERVICE (application-layer), not the pipe = T1499.
  * brute-force: FTP-Patator/SSH-Patator credential guessing = T1110.
  * botnet: CIC-IDS Bot traffic is C2 over HTTP = T1071.
  * web-attack: Web Attack Brute Force/XSS/Sql Injection -- attacks against a
    public-facing web application = T1190. (Web brute force alone would argue
    for T1110, but the attributor works at family level and cannot split the
    three; T1190 is the family's honest common denominator.)

HONESTY RULE: a family not in this table (notably "other", the attributor's
abstain class) and any prediction below the attributor's confidence threshold
map to UNATTRIBUTED -- "malicious - technique unattributed" -- never to a
forced wrong technique.
"""
from __future__ import annotations

FAMILY_TO_TECHNIQUE = {
    "port-scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
    },
    "ddos": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
    },
    "dos": {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact",
    },
    "brute-force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    },
    "botnet": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
    },
    "web-attack": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
}

# The explicit sentinel for "Stage 1 says malicious, Stage 2 declines to name a
# technique". technique_id stays NULL in the DB; the UI renders the label.
UNATTRIBUTED = {
    "technique_id": None,
    "technique_name": "technique unattributed",
    "tactic": None,
}


def technique_for_family(family: str | None) -> dict:
    """Family -> technique record, UNATTRIBUTED for anything unknown."""
    if family is None:
        return dict(UNATTRIBUTED)
    return dict(FAMILY_TO_TECHNIQUE.get(family, UNATTRIBUTED))
