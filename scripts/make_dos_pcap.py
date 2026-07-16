"""Build samples/dos-volumetric.pcap: REAL volumetric-attack flow shapes.

Why this exists: the detector's locked scope is volumetric DoS/DDoS and
rate-based attacks, and the operating point was chosen for exactly that claim.
The claim needs a replayable proof: a capture whose attack flows fire
"suspicious" through the live path while its benign flows stay quiet.

Hand-invented attack traffic is how the last false confidence happened (synthetic
PortScan probes looked nothing like CIC-IDS PortScan rows on the model's
features). So nothing here is invented: every flow is a row from the committed
CIC-IDS-2017 fixture (tests/fixtures/cicids_alignment_sample.csv), reconstructed
into a packet sequence exactly the way tests/test_feature_alignment.py does it --
fwd packets then bwd packets, byte totals on the first packet of each direction,
timestamps spread across the row's duration. flow_tracker aggregates the replay
back into the very feature vector the row came from.

Included classes: the volumetric scope (DDoS, the four DoS variants, PortScan)
plus BENIGN rows for the stays-quiet half of the check. Source IPs are public so
the enrichment path runs, same as the demo capture.

Regenerate (output IS committed -- see .gitignore's !samples/*.pcap):

    python scripts/make_dos_pcap.py
    python app_groq.py --replay samples/dos-volumetric.pcap
"""
import os
import random
import sys

import pandas as pd
from scapy.all import wrpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config  # noqa: E402
from train_flow_model import COLUMN_MAP, PROTO_ENCODING, LABEL_COL  # noqa: E402
from make_bench_pcap import SERVER, public_ip  # noqa: E402

FIXTURE = os.path.join(REPO, "tests", "fixtures", "cicids_alignment_sample.csv")
OUT = (sys.argv[1] if len(sys.argv) > 1 else
       os.path.join(REPO, "samples", "dos-volumetric.pcap"))

# The locked scope: attacks that are volumetrically separable. Content-based
# classes (Web Attack *, Brute Force, ...) are deliberately absent -- the model
# cannot see them and this capture must not pretend otherwise.
VOLUMETRIC_CLASSES = ["DDoS", "DoS Hulk", "DoS GoldenEye", "DoS slowloris",
                      "DoS Slowhttptest", "PortScan"]
ROWS_PER_CLASS = 8
BENIGN_ROWS = 16
# Keep every reconstructed flow clear of FLOW_ACTIVE_TIMEOUT_S (120s): a flow the
# tracker splits mid-replay would no longer aggregate back to its source row.
MAX_DURATION_S = 100.0
MAX_PACKETS_PER_FLOW = 2000
T0 = 1_600_000_000.0


def load_rows():
    df = pd.read_csv(FIXTURE, encoding="utf-8").rename(columns=COLUMN_MAP)
    df["label"] = df[LABEL_COL].astype(str)
    df["protocol"] = (df["protocol"].astype(str).str.lower()
                      .map(PROTO_ENCODING).fillna(0).astype(float))
    df["duration_s"] = (df["duration_s"].astype(float) / 1_000_000.0).clip(lower=0.0)
    return df


def usable(row):
    fp, bp = int(round(row["fwd_packets"])), int(round(row["bwd_packets"]))
    if fp + bp == 0 or fp + bp > MAX_PACKETS_PER_FLOW:
        return False
    # The reconstruction plays fwd packets first. A row with zero fwd packets
    # would put the flow's FIRST wire packet on the server side, so the tracker
    # would key the server as initiator and mirror every direction feature --
    # the replayed vector would no longer be this row. Client must speak first.
    if fp == 0:
        return False
    if row["fwd_bytes"] > 0 and fp == 0:
        return False
    if row["bwd_bytes"] > 0 and bp == 0:
        return False
    if row["duration_s"] >= MAX_DURATION_S:
        return False
    # flow_tracker expires a flow once the gap since its last packet reaches
    # FLOW_IDLE_TIMEOUT_S -- with capture timestamps, mid-replay. The
    # reconstruction spaces packets evenly, so a row whose average gap gets
    # near that limit would be split into fragments that no longer aggregate
    # back to the row (and a fragment starting with a bwd packet would even be
    # keyed as server-initiated). This is genuine serving behaviour: flows this
    # sparse are simply not reproducible as one flow through the live tracker.
    total = fp + bp
    gap = 0.0 if total <= 1 else row["duration_s"] / (total - 1)
    if gap >= config.FLOW_IDLE_TIMEOUT_S * 0.8:
        return False
    return int(round(row["protocol"])) in (6, 17)  # TCP/UDP only on the wire


def flow_packets(row, src, sport, base_ts):
    """Same reconstruction contract as tests/test_feature_alignment.py:
    fwd packets then bwd packets, each direction's byte total on its first
    packet, timestamps evenly spaced across the duration. TCP packets carry only
    ACK -- never FIN/RST, so the tracker cannot close the flow early; replay's
    end-of-capture flush emits it, like any real capture's trailing flows."""
    dur = float(row["duration_s"])
    proto = int(round(row["protocol"]))
    fp, bp = int(round(row["fwd_packets"])), int(round(row["bwd_packets"]))
    fb, bb = int(round(row["fwd_bytes"])), int(round(row["bwd_bytes"]))
    total = fp + bp

    dirs = ["f"] * fp + ["b"] * bp
    payloads = [0] * total
    if fp:
        payloads[0] = fb
    if bp:
        payloads[fp] = bb

    packets = []
    for i in range(total):
        ts = base_ts if total == 1 else base_ts + dur * i / (total - 1)
        if dirs[i] == "f":
            s_ip, d_ip, sp, dp = src, SERVER, sport, 80
        else:
            s_ip, d_ip, sp, dp = SERVER, src, 80, sport
        if proto == 6:
            l4 = TCP(sport=sp, dport=dp, flags="A")
        else:
            l4 = UDP(sport=sp, dport=dp)
        pkt = IP(src=s_ip, dst=d_ip) / l4
        if payloads[i]:
            pkt = pkt / Raw(load=b"x" * payloads[i])
        pkt.time = ts
        packets.append(pkt)
    return packets


def build():
    df = load_rows()
    rng = random.Random(20260716)
    packets = []
    picked = {}

    wanted = [(cls, ROWS_PER_CLASS) for cls in VOLUMETRIC_CLASSES]
    wanted.append(("BENIGN", BENIGN_ROWS))
    flow_i = 0
    for cls, n in wanted:
        rows = df[df["label"] == cls]
        rows = rows[rows.apply(usable, axis=1)]
        take = rows.head(n)
        picked[cls] = len(take)
        assert len(take) > 0, f"no usable {cls} rows in the fixture"
        for _, row in take.iterrows():
            src = public_ip(rng)
            # Distinct 5-tuple and a generous gap per flow: flows must never
            # merge, whatever their internal duration.
            packets.extend(flow_packets(row, src, 30000 + flow_i, T0 + flow_i * 0.2))
            flow_i += 1

    packets.sort(key=lambda p: p.time)
    return packets, picked


if __name__ == "__main__":
    pkts, picked = build()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    wrpcap(OUT, pkts)
    size_kb = os.path.getsize(OUT) / 1024
    print(f"wrote {len(pkts)} packets -> {OUT} ({size_kb:.1f} KB)")
    for cls, n in picked.items():
        print(f"  {cls:20s} {n} flows")
