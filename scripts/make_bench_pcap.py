"""Generate a synthetic benchmark capture with PUBLIC source IPs.

Why this exists: samples/heartbleed-excerpt.pcap is 100% loopback traffic (a
single source IP, 127.0.0.1). enrichment.is_enrichable() short-circuits private
addresses, so replaying it performs ZERO geo/reputation lookups -- it cannot
exercise the enrichment bottleneck the pipeline was built to fix, and would
report a meaningless "improvement".

This builds WAN-facing-sensor-shaped traffic instead: many distinct public client
IPs connecting to one server, each a complete TCP flow (SYN -> data -> FIN/FIN)
so the tracker closes it and cnn_engine.classify() actually runs.

Output is NOT committed (see .gitignore: *.pcap) -- regenerate it on demand:

    python scripts/make_bench_pcap.py /tmp/bench.pcap 300 2
    python scripts/bench_pipeline.py /tmp/bench.pcap 10
"""
import ipaddress
import random
import sys

from scapy.all import wrpcap
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

OUT = sys.argv[1] if len(sys.argv) > 1 else "bench.pcap"
N_IPS = int(sys.argv[2]) if len(sys.argv) > 2 else 300
FLOWS_PER_IP = int(sys.argv[3]) if len(sys.argv) > 3 else 2

rng = random.Random(1337)          # deterministic: same capture every run


def public_ip() -> str:
    """Random IPv4 that `ipaddress` agrees is globally routable. Anything private,
    loopback, multicast, reserved or link-local would skip enrichment entirely and
    silently invalidate the benchmark."""
    while True:
        ip = (f"{rng.randint(1, 223)}.{rng.randint(0, 255)}."
              f"{rng.randint(0, 255)}.{rng.randint(1, 254)}")
        o = ipaddress.ip_address(ip)
        if not (o.is_private or o.is_multicast or o.is_reserved or
                o.is_loopback or o.is_link_local):
            return ip


ips: list[str] = []
seen: set[str] = set()
while len(ips) < N_IPS:
    ip = public_ip()
    if ip not in seen:
        seen.add(ip)
        ips.append(ip)

SERVER = "93.184.216.34"
packets = []
t0 = 1_600_000_000.0

for i, src in enumerate(ips):
    for f in range(FLOWS_PER_IP):
        sport = 40000 + (i * 7 + f * 13) % 20000
        base = t0 + i * 0.001 + f * 0.4

        def mk(flags, payload=b"", rev=False):
            return (IP(src=SERVER if rev else src, dst=src if rev else SERVER) /
                    TCP(sport=80 if rev else sport, dport=sport if rev else 80,
                        flags=flags) /
                    (Raw(load=payload) if payload else b""))

        flow = [
            mk("S"),
            mk("SA", rev=True),
            mk("A"),
            mk("PA", b"GET /index.html HTTP/1.1\r\nHost: example\r\n\r\n"),
            mk("PA", b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 200, rev=True),
            mk("A"),
            mk("FA"),
            mk("FA", rev=True),
        ]
        for k, pkt in enumerate(flow):
            pkt.time = base + k * 0.001
        packets.extend(flow)

packets.sort(key=lambda p: p.time)
wrpcap(OUT, packets)

assert all(not ipaddress.ip_address(i).is_private for i in ips)
print(f"wrote {len(packets)} packets -> {OUT}")
print(f"unique public src IPs: {len(ips)} | flows: {len(ips) * FLOWS_PER_IP}")
