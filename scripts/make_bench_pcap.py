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

The flow builders below are also imported by make_demo_pcap.py, which uses real
routable IPs instead of random ones. Everything here is importable: the CLI runs
only under __main__.
"""
import ipaddress
import random
import sys

from scapy.all import wrpcap
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

SERVER = "93.184.216.34"


def public_ip(rng: random.Random) -> str:
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


def _pkt(src, dst, sport, dport, flags, payload=b""):
    return (IP(src=src, dst=dst) /
            TCP(sport=sport, dport=dport, flags=flags) /
            (Raw(load=payload) if payload else b""))


def http_flow(src: str, sport: int, base_ts: float, server: str = SERVER,
              dport: int = 80, step: float = 0.001) -> list:
    """A complete, ordinary TCP conversation: handshake, request, response,
    FIN/FIN. The double FIN matters -- it is what makes FlowTracker close the flow
    and hand it to the classifier instead of waiting out the idle timeout."""
    flow = [
        _pkt(src, server, sport, dport, "S"),
        _pkt(server, src, dport, sport, "SA"),
        _pkt(src, server, sport, dport, "A"),
        _pkt(src, server, sport, dport, "PA",
             b"GET /index.html HTTP/1.1\r\nHost: example\r\n\r\n"),
        _pkt(server, src, dport, sport, "PA",
             b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 200),
        _pkt(src, server, sport, dport, "A"),
        _pkt(src, server, sport, dport, "FA"),
        _pkt(server, src, dport, sport, "FA"),
    ]
    for k, pkt in enumerate(flow):
        pkt.time = base_ts + k * step
    return flow


def scan_flow(src: str, sport: int, dport: int, base_ts: float,
              server: str = SERVER, step: float = 0.001) -> list:
    """A port-scan probe: lone SYN, RST refusal, no payload, no handshake. Shaped
    to look nothing like http_flow on the features the model was trained on
    (bytes ~0, no ACK, RST set, sub-millisecond duration), so a capture built from
    both produces a mix of verdicts rather than one uniform colour."""
    flow = [
        _pkt(src, server, sport, dport, "S"),
        _pkt(server, src, dport, sport, "RA"),
    ]
    for k, pkt in enumerate(flow):
        pkt.time = base_ts + k * step
    return flow


def build_bench_packets(n_ips: int, flows_per_ip: int, seed: int = 1337) -> tuple:
    rng = random.Random(seed)              # deterministic: same capture every run
    ips, seen = [], set()
    while len(ips) < n_ips:
        ip = public_ip(rng)
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)

    packets = []
    t0 = 1_600_000_000.0
    for i, src in enumerate(ips):
        for f in range(flows_per_ip):
            sport = 40000 + (i * 7 + f * 13) % 20000
            packets.extend(http_flow(src, sport, t0 + i * 0.001 + f * 0.4))
    packets.sort(key=lambda p: p.time)
    return packets, ips


def main(argv):
    out = argv[1] if len(argv) > 1 else "bench.pcap"
    n_ips = int(argv[2]) if len(argv) > 2 else 300
    flows_per_ip = int(argv[3]) if len(argv) > 3 else 2

    packets, ips = build_bench_packets(n_ips, flows_per_ip)
    wrpcap(out, packets)

    assert all(not ipaddress.ip_address(i).is_private for i in ips)
    print(f"wrote {len(packets)} packets -> {out}")
    print(f"unique public src IPs: {len(ips)} | flows: {len(ips) * flows_per_ip}")


if __name__ == "__main__":
    main(sys.argv)
