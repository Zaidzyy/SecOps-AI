"""Build the committed demo capture: samples/demo-public-ips.pcap.

The problem this solves: samples/heartbleed-excerpt.pcap is 100% loopback
(127.0.0.1). enrichment.is_enrichable() answers private addresses locally, so
replaying it performs zero geo lookups, stores zero coordinates, and leaves
/threat-map with nothing to plot -- the demo would render an empty map and an
empty feed and look broken.

So this capture uses REAL, globally-routable source IPs, chosen to sit in as many
different countries as possible (public resolvers and root-server mirrors: stable,
well-known, unambiguously geolocated). On replay they resolve through the same
geolocation-db.com path live traffic uses, which is what puts real coordinates in
the DB and real points on the map.

Traffic mix is deliberately two-shaped, so the feed shows more than one verdict:
  * ordinary HTTP conversations (handshake -> request -> response -> FIN/FIN)
  * port-scan probes (lone SYN -> RST, no payload, no handshake)

Regenerate (output IS committed -- see .gitignore's !samples/*.pcap):

    python scripts/make_demo_pcap.py
    python app_groq.py --replay samples/demo-public-ips.pcap
"""
import ipaddress
import os
import sys

from scapy.all import wrpcap

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from make_bench_pcap import http_flow, scan_flow  # noqa: E402

OUT = (sys.argv[1] if len(sys.argv) > 1 else
       os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "samples", "demo-public-ips.pcap"))

# Real public IPs, one per operator/region, picked for geographic spread. The
# comment is the expected country -- geolocation-db.com is the authority at replay
# time and nothing here asserts these, they only explain the choice.
CLIENT_IPS = [
    "8.8.8.8",            # Google DNS            -- US
    "1.1.1.1",            # Cloudflare            -- AU/US
    "9.9.9.9",            # Quad9                 -- CH
    "77.88.8.8",          # Yandex DNS            -- RU
    "223.5.5.5",          # AliDNS                -- CN
    "168.126.63.1",       # KT (Korea Telecom)    -- KR
    "200.221.11.100",     # UOL                   -- BR
    "196.25.1.1",         # Telkom SA             -- ZA
    "193.0.14.129",       # RIPE k.root-servers   -- NL
    "202.12.27.33",       # WIDE m.root-servers   -- JP
    "202.54.1.30",        # VSNL                  -- IN
    "194.150.168.168",    # dns.as250.net         -- DE
    "80.67.169.12",       # FDN                   -- FR
    "165.21.83.88",       # SingNet               -- SG
]

SERVER = "93.184.216.34"        # the "monitored" host everything connects to
SCAN_PORTS = [22, 3389, 445, 8080]
T0 = 1_600_000_000.0


def build():
    packets = []
    for i, src in enumerate(CLIENT_IPS):
        base = T0 + i * 0.05

        # Every client makes normal web requests.
        for f in range(2):
            packets.extend(http_flow(src, 40000 + i * 11 + f, base + f * 0.01,
                                     server=SERVER))

        # Every third client also sweeps ports -- enough suspicious-shaped traffic
        # to prove the feed and the map distinguish verdicts, not so much that the
        # capture stops looking like a network.
        if i % 3 == 0:
            for k, port in enumerate(SCAN_PORTS):
                packets.extend(scan_flow(src, 51000 + i, port,
                                         base + 0.02 + k * 0.005, server=SERVER))

    packets.sort(key=lambda p: p.time)
    return packets


if __name__ == "__main__":
    pkts = build()
    # A demo that quietly contained a private IP would silently skip enrichment
    # for it and produce a missing map point with no error -- fail loudly instead.
    for ip in CLIENT_IPS:
        assert ipaddress.ip_address(ip).is_global, f"{ip} is not globally routable"

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    wrpcap(OUT, pkts)
    size_kb = os.path.getsize(OUT) / 1024
    print(f"wrote {len(pkts)} packets -> {OUT} ({size_kb:.1f} KB)")
    print(f"clients: {len(CLIENT_IPS)} public IPs | server: {SERVER}")
