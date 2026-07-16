"""Throughput benchmark for the ingestion pipeline: sustained packets/sec.

Replays a capture through app_groq's real path (capture_queue -> enrichment
workers -> write_queue -> DB writer) and reports sustained packets/sec.

The network is STUBBED with a fixed simulated latency, for two reasons:
  1. We must not fire thousands of requests at geolocation-db.com / blocklist.de.
  2. It isolates what we are measuring (pipeline architecture) from internet
     jitter, so before/after numbers are comparable.

SIM_MS defaults to 10ms, which is deliberately conservative -- real geo/reputation
APIs answer in ~50-200ms, so this UNDERSTATES both the bottleneck and the gain.

Runs against a throwaway database via SECOPS_DB, so it never touches your real
one.

    python scripts/make_bench_pcap.py /tmp/bench.pcap 300 2
    python scripts/bench_pipeline.py /tmp/bench.pcap 10

Reference numbers on the 4800-packet / 300-public-IP capture at sim_ms=10:

    synchronous per-packet          38.6 pkt/s   5701 HTTP calls
    3-stage pipeline               958.4 pkt/s    602 HTTP calls
    flow-sharded, no flow lock     ~920 pkt/s     602 HTTP calls

Compare the first two only as orders of magnitude; they were measured in another
session. The sharding change was A/B'd on ONE machine back to back, which is the
only comparison worth trusting:

    3-stage pipeline (shared queue + flow lock)   876.9 / 883.5 / 880.3  -> ~880
    flow-sharded (one tracker per worker, no lock) 902.6 / 941.5 / 920.9 -> ~920

So sharding costs nothing and gains a little (~4%). Do not expect more from
removing the lock: this pipeline is bound by simulated HTTP latency, not by lock
contention -- the lock was a correctness bug, not a throughput one, and the fix
was worth making at any price up to and including a small regression.
"""
import os
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP = os.path.abspath(sys.argv[1])
SIM_MS = float(sys.argv[2]) if len(sys.argv) > 2 else 10.0

# MUST be set before config is imported: config.DB_PATH is read once at import and
# is absolute, so (unlike the old relative path) chdir'ing no longer isolates the
# benchmark from the real system_metrics.db.
os.environ["SECOPS_DB"] = os.path.join(
    tempfile.mkdtemp(prefix="secops_bench_"), "bench.db")
sys.path.insert(0, REPO)

import requests  # noqa: E402

_calls = {"n": 0}


class _Resp:
    status_code = 200

    def __init__(self, payload):
        self._p = payload

    def json(self):
        return self._p


def _fake_get(url, *a, **k):
    """Simulate one geo/reputation HTTP round trip."""
    _calls["n"] += 1
    time.sleep(SIM_MS / 1000.0)
    if "blocklist.de" in url:
        return _Resp({"attacks": 0, "reports": 0})
    return _Resp({"country_name": "Testland", "city": "Testville", "state": "TS"})


requests.get = _fake_get

import app_groq  # noqa: E402  (imported AFTER stubbing)

t0 = time.perf_counter()
replayed = app_groq.replay_pcap(PCAP, with_telemetry=True)
app_groq._bench_drain()          # time the work, not just the enqueue
elapsed = time.perf_counter() - t0

stats = app_groq.pipeline_stats()
print(f"packets        : {replayed}")
print(f"elapsed        : {elapsed:.2f}s")
print(f"THROUGHPUT     : {replayed / elapsed:,.1f} packets/sec")
print(f"http calls     : {_calls['n']} (sim latency {SIM_MS}ms each)")
print(f"capture dropped: {stats['capture']['dropped']}")
print(f"db batches     : {stats['db_writer']['batches']} "
      f"for {stats['db_writer']['written']} rows")
print(f"cache          : {stats['enrichment_cache']}")
