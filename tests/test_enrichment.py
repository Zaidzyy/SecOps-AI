"""Enrichment cache tests.

The whole point of enrichment.py is that an IP costs at most ONE network call per
TTL window -- that is what makes per-packet enrichment affordable and what keeps
us inside upstream rate limits. These tests pin that contract, including under
concurrency, where a naive cache would let N workers stampede the same new IP.

Time is injected (cachetools TTLCache accepts a `timer`), so expiry is tested
deterministically instead of with sleeps.
"""
import os
import sys
import threading

import pytest
from cachetools import TTLCache

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402
import enrichment  # noqa: E402

PUBLIC_IP = "93.184.216.34"
PUBLIC_IP_2 = "8.8.8.8"


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


@pytest.fixture
def clock(monkeypatch):
    """Fresh caches driven by a controllable clock."""
    c = FakeClock()
    monkeypatch.setattr(enrichment, "_geo_cache",
                        TTLCache(maxsize=100, ttl=config.GEO_CACHE_TTL_S, timer=c))
    monkeypatch.setattr(enrichment, "_rep_cache",
                        TTLCache(maxsize=100, ttl=config.REP_CACHE_TTL_S, timer=c))
    monkeypatch.setattr(enrichment, "_inflight", {})
    for k in enrichment._stats:
        enrichment._stats[k] = 0
    return c


@pytest.fixture
def net(monkeypatch):
    """Stub the network and count calls per URL kind."""
    calls = {"geo": 0, "rep": 0}

    class Resp:
        status_code = 200

        def __init__(self, payload):
            self._p = payload

        def json(self):
            return self._p

    def fake_get(url, *a, **k):
        if "blocklist.de" in url:
            calls["rep"] += 1
            return Resp({"attacks": 3, "reports": 7})
        calls["geo"] += 1
        return Resp({"country_name": "Testland", "city": "Testville", "state": "TS"})

    monkeypatch.setattr(enrichment.requests, "get", fake_get)
    return calls


def test_geo_lookup_hits_network_once_per_ip(clock, net):
    for _ in range(10):
        out = enrichment.get_ip_country(PUBLIC_IP)
        assert "Testland" in out
    assert net["geo"] == 1, "without caching every packet costs an HTTP round trip"
    s = enrichment.stats()
    assert s["geo_misses"] == 1 and s["geo_hits"] == 9


def test_distinct_ips_are_cached_separately(clock, net):
    enrichment.get_ip_country(PUBLIC_IP)
    enrichment.get_ip_country(PUBLIC_IP_2)
    enrichment.get_ip_country(PUBLIC_IP)
    enrichment.get_ip_country(PUBLIC_IP_2)
    assert net["geo"] == 2


def test_reputation_cached_and_parsed(clock, net):
    r1 = enrichment.check_ip_reputation(PUBLIC_IP)
    r2 = enrichment.check_ip_reputation(PUBLIC_IP)
    assert r1 == {"blacklisted": True, "attacks": 3, "reports": 7}
    assert r2 == r1
    assert net["rep"] == 1


def test_cache_expires_after_ttl_then_refetches(clock, net):
    enrichment.get_ip_country(PUBLIC_IP)
    assert net["geo"] == 1

    clock.advance(config.GEO_CACHE_TTL_S - 1)      # still inside the window
    enrichment.get_ip_country(PUBLIC_IP)
    assert net["geo"] == 1

    clock.advance(2)                               # window has passed
    enrichment.get_ip_country(PUBLIC_IP)
    assert net["geo"] == 2, "TTL expiry must trigger exactly one refetch"


def test_private_and_excluded_ips_never_touch_the_network(clock, net):
    for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "::1",
               *enrichment.EXCLUDED_IPS):
        assert enrichment.get_ip_country(ip) in (enrichment.PRIVATE_LABEL,)
        assert enrichment.check_ip_reputation(ip)["blacklisted"] is False
    assert net["geo"] == 0 and net["rep"] == 0


def test_network_failure_degrades_without_raising(clock, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("upstream down")

    monkeypatch.setattr(enrichment.requests, "get", boom)
    assert enrichment.get_ip_country(PUBLIC_IP) == enrichment.UNKNOWN_LABEL
    assert enrichment.check_ip_reputation(PUBLIC_IP)["blacklisted"] is False


def test_concurrent_workers_single_flight_one_call(clock, monkeypatch):
    """8 workers hitting the same cold IP must produce ONE network call.

    Without single-flighting, a burst from a new IP fans out into N duplicate
    requests -- exactly what the TTL cache is supposed to prevent.
    """
    calls = {"n": 0}
    started = threading.Event()
    release = threading.Event()

    class Resp:
        status_code = 200

        def json(self):
            return {"country_name": "Testland", "city": "C", "state": "S"}

    def slow_get(url, *a, **k):
        calls["n"] += 1
        started.set()
        release.wait(2.0)          # hold the "network" open so others pile up
        return Resp()

    monkeypatch.setattr(enrichment.requests, "get", slow_get)

    results = []
    threads = [threading.Thread(target=lambda: results.append(
        enrichment.get_ip_country(PUBLIC_IP))) for _ in range(8)]
    for t in threads:
        t.start()
    started.wait(2.0)
    release.set()
    for t in threads:
        t.join(5.0)

    assert calls["n"] == 1, f"single-flight broken: {calls['n']} duplicate calls"
    assert len(results) == 8 and all("Testland" in r for r in results)
