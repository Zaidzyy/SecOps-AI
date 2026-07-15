"""IP enrichment (geolocation + reputation) with real TTL caching.

Replaces the previous `check_ip_blacklist_cached`, which used the
`network_requests` *data* table as a cache: it SELECTed the table to decide
whether to call blocklist.de, then INSERTed a second, half-empty row for the same
IP (on top of the row the telemetry path already wrote). That meant duplicate
rows, a "cache" that never expired, and -- for geolocation -- no caching at all,
so every single packet from a public IP paid a full HTTP round trip.

Here both lookups sit behind a `cachetools.TTLCache` keyed by IP, so each IP hits
the network at most once per TTL window. This is what makes per-packet enrichment
affordable, and it keeps us inside the rate limits of the upstream services.

Concurrency: N enrichment workers share these caches, so lookups are single-
flighted. If eight workers see the same new IP at once, exactly ONE performs the
HTTP call and the rest wait for its result. Without that, a burst of traffic from
a new IP would fire N duplicate requests. The HTTP call happens OUTSIDE the cache
lock -- holding it across the network would serialize every worker.
"""
from __future__ import annotations

import ipaddress
import threading

import requests
from cachetools import TTLCache

import config

# Hosts we never enrich (the app's own infra) -- preserved from the original.
EXCLUDED_IPS = {"144.76.114.3", "159.89.102.253"}

PRIVATE_LABEL = "Internal/Private Range (Non-Routable)"
UNKNOWN_LABEL = "Resolution Timeout/Error"
NO_REPUTATION = {"blacklisted": False, "attacks": 0, "reports": 0}

_geo_cache: TTLCache = TTLCache(maxsize=config.GEO_CACHE_MAX, ttl=config.GEO_CACHE_TTL_S)
_rep_cache: TTLCache = TTLCache(maxsize=config.REP_CACHE_MAX, ttl=config.REP_CACHE_TTL_S)
_lock = threading.Lock()
_inflight: dict[tuple, threading.Event] = {}

_stats = {"geo_hits": 0, "geo_misses": 0, "rep_hits": 0, "rep_misses": 0,
          "network_calls": 0, "single_flight_waits": 0}


def stats() -> dict:
    with _lock:
        return dict(_stats)


def reset(clear_stats: bool = True) -> None:
    """Drop all cached entries. For tests and for a manual cache flush."""
    with _lock:
        _geo_cache.clear()
        _rep_cache.clear()
        _inflight.clear()
        if clear_stats:
            for k in _stats:
                _stats[k] = 0


def is_enrichable(ip: str) -> bool:
    """True only for public IPs worth a network lookup. Private/loopback/IPv6 and
    our own excluded hosts are answered locally -- this is also why the shipped
    heartbleed capture (all 127.0.0.1) performs zero lookups."""
    if ip in EXCLUDED_IPS or ":" in ip:
        return False
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _cached_lookup(cache: TTLCache, key_ns: str, ip: str, fetch, default):
    """Return cache[ip], else fetch() exactly once across all threads.

    Single-flight: the first caller for a missing key becomes the leader and does
    the network call; concurrent callers wait on its Event and then read the
    cache. Guarantees one network call per IP per TTL window even under load.
    """
    key = (key_ns, ip)
    hit_stat = f"{key_ns}_hits"
    miss_stat = f"{key_ns}_misses"

    while True:
        with _lock:
            if ip in cache:
                _stats[hit_stat] += 1
                return cache[ip]
            waiter = _inflight.get(key)
            if waiter is None:
                # we are the leader for this key
                _stats[miss_stat] += 1
                event = threading.Event()
                _inflight[key] = event
                break
            _stats["single_flight_waits"] += 1

        # follower: wait for the leader, then re-check the cache
        waiter.wait(timeout=config.ENRICHMENT_HTTP_TIMEOUT_S + 1.0)
        with _lock:
            if ip in cache:
                _stats[hit_stat] += 1
                return cache[ip]
            if _inflight.get(key) is None:
                # leader finished but stored nothing (failure); don't spin
                return default
        # leader vanished mid-flight -- loop and try to become leader ourselves

    try:
        with _lock:
            _stats["network_calls"] += 1
        value = fetch(ip)
    except Exception:
        value = default
    finally:
        with _lock:
            _inflight.pop(key, None)
        event.set()

    with _lock:
        cache[ip] = value
    return value


def _fetch_geo(ip: str) -> str:
    r = requests.get(f"https://geolocation-db.com/json/{ip}&position=true",
                     timeout=config.ENRICHMENT_HTTP_TIMEOUT_S)
    d = r.json()
    return (f"{d.get('country_name', 'Unknown')}, {d.get('city', 'Unknown')}, "
            f"{d.get('state', 'Unknown')}")


def _fetch_reputation(ip: str) -> dict:
    r = requests.get(f"http://api.blocklist.de/api.php?ip={ip}&format=json",
                     timeout=config.ENRICHMENT_HTTP_TIMEOUT_S)
    if r.status_code != 200:
        return dict(NO_REPUTATION)
    d = r.json()
    attacks = int(d.get("attacks", 0) or 0)
    reports = int(d.get("reports", 0) or 0)
    return {"blacklisted": attacks > 0, "attacks": attacks, "reports": reports}


def get_ip_country(ip: str) -> str:
    """Geo string for an IP. Cached for GEO_CACHE_TTL_S; never hits the network
    for private/excluded addresses."""
    if not is_enrichable(ip):
        return PRIVATE_LABEL
    return _cached_lookup(_geo_cache, "geo", ip, _fetch_geo, UNKNOWN_LABEL)


def check_ip_reputation(ip: str) -> dict:
    """{"blacklisted": bool, "attacks": int, "reports": int}. Cached for
    REP_CACHE_TTL_S. Unlike the old version this NEVER writes to the database --
    the cache is a cache, not a table."""
    if not is_enrichable(ip):
        return dict(NO_REPUTATION)
    return dict(_cached_lookup(_rep_cache, "rep", ip, _fetch_reputation,
                               dict(NO_REPUTATION)))
