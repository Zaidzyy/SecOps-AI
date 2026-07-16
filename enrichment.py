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
import os
import threading

import requests
from cachetools import TTLCache

import config

# Hosts we never enrich (the app's own infra) -- preserved from the original.
EXCLUDED_IPS = {"144.76.114.3", "159.89.102.253"}

PRIVATE_LABEL = "Internal/Private Range (Non-Routable)"
UNKNOWN_LABEL = "Resolution Timeout/Error"

# Reputation record shape (Feature 4). One shape for every source, so callers
# never branch: blocklist.de rows carry abuse_score=None, AbuseIPDB rows carry
# attacks=0 (that count is blocklist.de's concept and pretending otherwise
# would be dishonest). `source` says which service actually answered:
#   "abuseipdb" | "blocklist.de" -- a real lookup
#   "none"      -- never checked (private/excluded address)
#   "unknown"   -- checked, but every source failed (marked, not invented)
# The abuse_score is a THIRD-PARTY reputation signal (AbuseIPDB's
# abuseConfidenceScore, 0-100); it is never the ML detector's verdict.
NO_REPUTATION = {"blacklisted": False, "attacks": 0, "reports": 0,
                 "abuse_score": None, "usage_type": None, "isp": None,
                 "source": "none"}
REPUTATION_UNKNOWN = {**NO_REPUTATION, "source": "unknown"}

# Geo results are dicts, not strings: the threat map needs coordinates, and
# lat/lon arrive in the SAME geolocation-db.com response the country came from --
# so capturing them costs nothing extra and stays inside the one-lookup-per-IP-
# per-TTL-window guarantee. lat/lon are None whenever we have no fix (private
# ranges, upstream failure, or a response without usable coordinates); callers
# must treat "no coordinates" as normal rather than as an error.
PRIVATE_GEO = {"country": PRIVATE_LABEL, "lat": None, "lon": None}
UNKNOWN_GEO = {"country": UNKNOWN_LABEL, "lat": None, "lon": None}

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


def _coord(value) -> float | None:
    """geolocation-db.com returns latitude/longitude as numbers when it has a fix
    and as the string "Not found" when it doesn't, so a bare float() would raise
    on a perfectly ordinary response. Anything non-numeric means "no fix"."""
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return None if f != f else f          # reject NaN


def _fetch_geo(ip: str) -> dict:
    r = requests.get(f"https://geolocation-db.com/json/{ip}&position=true",
                     timeout=config.ENRICHMENT_HTTP_TIMEOUT_S)
    d = r.json()
    # `or` rather than dict.get's default: the API sends the keys with an explicit
    # null for IPs it can only place at country level, and get(k, "Unknown") returns
    # that null -- which rendered real rows as "Singapore, None, None".
    return {
        "country": (f"{d.get('country_name') or 'Unknown'}, "
                    f"{d.get('city') or 'Unknown'}, {d.get('state') or 'Unknown'}"),
        "lat": _coord(d.get("latitude")),
        "lon": _coord(d.get("longitude")),
    }


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def _fetch_reputation_abuseipdb(ip: str, key: str) -> dict:
    """One AbuseIPDB /check. Raises on ANY non-200 -- including 429, which is
    the free tier saying no (1000 checks/day) -- so the dispatcher can fall
    back to blocklist.de instead of losing the lookup entirely."""
    r = requests.get(ABUSEIPDB_URL,
                     params={"ipAddress": ip,
                             "maxAgeInDays": config.ABUSEIPDB_MAX_AGE_DAYS},
                     headers={"Key": key, "Accept": "application/json"},
                     timeout=config.ENRICHMENT_HTTP_TIMEOUT_S)
    if r.status_code != 200:
        raise RuntimeError(f"AbuseIPDB HTTP {r.status_code}")
    d = r.json().get("data") or {}
    score = int(d.get("abuseConfidenceScore") or 0)
    return {
        "blacklisted": score >= config.ABUSE_SCORE_FLAG_THRESHOLD,
        "attacks": 0,                      # blocklist.de's field; no equivalent here
        "reports": int(d.get("totalReports") or 0),
        "abuse_score": score,
        "usage_type": d.get("usageType"),
        "isp": d.get("isp"),
        "source": "abuseipdb",
    }


def _fetch_reputation_blocklist(ip: str) -> dict:
    r = requests.get(f"http://api.blocklist.de/api.php?ip={ip}&format=json",
                     timeout=config.ENRICHMENT_HTTP_TIMEOUT_S)
    if r.status_code != 200:
        # "we could not check" is not "clean" -- mark it unknown.
        return dict(REPUTATION_UNKNOWN)
    d = r.json()
    attacks = int(d.get("attacks", 0) or 0)
    reports = int(d.get("reports", 0) or 0)
    return {"blacklisted": attacks > 0, "attacks": attacks, "reports": reports,
            "abuse_score": None, "usage_type": None, "isp": None,
            "source": "blocklist.de"}


def _fetch_reputation(ip: str) -> dict:
    """Source dispatch: AbuseIPDB when a key is configured, else blocklist.de.

    The key is read per call, not at import (load_dotenv in app_groq runs
    after this module is imported), and its absence is a supported
    configuration -- clone-and-run works with no key at all.

    An AbuseIPDB failure (429 when the daily tier is spent, network trouble,
    a malformed response) falls back to blocklist.de for THIS lookup rather
    than answering "unknown" while a working source remains. If blocklist.de
    also fails, _cached_lookup catches and returns REPUTATION_UNKNOWN -- and
    caches it, so a failing upstream is retried once per TTL window, not once
    per packet.
    """
    key = os.getenv("SECOPS_ABUSEIPDB_KEY")
    if key:
        try:
            return _fetch_reputation_abuseipdb(ip, key)
        except Exception as e:
            print(f"[WARN] AbuseIPDB lookup failed for {ip} ({e}); "
                  f"falling back to blocklist.de")
    return _fetch_reputation_blocklist(ip)


def get_ip_geo(ip: str) -> dict:
    """{"country": str, "lat": float|None, "lon": float|None} for an IP.

    Cached for GEO_CACHE_TTL_S and single-flighted, so an IP costs at most one
    HTTP round trip per window no matter how many packets or workers ask for it.
    Never hits the network for private/excluded addresses.
    """
    if not is_enrichable(ip):
        return dict(PRIVATE_GEO)
    return dict(_cached_lookup(_geo_cache, "geo", ip, _fetch_geo, UNKNOWN_GEO))


def get_ip_country(ip: str) -> str:
    """Just the country string, for callers (logs, LLM context) that have no use
    for coordinates. Shares get_ip_geo's cache entry -- it is not a second lookup."""
    return get_ip_geo(ip)["country"]


def check_ip_reputation(ip: str) -> dict:
    """Reputation record for an IP -- see NO_REPUTATION above for the shape
    and the source semantics. AbuseIPDB when SECOPS_ABUSEIPDB_KEY is set,
    blocklist.de otherwise. Cached for REP_CACHE_TTL_S and single-flighted:
    one lookup per IP per window is also what keeps AbuseIPDB's 1000/day free
    tier out of reach of a packet flood. NEVER writes to the database --
    the cache is a cache, not a table."""
    if not is_enrichable(ip):
        return dict(NO_REPUTATION)
    return dict(_cached_lookup(_rep_cache, "rep", ip, _fetch_reputation,
                               dict(REPUTATION_UNKNOWN)))
