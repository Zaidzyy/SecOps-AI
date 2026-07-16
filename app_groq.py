from flask import Flask, jsonify, request, render_template, session
import psutil
import datetime
import sqlite3
from ollama_lib import OllamaClient
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import ipaddress
import queue
import threading
import requests
import re
import os
# from transformers import TFAutoModel, AutoConfig
import GPUtil
from flask_socketio import SocketIO, emit
import time
from dotenv import load_dotenv
import os

import json

import auth
import config
import flow_tracker as ft
import cnn_engine
import enrichment
import migrations
import pipeline
import rag
import storage
import triage

load_dotenv()

# Groq API Key und Header
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_HEADERS = {
    "Authorization": f"Bearer {GROQ_API_KEY}",
    "Content-Type": "application/json"
}

app = Flask(__name__)

# Sessions are Flask's signed cookies: HttpOnly (no script access) and
# SameSite=Lax (no cross-site sends) always; Secure is config-gated because it
# needs HTTPS, which the local demo does not terminate. The signing key comes
# from SECOPS_SECRET_KEY -- imports (tests, --replay) tolerate an ephemeral
# fallback, but the server refuses to start without a real one (see __main__).
if not config.SECRET_KEY:
    print("[WARN] SECOPS_SECRET_KEY is not set. Using an ephemeral session key; "
          "the server will refuse to start until it is set.")
app.config.update(
    SECRET_KEY=config.SECRET_KEY or os.urandom(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=config.SESSION_COOKIE_SECURE,
)

# CORS locked to the console's own origins (config.ALLOWED_ORIGINS), never "*":
# the dashboard is same-origin, so nothing legitimate needs a wildcard.
# async_mode matches the server actually running this module: 'threading' for
# dev on Werkzeug, 'gevent' under the container's gunicorn gevent worker
# (which monkey-patches, so the pipeline's threads become greenlets there).
socketio = SocketIO(app, async_mode=config.SOCKETIO_ASYNC_MODE,
                    cors_allowed_origins=config.ALLOWED_ORIGINS)

# /register, /login, /logout + the default-deny gate over every other route.
# The lambda is late-bound on purpose: tests swap get_db_connection for a
# temp-DB provider and auth must follow.
auth.init_app(app, lambda: get_db_connection())



# --- Threat detection engine ---
# The borrowed SecIDS-CNN.h5 is intentionally NOT loaded for inference: its
# 10-feature training contract (feature names, order, scaler) was never
# published, so its verdicts on OUR features would be meaningless. We ship our
# own flow classifier instead -- trained on the exact features flow_tracker
# emits (see cnn_engine.py, train_flow_model.py, and the README).
try:
    cnn_engine.load_model()
    print(f"[OK] SecOps-AI: Flow threat-detection engine loaded (primary: {config.PRIMARY_MODEL_TYPE}).")
except Exception as e:
    print(f"[WARN] SecOps-AI: detection engine not loaded ({e}). "
          f"Run train_flow_model.py to build models/. Sniffing continues without verdicts.")

# --- Ingestion pipeline -----------------------------------------------------
# sniff -> shard by flow key -> N workers (one per shard, each owning its own
# FlowTracker) -> write_queue -> ONE DB writer.
#
# The sniff thread parses just enough to identify the flow and route the packet;
# everything expensive (geo/reputation HTTP, classification, DB writes) happens
# downstream.
#
# There is deliberately NO shared FlowTracker and no flow lock. Flow tracking is
# order-dependent -- the first packet defines the forward direction, FIN/FIN
# closes the flow -- so the previous shared-tracker-under-a-lock design was
# thread-safe but not order-preserving: workers raced within a flow, splitting it
# and flipping its direction at random. Each shard now owns its tracker outright,
# and a shard has exactly one worker, so the tracker is single-threaded by
# construction. That is a stronger guarantee than a lock can give, and it is free.
capture_queue = pipeline.ShardedCaptureQueue(config.ENRICHMENT_WORKERS,
                                             config.CAPTURE_QUEUE_MAX)
db_writer = pipeline.BatchedDBWriter(config.DB_PATH)


class _Shard:
    """One queue + the FlowTracker its single worker owns exclusively."""

    def __init__(self, index: int):
        self.index = index
        self.queue = capture_queue.queue(index)
        self.tracker = ft.FlowTracker()


_shards = [_Shard(i) for i in range(capture_queue.shards)]

# Sentinel: "flush your tracker's open flows and signal this event". Sent through
# a shard's queue rather than having the caller touch the tracker, so the owning
# worker remains the only thread that ever mutates it (same barrier trick as
# BatchedDBWriter.drain).
_FLUSH_FLOWS = object()

# Packets/sec, sampled off the capture counter on its own clock (see
# pipeline.RateTracker for why it is not measured between /stats reads).
capture_rate = pipeline.RateTracker(lambda: capture_queue.offered)

# Row->table routing lives in storage.py; the writer stays a generic
# (sql, params) pump. See storage.write_telemetry / storage.write_detection.
_SQL_INSERT_LOG = "INSERT INTO logs (timestamp, log) VALUES (?, ?)"
_SQL_INSERT_METRIC = """
    INSERT INTO metrics (timestamp, cpu, memory, disk, network) VALUES (?, ?, ?, ?, ?)
"""

_pipeline_started = False
_pipeline_lock = threading.Lock()
_workers: list = []


def _enrichment_worker(shard: _Shard):
    """Stage 2: drain ONE shard, enrich + track + classify. Never writes to
    SQLite directly -- rows go to the writer queue.

    This thread is the sole owner of `shard.tracker`: every read and mutation of
    it happens here, which is what keeps flow state correct without a lock.
    """
    while True:
        try:
            item = shard.queue.get(timeout=0.25)
        except queue.Empty:
            # The shard has gone quiet. Idle/long-lived flows still need to be
            # emitted, and this worker is the only thread allowed to do it.
            _expire_idle_flows(shard)
            continue
        try:
            if item is None:                         # shutdown sentinel
                return
            if item[0] is _FLUSH_FLOWS:              # (sentinel, event)
                _flush_shard_flows(shard)
                item[1].set()
                continue
            packet, meta = item
            _process_captured_packet(shard, packet, meta)
        except Exception as e:
            print(f"[ERROR] Enrichment worker (continuing): {e}")
        finally:
            shard.queue.task_done()


def start_pipeline():
    """Start the DB writer + enrichment workers exactly once. Called by both the
    server and pcap replay, so both drive the identical pipeline."""
    global _pipeline_started
    with _pipeline_lock:
        if _pipeline_started:
            return
        db_writer.start()
        capture_rate.start()
        for shard in _shards:
            t = threading.Thread(target=_enrichment_worker, args=(shard,),
                                 name=f"enrich-{shard.index}", daemon=True)
            t.start()
            _workers.append(t)
        _pipeline_started = True


def pipeline_stats() -> dict:
    """Health of the pipeline. `capture.dropped` is the number the operator cares
    about: packets the sniffer had to discard because enrichment fell behind."""
    return {
        "capture": capture_queue.stats(),
        "packets_per_sec": round(capture_rate.rate(), 2),
        "db_writer": db_writer.stats(),
        "enrichment_cache": enrichment.stats(),
        # Summed across shards. Reading len() of a tracker another thread owns is
        # a plain dict length -- atomic under the GIL, and a stat that is one flow
        # stale is not worth a lock on the hot path.
        "open_flows": sum(len(s.tracker) for s in _shards),
    }


ollama_client = OllamaClient(base_url=config.OLLAMA_URL)


def get_db_connection():
    conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    """Create/upgrade the schema. Idempotent -- see migrations.py, which also
    keeps WAL on and splits the old mixed network_requests table into
    telemetry + detections without losing a row."""
    with get_db_connection() as conn:
        migrations.migrate(conn, verbose=True)


initialize_database()

# Feature 3: index the existing incident history for the RAG chat at startup.
# Deltas afterwards -- /chat re-syncs before every retrieval, so new detections
# become searchable the moment an operator asks about them. Guarded: an index
# failure must never stop the console from booting (chat just retries).
try:
    with get_db_connection() as _conn:
        _indexed = rag.index.sync(_conn)
    print(f"[OK] SecOps-AI: BM25 incident index ready ({_indexed} detections indexed).")
except Exception as e:
    print(f"[WARN] BM25 incident index startup sync failed (chat will retry): {e}")


# Geolocation moved to enrichment.get_ip_country(), which is TTL-cached. The old
# version here had NO cache, so every packet from a public IP paid a full HTTP
# round trip on the sniff thread -- the main reason capture fell behind.
get_ip_country = enrichment.get_ip_country


@app.route('/system-info', methods=['GET'])
def system_info():
    try:
        # CPU Information
        cpu_freq = psutil.cpu_freq().current if psutil.cpu_freq() else 'N/A'
        cpu_cores = psutil.cpu_count(logical=False)
        cpu_usage = psutil.cpu_percent()
        memory = psutil.virtual_memory().total
        disk = psutil.disk_usage('/').total

        # GPU Information
        gpus = GPUtil.getGPUs()
        if gpus:
            gpu_usage = f"{gpus[0].load * 100:.2f}%"
            gpu_memory_used = f"{gpus[0].memoryUsed} MB"
            gpu_memory_total = f"{gpus[0].memoryTotal} MB"
        else:
            gpu_usage = "N/A"
            gpu_memory_used = "N/A"
            gpu_memory_total = "N/A"

        # Power Information for laptops
        battery = psutil.sensors_battery()
        power_usage = battery.percent if battery else 'N/A'

        
        system_info_data = {
            "cpu_frequency": cpu_freq,
            "cpu_cores": cpu_cores,
            "cpu_usage": cpu_usage,
            "gpu_usage": gpu_usage,
            "gpu_memory_used": gpu_memory_used,
            "gpu_memory_total": gpu_memory_total,
            "power_usage": power_usage,
            "memory_total": memory,
            "disk_total": disk
        }

        
        print("System Info:", system_info_data)

        return jsonify(system_info_data)

    except Exception as e:
        print("❌ Error fetching internal metrics payloads:", e)
        return jsonify({"error": "Failed to pull system diagnostic telemetry metrics"}), 500

def send_system_metrics():
    counter = 0  # Initialize a loop counter
    while True:
        cpu_usage = psutil.cpu_percent()
        memory_usage = psutil.virtual_memory().percent
        disk_usage = psutil.disk_usage('/').percent

        # 1. Instantly stream hardware utilization to update frontend graphs immediately (Every 5s)
        socketio.emit('update_metrics', {
            'cpu_usage': cpu_usage,
            'memory_usage': memory_usage,
            'disk_usage': disk_usage,
            'cpu_frequency': psutil.cpu_freq().current if psutil.cpu_freq() else 0,
            'cpu_cores': psutil.cpu_count(),
            'gpu_usage': 'N/A',  
            'gpu_memory_used': 'N/A',
            'gpu_memory_total': 'N/A',
            'power_usage': 'N/A',
            'memory_total': psutil.virtual_memory().total,
            'disk_total': psutil.disk_usage('/').total
        })

        # 2. Encapsulate the heavy cloud API interaction
        def run_groq_triage(cpu, mem, disk):
            logs = fetch_recent_logs()[:5]
            network_data = fetch_recent_network_data()[:5]

            payload = {
                "model": "llama-3.1-8b-instant",  
                "messages": [
                    {"role": "system", "content": f"System Metrics Tracking Matrix - CPU: {cpu}%, RAM: {mem}%, Disk Surface: {disk}%."},
                    {"role": "user", "content": f"Ingested Logs Matrix: {logs}, Live Network Telemetry Streams: {network_data}. Analyze for structural anomalies and return brief triage advisory updates."}
                ]
            }

            try:
                response = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=GROQ_HEADERS, json=payload)
                if response.status_code == 200:
                    response_data = response.json()
                    assistant_message = response_data.get("choices", [{}])[0].get("message", {}).get("content", "No advisory generated.")
                    save_log(f"SecOps-AI Background Operator: {assistant_message}")
            except Exception as e:
                print(f"❌ Error communicating with Groq hardware inference layer: {e}")

        # 3. ONLY run the background AI triage every 60 seconds (every 12th loop) to save tokens!
        if counter % 12 == 0:
            threading.Thread(target=run_groq_triage, args=(cpu_usage, memory_usage, disk_usage), daemon=True).start()

        counter += 1
        # socketio.sleep, not time.sleep: yields correctly under every async
        # mode (plain sleep in threading mode, cooperative under gevent).
        socketio.sleep(5)

def fetch_recent_logs():
    with get_db_connection() as conn:
        logs = conn.execute("SELECT log FROM logs ORDER BY timestamp DESC LIMIT 5").fetchall()
    return [log["log"] for log in logs]


def fetch_recent_network_data():
    with get_db_connection() as conn:
        network_data = conn.execute(
            "SELECT ip, country, summary FROM telemetry "
            "ORDER BY timestamp DESC, id DESC LIMIT 5").fetchall()
    return [{"ip": request["ip"], "country": request["country"], "summary": request["summary"]} for request in network_data]



# The metrics stream is one global loop, started on the first authenticated
# connect -- the old per-connect start leaked one immortal thread per page load.
_metrics_task_started = False
_metrics_task_lock = threading.Lock()


def _ensure_metrics_task():
    global _metrics_task_started
    with _metrics_task_lock:
        if _metrics_task_started:
            return
        socketio.start_background_task(send_system_metrics)
        _metrics_task_started = True


@socketio.on('connect')
def handle_connect():
    # GATE THE SOCKET: the HTTP guard means nothing if the live stream still
    # broadcasts. Flask-SocketIO shares the Flask session, so the same signed
    # cookie authenticates both; returning False rejects the connection and
    # the anonymous client receives no events at all.
    if not session.get("user_id"):
        return False
    print("🛡️ SecOps-AI: Operator console dashboard interface connected via WebSocket.")
    _ensure_metrics_task()


@socketio.on('new_log')
def handle_new_log(log_data):
    if not session.get("user_id"):
        return  # defense in depth; an anonymous socket never connects at all
    socketio.emit('new_log', log_data)


@socketio.on('new_network_request')
def handle_new_network_request(network_data):
    if not session.get("user_id"):
        return
    socketio.emit('new_network_request', network_data)



def _record_packet_telemetry(packet):
    """Stage 2 (enrichment worker): geo + reputation for one packet, queued for
    the DB writer.

    Runs on an enrichment worker, never on the sniff thread. Both lookups are
    TTL-cached in enrichment.py, so a given IP costs one HTTP round trip per cache
    window instead of one per packet.
    """
    ip = packet[IP].src
    summary = packet.summary()

    geo = enrichment.get_ip_geo(ip)
    country = geo["country"]
    reputation = enrichment.check_ip_reputation(ip)
    is_blacklisted = reputation["blacklisted"]

    storage.write_telemetry(
        db_writer, ip=ip, country=country, lat=geo["lat"], lon=geo["lon"],
        summary=summary, blacklisted="Yes" if is_blacklisted else "No",
        attacks=reputation["attacks"], reports=reputation["reports"],
        abuse_score=reputation.get("abuse_score"),
        rep_source=reputation.get("source"))

    log_message = (f"Network Packet Ingested from source address: {ip} ({country}) "
                   f"- Target Infrastructure Blacklisted State: {is_blacklisted}")
    save_log(log_message)
    if is_blacklisted:
        notify_ai(log_message)


def _handle_completed_flow(flow):
    """Classify a completed flow with OUR model, persist the verdict, and emit it
    to the dashboard. All model work is wrapped so a failure logs and continues
    rather than killing the sniffer thread."""
    try:
        result = cnn_engine.classify_flow(flow)
    except Exception as e:
        print(f"[ERROR] CNN flow classification failed (continuing): {e}")
        return

    verdict = result["verdict"]
    confidence = float(result["confidence"])
    src = flow.src_ip
    # TTL-cached; for a flow whose packets were just enriched this is a cache hit,
    # so the map gets coordinates without a second round trip.
    geo = enrichment.get_ip_geo(src)
    country = geo["country"]
    # Third-party reputation for the source (Feature 4). Same TTL cache as the
    # telemetry path, so this is normally a hit, never a second HTTP call.
    # Stored beside the verdict, never blended into it: cnn_verdict is OUR
    # detector's opinion, abuse_score is AbuseIPDB's.
    reputation = enrichment.check_ip_reputation(src)

    total_pkts = flow.fwd_packets + flow.bwd_packets
    summary = (f"Flow {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} "
               f"proto={flow.proto} pkts={total_pkts} dur={flow.duration_s:.2f}s")

    # Stage-2 attribution rides along only when Stage 1 flagged the flow;
    # normal flows carry NULLs, and so do flagged flows the attributor
    # declined to name ("technique unattributed" -- see cnn_engine.attribute).
    storage.write_detection(
        db_writer, src_ip=src, dst_ip=flow.dst_ip, src_port=flow.src_port,
        dst_port=flow.dst_port, proto=flow.proto, verdict=verdict,
        confidence=confidence, country=country, lat=geo["lat"], lon=geo["lon"],
        duration_s=flow.duration_s, fwd_packets=flow.fwd_packets,
        bwd_packets=flow.bwd_packets, fwd_bytes=flow.fwd_bytes,
        bwd_bytes=flow.bwd_bytes, summary=summary,
        attack_family=result.get("attack_family"),
        technique_id=result.get("technique_id"),
        technique_name=result.get("technique_name"),
        tactic=result.get("tactic"),
        abuse_score=reputation.get("abuse_score"),
        rep_reports=reputation.get("reports"),
        rep_source=reputation.get("source"))

    technique_note = ""
    if verdict == "suspicious":
        technique_note = (f" [{result['technique_id']} {result['technique_name']}]"
                          if result.get("technique_id")
                          else " [technique unattributed]")
    save_log(f"CNN flow verdict: {verdict} ({confidence:.2f}){technique_note} - {summary}")
    socketio.emit('cnn_verdict', {
        "ip": src, "verdict": verdict, "confidence": confidence,
        "summary": summary, "country": country,
        "lat": geo["lat"], "lon": geo["lon"],
        "attack_family": result.get("attack_family"),
        "technique_id": result.get("technique_id"),
        "technique_name": result.get("technique_name"),
        "tactic": result.get("tactic"),
        "abuse_score": reputation.get("abuse_score"),
        "rep_reports": reputation.get("reports"),
        "rep_source": reputation.get("source"),
    })


def _ingest_packet_flows(shard: _Shard, meta):
    """Feed one packet into this shard's tracker and classify completed flows.

    No lock: the calling worker is the tracker's only owner, and the shard's FIFO
    queue guarantees it sees this flow's packets in capture order.
    """
    try:
        completed = shard.tracker.update(meta)
    except Exception as e:
        print(f"[ERROR] Flow tracking failed (continuing): {e}")
        return
    for flow in completed:
        _handle_completed_flow(flow)


def _expire_idle_flows(shard: _Shard):
    """Emit idle/long-lived flows when a shard goes quiet.

    The packet-driven path only expires flows when new packets arrive, so a flow
    that simply stops would otherwise never be classified. Runs on the shard's own
    worker (the tracker's owner) when its queue has been empty for one poll.

    Disabled during replay: this compares flow timestamps against the WALL CLOCK,
    but a capture carries its own timestamps -- replaying a 2020 pcap in 2026 would
    make every flow look idle for six years and expire it mid-replay, fragmenting
    exactly what the sharding is here to keep whole. Replay ends with an explicit
    flush instead.
    """
    if not _idle_expiry_enabled:
        return
    try:
        expired = shard.tracker.expire()
    except Exception as e:
        print(f"[ERROR] Flow expiry failed (continuing): {e}")
        return
    for flow in expired:
        _handle_completed_flow(flow)


def _flush_shard_flows(shard: _Shard):
    """Emit every flow still open in this shard. End-of-replay only."""
    try:
        remaining = shard.tracker.flush()
    except Exception as e:
        print(f"[ERROR] Flow flush failed (continuing): {e}")
        return
    for flow in remaining:
        _handle_completed_flow(flow)


# Telemetry is enabled per-run rather than per-packet: replay turns it on via
# replay_pcap(with_telemetry=True); live sniffing always does it.
_telemetry_enabled = True
# See _expire_idle_flows: wall-clock expiry is meaningless against a pcap's own
# timestamps, so replay turns it off for the duration.
_idle_expiry_enabled = True


def _process_captured_packet(shard: _Shard, packet, meta):
    """Stage 2 body: everything the sniff thread used to do inline. Called only
    from the shard's enrichment worker.

    `meta` is not None: the capture stage only queues packets it could parse into
    a flow key, which is the same IPv4-TCP/UDP predicate this used to re-check.
    """
    if _telemetry_enabled:
        _record_packet_telemetry(packet)
    _ingest_packet_flows(shard, meta)


def _route(packet):
    """Parse one packet just far enough to identify its flow. Returns
    (canonical_key, meta), or None for anything that is not IPv4 TCP/UDP.

    Routing has to know the flow, so this parse is the one piece of real work the
    capture stage cannot avoid -- a packet can only be sent to the worker that owns
    its flow if we know which flow it belongs to. It stays cheap and CPU-only (no
    HTTP, no DB, no classification, and notably no packet.summary(), which builds a
    string and stays on the worker). The parse result rides along with the packet
    so the worker never repeats it.
    """
    try:
        meta = ft.meta_from_scapy(packet)
    except Exception as e:
        print(f"[ERROR] Packet->flow conversion failed (continuing): {e}")
        return None
    if meta is None:
        return None
    return ft.canonical_key(meta), meta


def packet_callback(packet):
    """Stage 1: the sniff thread's ONLY job -- route the packet to its shard.

    This must stay trivial, and must never raise: an exception here kills the
    sniffer. If the shard's queue is full the packet is dropped and counted rather
    than blocking, because a blocked sniffer stops seeing all traffic.
    """
    routed = _route(packet)
    if routed is None:
        capture_queue.count_ignored()
        return
    key, meta = routed
    capture_queue.offer(key, (packet, meta))


def replay_pcap(path, with_telemetry=False, drop_on_overflow=False):
    """Replay a .pcap/.pcapng through the SAME pipeline as live sniffing.

    Packets go through capture_queue -> enrichment workers -> write_queue -> DB
    writer, exactly as live traffic does, so replay exercises the real path.

    Unlike the sniffer, a file producer applies backpressure by default
    (`put_blocking`): there is no live traffic to miss, so replay stays lossless
    and its counts are deterministic. Pass drop_on_overflow=True to exercise the
    drop path deliberately (flood testing). Returns the packet count read.
    """
    global _telemetry_enabled, _idle_expiry_enabled
    from scapy.utils import PcapReader
    start_pipeline()
    _telemetry_enabled = with_telemetry
    _idle_expiry_enabled = False        # see _expire_idle_flows
    count = 0
    try:
        with PcapReader(path) as reader:
            for pkt in reader:
                count += 1
                routed = _route(pkt)
                if routed is None:
                    capture_queue.count_ignored()
                    continue
                key, meta = routed
                if drop_on_overflow:
                    capture_queue.offer(key, (pkt, meta))
                else:
                    capture_queue.put_blocking(key, (pkt, meta))
        # Wait for the workers to finish everything we queued.
        capture_queue.join()
        # End of capture: every shard flushes its own still-open flows.
        _flush_all_flows()
        db_writer.drain()
    finally:
        _telemetry_enabled = True
        _idle_expiry_enabled = True
    return count


def _flush_all_flows(timeout: float = 30.0) -> bool:
    """Ask every shard's worker to emit its remaining open flows, and wait.

    Goes through the queues rather than calling tracker.flush() from here: the
    owning worker must stay the only thread that touches its tracker, and the
    sentinel arrives behind that shard's packets, so the flush cannot race ahead
    of work still in flight.
    """
    if not _pipeline_started:
        return False
    events = []
    for shard in _shards:
        done = threading.Event()
        shard.queue.put_blocking((_FLUSH_FLOWS, done))
        events.append(done)
    return all(e.wait(timeout) for e in events)


def _bench_drain():
    """Block until the pipeline is fully idle. Used by the throughput benchmark so
    it times the work, not just the enqueue."""
    capture_queue.join()
    db_writer.drain()


# flow_expiry_worker() lived here: one thread expiring flows out of the shared
# tracker on a timer. It is gone because a tracker now has exactly one owner --
# its shard's worker, which expires its own flows when its queue goes quiet (see
# _expire_idle_flows). A separate thread reaching into every shard's tracker would
# reintroduce precisely the cross-thread mutation the sharding removed.



@app.route('/logs', methods=['GET'])
def get_logs():
    page = int(request.args.get('page', 1))
    page_size = 50
    offset = (page - 1) * page_size
    with get_db_connection() as conn:
        logs = conn.execute("""
            SELECT timestamp, log 
            FROM logs 
            ORDER BY timestamp DESC 
            LIMIT ? OFFSET ?
        """, (page_size, offset)).fetchall()
    return jsonify([{"timestamp": log["timestamp"], "log": log["log"]} for log in logs])


@app.route('/search-logs', methods=['POST'])
def search_logs():
    search_term = request.json.get('query', '')
    with get_db_connection() as conn:
        logs = conn.execute("""
            SELECT timestamp, log 
            FROM logs 
            WHERE log LIKE ? 
            ORDER BY timestamp DESC
        """, ('%' + search_term + '%',)).fetchall()
    return jsonify([{"timestamp": log["timestamp"], "log": log["log"]} for log in logs])


# All writes go through the single DB-writer thread. No other thread may write to
# SQLite -- see pipeline.BatchedDBWriter for why one batched writer beats many.
def save_metrics(cpu, memory, disk, network):
    db_writer.submit(_SQL_INSERT_METRIC,
                     (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                      cpu, memory, disk, network))


def save_log(log):
    db_writer.submit(_SQL_INSERT_LOG,
                     (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), log))


# AI Alert notification processing layer (Forces short parsing directly down to the local edge agent)
def notify_ai(message):
    """Ask the local Ollama agent to summarise an incident.

    Fully guarded: this runs on enrichment workers, and Ollama is an optional
    local service. If it is down, ollama_lib raises (connection refused, or a
    non-200 status) -- an unhandled exception here would kill the worker thread
    and silently shrink the pipeline. Degrade instead.
    """
    short_prompt = (f"Anomalous Incident Event Captured: {message}\n"
                    f"Provide a highly concise threat description summary in "
                    f"English using a maximum of 1-2 sentences.")
    try:
        # OllamaClient.chat() posts to /v1/chat/completions (Ollama's OpenAI-
        # compatible endpoint), so the reply is in choices[0].message.content.
        result = ollama_client.chat(
            model=config.OLLAMA_MODEL,
            messages=[{'role': 'user', 'content': short_prompt}],
        )
        response = result['choices'][0]['message']['content']
    except Exception as e:
        print(f"[WARN] Ollama edge alert unavailable (continuing): {e}")
        return
    save_log(f"SecOps-AI Edge Alert Notification: {response}")


def analyze_metrics(cpu, memory, disk):
    if cpu > 85 or memory > 80 or disk > 90:
        message = f"System Infrastructure Warning: Resource Saturation Threshold Breached - System CPU Usage: {cpu}%, RAM Utilization: {memory}%, Disk Space State: {disk}%."
        notify_ai(message)


@app.route('/')
def home():
    return render_template('index.html', username=session.get("username"))

# Server-Status
@app.route('/server-status', methods=['GET'])
def server_status():
    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    print(f"CPU: {cpu}, Memory: {memory}, Disk: {disk}")
    
    save_metrics(cpu, memory, disk, 0)
    analyze_metrics(cpu, memory, disk)
    
    return jsonify({
        "cpu_usage": cpu,
        "memory_usage": memory,
        "disk_usage": disk
    })


# check_ip_blacklist_cached() lived here. It used the network_requests *data*
# table as its cache: it SELECTed the table to decide whether to call
# blocklist.de, then INSERTed a second, half-empty row for the IP on top of the
# one the telemetry path already wrote. The "cache" never expired, and geo had no
# cache at all. It is replaced by enrichment.check_ip_reputation() /
# enrichment.get_ip_country(), which are backed by real TTLCaches and never write
# to the database.


def extract_ip_from_message(message):
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    match = re.search(ip_pattern, message)
    return match.group(0) if match else None


def initialize_groq_client():
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    return headers


@app.route('/chat', methods=['POST'])
def chat_with_groq():
    """Operator chat, now retrieval-grounded (Feature 3).

    The old version pasted the last 5 log lines into the prompt regardless of
    the question. Now the question is scored against the WHOLE incident
    history (BM25, in-process -- see rag.py) and the top-k relevant detections
    are what Groq answers from, with citations filtered against the retrieved
    ids in code. The index delta-syncs here, so the answer sees every
    detection written up to the moment of the question.

    Degradation, never a crash: retrieval failure falls back to the legacy
    last-N-logs context (plainly labelled); Groq failure is a clean 503.
    """
    data = request.get_json(silent=True) or {}
    user_message = (data.get('message') or '').strip()
    if not user_message:
        return jsonify({"error": "empty message"}), 400

    hits = None
    try:
        with get_db_connection() as conn:
            rag.index.sync(conn)
            hits = rag.index.retrieve(user_message, config.RAG_TOP_K)
    except Exception as e:
        print(f"[WARN] BM25 retrieval unavailable (falling back to recent logs): {e}")

    try:
        if hits is None:
            result = rag.answer_without_retrieval(user_message,
                                                  fetch_recent_logs()[:5])
        else:
            result = rag.answer_question(user_message, hits)
    except triage.TriageUnavailable as e:
        return jsonify({"error": "chat unavailable", "reason": str(e)}), 503

    save_log(f"Operator: {user_message}, SecOps-AI: {result['answer']}")
    return jsonify({
        "response": result["answer"],
        "citations": result["citations"],
        "retrieved": result["retrieved"],
        "retrieval": result["retrieval"],
        "label": result["label"],
    })





# --- Read API ---------------------------------------------------------------
# Three endpoints, three questions: /detections "what is bad?", /threat-map
# "where is it?", /stats "how is the pipeline doing?". Telemetry stays queryable
# at /telemetry but never leaks into the detection feed -- keeping 46k packet
# rows out of the operator's view is the entire point of the table split.

@app.route('/detections', methods=['GET'])
def get_detections():
    """Paginated detection feed, newest first, with verdict + confidence + geo.

    ?page=1&page_size=50&verdict=suspicious
    """
    try:
        with get_db_connection() as conn:
            return jsonify(storage.fetch_detections(
                conn,
                page=request.args.get('page', 1),
                page_size=request.args.get('page_size', config.API_PAGE_SIZE_DEFAULT),
                verdict=request.args.get('verdict'),
            ))
    except Exception as e:
        print(f"❌ Error fetching detections: {e}")
        return jsonify({"error": "Failed to fetch detections"}), 500


@app.route('/threat-map', methods=['GET'])
def get_threat_map():
    """Detections aggregated to map points: lat, lon, country, count, worst
    verdict. Points without coordinates are omitted, never plotted at 0,0."""
    try:
        with get_db_connection() as conn:
            return jsonify(storage.fetch_threat_map(conn))
    except Exception as e:
        print(f"❌ Error building threat map: {e}")
        return jsonify({"error": "Failed to build threat map"}), 500


@app.route('/stats', methods=['GET'])
def get_stats():
    """Live counters for the stat header: packets/sec, unique IPs, drops,
    suspicious count -- plus the full pipeline health block.

    This is the consolidated endpoint; /pipeline-stats is kept as an alias for
    the existing dashboard and returns the same pipeline sub-block.
    """
    try:
        with get_db_connection() as conn:
            counters = storage.fetch_counters(conn)
        pipe = pipeline_stats()
        return jsonify({
            "packets_per_sec": pipe["packets_per_sec"],
            "packets_captured": pipe["capture"]["offered"],
            "packets_dropped": pipe["capture"]["dropped"],
            **counters,
            "pipeline": pipe,
        })
    except Exception as e:
        print(f"❌ Error fetching stats: {e}")
        return jsonify({"error": "Failed to fetch stats"}), 500


@app.route('/telemetry', methods=['GET'])
def get_telemetry():
    """Raw per-packet telemetry, paginated. Separate from /detections by design."""
    try:
        with get_db_connection() as conn:
            return jsonify(storage.fetch_telemetry(
                conn,
                page=request.args.get('page', 1),
                page_size=request.args.get('page_size', config.API_PAGE_SIZE_DEFAULT),
            ))
    except Exception as e:
        print(f"❌ Error fetching telemetry: {e}")
        return jsonify({"error": "Failed to fetch telemetry"}), 500


@app.route('/network-requests', methods=['GET'])
def get_network_requests():
    """Back-compat for the current dashboard, which predates the table split.
    Serves telemetry as a bare list, the shape that template expects. New
    consumers should use /telemetry (paged envelope) or /detections."""
    try:
        with get_db_connection() as conn:
            page = storage.fetch_telemetry(conn, page=request.args.get('page', 1))
        return jsonify(page["items"])
    except Exception as e:
        print(f"❌ Error fetching network request table array fields from storage layer: {e}")
        return jsonify({"error": "Failed to safely fetch data arrays from persistent sqlite table parameters"}), 500


@app.route('/attack-coverage', methods=['GET'])
def get_attack_coverage():
    """ATT&CK coverage panel: which techniques have fired, how often, and how
    many flagged flows the attributor honestly declined to name."""
    try:
        with get_db_connection() as conn:
            return jsonify(storage.fetch_attack_coverage(conn))
    except Exception as e:
        print(f"❌ Error building attack coverage: {e}")
        return jsonify({"error": "Failed to build attack coverage"}), 500


@app.route('/triage/<int:detection_id>', methods=['POST'])
def triage_detection(detection_id):
    """On-demand agentic triage for one detection (Feature 2).

    Operator-triggered, never automatic: the bounded tool-use agent in
    triage.py costs real Groq tokens per run. The report is cached on the
    detection row, so re-opening it is a DB read, not a re-bill. Behind the
    auth gate like every other route (default-deny in auth._require_login).
    All failure modes degrade to a clean JSON error -- 404 for a bad id, 503
    when Groq is absent/unreachable -- never a crash.
    """
    try:
        with get_db_connection() as conn:
            det = storage.fetch_detection(conn, detection_id)
            if det is None:
                return jsonify({"error": "detection not found"}), 404
            if det.get("triage_json"):
                return jsonify({"detection_id": detection_id, "cached": True,
                                "triage": json.loads(det["triage_json"])})

            try:
                report = triage.run_triage(det, conn)
            except triage.TriageUnavailable as e:
                return jsonify({"error": "triage unavailable",
                                "reason": str(e)}), 503

            # Direct one-row UPDATE on this connection (see storage.save_triage
            # for why this bypasses the batched writer).
            storage.save_triage(conn, detection_id, json.dumps(report))
            conn.commit()

        save_log(f"AI triage generated for detection #{detection_id}: "
                 f"severity={report['severity']} ({report['summary']})")
        return jsonify({"detection_id": detection_id, "cached": False,
                        "triage": report})
    except Exception as e:
        print(f"❌ Error triaging detection {detection_id}: {e}")
        return jsonify({"error": "triage failed"}), 500


@app.route('/pipeline-stats', methods=['GET'])
def get_pipeline_stats():
    """Pipeline health, including the dropped-packet counter. Alias kept for the
    existing dashboard; /stats is the consolidated endpoint."""
    return jsonify(pipeline_stats())


def drop_monitor(interval=30):
    """Log the dropped-packet count whenever it grows. A drop that nobody can see
    is indistinguishable from working correctly, which is the failure mode this
    whole stage exists to avoid."""
    last = 0
    while True:
        time.sleep(interval)
        dropped = capture_queue.dropped
        if dropped > last:
            msg = (f"Capture queue overflow: {dropped - last} packets dropped in the "
                   f"last {interval}s ({dropped} total). Enrichment is behind the "
                   f"capture rate.")
            print(f"[WARN] {msg}")
            save_log(f"SecOps-AI Pipeline: {msg}")
            last = dropped


# Spin up packet sniffing tracking primitives as an asynchronous listener thread task
def start_sniffing():
    sniff(prn=packet_callback, store=0)

if __name__ == '__main__':
    import sys
    # Replay mode: run a pcap through the SAME flow-detection path as live
    # sniffing, without starting the server/sniffer. Useful for demos and for
    # verifying the pipeline without live capture:
    #     python app_groq.py --replay samples/heartbleed-excerpt.pcap
    if len(sys.argv) >= 3 and sys.argv[1] == '--replay':
        pcap_path = sys.argv[2]
        print(f"Replaying {pcap_path} through the flow-detection pipeline ...")
        # with_telemetry=True: replay must exercise the SAME enrichment the live
        # sniffer does, or it fills detections while leaving telemetry and the
        # map empty -- which is precisely the demo we need it to produce.
        replayed = replay_pcap(pcap_path, with_telemetry=True)
        print(f"Done. Replayed {replayed} packets -> {config.DB_PATH}: "
              f"telemetry + detections written, verdicts emitted over WebSocket.")
        sys.exit(0)

    # No key, no server: sessions signed with a random per-process key would
    # all die on restart, and silently generating one hides a misconfiguration.
    if not config.SECRET_KEY:
        sys.exit("[FATAL] SECOPS_SECRET_KEY is not set. Generate one "
                 "(e.g. python -c \"import secrets; print(secrets.token_hex(32))\") "
                 "and put it in .env or the environment, then restart.")

    print("="*75)
    print("🚀 SECOPS-AI: AI-DRIVEN REAL-TIME SIEM THREAT OPERATOR PIPELINE INITIALIZED")
    print("🛡️ Real-Time Packet Sniffing Engine & Groq LLM Triage Accelerator Active")
    print("="*75)

    # Stage 2 + 3: enrichment workers and the single batched DB writer. Must be up
    # before the sniffer starts pushing into the capture queue.
    start_pipeline()
    print(f"⚙️  Pipeline: {capture_queue.shards} flow-sharded enrichment workers -> "
          f"1 batched DB writer (WAL); capture queue max {config.CAPTURE_QUEUE_MAX} "
          f"({config.CAPTURE_QUEUE_MAX // capture_queue.shards}/shard)")

    # Stage 1: capture + route only.
    threading.Thread(target=start_sniffing, daemon=True).start()

    # Flow expiry needs no thread of its own: each worker expires the flows it
    # owns when its shard goes quiet (see _expire_idle_flows).

    # Surface dropped packets: a silent drop is a lie, a counted drop is a metric.
    threading.Thread(target=drop_monitor, daemon=True).start()

    # async_mode='threading' (see SocketIO above): the app is threaded throughout,
    # so there is no eventlet import and no monkey-patching.
    #
    # debug defaults to OFF (config.DEBUG): debug mode ships the Werkzeug
    # debugger, which is RCE for anyone who can reach the port. The hardcoded
    # allow_unsafe_werkzeug=True is gone -- Flask-SocketIO's production guard
    # (it raises on Werkzeug when stdin is not a TTY) now stays active by
    # default; SECOPS_ALLOW_WERKZEUG=1 is the explicit dev-only override for
    # non-interactive runs until Phase 4b brings a real WSGI server.
    socketio.run(app, debug=config.DEBUG, host=config.HOST, port=config.PORT,
                 use_reloader=False, allow_unsafe_werkzeug=config.ALLOW_WERKZEUG)
    
