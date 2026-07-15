from flask import Flask, jsonify, request, render_template
import psutil
import datetime
import sqlite3
from ollama_lib import OllamaClient
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import ipaddress
import threading
import requests
import re
import os
from collections import deque
# from transformers import TFAutoModel, AutoConfig
import GPUtil
from flask_socketio import SocketIO, emit
import time
from dotenv import load_dotenv
import os

import config
import flow_tracker as ft
import cnn_engine
import enrichment
import pipeline

load_dotenv()

# Groq API Key und Header
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_HEADERS = {
    "Authorization": f"Bearer {GROQ_API_KEY}",
    "Content-Type": "application/json"
}

app = Flask(__name__)
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")



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

# One flow tracker shared by live sniffing and pcap replay.
#
# It is shared by N enrichment workers, and FlowTracker itself does no locking
# (its dict is mutated by update/expire/flush), so every mutation goes through
# _flow_lock. The lock is held ONLY around the tracker call -- classification and
# enrichment happen outside it, so workers still run in parallel where it counts.
flow_tracker = ft.FlowTracker()
_flow_lock = threading.Lock()

# --- Ingestion pipeline (Phase 2) -------------------------------------------
# sniff -> capture_queue -> enrichment workers -> write_queue -> ONE DB writer.
# The sniff thread does capture ONLY; everything expensive (geo/reputation HTTP,
# flow tracking, classification, DB writes) happens downstream.
capture_queue = pipeline.DropCounterQueue(maxsize=config.CAPTURE_QUEUE_MAX)
db_writer = pipeline.BatchedDBWriter('system_metrics.db')

_SQL_INSERT_TELEMETRY = """
    INSERT INTO network_requests (ip, type, country, summary, blacklisted, attacks, reports)
    VALUES (?, ?, ?, ?, ?, ?, ?)
"""
_SQL_INSERT_FLOW = """
    INSERT INTO network_requests
        (ip, type, country, summary, blacklisted, attacks, reports,
         cnn_verdict, cnn_confidence)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
"""
_SQL_INSERT_LOG = "INSERT INTO logs (timestamp, log) VALUES (?, ?)"
_SQL_INSERT_METRIC = """
    INSERT INTO metrics (timestamp, cpu, memory, disk, network) VALUES (?, ?, ?, ?, ?)
"""

_pipeline_started = False
_pipeline_lock = threading.Lock()
_workers: list = []


def _enrichment_worker():
    """Stage 2: drain capture_queue, enrich + track + classify. Never writes to
    SQLite directly -- rows go to the writer queue."""
    while True:
        try:
            packet = capture_queue.get(timeout=0.25)
        except Exception:
            continue
        try:
            if packet is None:                       # shutdown sentinel
                capture_queue.task_done()
                return
            _process_captured_packet(packet)
        except Exception as e:
            print(f"[ERROR] Enrichment worker (continuing): {e}")
        finally:
            if packet is not None:
                capture_queue.task_done()


def start_pipeline():
    """Start the DB writer + enrichment workers exactly once. Called by both the
    server and pcap replay, so both drive the identical pipeline."""
    global _pipeline_started
    with _pipeline_lock:
        if _pipeline_started:
            return
        db_writer.start()
        for i in range(config.ENRICHMENT_WORKERS):
            t = threading.Thread(target=_enrichment_worker,
                                 name=f"enrich-{i}", daemon=True)
            t.start()
            _workers.append(t)
        _pipeline_started = True


def pipeline_stats() -> dict:
    """Health of the pipeline. `capture.dropped` is the number the operator cares
    about: packets the sniffer had to discard because enrichment fell behind."""
    return {
        "capture": capture_queue.stats(),
        "db_writer": db_writer.stats(),
        "enrichment_cache": enrichment.stats(),
        "open_flows": len(flow_tracker),
    }


ollama_client = OllamaClient(base_url="http://localhost:11434")


def get_db_connection():
    conn = sqlite3.connect('system_metrics.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    with get_db_connection() as conn:
        # WAL lets the dashboard's readers run concurrently with the single DB
        # writer instead of blocking on it. It is a persistent DB-level setting.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS network_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                type TEXT,
                country TEXT,
                summary TEXT,
                blacklisted TEXT,
                attacks INTEGER,
                reports INTEGER,
                cnn_verdict TEXT,
                cnn_confidence REAL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)
        # Migration for existing DBs: add the CNN verdict columns if missing.
        # SQLite has no "ADD COLUMN IF NOT EXISTS", so check PRAGMA first.
        existing_cols = {row["name"] for row in
                         conn.execute("PRAGMA table_info(network_requests)").fetchall()}
        if "cnn_verdict" not in existing_cols:
            conn.execute("ALTER TABLE network_requests ADD COLUMN cnn_verdict TEXT")
        if "cnn_confidence" not in existing_cols:
            conn.execute("ALTER TABLE network_requests ADD COLUMN cnn_confidence REAL")
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_network_requests_timestamp ON network_requests (timestamp);
        """)
        # logs table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                log TEXT
            );
        """)
        # Index for Logs
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs (timestamp);
        """)
        # Tabele for system
        conn.execute("""
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                cpu REAL,
                memory REAL,
                disk REAL,
                network INTEGER
            );
        """)
        # Index for metrics
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics (timestamp);
        """)
        conn.commit()


initialize_database()


# Geolocation moved to enrichment.get_ip_country(), which is TTL-cached. The old
# version here had NO cache, so every packet from a public IP paid a full HTTP
# round trip on the sniff thread -- the main reason capture fell behind.
get_ip_country = enrichment.get_ip_country


MAX_NETWORK_REQUESTS = 1000
network_requests = deque(maxlen=MAX_NETWORK_REQUESTS)

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
        time.sleep(5)

def fetch_recent_logs():
    with get_db_connection() as conn:
        logs = conn.execute("SELECT log FROM logs ORDER BY timestamp DESC LIMIT 5").fetchall()
    return [log["log"] for log in logs]


def fetch_recent_network_data():
    with get_db_connection() as conn:
        network_data = conn.execute("SELECT ip, country, summary FROM network_requests ORDER BY timestamp DESC LIMIT 5").fetchall()
    return [{"ip": request["ip"], "country": request["country"], "summary": request["summary"]} for request in network_data]



@socketio.on('connect')
def handle_connect():
    print("🛡️ SecOps-AI: Operator console dashboard interface connected via WebSocket.")
    socketio.start_background_task(send_system_metrics)  


@socketio.on('new_log')
def handle_new_log(log_data):
    socketio.emit('new_log', log_data) 


@socketio.on('new_network_request')
def handle_new_network_request(network_data):
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

    country = enrichment.get_ip_country(ip)
    reputation = enrichment.check_ip_reputation(ip)
    is_blacklisted = reputation["blacklisted"]

    db_writer.submit(_SQL_INSERT_TELEMETRY,
                     (ip, "IPv4", country, summary,
                      "Yes" if is_blacklisted else "No",
                      reputation["attacks"], reputation["reports"]))

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
    # TTL-cached; for a flow whose packets were just enriched this is a cache hit.
    country = enrichment.get_ip_country(src)

    total_pkts = flow.fwd_packets + flow.bwd_packets
    summary = (f"Flow {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} "
               f"proto={flow.proto} pkts={total_pkts} dur={flow.duration_s:.2f}s")

    db_writer.submit(_SQL_INSERT_FLOW,
                     (src, "FLOW", country, summary, "No", 0, 0, verdict, confidence))

    save_log(f"CNN flow verdict: {verdict} ({confidence:.2f}) - {summary}")
    socketio.emit('cnn_verdict', {
        "ip": src, "verdict": verdict, "confidence": confidence,
        "summary": summary, "country": country,
    })


def _ingest_packet_flows(packet):
    """Feed one packet into the flow tracker and classify any completed flows.
    Runs on an enrichment worker. The tracker mutation is locked (workers share
    one tracker); classification deliberately happens OUTSIDE the lock so the
    expensive part stays parallel."""
    try:
        meta = ft.meta_from_scapy(packet)
    except Exception as e:
        print(f"[ERROR] Packet->flow conversion failed (continuing): {e}")
        return
    if meta is None:
        return
    try:
        with _flow_lock:
            completed = flow_tracker.update(meta)
    except Exception as e:
        print(f"[ERROR] Flow tracking failed (continuing): {e}")
        return
    for flow in completed:
        _handle_completed_flow(flow)


# Telemetry is enabled per-run rather than per-packet: replay turns it on via
# replay_pcap(with_telemetry=True); live sniffing always does it.
_telemetry_enabled = True


def _process_captured_packet(packet):
    """Stage 2 body: everything the sniff thread used to do inline. Called only
    from enrichment workers."""
    if not (packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP))):
        return
    if _telemetry_enabled:
        _record_packet_telemetry(packet)
    _ingest_packet_flows(packet)


def packet_callback(packet):
    """Stage 1: the sniff thread's ONLY job -- hand the packet to the pipeline.

    This must stay trivial. It performs no geo/reputation/DB/classify work; if the
    capture queue is full the packet is dropped and counted rather than blocking,
    because a blocked sniffer stops seeing all traffic.
    """
    capture_queue.offer(packet)


def replay_pcap(path, with_telemetry=False, drop_on_overflow=False):
    """Replay a .pcap/.pcapng through the SAME pipeline as live sniffing.

    Packets go through capture_queue -> enrichment workers -> write_queue -> DB
    writer, exactly as live traffic does, so replay exercises the real path.

    Unlike the sniffer, a file producer applies backpressure by default
    (`put_blocking`): there is no live traffic to miss, so replay stays lossless
    and its counts are deterministic. Pass drop_on_overflow=True to exercise the
    drop path deliberately (flood testing). Returns the packet count read.
    """
    global _telemetry_enabled
    from scapy.utils import PcapReader
    start_pipeline()
    _telemetry_enabled = with_telemetry
    count = 0
    try:
        with PcapReader(path) as reader:
            for pkt in reader:
                count += 1
                if drop_on_overflow:
                    capture_queue.offer(pkt)
                else:
                    capture_queue.put_blocking(pkt)
        # Wait for the workers to finish everything we queued.
        capture_queue.join()
        # End of capture: flush still-open flows through the same handler.
        with _flow_lock:
            remaining = flow_tracker.flush()
        for flow in remaining:
            _handle_completed_flow(flow)
        db_writer.drain()
    finally:
        _telemetry_enabled = True
    return count


def _bench_drain():
    """Block until the pipeline is fully idle. Used by the throughput benchmark so
    it times the work, not just the enqueue."""
    capture_queue.join()
    db_writer.drain()


def flow_expiry_worker():
    """Emit idle/long-lived flows even when traffic goes quiet (the packet-driven
    path only expires flows when new packets arrive). Runs as a daemon thread."""
    while True:
        time.sleep(5)
        try:
            with _flow_lock:
                expired = flow_tracker.expire()
            for flow in expired:
                _handle_completed_flow(flow)
        except Exception as e:
            print(f"[ERROR] Flow expiry worker error (continuing): {e}")



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
            model='llama3.2',
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
    return render_template('index.html')

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
    data = request.get_json()
    user_message = data.get('message', '')

    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent

    # Apply array slices to drop token payload usage under Groq limit gates
    logs = fetch_recent_logs()[:5]
    network_data = fetch_recent_network_data()[:5]

    context_message = (
        f"Operator Query: {user_message}\n"
        f"Live Environment Metrics: System CPU Load: {cpu}%, RAM Space: {memory}%, Hard Disk Surface: {disk}%.\n"
        f"Forensic Logs Table Block: {logs}, Packet Telemetry Requests: {network_data}\n"
        f"Address the operator query briefly and decisively in professional English."
    )

    payload = {
        "model": "llama-3.1-8b-instant",  
        "messages": [{"role": "user", "content": context_message}]
    }

    try:
        response = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=GROQ_HEADERS, json=payload)
        response_data = response.json()
        
        # 🚨 THE FIX: Force the terminal to scream if Groq rejects the key or rate-limits you!
        if response.status_code != 200:
            print(f"\n❌ GROQ API REJECTED THE REQUEST (Code {response.status_code}): {response_data}\n")
            assistant_message = f"Cloud API Connection Error: {response_data.get('error', {}).get('message', 'Unknown Error')}"
        else:
            assistant_message = response_data.get("choices", [{}])[0].get("message", {}).get("content", "No advisory response generated.")
            
    except requests.RequestException as e:
        print("❌ Error querying remote hardware-accelerated Groq model platform:", e)
        assistant_message = f"Inference engine failure update: {e}"

    save_log(f"Operator: {user_message}, SecOps-AI: {assistant_message}")
    return jsonify({"response": assistant_message})





@app.route('/network-requests', methods=['GET'])
def get_network_requests():
    try:
        page = int(request.args.get('page', 1))
        page_size = 50
        offset = (page - 1) * page_size
        with get_db_connection() as conn:
            requests = conn.execute("""
                SELECT ip, type, country, summary, blacklisted, attacks, reports,
                       cnn_verdict, cnn_confidence, timestamp
                FROM network_requests
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            """, (page_size, offset)).fetchall()
        data = [dict(request) for request in requests]
        return jsonify(data)
    except Exception as e:
        print(f"❌ Error fetching network request table array fields from storage layer: {e}")
        return jsonify({"error": "Failed to safely fetch data arrays from persistent sqlite table parameters"}), 500


@app.route('/pipeline-stats', methods=['GET'])
def get_pipeline_stats():
    """Pipeline health, including the dropped-packet counter. Feeds the Phase 3
    stat header; exposed now so drops are observable rather than silent."""
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
        replayed = replay_pcap(pcap_path)
        print(f"Done. Replayed {replayed} packets; flow verdicts written to "
              f"system_metrics.db and emitted over WebSocket.")
        sys.exit(0)

    print("="*75)
    print("🚀 SECOPS-AI: AI-DRIVEN REAL-TIME SIEM THREAT OPERATOR PIPELINE INITIALIZED")
    print("🛡️ Real-Time Packet Sniffing Engine & Groq LLM Triage Accelerator Active")
    print("="*75)

    # Stage 2 + 3: enrichment workers and the single batched DB writer. Must be up
    # before the sniffer starts pushing into the capture queue.
    start_pipeline()
    print(f"⚙️  Pipeline: {config.ENRICHMENT_WORKERS} enrichment workers -> 1 batched DB writer (WAL); "
          f"capture queue max {config.CAPTURE_QUEUE_MAX}")

    # Stage 1: capture only.
    threading.Thread(target=start_sniffing, daemon=True).start()

    # Emit flow verdicts even when traffic goes quiet
    threading.Thread(target=flow_expiry_worker, daemon=True).start()

    # Surface dropped packets: a silent drop is a lie, a counted drop is a metric.
    threading.Thread(target=drop_monitor, daemon=True).start()

    # async_mode='threading' (see SocketIO above): the app is threaded throughout,
    # so there is no eventlet import and no monkey-patching.
    socketio.run(app, debug=True, host='127.0.0.1', port=5000, use_reloader=False, allow_unsafe_werkzeug=True)
    
