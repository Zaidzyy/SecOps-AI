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
import eventlet
from dotenv import load_dotenv
import os

import config
import flow_tracker as ft
import cnn_engine

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

# One flow tracker shared by live sniffing and (future) pcap replay.
flow_tracker = ft.FlowTracker()


ollama_client = OllamaClient(base_url="http://localhost:11434")


def get_db_connection():
    conn = sqlite3.connect('system_metrics.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    with get_db_connection() as conn:
        
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


def get_ip_country(ip):
    try:
        if ":" in ip or ipaddress.ip_address(ip).is_private:
            return "Internal/Private Range (Non-Routable)"
        
        response = requests.get(f"https://geolocation-db.com/json/{ip}&position=true").json()
        country = response.get("country_name", "Unbekannt")
        city = response.get("city", "Unbekannt")
        state = response.get("state", "Unbekannt")
        return f"{country}, {city}, {state}"
    except (requests.RequestException, ValueError):
        return "Resolution Timeout/Error"


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
    """Per-packet geo + blocklist enrichment and telemetry insert (unchanged
    behaviour). Note: this does synchronous HTTP on the sniff thread -- that is a
    known bottleneck addressed in Phase 2, out of scope for this step."""
    ip = packet[IP].src
    summary = packet.summary()

    excluded_ips = {"144.76.114.3", "159.89.102.253"}
    if ip in excluded_ips or ipaddress.ip_address(ip).is_private or ":" in ip:
        country = "Internal Loopback/Excluded IPv6 Target"
        is_blacklisted = False
        attacks = 0
        reports = 0
    else:
        country = get_ip_country(ip)
        blacklist_status = check_ip_blacklist_cached(ip)
        is_blacklisted = blacklist_status["blacklisted"]
        attacks = blacklist_status.get("attacks", 0)
        reports = blacklist_status.get("reports", 0)

    with get_db_connection() as conn:
        conn.execute("""
            INSERT INTO network_requests (ip, type, country, summary, blacklisted, attacks, reports)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (ip, "IPv4", country, summary, "Yes" if is_blacklisted else "No", attacks, reports))
        conn.commit()

    # Audit Log Tracking and AI Escalation triggers
    log_message = f"Network Packet Ingested from source address: {ip} ({country}) - Target Infrastructure Blacklisted State: {is_blacklisted}"
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
    try:
        if ":" in src or ipaddress.ip_address(src).is_private:
            country = "Internal/Private Range (Non-Routable)"
        else:
            country = get_ip_country(src)
    except ValueError:
        country = "Unknown"

    total_pkts = flow.fwd_packets + flow.bwd_packets
    summary = (f"Flow {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} "
               f"proto={flow.proto} pkts={total_pkts} dur={flow.duration_s:.2f}s")

    try:
        with get_db_connection() as conn:
            conn.execute("""
                INSERT INTO network_requests
                    (ip, type, country, summary, blacklisted, attacks, reports,
                     cnn_verdict, cnn_confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (src, "FLOW", country, summary, "No", 0, 0, verdict, confidence))
            conn.commit()
    except Exception as e:
        print(f"[ERROR] Failed to persist flow verdict (continuing): {e}")

    save_log(f"CNN flow verdict: {verdict} ({confidence:.2f}) - {summary}")
    socketio.emit('cnn_verdict', {
        "ip": src, "verdict": verdict, "confidence": confidence,
        "summary": summary, "country": country,
    })


def _ingest_packet_flows(packet):
    """Feed one packet into the flow tracker and classify any completed flows.
    Shared by live sniffing and pcap replay so both run the identical detection
    path. Guarded so a parsing/tracking error never takes down the caller."""
    try:
        meta = ft.meta_from_scapy(packet)
    except Exception as e:
        print(f"[ERROR] Packet->flow conversion failed (continuing): {e}")
        return
    if meta is None:
        return
    try:
        for flow in flow_tracker.update(meta):
            _handle_completed_flow(flow)
    except Exception as e:
        print(f"[ERROR] Flow tracking failed (continuing): {e}")


def packet_callback(packet):
    """Unified capture entry point for BOTH live sniffing and pcap replay. Does
    per-packet telemetry and feeds the packet into the flow tracker; completed
    flows are classified and their verdicts persisted + emitted."""
    if not (packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP))):
        return
    _record_packet_telemetry(packet)
    _ingest_packet_flows(packet)


def replay_pcap(path, with_telemetry=False):
    """Replay a .pcap/.pcapng through the SAME flow-detection path as live
    sniffing. Reuses _ingest_packet_flows + _handle_completed_flow, so verdicts
    are persisted and emitted exactly as they are for live traffic. Per-packet
    geo/blocklist telemetry is off by default (it does blocking HTTP per packet;
    it is the live path's job, not replay's). Returns the packet count."""
    from scapy.utils import PcapReader
    count = 0
    with PcapReader(path) as reader:
        for pkt in reader:
            count += 1
            if with_telemetry and pkt.haslayer(IP) and \
               (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
                _record_packet_telemetry(pkt)
            _ingest_packet_flows(pkt)
    # End of capture: flush any still-open flows through the same handler.
    for flow in flow_tracker.flush():
        _handle_completed_flow(flow)
    return count


def flow_expiry_worker():
    """Emit idle/long-lived flows even when traffic goes quiet (the packet-driven
    path only expires flows when new packets arrive). Runs as a daemon thread."""
    while True:
        time.sleep(5)
        try:
            for flow in flow_tracker.expire():
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


def save_metrics(cpu, memory, disk, network):
    with get_db_connection() as conn:
        conn.execute("""
            INSERT INTO metrics (timestamp, cpu, memory, disk, network) 
            VALUES (?, ?, ?, ?, ?)
        """, (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), cpu, memory, disk, network))
        conn.commit()

def save_log(log):
    with get_db_connection() as conn:
        conn.execute("""
            INSERT INTO logs (timestamp, log) 
            VALUES (?, ?)
        """, (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), log))
        conn.commit()


# AI Alert notification processing layer (Forces short parsing directly down to the local edge agent)
def notify_ai(message):
    short_prompt = f"Anomalous Incident Event Captured: {message}\nProvide a highly concise threat description summary in English using a maximum of 1-2 sentences."
    # OllamaClient.chat() posts to /v1/chat/completions (Ollama's OpenAI-compatible
    # endpoint), so the reply is in choices[0].message.content.
    result = ollama_client.chat(
        model='llama3.2',
        messages=[{'role': 'user', 'content': short_prompt}],
    )
    response = result['choices'][0]['message']['content']
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


def check_ip_blacklist_cached(ip):
    with get_db_connection() as conn:
        result = conn.execute("SELECT blacklisted, attacks, reports FROM network_requests WHERE ip = ?", (ip,)).fetchone()
        if result:
            
            return {
                "blacklisted": result["blacklisted"] == "Yes",
                "attacks": result["attacks"],
                "reports": result["reports"]
            }
        
        
        url = f"http://api.blocklist.de/api.php?ip={ip}&format=json"
        try:
            response = requests.get(url)
            data = response.json() if response.status_code == 200 else {"blacklisted": False}
            blacklisted = data.get("attacks", 0) > 0
            attacks = data.get("attacks", 0)
            reports = data.get("reports", 0)
            
            
            conn.execute(
                "INSERT INTO network_requests (ip, blacklisted, attacks, reports) VALUES (?, ?, ?, ?)",
                (ip, "Yes" if blacklisted else "No", attacks, reports)
            )
            conn.commit()

            return {"blacklisted": blacklisted, "attacks": attacks, "reports": reports}
        except requests.RequestException:
            return {"blacklisted": False}


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

    # Fire up the packet sniffer thread
    threading.Thread(target=start_sniffing, daemon=True).start()

    # Emit flow verdicts even when traffic goes quiet
    threading.Thread(target=flow_expiry_worker, daemon=True).start()

    # Force Flask-SocketIO to deploy utilizing the eventlet production layer wrapper
    socketio.run(app, debug=True, host='127.0.0.1', port=5000, use_reloader=False, allow_unsafe_werkzeug=True)
    
