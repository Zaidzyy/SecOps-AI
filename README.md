
![SIEM GROQ](ss.png)

# SecOps-AI: Real-Time AI-Driven SIEM Threat Operator

SecOps-AI is an advanced, high-performance Security Information and Event Management (SIEM) real-time threat detection and acceleration pipeline. Built to address modern Security Operations Center (SOC) bottlenecks and drastically reduce alert fatigue, the platform ingests high-volume Syslog and Windows event logs, applies dual-engine deep learning models, and leverages ultra-low-latency LLM inference to deliver instant, actionable threat triage.

---

## 🚀 System Architecture & Core Capabilities

The architecture is split into a high-concurrency data ingestion engine, an embedded deep learning classification layer, and an accelerated AI orchestration tier:

* **Flow-based ML threat detection:** Sniffed packets are aggregated into bidirectional flows (`flow_tracker.py`) and scored by a classifier we trained ourselves on CIC-IDS-2017 flow features (`cnn_engine.py`). See **Threat Detection Engine** below for the model, its held-out metrics, and why the borrowed `SecIDS-CNN.h5` is not used for inference.
* **Asynchronous Ingestion Engine:** Designed around an agile, event-driven web framework (Flask-SocketIO/FastAPI architecture) optimized for real-time, bi-directional telemetry streaming, live log parsing, and concurrent system metric tracking (CPU, RAM, GPU states).
* **Groq API Telemetry Acceleration:** Integrated directly with the Groq API to run lightning-fast hardware-accelerated LLM inference. It instantly transforms raw, cryptic, or high-volume log payloads into concise, structured, human-readable contextual threat summaries.
* **Automated Triage Dashboard:** Features a responsive, frontend console built with Tailwind CSS and Chart.js, visualizing streaming network metrics while maintaining an automated, rule-based triage and incident chat environment for rapid operator decision-making.

---

## 🧠 Threat Detection Engine

Packets alone can't be classified by a flow-trained model, so the pipeline is:

```
capture → flow aggregation (flow_tracker.py) → feature extraction → classifier (cnn_engine.py) → verdict → DB + dashboard
```

**Why we don't use the borrowed `SecIDS-CNN.h5`.** The project originally shipped
`Keyven/SecIDS-CNN`, but its input is a 10-feature vector whose **feature names,
order, and scaler were never published** (the upstream `preprocess_data()` is an
empty placeholder). Feeding our own flow features into it would produce
confident-looking but meaningless verdicts. Rather than fake it, we **trained our
own model** on the exact flow features our tracker emits. `SecIDS-CNN.h5` was
removed from the inference path entirely and is **not shipped** with this repo;
the detector loaded at runtime is our own, trained in-repo and stored in `models/`.

**Our model.** Trained on **CIC-IDS-2017** (CICFlowMeter flow features). Two
models are produced by `train_flow_model.py`:

* **Gradient-boosted trees (primary, shipped for inference).** On low-dimensional
  tabular flow features, trees beat the CNN — as expected.
* **Compact Conv1D (documented baseline).** Kept for comparison, not used live.

**The operating point is chosen from data, not intuition.** Training sweeps a
frontier of class-weighting strength (`w ∝ 1/n^α`, α ∈ {0…0.5}) × decision
threshold (0.5…0.95) and picks the point that **maximises macro attack recall
subject to a hard budget of per-flow benign FPR ≤ 1%**, selected on a validation
split and reported on a held-out test split the selection never saw. The chosen
point is **α = 0.5, threshold = 0.95** (`config.CLASSIFY_THRESHOLD`); the full
frontier table is in `models/metrics.json`.

**False positives are counted per FLOW, not per shape.** The dedup evaluation
scores each unique feature vector once, but one common benign shape stands for
thousands of real flows — a model that misfires on a few common shapes looks
fine per-shape and is unusable per-flow (we measured a 12× gap on an earlier
fully class-balanced fit). Every benign FPR quoted here weights each shape by
its real multiplicity in the dataset.

Held-out test, at the shipped operating point (GBT):

| Metric | Value |
|---|---|
| **Per-flow benign FPR** | **0.15%** (budget ≤ 1%) |
| Macro attack recall (every class counts once) | 0.72 |
| Weighted attack recall (by row count) | 0.97 |
| F1 (binary) | 0.985 |

| Split | Meaning | GBT F1 | Conv1D F1 |
|---|---|---|---|
| **Dedup + stratified, held-out test** | **Headline** — identical flows can't span splits | **0.985** | 0.091 |
| Random stratified | Optimistic upper bound (duplicate bursts leak) | 0.940 | 0.289 |
| Group by source IP | Degenerate — one IP emits 99.6% of attacks | 0.001 | 0.000 |

The shipped GBT is exactly the model the frontier measured (trained on the 60%
train split), so the selection evidence describes the deployed artifact. The
Conv1D baseline is evaluated at the GBT's operating point, which it was not
tuned for — its collapse at threshold 0.95 is part of why the GBT ships. A
per-feature leakage check found no single feature exceeding 0.72 AUC. Full
numbers, per-class recall, and the frontier: `models/metrics.json`.

**Retrain / reproduce:**
```bash
python train_flow_model.py --parquet path/to/CICIDS_Flow.parquet
```

**PCAP replay (live/replay share one code path).** You can run a capture file
through the exact same flow-detection path as live sniffing:
```bash
python app_groq.py --replay samples/heartbleed-excerpt.pcap
```
`replay_pcap()` reuses `_ingest_packet_flows` + `_handle_completed_flow`, so
replayed verdicts are persisted and emitted identically to live traffic.

`samples/dos-volumetric.pcap` is the in-scope proof capture: real CIC-IDS-2017
volumetric-attack flow shapes (DDoS, the four DoS variants, PortScan)
reconstructed into packets, plus benign flows. Replaying it fires suspicious on
the attack flows at each class's measured recall and keeps every benign flow
quiet. Regenerate with `scripts/make_dos_pcap.py`.

**The TCP flag features were removed — they never transferred.** Making the flag
features match CIC-IDS-2017's encoding (binary presence, not counts) was an earlier
fix that got them *in distribution* but not *correct*: CIC-IDS-2017 records
PortScan flows with `syn=rst=ack=0`, while a real port scan on the wire obviously
sets SYN. The model had learned "PortScan means the flags are zero" — true of the
dataset, false of the network — so it scored ~1.00 on dataset PortScan rows and
never fired on live scan traffic. A feature whose meaning differs between training
and serving is worse than no feature. The detector now uses only the **6 features
whose train/serve semantics are identical** (duration, protocol, per-direction
packet and byte counts). `flow_tracker` still tracks flags for TCP-teardown
detection; they are no longer model input.

**Serving fidelity is verified, not assumed.** `tests/test_feature_alignment.py`
runs a committed 452-row CIC-IDS-2017 fixture through the live path
(`flow_tracker → cnn_engine`) and asserts the live verdict matches the offline
model's own prediction on every row (0 disagreements), and reproduces its
probability to <1e-4. It runs on a fresh clone with no dataset download.

**Scope — what this detector actually detects.** All 6 features are measured
directly from packet headers and map to real CICFlowMeter columns — no fabricated
time-windowed host/service rate features. They describe a flow's *volume and
shape*, so they can only separate attacks that **look different volumetrically**:
DoS/DDoS floods and connection-rate brute force. They cannot distinguish a
malicious HTTP request from a benign one, because in packet/byte terms it is a
normal HTTP request — content-based classes (Web Attack XSS / SQL Injection /
Brute Force, Infiltration, Bot) would need payload or URI features this pipeline
does not extract. The frontier sweep confirmed this is not a tuning problem: at
**every** class-weighting strength that respects the FPR budget, the Web Attack
classes stay near zero recall. The scope is therefore locked — volumetric
DoS/DDoS and rate-based detection, no content-based detection claimed at any
weighting. Per-class recall at the shipped operating point is in
`models/metrics.json`; **coverage claims must come from that table, not from the
headline F1.**

---

## 🛠️ Tech Stack & Infrastructure

* **Backend Engine:** Python 3.10+ | Flask / FastAPI Core Architecture
* **AI/ML Layer:** PyTorch / TensorFlow (CNN Packet IDS & NLP Sequence Classification)
* **Inference Pipeline:** Groq API & Ollama Core Execution Edge (Llama 3.2 Deployment)
* **Real-Time Data Layer:** WebSockets (Socket.IO) & Asynchronous Event Loops
* **Storage Matrix:** Structured SQLite Database Engine for persistent audit logging and forensic traceability
* **UI/UX Layer:** Tailwind CSS, HTML5, Chart.js (Real-time Canvas Rendering)

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Zaidzyy/SecOps-AI.git
   cd SecOps-AI
   ```

2. **Set up a virtual environment (Recommended)**:
   
   It is best practice to run the application in a virtual environment to avoid dependency conflicts.

   ```bash
   # Create the virtual environment
   python -m venv venv

   # Activate it (Windows PowerShell)
   .\venv\Scripts\Activate.ps1
   ```

3. **Install dependencies**:

   Runtime only — Flask/SocketIO, Scapy, and the shipped GBT detector. This is all
   you need to run the dashboard, live sniffing, and pcap replay:

   ```bash
   pip install -r requirements.txt
   ```

   TensorFlow is **not** a runtime dependency: the shipped detector is the
   gradient-boosted model, and `cnn_engine.py` imports TensorFlow lazily, only in
   the Conv1D-baseline branch. Install the extra manifest only to retrain, run the
   Conv1D benchmark, or run the tests:

   ```bash
   pip install -r requirements.txt -r requirements-train.txt
   ```

   > Runtime versions are pinned to the environment the shipped model was
   > serialized under. `numpy`/`scikit-learn`/`joblib` must match, or loading
   > `models/secids_flow_gbt.joblib` fails with
   > `PCG64 is not a known BitGenerator module`.

4. **Configure environment variables**:
   
   Create a file named `.env` in the root directory. This file will securely store your credentials.

   ```env
   GROQ_API_KEY=your_groq_api_key_here
   ```

   - **GROQ_API_KEY**: Get your API key from `console.groq.com`

   > `HF_TOKEN` is no longer required. It existed only to download the borrowed
   > `SecIDS-CNN.h5`, which is no longer on the inference path — the shipped
   > detector is trained in-repo and loaded from `models/`.

5. **Install & run local AI dependencies**:
   
   The system leverages local LLM inference for edge alert generation.

   **Install Ollama**: Download and install Ollama from `ollama.com`

   **Pull Llama 3.2 model**:
   ```bash
   ollama pull llama3.2
   ```

   Ensure Ollama is running in the background before starting the application.

6. **Run the application**:
   
   Start the SecOps-AI pipeline.

   > **Note:** Packet sniffing requires **Administrator privileges**.

   ```bash
   # Run in Administrator PowerShell
   python app_groq.py
   ```

7. **Access the dashboard**:
   
   Once the server is running, open your browser and navigate to:

   ```text
   http://127.0.0.1:5000
   ```

## Pro Tips for Deployment

- **Npcap (Windows)**: Ensure Npcap is installed for the Scapy packet sniffer to capture live network traffic.

- **GPU Support**: TensorFlow defaults to CPU-only on Windows. For production-grade inference, consider running the project inside **WSL2 (Windows Subsystem for Linux)** to leverage CUDA/GPU acceleration.

## Usage

- **Real-time monitoring**: Receive live metrics, network activity, and AI-generated alerts in real-time.
- **Customizable API**: Integrate with Groq to leverage high-performance AI analysis.

## Data Model & Read API

Captured data lives in two tables, split by the question they answer:

| Table | Question | Contents |
| --- | --- | --- |
| `telemetry` | *What did we see?* | One row per enriched packet: IP, country, lat/lon, summary, reputation. |
| `detections` | *What is bad?* | One row per classified flow: 5-tuple, verdict, confidence, geo, flow features. |

These were previously one `network_requests` table separated by a `type` column,
which buried a few thousand flow verdicts under ~15x their volume in packet
noise. `migrations.py` splits existing databases automatically and idempotently
on startup; the original table is archived as `network_requests_legacy`, not
dropped.

| Endpoint | Returns |
| --- | --- |
| `GET /detections?page=&page_size=&verdict=` | Paginated detection feed, newest first. |
| `GET /threat-map` | Detections aggregated to map points: lat, lon, country, count, worst verdict. |
| `GET /stats` | Live counters: packets/sec, unique IPs, drops, suspicious count, pipeline health. |
| `GET /telemetry?page=&page_size=` | Raw per-packet telemetry, kept queryable but separate. |

### Demo data

`samples/heartbleed-excerpt.pcap` is 100% loopback traffic, so it performs zero
geo lookups and produces an empty map. For a populated demo, replay the
public-IP capture instead — its source addresses are real and routable, so
enrichment resolves genuine coordinates across ~14 countries:

```bash
python app_groq.py --replay samples/demo-public-ips.pcap
```

Regenerate it with `python scripts/make_demo_pcap.py`.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.
```
