
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
own model** on the exact 10 flow features our tracker emits. `SecIDS-CNN.h5` was
removed from the inference path entirely and is **not shipped** with this repo;
the detector loaded at runtime is our own, trained in-repo and stored in `models/`.

**Our model.** Trained on **CIC-IDS-2017** (CICFlowMeter flow features). Two
models are produced by `train_flow_model.py`:

* **Gradient-boosted trees (primary, shipped for inference).** On 10 low-dimensional
  tabular flow features, trees beat the CNN — as expected.
* **Compact Conv1D (documented baseline).** Kept for comparison, not used live.

**Held-out metrics (honest evaluation).** CIC-IDS-2017 contains huge bursts of
near-identical flows, so we report three splits:

| Split | Meaning | GBT F1 | Conv1D F1 |
|---|---|---|---|
| **Dedup + stratified** | **Headline** — identical flows can't span train/test | **0.990** | 0.923 |
| Random stratified | Optimistic upper bound (duplicate bursts leak) | 0.975 | 0.847 |
| Group by source IP | Degenerate — one IP emits 99.6% of attacks | 0.001 | 0.000 |

The shipped models are exactly the ones trained on the dedup split, so the
headline numbers describe what's deployed. A per-feature leakage check found no
single feature exceeding 0.72 AUC. Full numbers: `models/metrics.json`.

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

**Feature alignment was validated against a real pcap.** Replaying real traffic
surfaced a genuine semantic bug: CIC-IDS-2017's CICFlowMeter flag columns are
**binary presence indicators (0/1)**, not packet counts (verified: every flag
column has `max == 1`). A real TCP flow carries many ACKs, so emitting the true
count put those features wildly out of the training distribution and classified
everything as normal. `flow_tracker` now emits binary flag **presence**, after
which **all 10 features land 100% within the training min/max** on replayed
traffic. `tests/test_feature_alignment.py` further proves the live serving
pipeline reproduces the offline model's probability to <1e-4.

**Honesty note on features.** All 10 features (duration, protocol, per-direction
packet/byte counts, TCP flag presence) are measured directly from packet headers
and map to real CICFlowMeter columns — no fabricated time-windowed host/service
rate features. Note the model does **not** reliably detect attack classes that
were rare in training (e.g. Heartbleed, 11 of 2.8M rows); those replay in-range
but score as normal. This is a training-coverage limit, stated plainly, not a
pipeline defect.

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

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.
```
