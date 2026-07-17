
![SecOps-AI console: stat strip, threat map, live detection feed with ATT&CK badges, and traffic charts](docs/screenshots/console-overview.jpg)
*The console on a fresh `docker compose up`: the demo seed replays benign public-IP traffic (map spread) plus the in-scope attack capture, so the feed shows suspicious flows with ATT&CK technique badges and working triage/report actions — all real data through the live pipeline.*

# SecOps-AI: Real-Time AI-Driven SIEM Threat Operator

SecOps-AI is a real-time **network flow** threat-detection console. It captures
live traffic — or replays a pcap through the identical path — aggregates packets
into bidirectional flows, and scores each flow with a **gradient-boosted
classifier trained in-repo on CIC-IDS-2017**. Flagged flows are attributed to
**MITRE ATT&CK** techniques by a second-stage model, enriched with third-party
IP reputation, and made actionable by a **Groq-accelerated LLM layer**: bounded
agentic triage, retrieval-grounded operator chat, and one-click incident
reports — plus throttled outbound alerting on critical events. Every AI output
is grounded in real aggregated data and labelled advisory; nothing is
fabricated. See **Threat Detection Engine** below for the model and its
held-out metrics.

---

## 🚀 System Architecture & Core Capabilities

The architecture is split into a high-concurrency data ingestion engine, an embedded deep learning classification layer, and an accelerated AI orchestration tier:

* **Flow-based ML threat detection:** Sniffed packets are aggregated into bidirectional flows (`flow_tracker.py`) and scored by a classifier we trained ourselves on CIC-IDS-2017 flow features (`cnn_engine.py`). See **Threat Detection Engine** below for the model, its held-out metrics, and why the borrowed `SecIDS-CNN.h5` is not used for inference.
* **Sharded ingestion pipeline:** A Flask-SocketIO server with a flow-key-sharded capture→enrichment→single-writer pipeline (`pipeline.py`), optimized for real-time bi-directional telemetry streaming over WebSocket, TTL-cached geo/reputation enrichment, and concurrent system-metric tracking (CPU, RAM, disk).
* **Groq-accelerated AI layer:** Three grounded LLM features on the Groq API — bounded agentic **triage**, retrieval-grounded operator **chat** (BM25 over incident history), and one-click **incident reports** — each built only from real aggregated data, with citations filtered in code and an advisory label. Groq absent/unreachable degrades to a clean error, never a crash.
* **MITRE ATT&CK attribution & reputation:** Flagged flows are attributed to ATT&CK techniques by a curated two-stage model (never an LLM), and enriched with third-party IP reputation (AbuseIPDB / blocklist.de).
* **Outbound alerting:** Config-driven generic webhook (Slack/Discord-compatible) on critical events, throttled against alert storms and off by default.
* **SOC Console:** A self-contained operator dashboard (hand-written CSS, vendored Chart.js/Socket.IO, bundled world GeoJSON — no CDN, no tile server, renders offline): live threat map, ATT&CK-badged detection feed, pipeline counters, the coverage panel, and the triage / chat / report actions. See **SOC Console** below.

---

## 🖥️ SOC Console

![Detection feed: suspicious flows with confidence, ATT&CK technique labels, and triage/report actions](docs/screenshots/detection-feed-attack.png)
*The live detection feed after the demo seed: each suspicious flow carries a confidence, its ATT&CK technique (T1046 / T1498 / T1499), and per-row triage + report actions.*

One hierarchy, four elements with jobs: a thin stat strip (packets/sec,
captured, dropped, unique IPs, flows classified, suspicious) → a hero row of
**threat map + live detection feed** (verdict badges, ATT&CK technique tags on
flagged flows, confidence, a suspicious-only filter, per-row triage + report
actions, new detections ping the map over WebSocket) → traffic rate, top
origins, and host health charts → the ATT&CK coverage panel (which techniques
have fired, with the unattributed count shown beside them), the operator chat
(grounded in BM25 retrieval over incident history — see below), and the event
log.

The page is **self-contained by test, not by promise**: no CDN framework, no
external tile server. Chart.js and the Socket.IO client are vendored under
`static/`, and the map is bundled GeoJSON rendered to SVG through an
equirectangular projection — a fresh clone renders the full console offline.
`tests/test_api.py` pins that every `src`/`href` served by `/` is local. More
captures in `docs/screenshots/`.

### Operator chat — RAG with BM25 retrieval over incident history

![ATT&CK coverage panel and the operator chat answering with citation chips](docs/screenshots/attack-coverage-and-chat.jpg)
*Left: the ATT&CK coverage panel (techniques observed, with the honest unattributed counter). Right: the operator chat answering a question grounded in retrieved incidents, each reply carrying citation chips (detection id · technique · source IP).*

The chat answers from **retrieved incidents, not the model's memory**. Each
question is scored against the entire detections table with **BM25 lexical
retrieval** — in-process, zero new dependencies, index rebuilt from SQLite in
milliseconds and delta-synced before every answer. It is deliberately *not*
vector/embedding search: this corpus is IPs, ports, T-numbers and country
names, where exact-term matching wins (a question about `131.203.88.83` must
match that literal token), and an embedding stack would bloat the 639MB
container. The retriever sits behind a one-method interface so an embedding
backend could slot in later if the corpus grows prose.

Grounding is enforced in code, same discipline as the triage agent: the top-k
retrieved incidents are the model's only source of facts about this network,
its citations are filtered against the ids actually retrieved, and an empty
retrieval is stated in the answer rather than papered over. Replies carry
citation chips (detection id, technique, source IP) and an advisory label.
Degradation: retrieval failure falls back to the old recent-logs context,
plainly labelled; Groq absent/unreachable is a clean "chat unavailable", never
a crash.

### AI triage — bounded agent on demand

![AI triage modal: severity, summary, likely intent, advisory actions, and evidence citing the tools that ran](docs/screenshots/triage-modal.jpg)
*The triage modal for one detection: severity, one-line summary, likely intent, playbook-based advisory actions, and an evidence list where every row cites the local tool whose result produced it — a fabricated citation is dropped in code.*

Suspicious feed rows carry a **triage** action: a hard-bounded Groq tool-use
loop (max 5 tool calls, then forced synthesis) over real local tools only —
IP reputation, related flows, prior detections, and the curated ATT&CK
playbooks. Evidence citing a tool that never executed is dropped in code; the
report is cached on the detection so re-opening never re-bills the LLM, and
it is labelled AI-generated advisory throughout.

### Incident reports — the capstone over Features 1–4

![Incident report print view: executive summary, grounded narrative, detection table, ATT&CK mapping](docs/screenshots/incident-report.jpg)
*The print-optimized incident report (browser → Save as PDF). The narrative is LLM-synthesized but grounded: note it states the reputation gap honestly ("blocklist.de only provides report counts, not an abuse confidence score") rather than inventing a score. The tables below it are built directly from database rows.*

Suspicious feed rows also carry a **report** action (`POST /report/<id>`),
which aggregates everything the system already knows about a detection into
a SOC-style incident report:

- **the detection row** itself (5-tuple, verdict, confidence, flow stats);
- **MITRE ATT&CK attribution** from the stored Stage-2 columns plus the
  curated per-technique playbook;
- **the cached AI triage report**, if an operator ran one;
- **third-party reputation** as stored at classification time;
- **related flows and suspicious history** for the source IP, from which a
  chronological **timeline** and an **IOC table** are derived.

**Grounding, one step further than triage/chat:** the factual sections
(timeline, IOCs, ATT&CK mapping, reputation, activity counts, data gaps)
are **built in code from database rows** — the LLM never touches them. One
Groq call writes only the synthesis (executive summary, narrative, severity,
playbook-based recommended actions), and its cited detection ids are
filtered in code against the ids actually present in the aggregation. What
the system does not know is listed under **Known data gaps**, never papered
over. The whole document is labelled *AI-generated incident report
(advisory)*.

**Export:** `GET /report/<id>.md` downloads Markdown (zero-dependency, the
primary format); `GET /report/<id>/view` renders a print-optimized,
self-contained HTML view — the PDF path is the browser's own *Print → Save
as PDF*, so the container needs no PDF library and the image does not grow.
Both routes serve **only the cached report** (generation is the explicit
POST), so a GET can never bill Groq. Reports are cached on the detection row
(`report_json`), and generation degrades to a clean 503 when Groq is absent.

### Outbound alerting — critical events to a webhook

Set `SECOPS_ALERT_WEBHOOK` to a generic JSON webhook URL (Slack and Discord
incoming webhooks both work: the payload carries `text` for Slack, `content`
for Discord, and a structured `alert` object for everything else). **Unset —
the default — means alerting is off: no HTTP, no error.**

Two things alert, both deliberately rare (`alerts.py`, thresholds in
`config.py`):

- **corroborated** — a suspicious verdict with confidence ≥ 0.99 *and* a
  third-party abuse score ≥ 50: our detector and an external reputation
  source agree;
- **new-technique** — the first time the process observes a given ATT&CK
  technique.

Alerts are **throttled to one per (source IP, technique) per 5-minute
window**, so a flood that produces hundreds of detections sends one webhook,
not a storm. The payload carries technique, IP, severity, reputation,
timestamp, and a concise summary. Delivery failures are logged and swallowed
— the pipeline worker never notices, and a failed alert is not retried
(storms are worse than one lost alert).

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

**The benchmark is like-for-like: each model at its own tuned operating point.**
Both models are swept over the same α × threshold grid under the same FPR
budget, and each is reported at its own best point — scoring the baseline at
the primary's threshold would rig the comparison. On the CIC-IDS-2017
held-out test split:

| Model | Own operating point | Per-flow benign FPR (CIC-IDS-2017 held-out test) | Macro recall | Weighted recall | F1 |
|---|---|---|---|---|---|
| **GBT (shipped)** | α=0.5, thr=0.95 | **0.15%** (budget ≤ 1%) | **0.723** | 0.974 | **0.985** |
| Conv1D (baseline) | α=0.15, thr=0.65 | 0.98% | 0.294 | 0.596 | 0.727 |

Every number above is measured on CIC-IDS-2017, not on a live network. Live
benign traffic is a different distribution and runs hotter — in LAN capture we
observe benign flows scoring closer to the threshold than the dataset's benign
does — so no live-network FPR is claimed here; the budget governs the dataset
evaluation that selected the operating point.

| Split | Meaning | GBT F1 | Conv1D F1 |
|---|---|---|---|
| **Dedup + stratified, held-out test** | **Headline** — identical flows can't span splits | **0.985** | 0.727 |
| Random stratified | Optimistic upper bound (duplicate bursts leak) | 0.940 | 0.421 |
| Group by source IP | Degenerate — one IP emits 99.6% of attacks | 0.001 | 0.000 |

On the headline split, that is a GBT confusion of **tn=149 120, fp=252,
fn=1 667, tp=63 438** (214 477 test flows, 65 105 positive) versus the Conv1D's
**tn=146 485, fp=2 887, fn=26 306, tp=38 799** — the baseline misses 16× as many
attacks and raises 11× as many false positives at its own tuned point.

The shipped GBT is exactly the model the frontier measured (trained on the 60%
train split), so the selection evidence describes the deployed artifact. Even
at its own best operating point the Conv1D reaches less than half the GBT's
macro recall while spending nearly the whole FPR budget — which is why the GBT
ships.

**Leakage check.** A single feature that alone separates attack from benign
usually means the split leaked. Every one of the 6 features was scored on its
own (univariate AUC and a one-split decision stump); the strongest is
`protocol` at **0.72** stump AUC, and none reaches the 0.98 flag threshold — no
single feature is doing the work. Full numbers, both frontiers, and all four
split methodologies: `models/metrics.json`.

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
weighting. Per-class recall at the shipped operating point is the table below;
**coverage claims must come from it, not from the headline F1.**

**Per-class live recall at the shipped operating point** (α=0.5, thr=0.95, on
the dedup + stratified held-out **test** split — the headline split, computed
in `models/metrics.json`). Recall is what fraction of that class's flows the
Stage-1 gate flags suspicious. Grouped by whether the class is *in scope*:

| In-scope (volumetric / rate-based) | n (test) | Recall | | Out-of-scope (not claimed) | n (test) | Recall |
|---|---:|---:|---|---|---:|---:|
| DDoS | 25 312 | 0.990 | | Web Attack – Brute Force | 270 | 0.093 |
| DoS slowloris | 905 | 0.989 | | Web Attack – XSS | 132 | 0.008 |
| DoS Slowhttptest | 1 044 | 0.978 | | Web Attack – SQL Injection | 3 | 0.333 |
| DoS Hulk | 33 427 | 0.975 | | Bot | 254 | 0.925 |
| DoS GoldenEye | 1 960 | 0.958 | | Infiltration | 8 | 0.500 |
| FTP-Patator | 829 | 0.995 | | Heartbleed | 2 | 0.500 |
| SSH-Patator | 622 | 0.929 | | | | |
| PortScan | 337 | 0.944 | | | | |

Read this honestly, not as a scoreboard:
- **The in-scope classes are what the detector is shipped to catch**, and it
  does: 0.93–0.99 recall across DoS/DDoS, the two Patator brute-force families,
  and PortScan. `DoS GoldenEye` (0.958) is volumetric but sits just under 1.0 at
  this threshold, so it is pinned in the regression test at its measured value,
  not held to a target it does not meet.
- **The Web Attack classes (content-based) are near-zero by design, not by
  accident** — the 6 volume/shape features cannot separate a malicious HTTP
  request from a benign one, and the frontier sweep confirmed no class weighting
  fixes it (see scope above). They are shown here for honesty; the product
  claims none of them.
- **`Bot` (0.925) is incidental**, not a claim: CIC-IDS bot flows happen to be
  volumetrically distinct in this dataset; nothing about the feature set makes
  C2 detection reliable in general.
- **Three classes are statistically meaningless here** — `Heartbleed` (n=2),
  `Web Attack – SQL Injection` (n=3), `Infiltration` (n=8) are too rare in the
  test split for their recall to mean anything; they are in the table so the row
  is not silently dropped, not because 0.5 or 0.333 is informative.

Macro recall (every class equal) is **0.723**; weighted recall (by row count,
which lets the three high-volume DoS/DDoS classes dominate) is **0.974**. The
gap between them is the scope story in one number: strong where it is aimed,
weak on the content classes it does not claim.

### MITRE ATT&CK mapping — two-stage by design

A binary detector cannot name a technique, so attribution is a **separate,
honestly-scoped second stage**:

* **Stage 1 (unchanged):** the binary GBT gate at its FPR-tuned operating
  point (α=0.5, thr 0.95) decides *suspicious/normal*. It is the only thing
  that decides maliciousness, and its FPR discipline is untouched.
* **Stage 2:** a multi-class GBT **attributor** (`train_attributor.py`,
  `models/secids_attributor.joblib`) runs **only on flows Stage 1 flagged**,
  predicting the attack *family* from the same 6 transferable features. The
  family is then mapped to a technique through a **static, curated lookup**
  (`attack_mapping.py`) — every ID and name verified against attack.mitre.org;
  no LLM anywhere near a technique ID.

| family (CIC-IDS classes) | technique | tactic |
|---|---|---|
| port-scan (PortScan) | T1046 Network Service Discovery | Discovery |
| ddos (DDoS) | T1498 Network Denial of Service | Impact |
| dos (Hulk, GoldenEye, slowloris, Slowhttptest) | T1499 Endpoint Denial of Service | Impact |
| brute-force (FTP/SSH-Patator) | T1110 Brute Force | Credential Access |
| botnet (Bot) | T1071 Application Layer Protocol | Command and Control |
| web-attack (Brute Force/XSS/SQLi) | T1190 Exploit Public-Facing Application | Initial Access |

**Measured reliability** (held-out dedup test split, same methodology as
Stage 1 — exact-duplicate shapes removed before splitting): argmax macro-F1
**0.949** across 7 families, and **accuracy-when-attributed 0.998 at coverage
0.9999** (the confidence gate almost never has to abstain on the mapped
families). Per family:

| family | technique | n (test) | recall | accuracy when attributed |
|---|---|---:|---:|---:|
| ddos | T1498 | 25 433 | 0.9998 | 0.9998 |
| dos | T1499 | 37 200 | 0.998 | 0.9981 |
| botnet | T1071 | 265 | 0.996 | 0.996 |
| port-scan | T1046 | 322 | 0.994 | 0.994 |
| brute-force | T1110 | 1 480 | 0.990 | 0.990 |
| web-attack | T1190 | 418 | 0.976 | 0.976 |
| *other* (abstain class) | — unattributed | 9 | 0.778 | — |

The six mapped families all sit at 0.976–0.9998; the `other` grab-bag
(Infiltration + Heartbleed, 9 test shapes) is the abstain class and is
*supposed* to stay unattributed. Note this is Stage-2 accuracy **given a
correct Stage-1 flag** — it presumes the flow reached Stage 2, so it is bounded
by Stage 1's per-class recall above, not independent of it. Full confusion
matrix and per-family table: `models/secids_attributor_meta.json` and
`models/confusion_attributor.png`.

**Unattributed when unsure.** The attributor abstains rather than guess: a
prediction below its validation-chosen confidence threshold, or of the "other"
grab-bag (Infiltration, Heartbleed — 47 unique shapes, too rare to learn),
serves as **"malicious — technique unattributed"**, never a forced technique.
The console's coverage panel reports the unattributed count next to the
technique counts for the same reason. Two caveats to hold onto: these numbers
are measured on CIC-IDS-2017 shapes, and attribution is only as good as
Stage 1's coverage — families the gate rarely flags (the content-based classes
above) will rarely reach Stage 2 at all, so the mapped table is *potential*
coverage, not a detection claim.

---

## 🛠️ Tech Stack & Infrastructure

* **Backend Engine:** Python 3.10+ | Flask / FastAPI Core Architecture
* **AI/ML Layer:** PyTorch / TensorFlow (CNN Packet IDS & NLP Sequence Classification)
* **Inference Pipeline:** Groq API & Ollama Core Execution Edge (Llama 3.2 Deployment)
* **Real-Time Data Layer:** WebSockets (Socket.IO) & Asynchronous Event Loops
* **Storage Matrix:** Structured SQLite Database Engine for persistent audit logging and forensic traceability
* **UI/UX Layer:** Hand-written CSS design system, HTML5, vendored Chart.js + Socket.IO client, bundled-GeoJSON SVG threat map (fully offline-capable)

---

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
   SECOPS_SECRET_KEY=paste_a_long_random_hex_string_here
   SECOPS_ABUSEIPDB_KEY=your_abuseipdb_key_here   # optional — see below
   ```

   - **GROQ_API_KEY**: Get your API key from `console.groq.com`
   - **SECOPS_SECRET_KEY**: signs the login session cookies — **required to start
     the server**. Generate one with:
     ```bash
     python -c "import secrets; print(secrets.token_hex(32))"
     ```
   - **SECOPS_ABUSEIPDB_KEY** (optional): enables the richer AbuseIPDB
     reputation source — see **IP reputation sources** below. Without it,
     everything works on the keyless blocklist.de path.

   Optional overrides (defaults in parentheses): `SECOPS_HOST` (`127.0.0.1`),
   `SECOPS_PORT` (`5000`), `SECOPS_ALLOWED_ORIGINS` (the local origin),
   `SECOPS_DEBUG` (`0`), `SECOPS_COOKIE_SECURE` (`0`; set `1` behind HTTPS),
   `SECOPS_ALERT_WEBHOOK` (unset = outbound alerting off — see **Outbound
   alerting** above).

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

   You'll land on the sign-in page — register an operator account first
   (`/register`), then log in. Every console page, data endpoint, and the live
   WebSocket stream requires a logged-in session.

## Docker

Run the whole console with one command (requires Docker + Compose):

```bash
docker compose up
```

Then open `http://localhost:5000`, **register** an operator account, and log
in — the dashboard is already populated. On first boot the container replays
**two** captures through the real detection pipeline (`SECOPS_SEED_DEMO=1`,
default on): `samples/demo-public-ips.pcap` for benign traffic across ~14
countries (the threat map's spread and an honest benign baseline), then
`samples/dos-volumetric.pcap` for in-scope attack traffic. The result out of
the box: **44 suspicious detections with ATT&CK technique badges** (T1046
port-scan, T1498 DDoS, T1499 endpoint DoS) alongside the benign flows — so the
coverage panel, triage, and incident-report actions all have real detections to
act on, zero manual steps.

Configuration comes from `.env` (copy `.env.example`). If `SECOPS_SECRET_KEY`
is unset, compose falls back to a **demo-only key that is public in
`docker-compose.yml`** — fine for a local demo, never for a deployment others
can reach.

What the container is, deliberately:

- **Replay-only capture.** Live NIC sniffing is a host/bare-metal feature: it
  needs privileged access to a network interface, and this container is
  unprivileged by design — no `--privileged`, no host networking, runs as a
  non-root user (`secops`, uid 10001). To sniff live traffic, run
  `python app_groq.py` on the host as in [Installation](#installation).
- **A real WSGI server.** The container serves via gunicorn with a gevent
  worker (`SECOPS_SOCKETIO_ASYNC_MODE=gevent`), with real WebSocket upgrades
  through `gevent-websocket` — not the Werkzeug dev server. One worker per
  instance: Socket.IO requires sticky sessions.
- **SQLite on a volume.** Users, detections, and telemetry live in the
  `secops-data` volume and survive container recreation.

**Edge alerts (optional Ollama):** the default `up` skips the local LLM
entirely — `notify_ai()` just degrades gracefully. To enable it:

```bash
docker compose --profile edge-alerts up -d
docker compose exec ollama ollama pull llama3.2   # once, ~2 GB
```

The app targets the `ollama` compose service automatically
(`SECOPS_OLLAMA_URL`); swap the model with `SECOPS_OLLAMA_MODEL` if you want
something smaller.

## Pro Tips for Deployment

- **Npcap (Windows)**: Ensure Npcap is installed for the Scapy packet sniffer to capture live network traffic.

- **GPU Support**: TensorFlow defaults to CPU-only on Windows. For production-grade inference, consider running the project inside **WSL2 (Windows Subsystem for Linux)** to leverage CUDA/GPU acceleration.

## Usage

- **Real-time monitoring**: Receive live metrics, network activity, and AI-generated alerts in real-time.
- **Customizable API**: Integrate with Groq to leverage high-performance AI analysis.

## IP reputation sources

Every public source IP is enriched with a reputation lookup (TTL-cached in
`enrichment.py`). Two sources, chosen by configuration:

- **AbuseIPDB** (`/api/v2/check`) — used when `SECOPS_ABUSEIPDB_KEY` is set.
  Returns the **abuse confidence score (0–100)**, total report count, usage
  type, and ISP. The score and its report count are persisted on telemetry
  and detections (`abuse_score`, `rep_reports`, `rep_source`), shown as an
  amber `rep NN` chip in the detection feed, and fed to the triage agent's
  `ip_reputation` tool. Scores at or above 50 also set the pipeline's
  existing `blacklisted` boolean (`config.ABUSE_SCORE_FLAG_THRESHOLD`).
- **blocklist.de** — the keyless fallback. A fresh clone with no key runs
  entirely on this path; nothing requires AbuseIPDB.

**Free tier & caching**: AbuseIPDB's free tier allows 1000 checks/day
(resets 00:00 UTC). The reputation cache (`REP_CACHE_TTL_S`, 15 min) plus
single-flighting guarantees **one lookup per unique public IP per window,
no matter the packet rate** — a flood cannot burn the quota. A 429 (tier
exhausted) falls back to blocklist.de for that lookup; if every source
fails, the IP is marked reputation *unknown* (and the failure is cached,
so a down upstream is retried once per window, not per packet).

**Honesty rule**: the abuse score is a **third-party reputation signal**,
stored and rendered separately from `cnn_verdict` — the ML detector's
opinion. The UI styles them differently on purpose, and the triage agent is
told which is which. A high reputation score never makes a flow "suspicious"
by itself, and a clean score never vouches for one.

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
| `POST /triage/<id>` | On-demand AI triage for one detection (cached on the row). |
| `POST /report/<id>` | Generate (or return the cached) incident report for one detection. |
| `GET /report/<id>.md` | Markdown export of the cached report (404 until generated). |
| `GET /report/<id>/view` | Print-optimized HTML report view (browser → Save as PDF). |

### Demo data

`samples/heartbleed-excerpt.pcap` is 100% loopback traffic, so it performs zero
geo lookups and produces an empty map. For a populated demo, replay the
public-IP capture instead — its source addresses are real and routable, so
enrichment resolves genuine coordinates across ~14 countries:

```bash
python app_groq.py --replay samples/demo-public-ips.pcap
```

Regenerate it with `python scripts/make_demo_pcap.py`.

## Security

**Scope, honestly stated: this is app-level authentication for a demo/portfolio
project, not production hardening.**

What the app does:

- **Full multi-user auth** — `/register`, `/login`, `/logout` against a `users`
  table. Passwords are stored only as salted hashes
  (`werkzeug.security.generate_password_hash`); plaintext never touches the DB.
- **Default-deny access control** — every route except the auth pages requires a
  logged-in session (anonymous browsers are redirected to `/login`; API calls get
  a `401`). New routes are protected by default, not by remembering a decorator.
- **The WebSocket is gated too** — the Socket.IO connect handler rejects any
  connection without a logged-in session, so the live metric/verdict stream
  can't leak what the HTTP guard protects.
- **Session cookies** are `HttpOnly` + `SameSite=Lax`, `Secure` when you set
  `SECOPS_COOKIE_SECURE=1` behind HTTPS. The signing key must come from the
  environment (`SECOPS_SECRET_KEY`) — the server refuses to start without one.
- **CSRF tokens** on the login/register/logout forms (per-session,
  constant-time compared).
- **Login throttling** — 5 failed attempts per IP in 5 minutes returns `429`.
  In-memory and per-process: enough for a single-instance demo, not for a
  multi-process deployment.
- **No wildcard CORS, no debug mode** — Socket.IO origins are locked to the
  console's own origin (`SECOPS_ALLOWED_ORIGINS` to override), and Flask debug
  (which ships an RCE-grade debugger) is off unless you opt in.

What it deliberately does **not** claim:

- **No TLS termination** — the dev server speaks plain HTTP; anything
  security-relevant on a real network needs a TLS-terminating proxy in front.
- **No secrets manager** — keys live in `.env` (gitignored), which is fine for a
  demo and inadequate for production.
- **Werkzeug dev server** — still the dev server underneath; a production WSGI
  server is Phase 4b (Docker) territory, along with rate limiting that survives
  multiple processes.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.
```
