# SecOps-AI — Improvement Roadmap

**Goal:** Portfolio-grade project that survives a technical reviewer reading the code.
**Guiding principle:** Every claim in the README must be true in the code. Substance before shine.

This plan is written to be handed to Claude Code phase by phase. Do the phases in order — each one sets up the next.

---

## The core problem this plan fixes

Right now the README sells "dual-engine deep learning (CNN + NLP)" threat detection. In reality:

- `analyze_packet_with_cnn()` (app_groq.py:190) is **defined but never called**. The model loads and does nothing.
- `packet_callback()` (app_groq.py:275) only does a geo lookup + blocklist.de check + DB insert. No ML.
- There is **no NLP model** anywhere. That claim is fabricated.
- `login.html` / `register.html` call `url_for('login')` / `url_for('register')` — **routes that don't exist**. Auth is a non-functional stub.

A reviewer who opens the code finds this in ~2 minutes. Fixing it is the whole point.

---

## Phase 1 — Make the CNN real (your differentiator)

> **STATUS: DONE & COMMITTED** (15/15 tests green; fresh-clone install proven working without TensorFlow).
>
> **Outcome:** Trained our own flow classifier on CIC-IDS-2017 instead of the borrowed, unusable `SecIDS-CNN.h5`. **Gradient-boosted trees shipped as the live model** (F1 ≈ 0.99 on a dedup split; no single-feature leakage > 0.72 AUC); the compact **Conv1D was benchmarked and kept as a documented baseline** (F1 ≈ 0.92) — trees beat CNNs on 10 tabular flow features, and the comparison is a stronger portfolio story than the original "CNN" claim.
>
> **Dependency hygiene (fixed during closeout):** split into `requirements.txt` (runtime — no TensorFlow, since the shipped detector is the sklearn GBT and `cnn_engine` lazy-imports TF only for the Conv1D baseline) and `requirements-train.txt` (training/benchmark/tests). The old manifest could never have worked from a fresh clone: `numpy==1.26.4` couldn't load the model, `python-dotenv` was missing, `GPUtil` needs `setuptools` (distutils gone in py3.12, previously smuggled in by TF), `transformers` was dead. All fixed and proven in a throwaway venv.
>
> **Alignment caveat (important):** live verdicts only match offline metrics if `flow_tracker`'s features match CICFlowMeter's. A real-pcap replay caught a genuine semantic bug — CIC-IDS-2017's TCP flag columns are **binary presence (0/1), not counts** — now fixed (flow_tracker emits presence; no retrain needed since the model trained on 0/1). After the fix, all 10 features land 100% within the training range on replayed traffic. `tests/test_feature_alignment.py` proves the live pipeline reproduces the offline probability to < 1e-4.
>
> **Known coverage limit (state plainly, don't oversell):** the model does not reliably flag attack classes that were rare in training (e.g. Heartbleed, 11 of 2.8M rows) — they replay in-range but score normal. Live attack-detection true-positives are proven via reconstructed well-represented attack rows (check #1), not via the Heartbleed pcap.
>
> **Truthfulness + hygiene fixes (done at closeout):** the README had falsely claimed `SecIDS-CNN.h5` is "kept in the repo" while it is gitignored — reworded to state plainly that it is not shipped and not on the inference path (every README file reference was then audited against the tracked tree). Added `.gitattributes` (`* text=auto eol=lf`) to stop CRLF phantom diffs recurring, and gitignored the empty `AGENTS.md` stub.
>
> **Carried-forward debts (do later, don't lose):** (a) the feature-alignment test — your strongest verification — only runs when `CICIDS_PARQUET` is set; in CI it silently skips. Fix in Phase 5 by committing a tiny sampled-parquet fixture (few hundred rows). (b) Real-traffic true-positive on a *well-represented* attack class (DoS Hulk / PortScan / DDoS) — Heartbleed scores normal (rare in training); fold into the F1 PCAP-demo work.
>
> **TODO for the eventual README rewrite (Phase 4):** publish the full metrics table (GBT vs Conv1D, all splits, ROC-AUC, confusion matrices), the leakage-check result, and the "why GBT over CNN" narrative. Do this once the whole project is finished, not piecemeal.

**Why:** This is the one thing that separates the project from "another Flask + LLM dashboard."

### STEP 0 finding (verified — this changed the plan)

Inspecting `SecIDS-CNN.h5` revealed it is **not** the 41-feature NSL-KDD model assumed. Actual contract:

- Input `(None, 10, 1)` — **10 features**, reshaped for Conv1D. Output `(None, 1)` — a single sigmoid (`>0.5` → attack). (This also proves the dead `analyze_packet_with_cnn()` was doubly broken: it indexes `prediction[1]`, which doesn't exist — it would throw `IndexError` if ever called.)
- Architecture: Conv1D(32) → BN → Conv1D(64) → BN → Flatten → Dense(128) → Dropout → Dense(1, sigmoid).
- **The 10 feature names, their order, and the training scaler are unrecoverable.** The HF model card is gated; the upstream GitHub `preprocess_data()` is a no-op stub. Probe behavior (near-zero output for zeros/ones/random/hundreds alike) confirms we cannot reach the input regime that fires "attack" without the original scaler.

**Consequence:** feeding the borrowed model our own features would produce meaningless verdicts — relocating the "decorative AI" problem, not fixing it. Dataset-demo mode can't rescue it either, because that also requires the unknown input contract.

### DECISION: train our own model (don't use the borrowed .h5 for inference)

Train a classifier on a public **flow-based** dataset using the **exact features our flow tracker computes**. This makes the contract known and ours, the verdicts valid, and yields a real metric for the CV.

Tasks:

1. **Flow aggregation layer** (`flow_tracker.py`). Keyed by (src_ip, dst_ip, src_port, dst_port, proto), rolling time window, `Flow` dataclass. Canonical 10-feature vector (order defined once, becomes our contract): duration, protocol, src_bytes, dst_bytes, total_packets, fwd_packets, bwd_packets, syn_flag_count, rst_flag_count, same_host_conn_count. Honestly comment any approximated feature; do **not** pad with invented NSL-KDD rate features we can't derive.
2. **Train our own model.** Dataset: **CIC-IDS-2017** (CICFlowMeter-generated — its columns *are* flow features, matching our tracker; align our feature definitions to CICFlowMeter's). NSL-KDD is a fallback. Restrict training features to exactly what `flow_tracker` emits. Start with a gradient-boosted-tree baseline for a sanity metric, then the compact Conv1D. Save as `secids_flow.<ext>` + the fitted scaler.
   - **Class imbalance warning:** CIC-IDS-2017 is mostly benign. Subsample/balance or the model just predicts "benign" and reports fake-high accuracy. The metric that matters is **recall on attack classes / F1**, not raw accuracy.
   - Save `metrics.json` + confusion matrix; report precision/recall/F1 on a held-out split.
3. `cnn_engine.py`: loads **our** model; `extract_features(flow) -> np.ndarray` (using the saved scaler) and `classify(features) -> {"verdict", "confidence"}`. Keep model logic out of app_groq.py.
4. Wire into `packet_callback`: on flow completion/timeout, run `classify`, persist + emit the verdict. Live sniffing and future PCAP replay (F1) must share **one** code path.
5. Add DB columns `cnn_verdict` TEXT + `cnn_confidence` REAL to `network_requests` (safe migration on the existing DB).
6. Keep the borrowed `SecIDS-CNN.h5` out of the inference path. **Note in the README why it was replaced** (contract unrecoverable) — that honesty is a strength, not a weakness.

**Definition of done:** our own model, trained on matching features with reported held-out F1, produces valid verdicts that appear in the DB and UI. The README claim becomes true *and* defensible.

---

## Phase 2 — Fix the sniffer performance bottleneck

**Why:** Currently every packet does 2 synchronous HTTP calls + a DB insert on the sniff thread (`get_ip_country` app_groq.py:125, `check_ip_blacklist_cached` app_groq.py:394). Under real traffic it drops packets. This is your "I understand systems" story.

Tasks:

1. **Decouple capture from enrichment.** Sniff thread does nothing but push packets onto a `queue.Queue`. A separate worker pool handles geo/blacklist/DB. The sniffer must never block on I/O.
2. **Real caching with TTL.** Replace `check_ip_blacklist_cached` — it currently double-inserts and treats the log table as a cache. Use an in-memory dict (or `functools.lru_cache` / `cachetools.TTLCache`) keyed by IP so each IP is looked up once per TTL window.
3. **Batch DB writes.** Insert flows/logs in batches on a timer instead of one INSERT per packet. Use a single long-lived connection per worker, WAL mode (`PRAGMA journal_mode=WAL`).
4. **Fix the concurrency model.** You import `eventlet` (app_groq.py:21) but run `async_mode='threading'` with no monkey-patching. Pick one and commit — for a threading model, drop the eventlet import entirely.
5. Guard `notify_ai` (app_groq.py:356): if Ollama is unreachable it currently throws and can kill the calling thread. Wrap in try/except with a fallback.

**Definition of done:** Point it at a busy interface (or replay a pcap) and it keeps up without dropping packets or freezing the UI.

---

## Phase 3 — Frontend glow-up: cool + clean (do this AFTER 1 & 2)

**Why:** A great UI on a real engine is impressive. A great UI on a fake engine is a red flag. Order matters.

**Target aesthetic:** modern SOC console — dark, dense-but-not-cluttered, purposeful motion. "Cool" comes from real live data moving, not gratuitous animation. Keep the existing cyan-on-slate theme (it's already clean); elevate it, don't replace it. Consistent 8px spacing grid, one accent color used sparingly for alerts, generous whitespace, no visual noise. Reference feel: Grafana / Elastic SIEM / a clean trading terminal.

Ideas, roughly high-to-low impact:

1. **Live threat map.** Plot geo-located source IPs on a world map (e.g. Leaflet + a simple markercluster). This is the single most "wow" addition for a security dashboard.
2. **CNN verdict badges.** Color-code each network row by the CNN verdict + confidence (green/amber/red). Makes the ML visible — the whole point.
3. **Severity-driven alert feed.** Replace the flat log list with a prioritized incident feed (Critical / Warning / Info) sorted by severity, with the LLM triage summary inline.
4. **Stat header.** Top-line counters: packets/sec, unique IPs, blacklisted hits, suspicious verdicts — animated.
5. **Polish pass.** Consistent spacing, empty states, loading skeletons, a proper favicon/logo. Keep the existing dark cyber theme — it's already clean.
6. Consider extracting the inline `<script>` in index.html into a static JS file for readability (reviewers notice).

**Definition of done:** Screenshots that look like a real SOC console, where the visuals are backed by real data.

---

## Phase 4 — Security & professionalism

**Why:** Reviewers check for these. Their absence signals inexperience.

1. **Real auth.** Implement the missing `/login` `/register` `/logout` routes, hash passwords (`werkzeug.security` or `bcrypt`), use Flask sessions, and `@login_required`-guard the dashboard + APIs. The `users` table and templates already exist — just wire them.
2. **Kill unsafe defaults.** Remove `debug=True` and `allow_unsafe_werkzeug=True` (app_groq.py:521) for anything non-local. Lock `cors_allowed_origins` to a known origin, not `"*"`.
3. **Config over hardcode.** Move model name (`llama-3.1-8b-instant`), ports, thresholds, external API URLs into a config file / env vars.
4. **Rewrite the README to match reality.** Remove FastAPI, PyTorch, "NLP sequence classification," and the "Storage Matrix"-style buzzwords. Describe what actually exists. An honest, precise README beats an inflated one every time a technical person reads it.
   - **Metrics writeup (do this at the very end, once the whole project is finished):** publish the full detection-engine results — GBT vs Conv1D across all splits (dedup/stratified/random/group), precision/recall/F1/ROC-AUC, confusion matrices, and the leakage-check (no single feature > 0.72 AUC). Include the "why we replaced the borrowed model" and "why GBT over CNN on tabular flow features" narratives. This is the credibility centerpiece of the README — save it for last so the numbers are final.

---

## Phase 5 — The details that signal "engineer"

1. **Tests.** At least: feature extractor unit tests, a flow-aggregation test, an API smoke test (pytest). Even 10 good tests change the impression.
2. **Dockerfile + docker-compose** (app + Ollama). "Clone and `docker compose up`" is a huge credibility signal.
3. **CI.** A GitHub Actions workflow running lint + tests on push.
4. **Repo hygiene.** Don't ship `venv/` or the 18MB `system_metrics.db` in the working tree; confirm both are gitignored. Add a small sample DB or seed script instead.
5. **A short architecture diagram** in the README (Mermaid): capture → flow aggregation → CNN → LLM triage → dashboard.

---

## Committed integrations (Suricata, AbuseIPDB, RAG)

These three are IN. Build them **one at a time**, in the order below — not in parallel. Each is a real chunk of work; three half-finished features look worse than one polished one.

### A. Self-built flow aggregation layer (Suricata DROPPED)

**Decision:** Suricata is cut. It added WSL/Docker ops friction, and for a portfolio a **hand-built** flow-feature pipeline demonstrates more engineering skill than installing an off-the-shelf IDS. This is the same flow layer described in Phase 1 — build it yourself.

- Aggregate sniffed packets into flows keyed by (src_ip, dst_ip, src_port, dst_port, proto) over a rolling time window.
- Compute the feature subset the CNN needs (byte/packet counts, duration, flags, per-window connection counts). Use documented defaults for features that genuinely can't be derived from sniffed traffic — comment them honestly, don't fake precision.
- Feed completed/timed-out flows into `cnn_engine.classify()`.
- This *is* Phase 1's flow layer — treat A and Phase 1 as a single unit of work.

### B. AbuseIPDB reputation enrichment (alongside / replacing blocklist.de)

- Free tier is **1,000 checks/day, resets 00:00 UTC** (verified). This makes the Phase 2 TTL cache **mandatory** — a busy interface has thousands of unique IPs. Each IP must be looked up once per cache window, not per packet.
- Store the AbuseIPDB confidence score (0–100) and report count; surface it in the UI as part of the severity signal.
- Keep blocklist.de as a secondary source or drop it — AbuseIPDB's confidence score is richer. API key goes in `.env` / config, never hardcoded.
- Handle the 429 (rate-limit) response gracefully: fall back to cache / mark "reputation unknown," never crash the worker.

### C. Vector store + RAG for the LLM chat

**Why it's last:** it's the most self-contained and depends on having real incident data flowing (from A + B) to be worth anything.

- Use a **local** vector store — Chroma or FAISS. No paid account (no Pinecone). Keeps the project clone-and-run.
- Embed historical logs + incidents (network_requests + logs tables) with a local embedding model (e.g. `sentence-transformers`) so there's no extra API dependency.
- Rewrite `/chat` (app_groq.py:440): instead of slicing the last 5 logs (`fetch_recent_logs()[:5]`), **retrieve the top-k most relevant past incidents** for the operator's question and pass those as context to Groq.
- This turns the chat from "summarize recent noise" into "ask questions across the full incident history" — a genuine capability jump and the most on-trend part of the project.

**Scope discipline:** each of these adds dependencies. Don't also add Redis/Zeek/Pinecone on top — the three above already tell a strong, coherent story.

---

## Standout features (all four approved)

These are what make the project memorable. Build them after the core (CNN + performance + integrations) is real — they showcase the engine, so the engine must exist first.

### F1. PCAP replay + synthetic demo generator — **highest portfolio impact**

The point: a reviewer must see it work in 30 seconds without installing Npcap or sniffing live traffic.

- **PCAP upload:** an endpoint + UI control to upload a `.pcap`/`.pcapng`, then run the *entire* pipeline (flow aggregation → CNN → reputation → LLM triage) over it and stream results to the dashboard. Reuse `packet_callback` logic via `scapy.rdpcap()` so live and replay share one code path.
- **Synthetic attack generator:** a standalone script (`demo_traffic.py`) that simulates port scans, brute-force bursts, and beaconing so the dashboard lights up on demand. Ship a couple of sample `.pcap` files in the repo for instant demos.
- **Payoff:** pair with the Phase 5 public deploy so your resume link *just works* for anyone who clicks it.

### F2. MITRE ATT&CK mapping — **credibility with security reviewers**

- Tag each detection/alert with its ATT&CK technique ID + name (e.g. `T1046 – Network Service Discovery`). Let the LLM do the mapping from the alert context, constrained to a local list of technique IDs so it can't hallucinate fake ones.
- Surface the technique as a badge in the UI and store it in the DB.
- Optional: a small ATT&CK matrix view highlighting which techniques have fired. Very "real SOC."

### F3. Agentic auto-triage — **on-trend AI-agent story**

- On a critical alert, kick off an LLM agent that autonomously enriches: AbuseIPDB reputation, related flows for the same IP, geo, and (optionally) whois. It then produces a structured verdict + severity + recommended action.
- Implement as a bounded tool-use loop (the enrichment functions are the tools) — not an open-ended agent. Cap the steps so it can't spin.
- Persist the triage output and show it inline in the incident feed. This is the difference between "dashboard" and "analyst."

### F4. Incident reports + real-time alerting — **"real product" feel**

- **Incident reports:** on a significant event, the LLM writes a SOC-style report (summary, timeline, indicators, ATT&CK mapping, recommended actions), exportable as **PDF/markdown**. One-click "Export incident report" button.
- **Alerting:** push critical alerts to a webhook (Slack/Discord/Telegram/email — pick one). Config-driven, off by default so a fresh clone doesn't error.

**Sequencing within features:** F1 first (unlocks demoing everything else), then F2 (cheap, high signal), then F3 and F4.

---

## Recommended execution order for Claude Code

1. **Integration A (self-built flow layer) + Phase 1 (CNN real)** — one unit. The flow aggregator is what makes the CNN feasible. Nothing else matters until this works.
2. **Phase 2 (performance) + Integration B (AbuseIPDB)** — the TTL cache and the API rate limit are the same problem.
3. **F1 (PCAP replay + demo generator)** — do this early. It's how you (and reviewers) verify everything above actually works, without live capture.
4. **F2 (MITRE ATT&CK mapping)** — cheap, high signal.
5. **Phase 4 README rewrite** — now, so claims track the code; don't let the README drift ahead of reality again.
6. **Integration C (RAG chat) + F3 (agentic auto-triage)** — both need real incident data flowing; they share enrichment plumbing.
7. **F4 (incident reports + alerting)**.
8. **Phase 3 frontend** (cool + clean) — polish once the data behind it is real.
9. **Phase 4 security + Phase 5 polish** (auth, Docker, tests, CI, public demo deploy).

Start each Claude Code session by pointing it at this file and **one item at a time**. Do not try to do everything in one pass — that's how the project ends up half-finished in six places.
