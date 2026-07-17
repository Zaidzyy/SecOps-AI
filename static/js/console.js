/* SecOps-AI console.
 *
 * Data sources (all local):
 *   REST   /stats /detections /threat-map /logs /chat
 *   Socket update_metrics | new_log | cnn_verdict
 *
 * The map is self-contained: bundled GeoJSON rendered to SVG with a hand-rolled
 * equirectangular projection -- no tile server, no d3, works offline.
 *
 * All dynamic text goes through DOM text nodes (never string-concatenated
 * innerHTML): packet summaries and geo strings are attacker-influenced input.
 */
"use strict";

/* ---------- tiny utilities ---------- */

const $ = (id) => document.getElementById(id);

const el = (tag, className, text) => {
    const n = document.createElement(tag);
    if (className) n.className = className;
    if (text !== undefined) n.textContent = text;
    return n;
};

const fmt = (n) => {
    if (n === null || n === undefined) return "—";
    if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
    if (n >= 1e4) return (n / 1e3).toFixed(1) + "k";
    return String(n);
};

/* Geo strings arrive as "country, city, region" with filler for missing parts
   ("Singapore, None, None", "United States, Unknown, Unknown", "Not found,
   Not found, Not found" depending on the geo API's mood). Show what's real. */
const GEO_FILLER = new Set(["none", "unknown", "not found", ""]);
const cleanGeo = (s) => {
    if (!s) return "unknown";
    const parts = String(s).split(",").map((p) => p.trim())
        .filter((p) => !GEO_FILLER.has(p.toLowerCase()));
    return parts.length ? parts.join(", ") : "unknown";
};

const timeOf = (ts) => {
    if (!ts) return "";
    const m = String(ts).match(/\d{2}:\d{2}:\d{2}/);
    return m ? m[0] : String(ts);
};

/* ---------- chart theme (single accent + status colors, no palette cycling) */

const css = getComputedStyle(document.documentElement);
const C = {
    accent: css.getPropertyValue("--accent").trim(),
    ink2: css.getPropertyValue("--ink2").trim(),
    ink3: css.getPropertyValue("--ink3").trim(),
    line: css.getPropertyValue("--line").trim(),
    crit: css.getPropertyValue("--crit").trim(),
    mono: css.getPropertyValue("--font-mono").trim(),
};

Chart.defaults.color = C.ink3;
Chart.defaults.borderColor = C.line;
Chart.defaults.font.family = C.mono;
Chart.defaults.font.size = 10;
Chart.defaults.animation = false;

/* ---------- live indicator ---------- */

const setLive = (state, label) => {
    $("live-indicator").dataset.state = state;
    $("live-label").textContent = label;
};

/* ---------- threat map ---------- */

const MAP = {
    // Equirectangular, cropped: Antarctica and the empty far north are dead
    // pixels on a threat map.
    lonMin: -180, lonMax: 180, latMin: -60, latMax: 84,
    W: 1000,
    svg: null, landLayer: null, dotLayer: null, pingLayer: null,
};
MAP.H = (MAP.latMax - MAP.latMin) / 360 * MAP.W;   // keep degree aspect

const project = (lon, lat) => [
    (lon - MAP.lonMin) / (MAP.lonMax - MAP.lonMin) * MAP.W,
    (MAP.latMax - lat) / (MAP.latMax - MAP.latMin) * MAP.H,
];

const svgEl = (tag) => document.createElementNS("http://www.w3.org/2000/svg", tag);

function ringToPath(ring) {
    return ring.map((pt, i) => {
        const [x, y] = project(pt[0], pt[1]);
        return (i ? "L" : "M") + x.toFixed(1) + " " + y.toFixed(1);
    }).join("") + "Z";
}

function geomToPath(geom) {
    const polys = geom.type === "Polygon" ? [geom.coordinates]
        : geom.type === "MultiPolygon" ? geom.coordinates : [];
    return polys.map((poly) => poly.map(ringToPath).join("")).join("");
}

async function initMap() {
    const svg = $("worldmap");
    svg.setAttribute("viewBox", `0 0 ${MAP.W} ${MAP.H}`);
    svg.setAttribute("preserveAspectRatio", "xMidYMid meet");
    MAP.svg = svg;

    const grat = svgEl("g");
    for (let lon = -150; lon <= 150; lon += 30) {
        const p = svgEl("path");
        const [x] = project(lon, 0);
        p.setAttribute("d", `M${x} 0V${MAP.H}`);
        p.setAttribute("class", "map-grat");
        grat.appendChild(p);
    }
    for (let lat = -30; lat <= 60; lat += 30) {
        const p = svgEl("path");
        const [, y] = project(0, lat);
        p.setAttribute("d", `M0 ${y}H${MAP.W}`);
        p.setAttribute("class", "map-grat");
        grat.appendChild(p);
    }
    svg.appendChild(grat);

    MAP.landLayer = svgEl("g");
    MAP.dotLayer = svgEl("g");
    MAP.pingLayer = svgEl("g");
    svg.appendChild(MAP.landLayer);
    svg.appendChild(MAP.pingLayer);
    svg.appendChild(MAP.dotLayer);

    try {
        const res = await fetch("/static/data/world.geojson");
        const world = await res.json();
        for (const f of world.features) {
            if (f.properties && f.properties.name === "Antarctica") continue;
            const p = svgEl("path");
            p.setAttribute("d", geomToPath(f.geometry));
            p.setAttribute("class", "map-land");
            MAP.landLayer.appendChild(p);
        }
    } catch (e) {
        console.error("world.geojson failed to load:", e);
    }
}

function mapPing(lat, lon, suspicious) {
    if (lat === null || lat === undefined || lon === null || lon === undefined) return;
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const [x, y] = project(lon, lat);
    const c = svgEl("circle");
    c.setAttribute("cx", x); c.setAttribute("cy", y); c.setAttribute("r", 3);
    c.setAttribute("class", "map-ping");
    c.setAttribute("stroke", suspicious ? C.crit : C.accent);
    const anim = svgEl("animate");
    anim.setAttribute("attributeName", "r");
    anim.setAttribute("from", "3"); anim.setAttribute("to", "26");
    anim.setAttribute("dur", "1.6s"); anim.setAttribute("fill", "freeze");
    c.appendChild(anim);
    MAP.pingLayer.appendChild(c);
    setTimeout(() => c.remove(), 1700);
}

function showTip(evt, point) {
    const tip = $("map-tip");
    tip.replaceChildren(
        el("div", null, cleanGeo(point.country)),
        el("div", "map-tip-sub",
           `${point.count} detection${point.count === 1 ? "" : "s"}` +
           (point.suspicious_count ? ` · ${point.suspicious_count} suspicious` : "")),
        el("div", "map-tip-sub", `last seen ${point.last_seen || "—"}`),
    );
    tip.hidden = false;
    const wrap = tip.parentElement.getBoundingClientRect();
    const x = Math.min(evt.clientX - wrap.left + 12, wrap.width - 250);
    const y = Math.max(evt.clientY - wrap.top - 10, 4);
    tip.style.left = x + "px";
    tip.style.top = y + "px";
}

async function refreshMap() {
    try {
        const res = await fetch("/threat-map");
        const data = await res.json();
        const points = data.points || [];
        $("map-empty").hidden = points.length > 0;
        const maxCount = points.reduce((m, p) => Math.max(m, p.count), 1);

        MAP.dotLayer.replaceChildren();
        for (const p of points) {
            const [x, y] = project(p.lon, p.lat);
            const dot = svgEl("circle");
            dot.setAttribute("cx", x); dot.setAttribute("cy", y);
            // area encodes count: r ~ sqrt
            const r = 3 + 9 * Math.sqrt(p.count / maxCount);
            dot.setAttribute("r", r.toFixed(1));
            dot.setAttribute("class", "map-dot " +
                (p.worst_verdict === "suspicious" ? "map-dot-suspicious" : "map-dot-normal"));
            dot.addEventListener("mouseenter", (e) => showTip(e, p));
            dot.addEventListener("mousemove", (e) => showTip(e, p));
            dot.addEventListener("mouseleave", () => { $("map-tip").hidden = true; });
            MAP.dotLayer.appendChild(dot);
        }
        const sus = points.reduce((s, p) => s + (p.suspicious_count || 0), 0);
        $("map-meta").textContent =
            `${points.length} locations · ${sus} suspicious`;
    } catch (e) {
        console.error("threat-map refresh failed:", e);
    }
}

/* ---------- stat strip + traffic rate ---------- */

const rateChart = new Chart($("rate-chart"), {
    type: "line",
    data: { labels: [], datasets: [{
        label: "packets/s",
        data: [],
        borderColor: C.accent,
        backgroundColor: "rgba(57, 213, 242, 0.10)",
        borderWidth: 2,
        fill: true,
        pointRadius: 0,
        pointHitRadius: 12,
        tension: 0.3,
    }]},
    options: {
        responsive: true, maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        plugins: { legend: { display: false } },
        scales: {
            x: { grid: { display: false }, ticks: { maxTicksLimit: 6 } },
            y: { beginAtZero: true, grid: { color: C.line }, border: { display: false },
                 ticks: { maxTicksLimit: 5 } },
        },
    },
});

const RATE_POINTS = 90;

async function refreshStats() {
    try {
        const res = await fetch("/stats");
        const s = await res.json();
        setLive("live", "sensor live");

        $("st-pps").textContent = fmt(Math.round(s.packets_per_sec || 0));
        $("st-captured").textContent = fmt(s.packets_captured);
        $("st-ips").textContent = fmt(s.unique_ips);
        $("st-flows").textContent = fmt(s.detections);

        const drop = $("st-dropped");
        drop.textContent = fmt(s.packets_dropped);
        drop.classList.toggle("is-warn", (s.packets_dropped || 0) > 0);

        const sus = $("st-suspicious");
        sus.textContent = fmt(s.suspicious);
        sus.classList.toggle("is-crit", (s.suspicious || 0) > 0);

        const pps = Math.round(s.packets_per_sec || 0);
        $("rate-now").textContent = fmt(pps);
        const t = new Date().toLocaleTimeString([], { hour12: false });
        rateChart.data.labels.push(t);
        rateChart.data.datasets[0].data.push(pps);
        if (rateChart.data.labels.length > RATE_POINTS) {
            rateChart.data.labels.shift();
            rateChart.data.datasets[0].data.shift();
        }
        rateChart.update("none");
    } catch (e) {
        setLive("down", "backend down");
    }
}

/* ---------- top origins ---------- */

const originChart = new Chart($("origin-chart"), {
    type: "bar",
    data: { labels: [], datasets: [
        { label: "normal", data: [], backgroundColor: "rgba(57, 213, 242, 0.35)",
          borderRadius: 3, barThickness: 14 },
        { label: "suspicious", data: [], backgroundColor: C.crit,
          borderRadius: 3, barThickness: 14 },
    ]},
    options: {
        indexAxis: "y",
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: "bottom", labels: { boxWidth: 8, boxHeight: 8 } } },
        scales: {
            x: { stacked: true, grid: { color: C.line }, border: { display: false },
                 ticks: { maxTicksLimit: 5, precision: 0 } },
            y: { stacked: true, grid: { display: false }, ticks: { color: C.ink2 } },
        },
    },
});

function refreshOrigins(points) {
    // country name only (first geo segment), aggregated across cities
    const byCountry = new Map();
    for (const p of points || []) {
        const name = cleanGeo(p.country).split(",")[0];
        const cur = byCountry.get(name) || { count: 0, sus: 0 };
        cur.count += p.count; cur.sus += p.suspicious_count || 0;
        byCountry.set(name, cur);
    }
    const top = [...byCountry.entries()]
        .sort((a, b) => b[1].count - a[1].count).slice(0, 6);
    originChart.data.labels = top.map(([name]) => name);
    originChart.data.datasets[0].data = top.map(([, v]) => v.count - v.sus);
    originChart.data.datasets[1].data = top.map(([, v]) => v.sus);
    originChart.update("none");
}

/* one fetch feeds both map + origins */
async function refreshGeo() {
    try {
        const res = await fetch("/threat-map");
        const data = await res.json();
        refreshOrigins(data.points);
    } catch (e) { /* map refresh already logs */ }
}

/* ---------- detection feed ---------- */

const FEED = { page: 1, pageSize: 40, verdict: null, total: 0 };

function feedRow(d) {
    const row = el("div", "feed-row");
    row.appendChild(el("span", "feed-time", timeOf(d.timestamp)));

    const main = el("div", "feed-main");
    const ipLine = el("div");
    ipLine.appendChild(el("span", "feed-ip", d.src_ip || d.ip || "?"));
    // Third-party reputation indicator (Feature 4): AbuseIPDB confidence,
    // shown as "rep NN" — deliberately NOT the verdict badge's styling, so a
    // reputation signal is never mistaken for the detector's opinion.
    if (typeof d.abuse_score === "number" && d.abuse_score > 0) {
        const rep = el("span",
            "feed-rep" + (d.abuse_score >= 75 ? " feed-rep-high" : ""),
            `rep ${d.abuse_score}`);
        rep.title = `AbuseIPDB abuse confidence ${d.abuse_score}/100` +
            (d.rep_reports ? ` · ${d.rep_reports} reports` : "") +
            ` · third-party reputation signal, not the detector's verdict`;
        ipLine.appendChild(rep);
    }
    main.appendChild(ipLine);
    main.appendChild(el("div", "feed-geo", cleanGeo(d.country)));
    if (d.summary) main.title = d.summary;

    const verdict = d.cnn_verdict || d.verdict || "normal";

    // Stage-2 attribution: only flagged flows carry a technique, and a flagged
    // flow the attributor declined to name says so instead of guessing.
    if (verdict === "suspicious") {
        const tech = el("div",
            d.technique_id ? "feed-tech" : "feed-tech feed-tech-none",
            d.technique_id ? `${d.technique_id} ${d.technique_name || ""}`
                           : "technique unattributed");
        if (d.tactic) tech.title = `ATT&CK tactic: ${d.tactic}`;
        main.appendChild(tech);
    }
    row.appendChild(main);
    row.appendChild(el("span",
        "badge " + (verdict === "suspicious" ? "badge-suspicious" : "badge-normal"),
        verdict));

    const conf = d.cnn_confidence ?? d.confidence;
    row.appendChild(el("span", "feed-conf",
        conf === undefined || conf === null ? "" : Number(conf).toFixed(2)));

    // On-demand AI triage: suspicious rows only, and only rows that exist in
    // the DB (live socket rows carry no id until the feed refreshes).
    if (verdict === "suspicious" && d.id) {
        const btn = el("button", "btn-triage", "triage");
        btn.title = "Run AI triage on this detection (advisory)";
        btn.addEventListener("click", () => openTriage(d.id));
        row.appendChild(btn);

        // Incident report (Feature 5): generate (or fetch the cached) report,
        // then open the print-optimized view — which links the .md download.
        const rbtn = el("button", "btn-triage btn-report", "report");
        rbtn.title = "Generate the incident report for this detection (advisory)";
        rbtn.addEventListener("click", () => openReport(d.id, rbtn));
        row.appendChild(rbtn);
    }
    return row;
}

/* ---------- Incident report (Feature 5) ----------
 * POST /report/<id> aggregates Features 1-4 server-side and synthesizes the
 * narrative (or returns the cached report). On success the print view opens
 * in a new tab; the view carries the Markdown download link. */

async function openReport(id, btn) {
    const original = btn.textContent;
    btn.disabled = true;
    btn.textContent = "generating…";
    try {
        const res = await fetch(`/report/${id}`, { method: "POST" });
        const data = await res.json();
        if (!res.ok) {
            btn.textContent = "unavailable";
            btn.title = (data.error || "report failed") +
                (data.reason ? ` — ${data.reason}` : "");
            setTimeout(() => { btn.textContent = original; btn.disabled = false; }, 4000);
            return;
        }
        window.open(`/report/${id}/view`, "_blank", "noopener");
        btn.textContent = original;
        btn.disabled = false;
    } catch {
        btn.textContent = "failed";
        setTimeout(() => { btn.textContent = original; btn.disabled = false; }, 4000);
    }
}

/* ---------- AI triage modal (Feature 2) ----------
 * POST /triage/<id> runs the bounded tool-use agent server-side (or returns
 * the cached report). Everything below renders through DOM text nodes: the
 * report is LLM output and must never reach innerHTML. */

const SEVERITY_CLASS = {
    low: "sev-low", medium: "sev-medium", high: "sev-high",
    critical: "sev-critical",
};

function triageSection(title) {
    return el("div", "triage-sec-title", title);
}

function renderTriage(t, cached, detectionId) {
    const box = el("div", "triage-report");

    const head = el("div", "triage-headline");
    head.appendChild(el("span",
        "sev-badge " + (SEVERITY_CLASS[t.severity] || "sev-unspecified"),
        t.severity || "unspecified"));
    head.appendChild(el("span", "triage-meta",
        `detection #${detectionId} · ${t.model || "?"}` +
        (cached ? " · cached" : "") +
        (t.generated_at ? ` · ${t.generated_at}` : "")));
    box.appendChild(head);

    box.appendChild(triageSection("Summary"));
    box.appendChild(el("p", "triage-text", t.summary || "—"));

    box.appendChild(triageSection("Likely intent"));
    box.appendChild(el("p", "triage-text", t.likely_intent || "—"));

    box.appendChild(triageSection("Recommended actions (advisory)"));
    const actions = el("ol", "triage-actions");
    for (const a of t.recommended_actions || []) {
        actions.appendChild(el("li", null, a));
    }
    if (!actions.children.length) actions.appendChild(el("li", null, "—"));
    box.appendChild(actions);

    box.appendChild(triageSection("Evidence (from tool results)"));
    const ev = el("div", "triage-evidence");
    for (const e of t.evidence || []) {
        const row = el("div", "triage-ev-row");
        row.appendChild(el("span", "triage-ev-tool", e.tool));
        row.appendChild(el("span", "triage-ev-finding", e.finding));
        ev.appendChild(row);
    }
    if (!ev.children.length) {
        ev.appendChild(el("div", "triage-ev-row", "no evidence cited"));
    }
    box.appendChild(ev);

    const tools = (t.tool_trace || []).map((x) => x.tool).join(", ");
    box.appendChild(el("div", "triage-foot",
        `${t.label || "AI-generated triage (advisory)"} · tools run: ${tools || "none"}`));
    return box;
}

async function openTriage(id) {
    const modal = $("triage-modal");
    const body = $("triage-body");
    modal.hidden = false;
    body.replaceChildren(el("div", "triage-loading",
        "gathering context and generating the report…"));
    try {
        const res = await fetch(`/triage/${id}`, { method: "POST" });
        const data = await res.json();
        if (!res.ok) {
            const reason = data.reason ? ` — ${data.reason}` : "";
            body.replaceChildren(el("div", "triage-error",
                (data.error || "triage failed") + reason));
            return;
        }
        body.replaceChildren(renderTriage(data.triage, data.cached, data.detection_id));
    } catch (e) {
        body.replaceChildren(el("div", "triage-error",
            "Triage request failed — backend unreachable."));
    }
}

$("triage-close").addEventListener("click", () => { $("triage-modal").hidden = true; });
$("triage-modal").addEventListener("click", (e) => {
    if (e.target === $("triage-modal")) $("triage-modal").hidden = true;
});
document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") $("triage-modal").hidden = true;
});

async function refreshFeed() {
    try {
        const q = new URLSearchParams({ page: FEED.page, page_size: FEED.pageSize });
        if (FEED.verdict) q.set("verdict", FEED.verdict);
        const res = await fetch("/detections?" + q);
        const data = await res.json();
        FEED.total = data.total || 0;

        const feed = $("feed");
        feed.replaceChildren(...(data.items || []).map(feedRow));
        $("feed-empty").hidden = FEED.total > 0;

        const pages = Math.max(1, Math.ceil(FEED.total / FEED.pageSize));
        $("feed-page").textContent =
            `${FEED.page} / ${pages} · ${fmt(FEED.total)} flows`;
        $("feed-prev").disabled = FEED.page <= 1;
        $("feed-next").disabled = FEED.page >= pages;
    } catch (e) {
        console.error("detections refresh failed:", e);
    }
}

function liveDetection(v) {
    // Live rows only make sense on the newest page with a matching filter.
    const suspicious = v.verdict === "suspicious";
    if (FEED.page === 1 && (!FEED.verdict || FEED.verdict === v.verdict)) {
        const row = feedRow({
            timestamp: new Date().toLocaleTimeString([], { hour12: false }),
            src_ip: v.ip, country: v.country, verdict: v.verdict,
            confidence: v.confidence, summary: v.summary,
            technique_id: v.technique_id, technique_name: v.technique_name,
            tactic: v.tactic,
            abuse_score: v.abuse_score, rep_reports: v.rep_reports,
        });
        row.classList.add(suspicious ? "is-new-sus" : "is-new");
        const feed = $("feed");
        feed.prepend(row);
        while (feed.children.length > FEED.pageSize) feed.lastChild.remove();
        $("feed-empty").hidden = true;
    }
    mapPing(v.lat, v.lon, suspicious);
}

$("feed-prev").addEventListener("click", () => {
    if (FEED.page > 1) { FEED.page--; refreshFeed(); }
});
$("feed-next").addEventListener("click", () => { FEED.page++; refreshFeed(); });

const setFilter = (verdict) => {
    FEED.verdict = verdict; FEED.page = 1;
    $("feed-all").classList.toggle("is-active", verdict === null);
    $("feed-sus").classList.toggle("is-active", verdict === "suspicious");
    refreshFeed();
};
$("feed-all").addEventListener("click", () => setFilter(null));
$("feed-sus").addEventListener("click", () => setFilter("suspicious"));

/* ---------- ATT&CK coverage ---------- */

function coverageRow(t) {
    const row = el("div", "attack-row");
    row.appendChild(el("span", "attack-id", t.technique_id));
    const main = el("div");
    main.appendChild(el("div", "attack-name", t.technique_name));
    main.appendChild(el("div", "attack-tactic",
        `${t.tactic} · family: ${t.attack_family}`));
    row.appendChild(main);
    row.appendChild(el("span", "attack-count", fmt(t.count)));
    row.title = `last seen ${t.last_seen}`;
    return row;
}

async function refreshCoverage() {
    try {
        const res = await fetch("/attack-coverage");
        const data = await res.json();
        const list = $("attack-list");
        list.replaceChildren(...(data.techniques || []).map(coverageRow));
        $("attack-empty").hidden = (data.techniques || []).length > 0;
        // The honesty counter stays visible: flows the attributor declined to
        // name are part of the coverage story, not a footnote to hide.
        $("attack-foot").textContent =
            `${fmt(data.attributed)} attributed · ${fmt(data.unattributed)} ` +
            `flagged but unattributed`;
    } catch (e) {
        console.error("attack coverage refresh failed:", e);
    }
}

/* ---------- host health ---------- */

const cpuChart = new Chart($("cpu-chart"), {
    type: "line",
    data: { labels: [], datasets: [{
        label: "CPU %",
        data: [],
        borderColor: C.accent,
        backgroundColor: "rgba(57, 213, 242, 0.08)",
        borderWidth: 2, fill: true, pointRadius: 0, pointHitRadius: 12, tension: 0.3,
    }]},
    options: {
        responsive: true, maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        plugins: { legend: { display: false } },
        scales: {
            x: { display: false },
            y: { beginAtZero: true, max: 100, grid: { color: C.line },
                 border: { display: false }, ticks: { maxTicksLimit: 3 } },
        },
    },
});

function setMeter(fillId, valueId, pct) {
    const fill = $(fillId);
    fill.style.width = Math.min(100, pct) + "%";
    fill.classList.toggle("is-warn", pct >= 70 && pct < 90);
    fill.classList.toggle("is-crit", pct >= 90);
    $(valueId).textContent = pct.toFixed(0) + "%";
}

function onMetrics(d) {
    cpuChart.data.labels.push("");
    cpuChart.data.datasets[0].data.push(d.cpu_usage);
    if (cpuChart.data.datasets[0].data.length > 40) {
        cpuChart.data.labels.shift();
        cpuChart.data.datasets[0].data.shift();
    }
    cpuChart.update("none");
    setMeter("mem-fill", "mem-value", d.memory_usage || 0);
    setMeter("disk-fill", "disk-value", d.disk_usage || 0);
    $("host-meta").textContent =
        `cpu ${d.cpu_usage}% · ${d.cpu_cores} cores`;
}

/* ---------- event log ---------- */

const LOG = { page: 1 };

function logRow(entry) {
    const row = el("div", "log-row");
    row.appendChild(el("span", "log-time", timeOf(entry.timestamp)));
    row.appendChild(el("span", "log-text", entry.log));
    return row;
}

async function refreshLogs() {
    try {
        const res = await fetch("/logs?page=" + LOG.page);
        const data = await res.json();
        $("log-list").replaceChildren(...(Array.isArray(data) ? data : []).map(logRow));
        $("log-page").textContent = "page " + LOG.page;
        $("log-prev").disabled = LOG.page <= 1;
        $("log-next").disabled = !Array.isArray(data) || data.length === 0;
    } catch (e) {
        console.error("logs refresh failed:", e);
    }
}

$("log-prev").addEventListener("click", () => {
    if (LOG.page > 1) { LOG.page--; refreshLogs(); }
});
$("log-next").addEventListener("click", () => { LOG.page++; refreshLogs(); });

/* ---------- triage chat ---------- */

function chatAppend(node) {
    const box = $("chat-box");
    const hint = box.querySelector(".chat-hint");
    if (hint) hint.remove();
    box.appendChild(node);
    box.scrollTop = box.scrollHeight;
}

/* escape, then allow only **bold** back in */
function renderReply(text) {
    const span = el("div", "chat-msg chat-msg-ai");
    const parts = String(text).split(/\*\*(.+?)\*\*/g);
    parts.forEach((part, i) => {
        if (i % 2) span.appendChild(el("strong", null, part));
        else span.appendChild(document.createTextNode(part));
    });
    return span;
}

/* Citation chips under an AI reply: the detections the answer was grounded
   in (BM25-retrieved rows, filtered server-side against what was actually
   retrieved). Text nodes only — these fields come from the DB and the LLM. */
function renderCitations(citations) {
    const wrap = el("div", "chat-citations");
    wrap.appendChild(el("span", "chat-cite-label", "cited:"));
    for (const c of citations) {
        const chip = el("span", "chat-cite",
            `#${c.id}${c.technique_id ? " " + c.technique_id : ""}` +
            `${c.src_ip ? " " + c.src_ip : ""}`);
        chip.title = [c.technique_name, cleanGeo(c.country), c.timestamp]
            .filter(Boolean).join(" · ");
        wrap.appendChild(chip);
    }
    return wrap;
}

async function sendChat() {
    const input = $("chat-input");
    const message = input.value.trim();
    if (!message) return;
    input.value = "";
    chatAppend(el("div", "chat-msg chat-msg-user", message));
    const loading = el("div", "chat-loading", "retrieving incidents…");
    chatAppend(loading);
    try {
        const res = await fetch("/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message }),
        });
        const data = await res.json();
        loading.remove();
        if (!res.ok) {
            const reason = data.reason ? ` — ${data.reason}` : "";
            chatAppend(el("div", "chat-msg chat-msg-err",
                (data.error || "chat failed") + reason));
            return;
        }
        chatAppend(renderReply(data.response || data.message || "No response received."));
        if (Array.isArray(data.citations) && data.citations.length) {
            chatAppend(renderCitations(data.citations));
        }
    } catch (e) {
        loading.remove();
        chatAppend(el("div", "chat-msg chat-msg-err",
            "The assistant is unreachable. Check that the backend is running."));
    }
}

$("chat-send").addEventListener("click", sendChat);
$("chat-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") sendChat();
});

/* ---------- sockets ---------- */

const socket = io();
socket.on("connect", () => setLive("live", "sensor live"));
socket.on("disconnect", () => setLive("down", "disconnected"));
socket.on("update_metrics", onMetrics);
socket.on("cnn_verdict", liveDetection);
socket.on("new_log", (entry) => {
    if (LOG.page !== 1) return;
    const list = $("log-list");
    list.prepend(logRow(entry));
    while (list.children.length > 50) list.lastChild.remove();
});

/* ---------- boot ---------- */

initMap().then(refreshMap);
refreshStats();
refreshGeo();
refreshFeed();
refreshLogs();
refreshCoverage();
setInterval(refreshStats, 2000);
setInterval(() => { refreshMap(); refreshGeo(); refreshCoverage(); }, 10000);
