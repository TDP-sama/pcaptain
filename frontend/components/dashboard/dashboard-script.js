import { SERVER, API_PATH, SERVER_HEALTH_CHECK_INTERVAL } from "../constant.js";

const $ = (id) => document.getElementById(id);
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

let charts = {};
let tables = {};      // card key -> { headers, rows } for the table view
let pollTimer = null;

// Ordered bands as the backend produces them (keep in sync with routes/dashboard.py).
const SIZE_BANDS = ["<10MB", "10-100MB", "100MB-1GB", ">1GB"];
const PACKET_BANDS = ["0", "<1k", "1k-100k", ">100k"];
const AGE_BANDS = ["<24h", "1-7d", "7-30d", ">30d"];
const PKT_SIZE_BANDS = ["<64B", "64-128B", "128-256B", "256-512B", "512B-1KB", "1KB-MTU", ">MTU", "(small sample)", "(no packets)"];
const DIVERSITY_BANDS = [[1, 5], [6, 10], [11, 15], [16, 20], [21, 30], [31, Infinity]];

const SCAN_MODES = [
    { key: "full", label: "Full", desc: "tshark decoded every packet", color: "--cat-1" },
    { key: "quick", label: "Quick", desc: "tshark decoded the first part", color: "--cat-2" },
    { key: "fast", label: "Fast", desc: "guessed from port numbers", color: "--cat-3" },
];

function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function formatBytes(bytes) {
    bytes = Number(bytes) || 0;
    if (!bytes) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    return `${parseFloat((bytes / Math.pow(1024, i)).toFixed(i ? 1 : 0))} ${units[i]}`;
}

function formatCompact(n) {
    n = Number(n) || 0;
    if (n >= 1e9) return `${(n / 1e9).toFixed(1)}B`;
    if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
    if (n >= 1e4) return `${(n / 1e3).toFixed(1)}k`;
    return n.toLocaleString();
}

function searchUrl(query) {
    return `/?${new URLSearchParams({ q: query })}`;
}

// --- DATA ---
async function loadSummary(refresh = false) {
    clearTimeout(pollTimer);
    $("dashboard").setAttribute("aria-busy", "true");
    $("refreshBtn").disabled = true;
    setStatus("", refresh ? "Recomputing the summary…" : "Loading the catalog summary…");
    try {
        const url = new URL(API_PATH.DASHBOARD_SUMMARY_PATH, SERVER);
        if (refresh) url.searchParams.set("refresh", "true");
        const res = await fetch(url);
        if (res.status === 202) {
            // The backend is building the summary; ask again shortly.
            pollTimer = setTimeout(() => loadSummary(false), 1500);
            return;
        }
        const body = await res.json().catch(() => ({}));
        if (!res.ok || !body.data) throw new Error(body.detail || body.error || `${res.status} ${res.statusText}`);
        render(body.data);
        setStatus("", "");
        $("dashboard").setAttribute("aria-busy", "false");
        $("refreshBtn").disabled = false;
    } catch (err) {
        console.error("Dashboard load failed", err);
        setStatus("error", `Could not load the summary: ${err.message}. Check that the backend is running, then press Refresh.`);
        $("dashboard").setAttribute("aria-busy", "false");
        $("refreshBtn").disabled = false;
    }
}

function setStatus(kind, text) {
    $("statusLine").dataset.kind = kind;
    $("statusLine").textContent = text;
}

async function checkHealth() {
    const pill = $("serverStatus");
    try {
        const res = await fetch(new URL(API_PATH.SERVER_HEALTH_CHECK_PATH, SERVER));
        const ok = res.ok && (await res.json()).status === "OK";
        pill.dataset.state = ok ? "ok" : "down";
        pill.textContent = ok ? "Server online" : "Server error";
    } catch (_) {
        pill.dataset.state = "down";
        pill.textContent = "Server offline";
    }
}

// --- RENDER ---
function render(d) {
    const updated = new Date(d.generated_at * 1000);
    $("lastUpdated").textContent = `Updated ${updated.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
    $("lastUpdated").title = updated.toLocaleString();
    $("refreshBtn").title = `Summary computed ${updated.toLocaleString()}. Click to recompute.`;

    const total = d.total_files || 0;
    const full = d.scan_mode_distribution?.full || 0;
    $("tileFiles").textContent = total.toLocaleString();
    $("tileSize").textContent = d.total_bytes != null ? formatBytes(d.total_bytes) : "–";
    $("tilePackets").textContent = d.total_packets != null ? formatCompact(d.total_packets) : "–";
    $("tilePackets").title = d.total_packets != null ? `${Number(d.total_packets).toLocaleString()} packets` : "";
    $("tileProtocols").textContent = (d.distinct_protocols ?? Object.keys(d.protocol_presence_distribution || {}).length).toLocaleString();
    $("tileFull").textContent = total ? `${Math.round((full / total) * 100)}%` : "–";
    $("tileFullNote").textContent = total ? `${full} of ${total} captures` : "";

    Object.values(charts).forEach(c => c.destroy());
    charts = {};
    tables = {};

    // Most common protocols: ranked horizontal bars, one color, top 20.
    const protos = Object.entries(d.protocol_presence_distribution || {})
        .filter(([p]) => p)
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    const top = protos.slice(0, 20);
    charts.protocols = barChart("protocolChart", top.map(([p]) => p), top.map(([, n]) => n), {
        horizontal: true,
        onClick: (label) => { window.location.href = searchUrl(label); },
        tooltipTitle: (label) => `${label} (click to search)`,
    });
    tables.protocols = { headers: ["Protocol", "Captures"], rows: protos.map(([p, n]) => [p, n]) };

    renderCombos(d.protocol_combination_distribution || {}, total);
    renderScanModes(d.scan_mode_distribution || {}, total);

    const diversity = bandDiversity(d.protocol_diversity_distribution || {});
    charts.diversity = barChart("diversityChart", diversity.map(([l]) => l), diversity.map(([, n]) => n),
        { xTitle: "protocols in the capture" });
    tables.diversity = { headers: ["Protocols", "Captures"], rows: diversity };

    for (const [key, canvas, data, bands] of [
        ["size", "sizeChart", d.pcap_size_distribution, SIZE_BANDS],
        ["packets", "packetChart", d.packet_count_distribution, PACKET_BANDS],
        ["pktsize", "pktSizeChart", d.size_per_packet_distribution, PKT_SIZE_BANDS],
        ["age", "ageChart", d.file_age_distribution, AGE_BANDS],
    ]) {
        const rows = orderedRows(data || {}, bands);
        charts[key] = barChart(canvas, rows.map(([l]) => l), rows.map(([, n]) => n));
        tables[key] = { headers: ["Band", "Captures"], rows };
    }

    renderDirectoryTree(d.directory_distribution || {});
    renderExtensions(d.extension_distribution || {});
    refreshOpenTables();
}

function orderedRows(data, bands) {
    // Keep the bands' natural order; add any label the backend sends that we do not know.
    const known = bands.map(b => [b, data[b] || 0]);
    const extra = Object.keys(data).filter(k => !bands.includes(k)).map(k => [k, data[k]]);
    return [...known, ...extra];
}

function bandDiversity(data) {
    const counts = DIVERSITY_BANDS.map(() => 0);
    for (const [k, n] of Object.entries(data)) {
        const v = parseInt(k, 10);
        const i = DIVERSITY_BANDS.findIndex(([lo, hi]) => v >= lo && v <= hi);
        if (i >= 0) counts[i] += n;
    }
    return DIVERSITY_BANDS.map(([lo, hi], i) => [hi === Infinity ? `${lo}+` : `${lo}–${hi}`, counts[i]]);
}

function barChart(canvasId, labels, values, { horizontal = false, onClick, tooltipTitle, xTitle } = {}) {
    const ink = css("--ink");
    const muted = css("--muted");
    const grid = css("--grid");
    const axis = css("--axis");
    const font = { family: css("--font-ui") || "system-ui", size: 12 };
    const valueAxis = horizontal ? "x" : "y";
    const catAxis = horizontal ? "y" : "x";

    return new Chart($(canvasId), {
        type: "bar",
        data: {
            labels,
            datasets: [{
                data: values,
                backgroundColor: css("--series"),
                hoverBackgroundColor: "#094f8a",
                // rounded data-end, square at the baseline
                borderRadius: horizontal
                    ? { topRight: 4, bottomRight: 4 }
                    : { topLeft: 4, topRight: 4 },
                borderSkipped: false,
                maxBarThickness: horizontal ? 16 : 36,
                categoryPercentage: 0.9,
                barPercentage: 0.85,
            }],
        },
        options: {
            indexAxis: horizontal ? "y" : "x",
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 250 },
            layout: { padding: { right: horizontal ? 8 : 0 } },
            scales: {
                [valueAxis]: {
                    beginAtZero: true,
                    ticks: { precision: 0, color: muted, font },
                    grid: { color: grid, drawTicks: false },
                    border: { display: false },
                    title: { display: true, text: "captures", color: muted, font },
                },
                [catAxis]: {
                    ticks: {
                        color: horizontal ? ink : muted,
                        font: horizontal ? { ...font, family: css("--font-mono") } : font,
                        autoSkip: false,
                    },
                    grid: { display: false },
                    border: { color: axis },
                    title: xTitle ? { display: true, text: xTitle, color: muted, font } : { display: false },
                },
            },
            plugins: {
                legend: { display: false }, // single series: the card title names it
                tooltip: {
                    backgroundColor: ink,
                    titleFont: { ...font, weight: "600" },
                    bodyFont: font,
                    padding: 10,
                    displayColors: false,
                    callbacks: {
                        title: (items) => tooltipTitle ? tooltipTitle(items[0].label) : items[0].label,
                        label: (item) => `${item.raw.toLocaleString()} ${item.raw === 1 ? "capture" : "captures"}`,
                    },
                },
            },
            onHover: onClick
                ? (evt, elements) => { evt.native.target.style.cursor = elements.length ? "pointer" : "default"; }
                : undefined,
            onClick: onClick
                ? (evt, elements) => { if (elements.length) onClick(labels[elements[0].index]); }
                : undefined,
        },
    });
}

function renderCombos(data, total) {
    const list = $("comboList");
    list.replaceChildren();
    const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
    if (!entries.length) {
        list.innerHTML = '<li class="rank-empty">No captures catalogued yet.</li>';
        return;
    }
    const max = entries[0][1];
    for (const [combo, n] of entries) {
        const protos = combo.split(" + ").filter(Boolean);
        const li = document.createElement("li");
        li.innerHTML = `
            <a class="rank-item" href="${escapeHtml(searchUrl(protos.join(" ")))}"
               title="Search captures with all of: ${escapeHtml(protos.join(", "))}">
                <span class="rank-protos">${protos.map(p => `<span>${escapeHtml(p)}</span>`).join("")}</span>
                <span class="rank-track"><span class="rank-fill" style="width:${Math.max(3, (n / max) * 100)}%"></span></span>
                <span class="rank-count" title="${n} of ${total} captures">${n}</span>
            </a>`;
        list.append(li);
    }
}

function renderScanModes(data, total) {
    const bar = $("scanModeBar");
    const legend = $("scanModeLegend");
    bar.replaceChildren();
    legend.replaceChildren();
    const modes = [...SCAN_MODES];
    for (const key of Object.keys(data)) {
        if (!modes.some(m => m.key === key)) modes.push({ key, label: key, desc: "", color: "--muted" });
    }
    const parts = [];
    for (const m of modes) {
        const n = data[m.key] || 0;
        const pct = total ? (n / total) * 100 : 0;
        if (n) {
            const seg = document.createElement("span");
            seg.className = "seg";
            seg.style.flex = `${n} 0 0`;
            seg.style.background = css(m.color);
            seg.title = `${m.label}: ${n} captures (${pct.toFixed(1)}%)`;
            bar.append(seg);
            parts.push(`${m.label} ${pct.toFixed(0)}%`);
        }
        const li = document.createElement("li");
        li.innerHTML = `
            <span class="seg-swatch" style="background:${css(m.color)}"></span>
            <span><b>${escapeHtml(m.label)}</b> <span class="seg-desc">${escapeHtml(m.desc)}</span></span>
            <span class="seg-count">${n.toLocaleString()}</span>
            <span class="seg-pct">${pct.toFixed(1)}%</span>`;
        legend.append(li);
    }
    bar.setAttribute("aria-label", total ? `Scan coverage: ${parts.join(", ")}` : "No captures catalogued yet");
}

function renderDirectoryTree(data) {
    const root = $("directoryTree");
    root.replaceChildren();
    const paths = Object.keys(data).sort();
    if (!paths.length) {
        root.innerHTML = '<p class="rank-empty">No captures catalogued yet.</p>';
        return;
    }
    // Paths arrive flattened ("a", "a/b"); rebuild the hierarchy.
    const tree = {};
    for (const path of paths) {
        let node = tree;
        const parts = path.split("/");
        parts.forEach((part, i) => {
            const sub = parts.slice(0, i + 1).join("/");
            node[part] ??= { count: data[sub] || 0, path: sub, children: {} };
            node = node[part].children;
        });
    }
    const draw = (nodes, container, depth) => {
        for (const [name, node] of Object.entries(nodes).sort((a, b) => a[0].localeCompare(b[0]))) {
            const hasChildren = Object.keys(node.children).length > 0;
            const row = document.createElement(hasChildren ? "button" : "div");
            if (hasChildren) {
                row.type = "button";
                row.setAttribute("aria-expanded", "false");
            }
            row.className = "tree-row";
            row.style.paddingLeft = `${8 + depth * 18}px`;
            row.innerHTML = `
                <span class="tree-name" title="${escapeHtml(node.path)}">
                    <i class="fa ${hasChildren ? "fa-folder" : "fa-folder-o"}" aria-hidden="true"></i>
                    <span>${escapeHtml(name)}</span>
                </span>
                <span class="tree-count">${node.count} ${node.count === 1 ? "capture" : "captures"}</span>`;
            container.append(row);
            if (hasChildren) {
                const kids = document.createElement("div");
                kids.hidden = true;
                container.append(kids);
                draw(node.children, kids, depth + 1);
                row.addEventListener("click", () => {
                    const open = row.getAttribute("aria-expanded") !== "true";
                    row.setAttribute("aria-expanded", String(open));
                    kids.hidden = !open;
                    row.querySelector(".fa").className = `fa ${open ? "fa-folder-open" : "fa-folder"}`;
                });
            }
        }
    };
    draw(tree, root, 0);
}

function renderExtensions(data) {
    const tbody = $("extensionTable");
    const rows = Object.entries(data).sort((a, b) => b[1] - a[1]);
    tbody.innerHTML = rows.length
        ? rows.map(([ext, n]) => `<tr><td><code>${escapeHtml(ext)}</code></td><td class="num">${n}</td></tr>`).join("")
        : '<tr><td class="rank-empty">No captures catalogued yet.</td></tr>';
}

// --- TABLE VIEW (every chart's numbers, readable without color) ---
function fillTable(card) {
    const t = tables[card.dataset.chart];
    const box = card.querySelector(".table-view");
    if (!t || !box) return;
    box.innerHTML = `<table class="mini-table">
        <thead><tr>${t.headers.map((h, i) => `<th${i ? ' class="num"' : ""}>${escapeHtml(h)}</th>`).join("")}</tr></thead>
        <tbody>${t.rows.map(r => `<tr>${r.map((c, i) => `<td${i ? ' class="num"' : ""}>${escapeHtml(typeof c === "number" ? c.toLocaleString() : c)}</td>`).join("")}</tr>`).join("")}</tbody>
    </table>`;
}

function refreshOpenTables() {
    document.querySelectorAll(".card[data-chart]").forEach(card => {
        const box = card.querySelector(".table-view");
        if (box && !box.hidden) fillTable(card);
    });
}

document.querySelectorAll(".table-toggle").forEach(btn => {
    btn.addEventListener("click", () => {
        const card = btn.closest(".card");
        const box = card.querySelector(".table-view");
        const chart = card.querySelector(".chart-box");
        const showTable = box.hidden;
        if (showTable) fillTable(card);
        box.hidden = !showTable;
        chart.hidden = showTable;
        btn.textContent = showTable ? "Show chart" : "Show table";
    });
});

// --- START ---
$("refreshBtn").addEventListener("click", () => loadSummary(true));
checkHealth();
setInterval(checkHealth, SERVER_HEALTH_CHECK_INTERVAL);
loadSummary(false);
window.addEventListener("beforeunload", () => clearTimeout(pollTimer));
