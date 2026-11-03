import { showToast } from "./toast-script.js";
import {
    API_PATH,
    CHECK_SCAN_FILES_STATUS_INTERVAL,
    SERVER,
    SERVER_HEALTH_CHECK_INTERVAL,
    SERVER_SCANNING_FILE_STATUS,
    TOAST_STATUS
} from "./constant.js";
import { openInfoModal } from "./info-modal.js";

// --- STATE ---
// A search is a list of terms. Each term is one of:
//   { kind: "proto", value: "sip", neg: false }       has / has not a protocol
//   { kind: "any",   value: ["isup", "bicc"] }         has at least one of them
//   { kind: "name",  value: "camel", neg: false }      filename contains / does not contain
let terms = [];
let knownProtocols = new Map(); // protocol -> number of files containing it
let currentPage = 1;
let itemsPerPage = 10;
let currentSortBy = "filename";
let currentDescending = false;
let lastResponse = null;
let currentFiles = [];
let facetsExpanded = false;
let activeSuggestion = -1;
let suggestions = [];
let scanTimer = null;

const FACETS_COLLAPSED = 18;
const SUGGESTION_LIMIT = 8;

const $ = (id) => document.getElementById(id);
const queryInput = $("queryInput");
const suggestList = $("suggestList");

// --- HELPERS ---
function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function formatFileSize(bytes) {
    bytes = parseInt(bytes);
    if (!bytes) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    return `${parseFloat((bytes / Math.pow(1024, i)).toFixed(i ? 1 : 0))} ${units[i]}`;
}

function formatCount(value) {
    const n = parseInt(value);
    return Number.isFinite(n) ? n.toLocaleString() : "–";
}

async function api(path, { method = "GET", params } = {}) {
    const url = new URL(path, SERVER);
    if (params) {
        for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    }
    const res = await fetch(url, { method });
    if (!res.ok) {
        const err = new Error(`${res.status} ${res.statusText}`);
        err.status = res.status;
        throw err;
    }
    return res.json();
}

// --- QUERY TERMS ---
function termKey(t) {
    return t.kind === "any" ? `any:${t.value.join("|")}` : `${t.kind}:${t.value}`;
}

function serializeTerms(list) {
    return list.map(t => {
        if (t.kind === "any") return t.value.join("|");
        const body = t.kind === "name" ? `name:${t.value}` : t.value;
        return (t.neg ? "!" : "") + body;
    }).join(" ");
}

// Mirrors parse_query() in backend/routes/search.py so chips match what the server searches.
function parseText(text) {
    const raw = text.toLowerCase().split(/[\s,]+/).filter(Boolean);
    const tokens = [];
    for (let i = 0; i < raw.length; i++) {
        if (raw[i] === "or" && tokens.length && i + 1 < raw.length) {
            tokens[tokens.length - 1] += `|${raw[++i]}`;
        } else {
            tokens.push(raw[i]);
        }
    }

    const parsed = [];
    for (let token of tokens) {
        const neg = (token[0] === "!" || token[0] === "-") && token.length > 1;
        if (neg) token = token.slice(1);

        const m = token.match(/^(name|file):(.+)$/);
        if (m) {
            parsed.push({ kind: "name", value: m[2], neg });
            continue;
        }
        if (token.includes("|")) {
            const group = [...new Set(token.split("|").filter(p => knownProtocols.has(p)))];
            if (neg) group.forEach(p => parsed.push({ kind: "proto", value: p, neg: true }));
            else if (group.length === 1) parsed.push({ kind: "proto", value: group[0], neg: false });
            else if (group.length > 1) parsed.push({ kind: "any", value: group });
            continue;
        }
        parsed.push(knownProtocols.has(token)
            ? { kind: "proto", value: token, neg }
            : { kind: "name", value: token, neg });
    }
    return parsed;
}

function addTerms(newTerms) {
    for (const t of newTerms) {
        const i = terms.findIndex(x => termKey(x) === termKey(t));
        if (i >= 0) terms[i] = t;
        else terms.push(t);
    }
}

function setTerms(list) {
    terms = [];
    addTerms(list);
}

function renderChips() {
    const box = $("chipList");
    box.replaceChildren();
    terms.forEach((t, i) => {
        const chip = document.createElement("span");
        chip.className = `chip chip-${t.kind}${t.neg ? " is-neg" : ""}`;

        const label = document.createElement("button");
        label.type = "button";
        label.className = "chip-label";
        if (t.kind === "any") {
            label.innerHTML = `<span class="chip-op">any</span>${t.value.map(escapeHtml).join('<span class="chip-or">|</span>')}`;
            label.title = "Files containing at least one of these";
            label.disabled = true;
        } else {
            const op = t.neg ? (t.kind === "name" ? "name not" : "not") : (t.kind === "name" ? "name" : "");
            label.innerHTML = `${op ? `<span class="chip-op">${op}</span>` : ""}<span class="chip-value">${escapeHtml(t.value)}</span>`;
            label.title = t.neg ? "Click to require instead" : "Click to exclude instead";
            label.addEventListener("click", () => {
                t.neg = !t.neg;
                runSearch();
            });
        }

        const remove = document.createElement("button");
        remove.type = "button";
        remove.className = "chip-remove";
        remove.setAttribute("aria-label", `Remove ${t.kind === "any" ? t.value.join(" or ") : t.value}`);
        remove.innerHTML = '<i class="fa fa-times" aria-hidden="true"></i>';
        remove.addEventListener("click", () => {
            terms.splice(i, 1);
            runSearch();
            queryInput.focus();
        });

        chip.append(label, remove);
        box.append(chip);
    });
    $("clearQueryBtn").hidden = terms.length === 0 && !queryInput.value;
    queryInput.placeholder = terms.length ? "Add another term" : "Add a protocol or filename, e.g. sip";
}

// --- SUGGESTIONS ---
function buildSuggestions(text) {
    const neg = /^[!-]/.test(text);
    const needle = text.replace(/^[!-]/, "").toLowerCase().trim();
    if (!needle || /[|:\s,]/.test(needle)) return [];

    const inQuery = new Set(terms.filter(t => t.kind === "proto").map(t => t.value));
    const prefix = [];
    const contains = [];
    for (const [proto, files] of knownProtocols) {
        if (inQuery.has(proto)) continue;
        if (proto.startsWith(needle)) prefix.push([proto, files]);
        else if (proto.includes(needle)) contains.push([proto, files]);
    }
    const byFiles = (a, b) => b[1] - a[1] || a[0].localeCompare(b[0]);
    const protos = [...prefix.sort(byFiles), ...contains.sort(byFiles)]
        .slice(0, SUGGESTION_LIMIT)
        .map(([proto, files]) => ({ term: { kind: "proto", value: proto, neg }, proto, files }));

    protos.push({ term: { kind: "name", value: needle, neg }, name: needle });
    return protos;
}

function renderSuggestions() {
    suggestList.replaceChildren();
    if (!suggestions.length) {
        suggestList.hidden = true;
        queryInput.setAttribute("aria-expanded", "false");
        return;
    }
    suggestions.forEach((s, i) => {
        const li = document.createElement("li");
        li.id = `suggest-${i}`;
        li.setAttribute("role", "option");
        li.className = "suggest-item" + (i === activeSuggestion ? " is-active" : "");
        li.setAttribute("aria-selected", i === activeSuggestion ? "true" : "false");
        const verb = s.term.neg ? "Without" : "With";
        if (s.proto) {
            li.innerHTML = `<span class="suggest-kind">${verb} protocol</span>
                <span class="suggest-value">${escapeHtml(s.proto)}</span>
                <span class="suggest-count">${s.files} ${s.files === 1 ? "file" : "files"}</span>`;
        } else {
            li.innerHTML = `<span class="suggest-kind">${s.term.neg ? "Filename without" : "Filename contains"}</span>
                <span class="suggest-value">“${escapeHtml(s.name)}”</span>`;
        }
        li.addEventListener("mousedown", (e) => {
            e.preventDefault(); // keep focus in the input
            acceptSuggestion(i);
        });
        suggestList.append(li);
    });
    suggestList.hidden = false;
    queryInput.setAttribute("aria-expanded", "true");
    queryInput.setAttribute("aria-activedescendant", activeSuggestion >= 0 ? `suggest-${activeSuggestion}` : "");
}

function hideSuggestions() {
    suggestions = [];
    activeSuggestion = -1;
    renderSuggestions();
}

function acceptSuggestion(i) {
    addTerms([suggestions[i].term]);
    queryInput.value = "";
    hideSuggestions();
    runSearch();
}

queryInput.addEventListener("input", () => {
    suggestions = buildSuggestions(queryInput.value);
    activeSuggestion = suggestions.length > 1 ? 0 : -1;
    renderSuggestions();
    $("clearQueryBtn").hidden = terms.length === 0 && !queryInput.value;
});

queryInput.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown" && suggestions.length) {
        e.preventDefault();
        activeSuggestion = (activeSuggestion + 1) % suggestions.length;
        renderSuggestions();
    } else if (e.key === "ArrowUp" && suggestions.length) {
        e.preventDefault();
        activeSuggestion = (activeSuggestion - 1 + suggestions.length) % suggestions.length;
        renderSuggestions();
    } else if (e.key === "Escape") {
        hideSuggestions();
    } else if (e.key === "Backspace" && !queryInput.value && terms.length) {
        terms.pop();
        runSearch();
    }
});

queryInput.addEventListener("blur", () => setTimeout(hideSuggestions, 100));

$("queryForm").addEventListener("submit", (e) => {
    e.preventDefault();
    if (activeSuggestion >= 0 && suggestions.length) {
        acceptSuggestion(activeSuggestion);
        return;
    }
    if (queryInput.value.trim()) {
        addTerms(parseText(queryInput.value));
        queryInput.value = "";
    }
    hideSuggestions();
    runSearch();
});

$("clearQueryBtn").addEventListener("click", () => {
    terms = [];
    queryInput.value = "";
    hideSuggestions();
    runSearch();
    queryInput.focus();
});

document.querySelectorAll(".query-help .example").forEach(btn => {
    btn.addEventListener("click", () => {
        setTerms(parseText(btn.dataset.q));
        runSearch();
    });
});

// --- SEARCH ---
function runSearch() {
    currentPage = 1;
    renderChips();
    fetchResults();
}

function syncUrl() {
    const url = new URL(window.location.href);
    const q = serializeTerms(terms);
    if (q) url.searchParams.set("q", q);
    else url.searchParams.delete("q");
    history.replaceState(null, "", url);
}

async function fetchResults() {
    syncUrl();
    $("resultSummary").textContent = "Searching…";
    try {
        const data = await api(API_PATH.PCAP_SEARCHING_PATH, {
            params: {
                protocol: serializeTerms(terms),
                page: currentPage,
                limit: itemsPerPage,
                sort_by: currentSortBy,
                descending: currentDescending,
            }
        });
        lastResponse = data;
        currentFiles = data.data || [];
        renderSummary(data);
        renderTable(currentFiles);
        renderFacets();
        renderEmptyState(data);
        renderPagination(data.total);
    } catch (err) {
        console.error("Search failed", err);
        $("resultSummary").textContent = "Search failed. Check that the backend is running, then try again.";
        showToast(TOAST_STATUS.ERROR, "Search failed");
    }
}

function describeQuery(q) {
    const parts = [];
    if (q.all.length) parts.push(`with ${q.all.map(strong).join(" and ")}`);
    q.any.forEach(group => parts.push(`with ${group.map(strong).join(" or ")}`));
    if (q.none.length) parts.push(`without ${q.none.map(strong).join(" or ")}`);
    if (q.name.length) parts.push(`named like ${q.name.map(s => strong(`“${s}”`)).join(" and ")}`);
    if (q.not_name.length) parts.push(`not named like ${q.not_name.map(s => strong(`“${s}”`)).join(" or ")}`);
    return parts.join(", ");
}

function strong(text) {
    return `<b>${escapeHtml(text)}</b>`;
}

function renderSummary(data) {
    const noun = data.total === 1 ? "capture" : "captures";
    const desc = describeQuery(data.query);
    $("resultSummary").innerHTML = desc
        ? `<span class="count">${data.total.toLocaleString()}</span> ${noun} ${desc}`
        : `<span class="count">${data.total.toLocaleString()}</span> ${noun} in the catalog`;
}

function displayFilterFor(q) {
    const parts = [
        ...q.all,
        ...q.any.map(group => `(${group.join(" or ")})`),
        ...q.none.map(p => `not ${p}`),
    ];
    return parts.join(" and ");
}

function scanModeLabel(file) {
    const mode = (file.scan_mode || "full").toLowerCase();
    if (mode === "quick") return `quick ${file.pebc || ""}`.trim();
    return mode === "normal" ? "full" : mode;
}

function renderTable(files) {
    const tbody = $("resultBody");
    tbody.replaceChildren();
    const q = lastResponse?.query;
    const filter = q ? displayFilterFor(q) : "";

    files.forEach((file, index) => {
        let counts = {};
        try { counts = JSON.parse(file.protocol_counts || "{}"); } catch (_) { /* keep empty */ }
        const matched = new Set(file.matched_protocols || []);
        const others = Object.entries(counts)
            .filter(([p]) => !matched.has(p))
            .sort((a, b) => b[1] - a[1])
            .map(([p]) => p);
        const shownOthers = others.slice(0, 6);
        const hidden = others.length - shownOthers.length;

        const badge = (p, cls) =>
            `<button type="button" class="proto ${cls}" data-proto="${escapeHtml(p)}" title="${escapeHtml(`${p}: ${formatCount(counts[p])} packets. Click to add to search`)}">${escapeHtml(p)}</button>`;

        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td class="capture">
                <div class="capture-name">
                    <span class="filename">${escapeHtml(file.filename)}</span>
                    <span class="mode-tag mode-${escapeHtml(scanModeLabel(file).split(" ")[0])}" title="Scan mode used for this file">${escapeHtml(scanModeLabel(file))}</span>
                </div>
                <div class="capture-path">
                    <span class="path" title="${escapeHtml(file.path)}">${escapeHtml(file.path)}</span>
                    <button type="button" class="icon-btn copy-path" data-index="${index}" title="Copy path" aria-label="Copy path">
                        <i class="fa fa-clone" aria-hidden="true"></i>
                    </button>
                </div>
            </td>
            <td class="protos">
                ${[...matched].map(p => badge(p, "is-match")).join("")}
                ${shownOthers.map(p => badge(p, "")).join("")}
                ${hidden > 0 ? `<span class="proto-more" title="${escapeHtml(others.slice(6).join(", "))}">+${hidden}</span>` : ""}
            </td>
            <td class="num" data-label="Packets">${formatCount(file.total_packets)}</td>
            <td class="num" data-label="Size">${formatFileSize(file.size_bytes)}</td>
            <td class="actions">
                <a class="btn btn-small" href="${escapeHtml(file.download_url)}" download title="Download the whole capture">
                    <i class="fa fa-download" aria-hidden="true"></i> File
                </a>
                <button type="button" class="btn btn-small btn-outline export-btn" data-index="${index}"
                        title="${escapeHtml(filter ? `Export only packets matching: ${filter}` : "Export the packets matching a display filter")}">
                    <i class="fa fa-filter" aria-hidden="true"></i> Export…</button>
                <button type="button" class="icon-btn info-btn" data-index="${index}" title="Details" aria-label="Details">
                    <i class="fa fa-info-circle" aria-hidden="true"></i>
                </button>
            </td>`;
        tbody.append(tr);
    });
}

$("resultBody").addEventListener("click", (e) => {
    const proto = e.target.closest(".proto");
    if (proto) {
        addTerms([{ kind: "proto", value: proto.dataset.proto, neg: false }]);
        runSearch();
        return;
    }
    const copy = e.target.closest(".copy-path");
    if (copy) {
        const path = currentFiles[copy.dataset.index]?.path || "";
        navigator.clipboard.writeText(path)
            .then(() => showToast(TOAST_STATUS.SUCCESS, "Path copied"))
            .catch(() => showToast(TOAST_STATUS.ERROR, "Could not copy the path"));
        return;
    }
    const exportBtn = e.target.closest(".export-btn");
    if (exportBtn) {
        openExportDialog(currentFiles[exportBtn.dataset.index]);
        return;
    }
    const info = e.target.closest(".info-btn");
    if (info) {
        e.stopPropagation(); // the modal closes on any click that reaches window
        openInfoModal(currentFiles[info.dataset.index], { currentTarget: info });
    }
});

function renderFacets() {
    const list = $("facetList");
    list.replaceChildren();
    const facets = lastResponse?.facets || [];
    const total = lastResponse?.total || 0;
    const used = new Set(terms.flatMap(t => t.kind === "any" ? t.value : t.kind === "proto" ? [t.value] : []));
    const needle = $("facetFilter").value.trim().toLowerCase();
    const visible = facets.filter(f => !used.has(f.protocol) && (!needle || f.protocol.includes(needle)));
    const shown = facetsExpanded || needle ? visible : visible.slice(0, FACETS_COLLAPSED);

    for (const f of shown) {
        const li = document.createElement("li");
        li.className = "facet";
        const pct = total ? Math.max(4, Math.round((f.files / total) * 100)) : 0;
        li.innerHTML = `
            <span class="facet-name">${escapeHtml(f.protocol)}</span>
            <span class="facet-count">${f.files}</span>
            <span class="facet-bar" style="--pct:${pct}%"></span>
            <span class="facet-actions">
                <button type="button" data-act="add" title="Require ${escapeHtml(f.protocol)}" aria-label="Require ${escapeHtml(f.protocol)}">+</button>
                <button type="button" data-act="exclude" title="Exclude ${escapeHtml(f.protocol)}" aria-label="Exclude ${escapeHtml(f.protocol)}">−</button>
            </span>`;
        li.querySelectorAll("button").forEach(b => b.addEventListener("click", () => {
            addTerms([{ kind: "proto", value: f.protocol, neg: b.dataset.act === "exclude" }]);
            runSearch();
        }));
        list.append(li);
    }
    if (!visible.length) {
        list.innerHTML = `<li class="facet-empty">${facets.length ? "No other protocols." : "Nothing to refine."}</li>`;
    }
    $("facetTotal").textContent = visible.length ? `· ${visible.length}` : "";
    const more = $("facetMore");
    more.hidden = needle || visible.length <= FACETS_COLLAPSED;
    more.textContent = facetsExpanded ? "Show fewer" : `Show all ${visible.length}`;
}

$("facetFilter").addEventListener("input", renderFacets);
$("facetToggle").addEventListener("click", () => {
    const open = !$("facets").classList.contains("is-open");
    $("facets").classList.toggle("is-open", open);
    $("facetToggle").setAttribute("aria-expanded", String(open));
});
$("facetMore").addEventListener("click", () => {
    facetsExpanded = !facetsExpanded;
    renderFacets();
});

function renderEmptyState(data) {
    const box = $("emptyState");
    if (data.total > 0) {
        box.hidden = true;
        return;
    }
    const suggestionsHtml = (data.suggestions || []).length
        ? `<p>Did you mean ${data.suggestions.map(p =>
            `<button type="button" class="proto" data-suggest="${escapeHtml(p)}">${escapeHtml(p)}</button>`).join(" ")}?</p>`
        : "";
    box.innerHTML = terms.length
        ? `<h3>No capture matches this search</h3>
           <p>Remove a term, switch one between has and has not, or try a broader protocol.</p>
           ${suggestionsHtml}`
        : `<h3>The catalog is empty</h3><p>Press <b>Scan</b> to index the capture directory.</p>`;
    box.querySelectorAll("[data-suggest]").forEach(b => b.addEventListener("click", () => {
        // Replace the filename terms that matched nothing with the suggested protocol.
        terms = terms.filter(t => t.kind !== "name");
        addTerms([{ kind: "proto", value: b.dataset.suggest, neg: false }]);
        runSearch();
    }));
    box.hidden = false;
}

function renderPagination(totalItems) {
    const nav = $("pagination");
    nav.replaceChildren();
    const totalPages = Math.ceil(totalItems / itemsPerPage);
    if (totalPages <= 1) return;

    const add = (label, page, { active = false, disabled = false, aria } = {}) => {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "page-btn" + (active ? " is-active" : "");
        b.innerHTML = label;
        b.disabled = disabled || active;
        if (aria) b.setAttribute("aria-label", aria);
        if (active) b.setAttribute("aria-current", "page");
        b.addEventListener("click", () => {
            currentPage = page;
            fetchResults();
        });
        nav.append(b);
    };
    const gap = () => {
        const s = document.createElement("span");
        s.className = "page-gap";
        s.textContent = "…";
        nav.append(s);
    };

    add('<i class="fa fa-chevron-left" aria-hidden="true"></i>', currentPage - 1, { disabled: currentPage === 1, aria: "Previous page" });
    const pages = new Set([1, totalPages, currentPage - 1, currentPage, currentPage + 1]);
    let prev = 0;
    [...pages].filter(p => p >= 1 && p <= totalPages).sort((a, b) => a - b).forEach(p => {
        if (p - prev > 1) gap();
        add(String(p), p, { active: p === currentPage });
        prev = p;
    });
    add('<i class="fa fa-chevron-right" aria-hidden="true"></i>', currentPage + 1, { disabled: currentPage === totalPages, aria: "Next page" });
}

// --- FILTERED EXPORT ---
// Exports run on the server as background jobs; finished extracts are cached,
// so asking again for the same file + filter downloads immediately.
const EXPORT_PRESETS = [
    { label: "SIP signalling", filter: "sip || sdp" },
    { label: "SIP INVITEs", filter: 'sip.Method == "INVITE"' },
    { label: "SS7 / SIGTRAN", filter: "m2ua || m3ua || m2pa || sua || sccp || tcap || isup || camel || gsm_map || bicc" },
    { label: "Without RTP", filter: "!rtp" },
    { label: "First 60 s", filter: "frame.time_relative <= 60" },
    { label: "One host", filter: "ip.addr == 10.0.0.1" },
];
const exportState = { file: null, jobId: null, timer: null, validateTimer: null, autoDownload: false };

function exportFilterFor(file) {
    const q = lastResponse?.query;
    return q ? displayFilterFor(q) : "";
}

function renderPresets(file) {
    const list = $("presetList");
    list.replaceChildren();
    const fromSearch = exportFilterFor(file);
    const presets = fromSearch ? [{ label: "From your search", filter: fromSearch }, ...EXPORT_PRESETS] : EXPORT_PRESETS;
    for (const p of presets) {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "preset";
        b.title = p.filter;
        b.textContent = p.label;
        b.addEventListener("click", () => {
            $("exportFilter").value = p.filter;
            onFilterInput();
            $("exportFilter").focus();
        });
        list.append(b);
    }
}

function setFilterStatus(kind, text) {
    const el = $("filterStatus");
    el.dataset.kind = kind;
    el.textContent = text;
}

function resetExportResult() {
    clearInterval(exportState.timer);
    exportState.jobId = null;
    $("exportProgress").hidden = true;
    $("exportDownload").hidden = true;
    $("exportStart").hidden = false;
    $("exportStart").disabled = false;
}

function openExportDialog(file) {
    if (!file) return;
    exportState.file = file;
    $("exportFile").textContent = `${file.filename} · ${formatFileSize(file.size_bytes)} · ${formatCount(file.total_packets)} packets`;
    $("exportFilter").value = exportFilterFor(file);
    renderPresets(file);
    resetExportResult();
    setFilterStatus("", "");
    $("exportDialog").showModal();
    if ($("exportFilter").value) onFilterInput();
    $("exportFilter").focus();
}

function closeExportDialog() {
    clearInterval(exportState.timer);
    clearTimeout(exportState.validateTimer);
    exportState.autoDownload = false; // the job keeps running on the server
    $("exportDialog").close();
}

function onFilterInput() {
    resetExportResult();
    clearTimeout(exportState.validateTimer);
    const filter = $("exportFilter").value.trim();
    if (!filter) {
        setFilterStatus("", "");
        return;
    }
    setFilterStatus("pending", "Checking filter…");
    exportState.validateTimer = setTimeout(async () => {
        try {
            const res = await api("exports/validate", { params: { filter } });
            if ($("exportFilter").value.trim() !== filter) return; // user kept typing
            if (res.valid) setFilterStatus("ok", "Valid filter");
            else setFilterStatus("error", res.error);
        } catch (_) {
            setFilterStatus("", "Could not check the filter right now.");
        }
    }, 400);
}

function showExportJob(job) {
    exportState.jobId = job.id;
    const progress = $("exportProgress");
    const text = $("exportProgressText");
    const bar = $("exportBar");
    progress.hidden = false;
    progress.dataset.state = job.state;
    bar.style.width = `${Math.round((job.progress || 0) * 100)}%`;

    if (job.state === "queued") {
        text.textContent = "Waiting for a free export slot…";
    } else if (job.state === "running") {
        const secs = Math.round(Date.now() / 1000 - job.created_at);
        text.textContent = `Decoding the capture… ${Math.round(job.progress * 100)}% · ${secs}s`;
    } else if (job.state === "ready") {
        bar.style.width = "100%";
        text.textContent = `${formatCount(job.packets)} packets · ${formatFileSize(job.size_bytes)}` +
            (job.cached ? " · from cache" : "");
        const link = $("exportDownload");
        link.href = job.download_url;
        link.hidden = false;
        $("exportStart").hidden = true;
        if (exportState.autoDownload) {
            exportState.autoDownload = false;
            link.click();
        }
    } else if (job.state === "empty") {
        bar.style.width = "100%";
        text.textContent = "No packet in this capture matches the filter.";
        $("exportStart").disabled = false;
    } else if (job.state === "failed") {
        text.textContent = `Export failed: ${job.error}`;
        $("exportStart").disabled = false;
    }
    return job.state === "queued" || job.state === "running";
}

async function startExport() {
    const filter = $("exportFilter").value.trim();
    if (!filter) {
        setFilterStatus("error", "Enter a display filter first.");
        return;
    }
    $("exportStart").disabled = true;
    try {
        const res = await fetch(new URL("exports", SERVER), {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ file_hash: exportState.file.hash, filter }),
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) {
            const detail = typeof body.detail === "string" ? body.detail : `${res.status} ${res.statusText}`;
            setFilterStatus("error", detail.replace(/^Invalid display filter: /, ""));
            $("exportStart").disabled = false;
            return;
        }
        exportState.autoDownload = true;
        if (showExportJob(body)) pollExport(body.id);
    } catch (err) {
        setFilterStatus("error", `Could not start the export: ${err.message}`);
        $("exportStart").disabled = false;
    }
}

function pollExport(jobId) {
    clearInterval(exportState.timer);
    exportState.timer = setInterval(async () => {
        try {
            const job = await api(`exports/${jobId}`);
            if (!showExportJob(job)) clearInterval(exportState.timer);
        } catch (_) {
            clearInterval(exportState.timer);
            $("exportProgressText").textContent = "Lost track of the export. Press Export to check again.";
            $("exportStart").hidden = false;
            $("exportStart").disabled = false;
        }
    }, 1000);
}

$("exportFilter").addEventListener("input", onFilterInput);
$("exportFilter").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) startExport();
});
$("exportStart").addEventListener("click", startExport);
$("exportClose").addEventListener("click", closeExportDialog);
$("exportCancel").addEventListener("click", closeExportDialog);
$("exportDialog").addEventListener("cancel", () => clearInterval(exportState.timer));

// --- SORT / PAGE SIZE ---
$("sortBy").addEventListener("change", (e) => { currentSortBy = e.target.value; currentPage = 1; fetchResults(); });
$("sortOrder").addEventListener("change", (e) => { currentDescending = e.target.value === "true"; currentPage = 1; fetchResults(); });
$("limitSelect").addEventListener("change", (e) => { itemsPerPage = parseInt(e.target.value); currentPage = 1; fetchResults(); });

// --- SERVER STATUS, SCAN ---
function setServerStatus(state, text) {
    const pill = $("serverStatus");
    pill.dataset.state = state;
    pill.textContent = text;
}

async function checkHealth() {
    try {
        const res = await api(API_PATH.SERVER_HEALTH_CHECK_PATH);
        if ($("serverStatus").dataset.state !== "scanning") {
            setServerStatus(res.status === "OK" ? "ok" : "down", res.status === "OK" ? "Server online" : "Server error");
        }
    } catch (_) {
        setServerStatus("down", "Server offline");
    }
}

const SCAN_MODE_HELP = {
    fast: "Fast: reads packet headers and guesses protocols from port numbers. Very quick, misses protocols on unusual ports and inside SCTP.",
    quick: "Quick: tshark decodes only the first part of each large file.",
    full: "Full: tshark decodes every packet. Most accurate, slowest.",
};

function showScanConfig(cfg) {
    const select = $("scanModeSelect");
    select.value = cfg.scan_mode;
    select.dataset.current = cfg.scan_mode;
    select.title = cfg.scan_mode === "quick"
        ? `${SCAN_MODE_HELP.quick} Now: first ${Math.round(cfg.pebc * 100)}% of files from ${cfg.min_file_size} up.`
        : SCAN_MODE_HELP[cfg.scan_mode] || "Scan mode used by the next scan";
}

async function loadScanConfig() {
    try {
        showScanConfig(await api(API_PATH.SCAN_CONFIG_PATH));
    } catch (_) {
        $("scanModeSelect").title = "Could not read the scan mode from the server";
    }
}

$("scanModeSelect").addEventListener("change", async (e) => {
    const select = e.target;
    const previous = select.dataset.current;
    select.disabled = true;
    try {
        const res = await fetch(new URL(API_PATH.SCAN_CONFIG_PATH, SERVER), {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ scan_mode: select.value }),
        });
        if (!res.ok) {
            const detail = (await res.json().catch(() => ({}))).detail;
            throw new Error(detail || `${res.status} ${res.statusText}`);
        }
        const cfg = await res.json();
        showScanConfig(cfg);
        const note = cfg.persisted ? "" : " (until the backend restarts)";
        showToast(TOAST_STATUS.SUCCESS, `Scan mode set to ${cfg.scan_mode}${note}. Press Scan to apply it.`);
    } catch (err) {
        select.value = previous;
        showToast(TOAST_STATUS.ERROR, `Could not change the scan mode: ${err.message}`);
    } finally {
        select.disabled = $("scanBtn").disabled; // stays locked while a scan runs
    }
});

async function loadProtocols() {
    try {
        const rows = await api(API_PATH.PROTOCOLS_PATH);
        knownProtocols = new Map(rows.map(r => [r.protocol.toLowerCase(), r.files]));
    } catch (err) {
        console.error("Could not load the protocol list", err);
    }
}

function setScanning(on) {
    $("scanBtn").disabled = on;
    $("scanModeSelect").disabled = on;
    $("scanBtn").querySelector("span").textContent = on ? "Scanning…" : "Scan";
    $("scanBtn").querySelector("i").classList.toggle("fa-spin", on);
    $("cancelScanBtn").hidden = !on;
    if (on) setServerStatus("scanning", "Scanning");
}

function pollScan() {
    clearInterval(scanTimer);
    scanTimer = setInterval(async () => {
        try {
            const s = await api(API_PATH.SCAN_STATUS_PATH);
            if (s.state === SERVER_SCANNING_FILE_STATUS.RUNNING) return;
            clearInterval(scanTimer);
            setScanning(false);
            setServerStatus("ok", "Server online");
            if (s.state === SERVER_SCANNING_FILE_STATUS.FAILED) {
                showToast(TOAST_STATUS.ERROR, `Scan failed: ${s.message}`);
            } else {
                showToast(TOAST_STATUS.SUCCESS, s.message || "Scan finished");
            }
            await loadProtocols();
            fetchResults();
        } catch (_) {
            clearInterval(scanTimer);
            setScanning(false);
            setServerStatus("down", "Server offline");
        }
    }, CHECK_SCAN_FILES_STATUS_INTERVAL);
}

$("scanBtn").addEventListener("click", async () => {
    try {
        await api(API_PATH.PCAP_REINDEX_PATH, { method: "POST" });
        setScanning(true);
        pollScan();
    } catch (err) {
        showToast(TOAST_STATUS.ERROR, err.status === 409 ? "A scan is already running" : "Could not start the scan");
    }
});

$("cancelScanBtn").addEventListener("click", async () => {
    try {
        await api(API_PATH.SCAN_CANCEL_PATH, { method: "POST" });
        showToast(TOAST_STATUS.INFO, "Cancelling the scan");
    } catch (_) {
        showToast(TOAST_STATUS.ERROR, "Could not cancel the scan");
    }
});

// --- START ---
async function init() {
    checkHealth();
    setInterval(checkHealth, SERVER_HEALTH_CHECK_INTERVAL);
    loadScanConfig();
    await loadProtocols();

    const q = new URL(window.location.href).searchParams.get("q");
    if (q) setTerms(parseText(q));
    renderChips();
    fetchResults();

    try {
        const s = await api(API_PATH.SCAN_STATUS_PATH);
        if (s.state === SERVER_SCANNING_FILE_STATUS.RUNNING) {
            setScanning(true);
            pollScan();
        }
    } catch (_) { /* health check reports it */ }
}

init();
