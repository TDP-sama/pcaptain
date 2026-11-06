import { showToast } from "./toast-script.js";
import { SCAN_MODE_TEXT, SERVER, TOAST_STATUS } from "./constant.js";

export function formatDate(timestamp) {
    if (!timestamp) return "N/A";
    const date = new window.Date(parseFloat(timestamp) * 1000);
    return date.toLocaleString();
}

function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// The drawer is docked to the right edge (see info-modal-style.css), so it
// always fits the screen. It closes on its X, a click on the backdrop, or Esc,
// and gives focus back to the button that opened it.
let currentFile = null;
let opener = null;

function closeInfoModal() {
    const modal = document.getElementById("infoModal");
    if (!modal || modal.hidden) return;
    modal.hidden = true;
    document.getElementById("infoBackdrop").hidden = true;
    document.documentElement.classList.remove("drawer-open");   // page scrolls again
    if (opener) opener.focus();
}

// The drawer is modal (aria-modal): Tab and Shift+Tab cycle through its own
// controls instead of wandering into the page behind it.
function trapFocus(e) {
    const modal = document.getElementById("infoModal");
    if (e.key !== "Tab" || !modal || modal.hidden) return;
    const focusable = [...modal.querySelectorAll(
        'button:not([disabled]), input:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])'
    )].filter(el => el.offsetParent !== null);
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    const inside = modal.contains(document.activeElement);
    if (e.shiftKey && (document.activeElement === first || !inside)) {
        e.preventDefault();
        last.focus();
    } else if (!e.shiftKey && (document.activeElement === last || !inside)) {
        e.preventDefault();
        first.focus();
    }
}

document.addEventListener("click", (e) => {
    if (e.target.closest("#infoClose") || e.target.id === "infoBackdrop") closeInfoModal();
    if (e.target.closest("#infoCopyPath") && currentFile) {
        navigator.clipboard.writeText(currentFile.path || "")
            .then(() => showToast(TOAST_STATUS.SUCCESS, "Path copied"))
            .catch(() => showToast(TOAST_STATUS.ERROR, "Could not copy the path"));
    }
});
document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeInfoModal();
    trapFocus(e);
});

export function openInfoModal(file, event) {
    const modal = document.getElementById("infoModal");
    if (!modal) return;
    currentFile = file;
    opener = event?.currentTarget || null;

    document.getElementById("infoFilename").innerText = file.filename || "N/A";
    document.getElementById("infoPath").innerText = file.path || "N/A";
    document.getElementById("infoSize").innerText = (function(bytes){
        bytes = parseInt(bytes);
        if (!bytes || bytes === 0) return '0 Bytes';
        const units = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const k = 1024;
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        const size = parseFloat((bytes / Math.pow(k, i)).toFixed(2));
        return `${size} ${units[i]}`;
    })(file.size_bytes);
    document.getElementById("infoPackets").innerText = file.total_packets || 0;
    document.getElementById("infoPacketsScanned").innerText = file.packets_scanned || "N/A";

    document.getElementById("infoModified").innerText = formatDate(file.last_modified);
    document.getElementById("infoScanned").innerText = formatDate(file.last_scanned);
    const scanModeValue = SCAN_MODE_TEXT[file.scan_mode] || "Full";
    const pebcValue =
        file.scan_mode === "quick" && file.pebc !== undefined && file.pebc !== null && String(file.pebc).trim() !== ""
            ? file.pebc
            : "N/A";
    document.getElementById("infoScanMode").innerText = scanModeValue;
    document.getElementById("infoScanPebc").innerText = pebcValue;
    document.getElementById("infoScanConfigVersion").innerText = file.config_version || "N/A";
    const pebcRow = document.getElementById("infoScanPebcRow");
    const configRow = document.getElementById("infoScanConfigVersionRow");
    if (file.scan_mode === "quick") {
        if (pebcRow) pebcRow.style.display = "";
        if (configRow) configRow.style.display = "";
    } else {
        if (pebcRow) pebcRow.style.display = "none";
        if (configRow) configRow.style.display = "none";
    }


    renderProtocolTable(file);

    document.getElementById("infoBackdrop").hidden = false;
    modal.hidden = false;
    document.documentElement.classList.add("drawer-open");      // no scrolling behind the drawer
    document.getElementById("infoClose").focus();
}

let currentProtocolData = [];
let allProtocolData = [];
let currentSortColumn = null;
let currentSortAscending = true;
let sortListenersAttached = false;
let searchListenerAttached = false;

function renderProtocolTable(file) {
    resetSortState();
    resetSearchInput();

    const tbody = document.getElementById("protocolTableBody");
    if (!tbody) return;
    tbody.innerHTML = "";

    let percentMap = {};
    let countMap = {};

    if (file.protocol_percentages) {
        try {
            percentMap = JSON.parse(file.protocol_percentages);
        } catch (e) {
            console.error("Error parsing percentages:", e);
        }
    }

    if (file.protocol_counts) {
        try {
            countMap = JSON.parse(file.protocol_counts);
        } catch (e) {
            console.error("Error parsing counts:", e);
        }
    }

    if (!file.protocols) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;">No protocols found</td></tr>';
        return;
    }

    const protos = file.protocols.split(",");
    allProtocolData = protos.map(p => ({
        protocol: p,
        percent: percentMap[p] || 0,
        count: countMap[p] || 0
    }));
    currentProtocolData = [...allProtocolData];

    renderTableRows(file);

    if (!sortListenersAttached) {
        attachSortListeners(file);
        sortListenersAttached = true;
    }

    if (!searchListenerAttached) {
        attachSearchListener(file);
        searchListenerAttached = true;
    }
}

function renderTableRows(file) {
    const tbody = document.getElementById("protocolTableBody");
    if (!tbody) return;
    tbody.innerHTML = "";

    currentProtocolData.forEach(data => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td>${escapeHtml(data.protocol)}</td>
            <td class="num">${data.percent.toFixed(2)}</td>
            <td class="num">${Number(data.count).toLocaleString()}</td>
            <td>
                <button type="button" class="download-protocol-btn" data-protocol="${escapeHtml(data.protocol)}"
                        title="${escapeHtml(`Export only the ${data.protocol} packets`)}">
                    <i class="fa fa-filter" aria-hidden="true"></i> Export
                </button>
            </td>
        `;
        tbody.appendChild(tr);

        const downloadBtn = tr.querySelector(".download-protocol-btn");
        downloadBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            // Hand over to the export dialog (background job + cache) instead of
            // the old synchronous /filter download, which held the request for
            // minutes on large captures.
            closeInfoModal();
            document.dispatchEvent(new CustomEvent("pcap-export", {
                detail: { file, filter: downloadBtn.getAttribute("data-protocol") },
            }));
        });
    });
}

function attachSortListeners(file) {
    const sortHeaders = document.querySelectorAll("th.sortable");
    sortHeaders.forEach(th => {
        // Remove any existing listener first to prevent duplicates
        th.removeEventListener("click", th._sortClickHandler);

        // Create and store the handler
        th._sortClickHandler = (e) => {
            e.stopPropagation();
            const sortColumn = th.getAttribute("data-sort");

            if (currentSortColumn === sortColumn) {
                currentSortAscending = !currentSortAscending;
            } else {
                currentSortColumn = sortColumn;
                currentSortAscending = true;
            }

            sortProtocolData(sortColumn, currentSortAscending);
            renderTableRows(file);
            updateSortIcons(sortColumn, currentSortAscending);
        };

        th.addEventListener("click", th._sortClickHandler);
    });
}

function sortProtocolData(column, ascending) {
    currentProtocolData.sort((a, b) => {
        let valA = a[column];
        let valB = b[column];

        if (column === "protocol") {
            valA = valA.toLowerCase();
            valB = valB.toLowerCase();
            return ascending ? valA.localeCompare(valB) : valB.localeCompare(valA);
        } else {
            return ascending ? valA - valB : valB - valA;
        }
    });
}

function updateSortIcons(activeColumn, ascending) {
    const sortHeaders = document.querySelectorAll("th.sortable");
    sortHeaders.forEach(th => {
        const icon = th.querySelector("i");
        const column = th.getAttribute("data-sort");

        if (column === activeColumn) {
            icon.className = ascending ? "fa fa-sort-asc" : "fa fa-sort-desc";
            th.setAttribute("aria-sort", ascending ? "ascending" : "descending");
        } else {
            icon.className = "fa fa-sort";
            th.setAttribute("aria-sort", "none");
        }
    });
}

function attachSearchListener(file) {
    const searchInput = document.getElementById("protocolSearchInput");
    if (!searchInput) return;

    searchInput.removeEventListener("input", searchInput._searchHandler);

    searchInput._searchHandler = (e) => {
        const query = e.target.value.toLowerCase().trim();

        if (query === "") {
            currentProtocolData = [...allProtocolData];
        } else {
            currentProtocolData = allProtocolData.filter(p =>
                p.protocol.toLowerCase().includes(query)
            );
        }

        // Re-apply current sort if any
        if (currentSortColumn) {
            sortProtocolData(currentSortColumn, currentSortAscending);
        }

        renderTableRows(file);
    };

    searchInput.addEventListener("input", searchInput._searchHandler);
}

function resetSearchInput() {
    const searchInput = document.getElementById("protocolSearchInput");
    if (searchInput) {
        searchInput.value = "";
    }
    searchListenerAttached = false;
}

function resetSortState() {
    currentSortColumn = null;
    currentSortAscending = true;
    currentProtocolData = [];
    allProtocolData = [];
    sortListenersAttached = false;

    // Reset all sort icons to default
    const sortHeaders = document.querySelectorAll("th.sortable");
    sortHeaders.forEach(th => {
        const icon = th.querySelector("i");
        if (icon) {
            icon.className = "fa fa-sort";
        }
        th.setAttribute("aria-sort", "none");
    });
}
