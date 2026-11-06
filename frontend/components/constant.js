// constant.js
const API_PATH = Object.freeze({
    PCAP_REINDEX_PATH: "reindex",
    PCAP_SEARCHING_PATH: "search",
    PROTOCOLS_PATH: "protocols",
    SERVER_HEALTH_CHECK_PATH: "health",
    SCAN_STATUS_PATH: "scan-status",
    SEARCH_SUGGESTION: "protocols/suggest",
    SCAN_CANCEL_PATH: "scan-cancel",
    DASHBOARD_SUMMARY_PATH: "dashboard-summary",
    SCAN_CONFIG_PATH: "scan-config"
});

const TOAST_STATUS = Object.freeze({
    SUCCESS: "Success",
    WARNING: "Warning",
    NOT_FOUND: "Not found",
    ERROR: "Error",
    INFO: "Info"
});

const SERVER_SCANNING_FILE_STATUS = Object.freeze({
    IDLE: "idle",
    RUNNING: "running",
    COMPLETED: "completed",
    FAILED: "failed"
});

const SERVER_HEALTH_CHECK_INTERVAL = 20000; // millisecond
const CHECK_SCAN_FILES_STATUS_INTERVAL = 2000; // millisecond
const MIN_QUERY_LENGTH = 1;

// API base. Default "/api/": the same server that serves this page, which
// forwards to the backend (see frontend/config/nginx.conf). Resolved against
// the page address, so the UI works under any host name. The trailing slash
// matters: API paths are joined onto it.
const configuredBase = (window.APP_CONFIG && window.APP_CONFIG.BE_BASE_URL) || "/api/";
const SERVER = new URL(configuredBase.endsWith("/") ? configuredBase : `${configuredBase}/`, window.location.href).href;

export {
    API_PATH,
    CHECK_SCAN_FILES_STATUS_INTERVAL,
    MIN_QUERY_LENGTH,
    SERVER,
    SERVER_HEALTH_CHECK_INTERVAL,
    SERVER_SCANNING_FILE_STATUS,
    TOAST_STATUS
}


export const SCAN_MODE_TEXT = {
    "full": "Full",
    "normal": "Normal",
    "quick": "Quick",
    "fast": "Fast"
};


// const SERVER = "http://192.168.56.101:8080/packet-capture-service";
// const PCAP_REINDEX_PATH = "/api/v2/protocol/scan";
// const PCAP_SEARCHING_PATH = "/api/v2/protocol/search";
// const PCAP_DOWNLOAD_PATH = "/api/v2/protocol/download";