# Pcap Catalog Service

[![tests](https://github.com/TDP-sama/pcaptain/actions/workflows/tests.yml/badge.svg)](https://github.com/TDP-sama/pcaptain/actions/workflows/tests.yml)

A high-performance, asynchronous web service that scans directories of pcap files, catalogs them in Redis based on detailed protocol analysis, and provides a powerful REST API to search, download, and get autocomplete suggestions for protocols.

This project uses `tshark` (and a small C++ pre-scanner, `fastscan`) to find the protocols in each capture, and Redis for high-speed indexing and searching. It's designed for efficiency and ease of use, packaged with Docker for simple deployment.

## Features

- Three Scan Modes:
    - `fast` (default): `fastscan` reads packet headers and infers application protocols from port numbers. Very fast, but it can miss protocols on non-standard ports or inside SCTP. Captures it cannot parse (e.g. MTP2, Linux cooked capture) are handed to tshark automatically.
    - `quick`: `tshark` decodes only the first part of each large file (`pebc`, 10% by default).
    - `full`: `tshark` decodes every packet (`-T fields -e frame.protocols`). Most accurate, slowest.
- Intelligent Indexing: Scans are incremental; already indexed and unchanged files are skipped.
- Detailed Metadata: Catalogs not just which protocols are present, but also the packet count for every protocol in the file and the total packet count (counted during the scan; `capinfos` is only used in `quick` mode).
- Redis-Powered: All metadata and indexes are stored in Redis for extremely fast lookups.
- Asynchronous & Non-Blocking: Scanning runs in a background thread, so the API remains responsive at all times.
- Fuzzy Search / Autocomplete: Provides an API endpoint to get live suggestions for protocol names as the user types.
- Dockerized: Fully containerized with Docker and Docker Compose for one-command setup and deployment.
- Interactive API Docs: Automatically generates Swagger/OpenAPI documentation for all endpoints.
- Large Capture Support: tshark and fastscan output is counted line by line while it streams, so memory stays flat on multi-GB files (a 1.2 GB capture scans with about 60 MB of Python memory).
- Fast Rescans: unchanged files are recognised by path, size and modification time and skipped without being re-hashed.
- Search Syntax: `sip rtp` (both), `isup|bicc` (either), `sip !rtp` (without), `name:camel` (filename), with per-protocol facets and "did you mean" suggestions.
- Filtered Exports: extract only the packets matching any Wireshark display filter, as a background job with progress; finished extracts are cached.
- Scan Mode from the UI: switch between `fast`, `quick` and `full` without editing files or restarting.
- Automated Tests: 80 unit and integration tests, run against the real `tshark` on every push.

## Requirements

-   Docker
-   Docker Compose

The service, including `tshark`, `capinfos`, and all dependencies, runs inside a Docker container, so you do not need to install anything on your host machine.

## How to Run

1.  **Place PCAPs:** Place your pcap files into the `pcaps` directory. If it doesn't exist, create it:
    ```bash
    mkdir pcaps
    ```

2.  **Configure (Optional):** The service can be configured using a `.env` file in the project root. You can copy the provided example:
    ```bash
    cp .env.example .env
    ```
    You can then edit the `.env` file to change the pcap directories, ports, etc. `PCAP_DIRECTORIES` is the folder on your machine that gets scanned (mounted read-only).

3.  **Build and Run:** From the project root directory, build and run the service with a single command:
    ```bash
    docker compose up --build
    ```
4.  The service is now running (ports from `.env.example`):
    -   Web UI: `http://localhost:5000`
    -   API: `http://localhost:7000`

## API Endpoints

An interactive API documentation (Swagger UI) is available at [http://localhost:7000/docs](http://localhost:7000/docs) after you start the service.

You can also use `curl` for testing.

---

### 1. Scanning and Indexing

*(Note: An initial scan runs automatically on the first startup.)*

-   **Trigger a full re-scan of all directories:**
    ```bash
    curl -X POST http://localhost:7000/reindex
    ```

-   **Check the status of an ongoing scan:**
    ```bash
    curl http://localhost:7000/scan-status | jq
    ```

-   **Backfill total packet counts for already-indexed files:**
    ```bash
    curl -X POST http://localhost:7000/backfill/total-packets
    ```

-   **Check the status of a backfill:**
    ```bash
    curl http://localhost:7000/backfill-status | jq
    ```

    *(Note: backfill is manual-only and does not run on startup.)*

### 2. Searching and Suggestions

-   **Get autocomplete suggestions (fuzzy search):**
    ```bash
    # Example: User types "ht"
    curl "http://localhost:7000/protocols/suggest?q=ht" | jq
    ```

-   **Search for pcaps containing a specific protocol (e.g., 'sip'):**
    ```bash
    curl "http://localhost:7000/search?protocol=sip" | jq
    ```
    
### 3. Downloading a File

-   **To download a file, you must use its SHA256 hash from the search results.**
  
    **Step 1:** Find the hash from the search results (using CLI).
    **Step 2:** Use the hash in the download URL.
    ```bash
    # Example hash found from searching for 'sip'
    FILE_HASH="a1b2c3d4e5f6..." 

    curl -o sip_capture_downloaded.pcap http://localhost:7000/pcaps/download/$FILE_HASH
    ```

### 4. Service Health

-   **Check if the service is running:**
    ```bash
    curl http://localhost:7000/health
    ```

### 5. Backfill search index

Trigger
```
curl -X POST http://localhost:7000/backfill/rebuild-searchindex
```

Status
```
curl http://localhost:7000/backfill/rebuild-searchindex-status
```

### 6. Search Syntax

-   **Combine protocols in one query** (words are separated by spaces or commas):

    | Query | Meaning |
    | --- | --- |
    | `sip rtp` | files containing **both** SIP and RTP |
    | `isup\|bicc` or `isup OR bicc` | files containing **at least one** of them |
    | `sip !rtp` or `sip -rtp` | files with SIP and **without** RTP |
    | `name:camel` | filename contains `camel` (`!name:camel` excludes) |

    A word that is not a known protocol is matched against filenames, so plain filename searches keep working.
    ```bash
    curl -G "http://localhost:7000/search" --data-urlencode "protocol=sip !rtp" | jq
    ```
    The response also contains `query` (how the search was understood), `facets` (protocols in the result with file counts) and `suggestions` (close protocol names when nothing matched).

-   **List every known protocol with its file count:**
    ```bash
    curl http://localhost:7000/protocols | jq
    ```

### 7. Filtered Exports

-   **Extract only the packets that match a Wireshark display filter.** The export runs in the background; the same file and filter are served from the cache next time.
    ```bash
    # check a filter without running it
    curl -G "http://localhost:7000/exports/validate" --data-urlencode 'filter=sip.Method == "INVITE"'

    # start (or reuse) an export
    curl -X POST http://localhost:7000/exports -H "Content-Type: application/json" \
         -d '{"file_hash": "'"$FILE_HASH"'", "filter": "sip || sdp"}'

    # follow its progress, then download when "state" is "ready"
    curl http://localhost:7000/exports/$EXPORT_ID | jq
    curl -OJ http://localhost:7000/exports/$EXPORT_ID/download
    ```

### 8. Scan Mode

-   **Show or change the scan mode** used by the next scan (`fast`, `quick` or `full`). The change is written to `config.yaml`, so it survives a restart; it is refused while a scan is running.
    ```bash
    curl http://localhost:7000/scan-config
    curl -X PUT http://localhost:7000/scan-config -H "Content-Type: application/json" -d '{"scan_mode": "full"}'
    ```
    Switching from `fast` to `full` rescans the files that were catalogued in fast mode.

### 9. Cancel a Scan

-   **Stop the scan that is running:**
    ```bash
    curl -X POST http://localhost:7000/scan-cancel
    ```

## Configuration

Settings added to `backend/config/config.yaml`:

| Key | Default | Meaning |
| --- | --- | --- |
| `pcap.max_parallel_scans` | `4` | Files scanned at the same time |
| `pcap.large_file_size` | `512M` | Files this big or bigger are scanned one at a time |
| `pcap.tshark_session_reset` | `500000` | tshark `-M`: reset dissector state every N packets to bound memory (`0` = never) |
| `export.cache_dir` | `/data/exports` | Where filtered extracts are kept (the `export_cache` volume) |
| `export.cache_max_size` | `5G` | Least recently used extracts are deleted above this |
| `export.max_jobs` | `2` | Filtered exports running at once |

The first three can also be set with the environment variables `MAX_PARALLEL_SCANS`, `LARGE_FILE_SIZE` and `TSHARK_SESSION_RESET`.

## Tests

The tests live in `backend/tests/` and build their own tiny pcap files, so they need no sample captures. Each test runs against a fake Redis and temporary directories; the real catalog, `config.yaml` and pcap directory are never touched.

| File | Covers |
| --- | --- |
| `test_search_query.py` | search syntax parsing |
| `test_scan_logic.py` | rescan rules, streaming protocol counts, skipping unchanged files, hashing |
| `test_config_export.py` | saving the scan mode, export cache keys and eviction, filter validation |
| `test_scan_integration.py` | real scans with tshark and fastscan: incremental rescans, duplicates, moved and broken files, fallback from fastscan to tshark |
| `test_api.py` | search, protocols, scan mode and export endpoints |

-   **Run them inside the backend container** (it already has `tshark` and `fastscan`):
    ```bash
    docker exec backend pip install -r requirements-dev.txt
    docker exec -w /app backend python -m pytest -q
    ```

-   **Or on the host** (needs Python 3.10+, `tshark`; tests that need `fastscan` are skipped if it is not built):
    ```bash
    cd backend
    pip install -r requirements-dev.txt
    python -m pytest -q
    ```

GitHub Actions runs the whole suite on every push (`.github/workflows/tests.yml`).