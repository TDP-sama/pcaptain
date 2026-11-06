# Pcap Catalog Service

[![tests](https://github.com/TDP-sama/pcaptain/actions/workflows/tests.yml/badge.svg)](https://github.com/TDP-sama/pcaptain/actions/workflows/tests.yml)

A high-performance, asynchronous web service that scans directories of pcap files, catalogs them in Redis based on detailed protocol analysis, and provides a powerful REST API to search, download, and get autocomplete suggestions for protocols.

This project uses `tshark` (and a small C++ pre-scanner, `fastscan`) to find the protocols in each capture, and Redis for high-speed indexing and searching. It's designed for efficiency and ease of use, packaged with Docker for simple deployment.

## Features

- Three Scan Modes:
    - `fast` (default): `fastscan` reads packet headers and infers application protocols from port numbers. Very fast, but it can miss protocols on non-standard ports or inside SCTP. Captures it cannot parse (e.g. MTP2, Linux cooked capture) are handed to tshark automatically.
    - `quick`: `tshark` decodes only the first part (`pebc`, 10% by default) of each file at least `QUICK_SCAN_MIN_FILE_SIZE` big (1 KB by default); smaller files get a full decode.
    - `full`: `tshark` decodes every packet (`-T fields -e frame.protocols`). Most accurate, slowest.
- Intelligent Indexing: Scans are incremental; already indexed and unchanged files are skipped.
- Detailed Metadata: Catalogs not just which protocols are present, but also the packet count for every protocol in the file and the total packet count (counted during the scan; `capinfos` is only used in `quick` mode and by the manual total-packets backfill).
- Redis-Powered: All metadata and indexes are stored in Redis for extremely fast lookups.
- Asynchronous & Non-Blocking: Scanning runs in a background thread, so the API remains responsive at all times.
- Fuzzy Search / Autocomplete: Provides an API endpoint to get live suggestions for protocol names as the user types.
- Dockerized: Fully containerized with Docker and Docker Compose for one-command setup and deployment.
- Interactive API Docs: Automatically generates Swagger/OpenAPI documentation for all endpoints.
- Large Capture Support: tshark and fastscan output is counted line by line while it streams, so memory stays flat on multi-GB files (a 1.2 GB capture scans with about 60 MB of Python memory).
- Fast Rescans: unchanged files are recognised by path, size and modification time and skipped without being re-hashed.
- Catalog Matches the Disk: a rescan drops protocols a file no longer has, replaces the entry of a file whose content changed, and removes files that were deleted. A file still being written during its scan is left for the next scan.
- Scan Progress: `/scan-status` and the Scan button show how many files are done and which ones are being read.
- Works Offline: the UI ships its own copies of its JavaScript libraries and icon font, so it needs no internet access.
- Search Syntax: `sip rtp` (both), `isup|bicc` (either), `sip !rtp` (without), `name:camel` (filename), with per-protocol facets and "did you mean" suggestions.
- Filtered Exports: extract only the packets matching any Wireshark display filter, as a background job with progress; finished extracts are cached.
- Scan Mode from the UI: switch between `fast`, `quick` and `full` without editing files or restarting.
- Automated Tests: 116 unit and integration tests, run against the real `tshark` on every push.

## Requirements

-   Docker
-   Docker Compose

The service, including `tshark`, `capinfos`, and all dependencies, runs inside a Docker container, so you do not need to install anything on your host machine.

## How to Run

1.  **Place PCAPs:** Place your pcap files into the `pcaps` directory. If it doesn't exist, create it:
    ```bash
    mkdir pcaps
    ```
    The folder must exist (or `PCAP_DIRECTORIES` must point at one that does): `docker compose up` stops with "bind source path does not exist" rather than starting with an empty catalog.

2.  **Configure (Optional):** The service can be configured using a `.env` file in the project root. You can copy the provided example:
    ```bash
    cp .env.example .env
    ```
    You can then edit the `.env` file to change the pcap directories, ports, etc. `PCAP_DIRECTORIES` is the folder on your machine that gets scanned (mounted read-only). `.env` configures every service, the backend included; every value has a default, so this step is optional.

3.  **Build and Run:** From the project root directory, build and run the service with a single command:
    ```bash
    docker compose up --build
    ```
4.  The service is now running (ports from `.env.example`):
    -   Web UI: `http://localhost:5000`. The UI reaches the API through the same address (`/api/`), so this is the only port users need.
    -   API (optional, for scripts): `http://localhost:7000`, or `http://<host>:5000/api/` from other machines. Port 7000 only listens on the machine itself by default, because the API has no authentication; set `BE_BIND_ADDRESS=0.0.0.0` to publish it.

    If you reuse a `.env` from an older version, check `BE_PUBLIC_URL`: it used to be `http://localhost:7000`, which makes browsers on other machines call their own localhost. Leave it empty.

### Running on Another Machine

The images contain everything they need: nothing but the pcap folder is mounted, and no config file is required on the target machine.

1.  **Build and push** (set `IMAGE_PREFIX` in `.env` to your registry, e.g. `registry.example.com/team/pcaptain`):
    ```bash
    docker compose build
    docker compose push
    ```
2.  **On the target machine**, copy only `docker-compose.yml` and `.env`, set `PCAP_DIRECTORIES` to the pcap folder there, then:
    ```bash
    docker compose pull
    docker compose up -d --no-build
    ```
3.  Open `http://<that machine>:5000`. The browser only talks to that address; the frontend forwards `/api/` to the backend over the compose network.

The catalog lives in the `<project>_redis_data` volume, where `<project>` is the folder name by default. A folder name already used by an earlier deployment therefore reuses that deployment's catalog. To start from an empty catalog, use another project name (`docker compose -p pcaptain-test up -d`) or remove the old volumes with `docker compose down -v`.

On startup the backend waits for Redis to finish loading its data (up to `REDIS_WAIT_SECONDS`). Meanwhile `/health` reports `"redis": "loading"` and catalog requests answer `503`, and the service recovers on its own once Redis is ready.

## API Endpoints

An interactive API documentation (Swagger UI) is available at [http://localhost:7000/docs](http://localhost:7000/docs) after you start the service, and through the web UI at `http://<host>:5000/api/docs`.

You can also use `curl` for testing.

---

### 1. Scanning and Indexing

*(Note: An initial scan runs automatically on the first startup.)*

-   **Rescan all directories** (incremental: unchanged files are skipped, changed and new ones are scanned, deleted ones leave the catalog). Answers `409` while a scan runs and `503` while Redis is unavailable:
    ```bash
    curl -X POST http://localhost:7000/reindex
    ```

-   **Check the status of an ongoing scan** (`total_files`, `processed_files` and `current_files` show its progress):
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

-   **Show or change the scan mode** used by the next scan (`fast`, `quick` or `full`). The change is stored with the catalog in Redis, so it survives a restart and takes precedence over `SCAN_MODE`; it is refused while a scan is running. To go back to the `.env` value, pick it in the UI or run `docker compose exec redis redis-cli HDEL pcap:settings scan_mode` and restart the backend.
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

Everything is set in `.env` (start from `.env.example`). The backend reads the same variables; its `backend/config/config.yaml` only holds the built-in defaults inside the image and does not need to be edited or mounted.

| Variable | Default | Meaning |
| --- | --- | --- |
| `PCAP_DIRECTORIES` | `./pcaps` | Folder on the host to catalog (mounted read-only); must exist |
| `FRONTEND_PORT` | `5000` | Web UI; the only port users need |
| `BE_BASE_PORT` | `7000` | REST API on the host, for scripts (optional) |
| `BE_BIND_ADDRESS` | `127.0.0.1` | Interface `BE_BASE_PORT` listens on; `0.0.0.0` publishes the API to the network (it has no authentication) |
| `BE_INTERNAL_PORT`, `REDIS_INTERNAL_PORT` | `7000`, `6379` | Ports inside the compose network; change only if they clash |
| `IMAGE_PREFIX`, `IMAGE_TAG` | `pcaptain`, `latest` | Image names used by `docker compose build` / `push` |
| `SCAN_MODE` | `fast` | `fast`, `quick` or `full`; a change made in the UI takes precedence |
| `PCAP_SCAN_INTERVAL_SECONDS` | `3600` | Automatic rescan interval |
| `MAX_PARALLEL_SCANS` | `4` | Files scanned at the same time |
| `LARGE_FILE_SIZE` | `512M` | Files this big or bigger count as large |
| `LARGE_FILE_PARALLEL_SCANS` | `1` | Large files scanned at the same time (about 7 MB each in fast mode, 0.5 GB in full mode) |
| `QUICK_SCAN_PEBC`, `QUICK_SCAN_MIN_FILE_SIZE`, `QUICK_SCAN_CONFIG_VERSION` | `0.1`, `1024`, `v1` | quick mode: share of each file decoded, smallest file sampled (smaller ones get a full decode), and a version to bump to force quick rescans |
| `TSHARK_SESSION_RESET` | `500000` | tshark `-M`: reset dissector state every N packets to bound memory (`0` = never) |
| `EXPORT_CACHE_MAX_SIZE` | `5G` | Least recently used extracts are deleted above this |
| `EXPORT_MAX_JOBS` | `2` | Filtered exports running at once |
| `BACKEND_MEMORY_LIMIT` | `4g` | Memory cap for the backend container |
| `LOG_LEVEL` | `INFO` | Backend log level |
| `REDIS_WAIT_SECONDS` | `120` | How long startup waits for Redis to finish loading |
| `BE_PUBLIC_URL` | empty | Only if the UI must call a backend on another host (default: `/api/` on its own host) |
| `PUBLIC_URL` | empty | Put in front of the download links the API returns; empty gives relative links, which is right for the web UI |

Sizes accept bytes or a `K`/`M`/`G`/`T` suffix and are checked at startup: an invalid value stops the backend with an error naming the setting.

## Tests

The tests live in `backend/tests/` and build their own tiny pcap files, so they need no sample captures. Each test runs against a fake Redis and temporary directories; the real catalog, `config.yaml` and pcap directory are never touched.

| File | Covers |
| --- | --- |
| `test_search_query.py` | search syntax parsing |
| `test_scan_logic.py` | rescan rules, streaming protocol counts, skipping unchanged files, hashing |
| `test_config_export.py` | configuration from environment variables (incl. a config path Docker turned into a directory), the UI scan mode kept in Redis, export cache keys and eviction, filter validation |
| `test_redis_startup.py` | waiting for Redis while it loads its dataset, instead of failing at startup |
| `test_catalog_consistency.py` | the catalog follows the disk: stale protocols, changed, deleted, vanishing and growing files, cancelled and concurrent scans, the one-time index repair |
| `test_scan_integration.py` | real scans with tshark and fastscan: incremental rescans, duplicates, moved and broken files, fallback from fastscan to tshark |
| `test_api.py` | search, protocols, scan mode, download and export endpoints |

-   **Run them inside the backend container** (it already has `tshark` and `fastscan`):
    ```bash
    docker compose exec backend pip install -r requirements-dev.txt
    docker compose exec -w /app backend python -m pytest -q
    ```

-   **Or on the host** (needs Python 3.10+, `tshark`; tests that need `fastscan` are skipped if it is not built):
    ```bash
    cd backend
    pip install -r requirements-dev.txt
    python -m pytest -q
    ```

GitHub Actions runs the whole suite on every push (`.github/workflows/tests.yml`).