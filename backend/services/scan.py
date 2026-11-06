from collections import Counter, deque
import contextlib
from enum import Enum
from itertools import islice
import json
import os
import re
from typing import Any, Dict, Optional, List, Tuple, Set
from threading import Event
import hashlib
import asyncio
import subprocess
import time
import threading

from redis import Redis

from .logger import get_logger
from .context import AppContext, get_app_context, with_app_context
from .config import ScanMode, parse_size_bytes  # parse_size_bytes re-exported for callers

logger = get_logger(__name__)


AUTOCOMPLETE_KEY = "pcap:protocols:autocomplete"
# Index keys
PCAP_FILE_KEY_PREFIX = "pcap:file"
PROTOCOCOL_INDEX_PREFIX = "pcap:index:protocol"
# path -> sha256, so an unchanged file can be skipped without re-hashing it
PATH_MAP_KEY = "pcap:pathmap"

SORT_INDEX_PREFIX = "pcap:sort"

SORT_INDEX_FILENAME = f"{SORT_INDEX_PREFIX}:filename"
SORT_INDEX_PATH = f"{SORT_INDEX_PREFIX}:path"
SORT_INDEX_SIZE = f"{SORT_INDEX_PREFIX}:size_bytes"
SORT_INDEX_PACKET_COUNT = f"{SORT_INDEX_PREFIX}:protocol_packet_count"

LEX_INDEX_FILENAME = "pcap:lex:filename"
LEX_INDEX_PATH = "pcap:lex:path"

REBUILD_LOCK = "pcap:lex:rebuild:lock"
REBUILD_DIRTY = "pcap:lex:dirty"

# Temporary keys
TMP_RESULT_PREFIX = "pcap:tmp:search"
TMP_KEY_TTL_SECONDS = 5

# Full mode only needs to know which protocols appear, not reassembled
# payloads, so turn off the per-flow bookkeeping that grows tshark's memory.
TSHARK_LEAN_PREFS = (
    "tcp.desegment_tcp_streams:FALSE",
    "tcp.analyze_sequence_numbers:FALSE",
    "tcp.calculate_timestamps:FALSE",
    "ip.defragment:FALSE",
    "ipv6.defragment:FALSE",
)

# How many output lines the streaming reader counts per batch; it checks for a
# cancel request between batches.
CANCEL_CHECK_EVERY_LINES = 50_000

# Bumped when the layout of the protocol index changes; startup rebuilds the
# index once when the stored version is older (see ensure_index_version).
INDEX_VERSION = "2"
INDEX_VERSION_FIELD = "index_version"
SETTINGS_KEY = "pcap:settings"
DASHBOARD_SUMMARY_KEY = "dashboard:summary"
SORT_INDEXES = (SORT_INDEX_SIZE, SORT_INDEX_PACKET_COUNT, SORT_INDEX_FILENAME, SORT_INDEX_PATH)


def _protocol_key(protocol: str) -> str:
    return f"{PROTOCOCOL_INDEX_PREFIX}:{protocol.lower()}"


def _split_protocols(value: Optional[str]) -> List[str]:
    return [p for p in (value or "").split(",") if p]


def remove_catalog_entry(redis_client, file_hash: str, stored: Optional[Dict[str, str]] = None) -> List[str]:
    """Delete one file from the catalog: its hash, its protocol index
    memberships and its sort scores. Returns the protocols it had."""
    pcap_key = f"{PCAP_FILE_KEY_PREFIX}:{file_hash}"
    if stored is None:
        stored = redis_client.hgetall(pcap_key)
    protocols = _split_protocols(stored.get("protocols"))
    pipe = redis_client.pipeline()
    for proto in protocols:
        pipe.srem(_protocol_key(proto), file_hash)
    for index in SORT_INDEXES:
        pipe.zrem(index, file_hash)
    pipe.delete(pcap_key)
    pipe.execute()
    path = stored.get("path")
    # only if the path still points at this entry
    if path and redis_client.hget(PATH_MAP_KEY, path) == file_hash:
        redis_client.hdel(PATH_MAP_KEY, path)
    return protocols


def drop_unused_protocols(redis_client, protocols) -> None:
    """Remove protocols that no file has any more from autocomplete."""
    protocols = sorted(set(protocols))
    if not protocols:
        return
    pipe = redis_client.pipeline()
    for proto in protocols:
        pipe.exists(_protocol_key(proto))
    gone = [p for p, exists in zip(protocols, pipe.execute()) if not exists]
    if gone:
        redis_client.zrem(AUTOCOMPLETE_KEY, *gone)


def rebuild_protocol_index_sync(redis_client) -> int:
    """Rebuild every protocol set and the autocomplete list from the file
    entries themselves. Repairs catalogs indexed before re-indexing removed
    old memberships (a file rescanned in full mode kept the protocols fast
    mode had guessed, so searches returned files without the protocol)."""
    members: Dict[str, Set[str]] = {}
    names: Set[str] = set()
    files = 0
    keys = list(redis_client.scan_iter(f"{PCAP_FILE_KEY_PREFIX}:*", count=1000))
    for start in range(0, len(keys), 1000):
        batch = keys[start:start + 1000]
        pipe = redis_client.pipeline(transaction=False)
        for key in batch:
            pipe.hget(key, "protocols")
        for key, value in zip(batch, pipe.execute()):
            file_hash = key.rsplit(":", 1)[-1]
            files += 1
            for proto in _split_protocols(value):
                names.add(proto)
                members.setdefault(proto.lower(), set()).add(file_hash)

    old_keys = list(redis_client.scan_iter(f"{PROTOCOCOL_INDEX_PREFIX}:*", count=1000))
    pipe = redis_client.pipeline()  # MULTI: searches never see a half-built index
    if old_keys:
        pipe.delete(*old_keys)
    for proto, hashes in members.items():
        pipe.sadd(_protocol_key(proto), *hashes)
    pipe.delete(AUTOCOMPLETE_KEY)
    if names:
        pipe.zadd(AUTOCOMPLETE_KEY, {p: 0 for p in names})
    pipe.hset(SETTINGS_KEY, INDEX_VERSION_FIELD, INDEX_VERSION)
    pipe.execute()
    logger.info("Rebuilt the protocol index from %d files (%d protocols)", files, len(members))
    return files


def ensure_index_version(redis_client) -> None:
    if redis_client.hget(SETTINGS_KEY, INDEX_VERSION_FIELD) != INDEX_VERSION:
        rebuild_protocol_index_sync(redis_client)


def _file_size_or_none(path: str) -> Optional[int]:
    try:
        return os.path.getsize(path)
    except OSError:  # deleted since it was listed, or a dangling symlink
        return None


def get_effective_scan_mode(
    file_size_bytes: int,
    base_scan_mode: ScanMode,
    *,
    quick_scan_pebc: float,
    quick_scan_min_file_size_bytes: int,
    quick_scan_config_version: str,
) -> Tuple[ScanMode, Optional[float], str]:
    """Compute per-file scan mode.

    - base_scan_mode == 'fast'  -> always 'fast' (fastscan binary)
    - base_scan_mode == 'quick' -> always 'quick' if file size >= min_file_size
    - base_scan_mode == 'full'
    """
    if base_scan_mode == ScanMode.FAST:
        return ScanMode.FAST, None, quick_scan_config_version

    if base_scan_mode == ScanMode.QUICK and file_size_bytes >= quick_scan_min_file_size_bytes:
        return ScanMode.QUICK, quick_scan_pebc, quick_scan_config_version

    return ScanMode.FULL, None, quick_scan_config_version


def _normalize_scan_param(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    stripped = str(value).strip()
    return stripped if stripped else None


def _parse_float(value: Optional[str]) -> Optional[float]:
    normalized = _normalize_scan_param(value)
    if normalized is None:
        return None
    try:
        return float(normalized)
    except ValueError:
        return None


def _parse_int(value: Any) -> Optional[int]:
    normalized = _normalize_scan_param(value)
    if normalized is None:
        return None
    try:
        return int(normalized)
    except ValueError:
        try:
            return int(float(normalized))
        except ValueError:
            return None


def should_rescan_file(
    *,
    current_scan_mode: str,
    current_pebc: Optional[float],
    current_config_version: str,
    stored_scan_mode: Optional[str],
    stored_pebc: Optional[float],
    stored_config_version: Optional[str],
) -> bool:
    """Decide whether a file requires a rescan based on scan parameters."""
    stored_scan_mode = _normalize_scan_param(stored_scan_mode)
    stored_config_version = _normalize_scan_param(stored_config_version)

    if stored_scan_mode is None:
        return True

    # upgrading from partial sampling -> full-file modes
    if stored_scan_mode == "quick" and current_scan_mode in {ScanMode.FULL.value, ScanMode.FAST.value}:
        return True

    # switching from the port-guessing fast mode to a real tshark decode
    if stored_scan_mode == ScanMode.FAST.value and current_scan_mode == ScanMode.FULL.value:
        return True

    # quick scan parameter changes
    if current_scan_mode == "quick" and stored_scan_mode == "quick":
        if (
            current_pebc is not None
            and stored_pebc is not None
            and current_pebc > stored_pebc
        ):
            return True
        if current_config_version != stored_config_version:
            return True

    return False


# 1 MiB reads: with 4 KiB reads the Python loop, not SHA256, was the limit
# (265 vs 538 MB/s measured on a 1.2 GB capture inside the container).
HASH_CHUNK_BYTES = 1 << 20


def calculate_sha256_sync(file_path: str) -> str:
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(HASH_CHUNK_BYTES), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


async def calculate_sha256(file_path: str) -> str:
    return await asyncio.to_thread(calculate_sha256_sync, file_path)


def calculate_protocol_percentages(protocol_counts: Dict[str, int], packets_scanned: int) -> Dict[str, float]:
    """Calculate protocol presence percentage relative to scanned packets."""
    if not protocol_counts:
        return {}

    if packets_scanned <= 0:
        return {k: 0.0 for k in protocol_counts}

    return {
        proto: round((count / packets_scanned) * 100, 2)
        for proto, count in protocol_counts.items()
    }


def check_cancellation(cancel_event: Optional[Event]):
    """Check if cancellation has been requested and raise CancelledError if so."""
    if cancel_event and cancel_event.is_set():
        logger.info("Scan cancelled by user")
        raise asyncio.CancelledError("Scan cancelled by user")


async def get_all_protocols(redis: Redis):
    # ZSET → list[str]
    return await asyncio.to_thread(redis.zrange, AUTOCOMPLETE_KEY, 0, -1)


def get_total_packets_from_pcap_sync(pcap_file: str) -> Optional[int]:
    command = ["capinfos", "-M", "-c", pcap_file]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        if result.returncode != 0:
            logger.error(
                "capinfos exited with error for %s: %s",
                pcap_file,
                result.stderr.strip(),
            )
            return None

        match = re.search(
            r"(?:Number of packets|Packets)\s*[:=]\s*(\d+)",
            result.stdout,
        )
        if not match:
            logger.error(
                "Could not parse packet count from capinfos output for %s",
                pcap_file,
            )
            return None

        return int(match.group(1))

    except FileNotFoundError:
        logger.error("capinfos not found — please install it.")
        return None
    except Exception as e:
        logger.error("Unexpected error while running capinfos on %s: %s", pcap_file, e)
        return None


async def get_total_packets_from_pcap(pcap_file: str) -> Optional[int]:
    return await asyncio.to_thread(get_total_packets_from_pcap_sync, pcap_file)


class ScanState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class BackfillState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class RebuildSearchIndexState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanService:
    scan_status: Dict[str, Any] = {
        "state": ScanState.IDLE,
        "indexed_files": 0,
        "message": "Ready",
        # progress of the running scan
        "total_files": 0,
        "processed_files": 0,
        "current_files": [],
        "removed_files": 0,
        "started_at": None,
    }
    _start_lock = threading.Lock()

    backfill_status: Dict[str, Any] = {
        "state": BackfillState.IDLE,
        "processed": 0,
        "updated": 0,
        "total": 0,
        "message": "Ready",
    }

    rebuild_searchindex_status: Dict[str, Any] = {
        "state": RebuildSearchIndexState.IDLE,
        "processed": 0,
        "backfilled": 0,
        "total": 0,
        "message": "Ready",
    }

    scan_cancel_event = Event()
    scan_process: Dict[str, Optional[subprocess.Popen]] = {"tshark": None}

    def try_begin_scan(self) -> bool:
        """Mark a scan as running unless one already is. Callers that get True
        must then run scan_wrapper. Checking and setting under one lock stops
        two requests (or a request and the scheduler) from both starting one."""
        with self._start_lock:
            if self.scan_status["state"] == ScanState.RUNNING:
                return False
            self.scan_status.update(
                state=ScanState.RUNNING, indexed_files=0, message="Starting scan...",
                total_files=0, processed_files=0, current_files=[], removed_files=0,
                started_at=time.time(),
            )
            # A cancel request belongs to the scan it was made for; without this
            # every later scan (including the scheduled ones) stopped at once.
            self.scan_cancel_event.clear()
            return True

    def status_snapshot(self) -> Dict[str, Any]:
        snapshot = dict(self.scan_status)
        snapshot["current_files"] = list(snapshot.get("current_files") or [])
        snapshot["state"] = ScanState(snapshot["state"]).value
        return snapshot

    async def should_process_file(
        self,
        *,
        redis_client,
        pcap_key: str,
        file_path: str,
        current_scan_mode: ScanMode,
        current_pebc: Optional[float],
        current_config_version: str,
    ) -> bool:
        """Return True if we should scan/index the file now.

        This collapses the nested "exists/path/moved/duplicate/rescan" logic into one place.
        """
        if not await asyncio.to_thread(redis_client.exists, pcap_key):
            return True

        stored = await asyncio.to_thread(redis_client.hgetall, pcap_key)
        stored_path = stored.get("path")

        if stored_path == file_path:
            stored_scan_mode = stored.get("scan_mode")
            stored_pebc = _parse_float(stored.get("pebc"))
            stored_config_version = stored.get("config_version")

            if should_rescan_file(
                current_scan_mode=current_scan_mode.value,
                current_pebc=current_pebc,
                current_config_version=current_config_version,
                stored_scan_mode=stored_scan_mode,
                stored_pebc=stored_pebc,
                stored_config_version=stored_config_version,
            ):
                logger.info(
                    "Rescanning %s due to scan param change (stored_mode=%s current_mode=%s)",
                    file_path,
                    stored_scan_mode,
                    current_scan_mode,
                )
                return True

            # Same content at the same path (e.g. only touched, or indexed before
            # the path map existed): refresh size/mtime and remember the path so
            # the next scan can skip it without hashing.
            pipe = redis_client.pipeline()
            pipe.hset(
                pcap_key,
                mapping={
                    "last_scanned": time.time(),
                    "size_bytes": await asyncio.to_thread(os.path.getsize, file_path),
                    "last_modified": await asyncio.to_thread(os.path.getmtime, file_path),
                },
            )
            pipe.hset(PATH_MAP_KEY, file_path, pcap_key.rsplit(":", 1)[-1])
            await asyncio.to_thread(pipe.execute)
            logger.info("Skipping %s (already indexed and unchanged)", file_path)
            return False

        if stored_path and await asyncio.to_thread(os.path.exists, stored_path):
            logger.info(
                "Duplicate file detected at %s (hash exists at %s)",
                stored_path,
                file_path,
            )
            return False

        # stored_path missing or points to a file that no longer exists -> consider it moved
        logger.info("File moved. Updating Redis path for %s", file_path)
        stat = await asyncio.to_thread(os.stat, file_path)
        filename = os.path.basename(file_path)
        pipe = redis_client.pipeline()
        pipe.hset(
            pcap_key,
            mapping={
                "path": file_path,
                "path_sort": file_path.lower(),
                # a move can also rename the file: search and sorting use these
                "filename": filename,
                "filename_sort": filename.lower(),
                "source_directory": os.path.dirname(file_path),
                "size_bytes": stat.st_size,
                "last_modified": stat.st_mtime,
                "last_scanned": time.time(),
            },
        )
        pipe.zadd(LEX_INDEX_FILENAME, {filename.lower(): 0}, nx=True)
        pipe.zadd(LEX_INDEX_PATH, {file_path.lower(): 0}, nx=True)
        if stored_path:
            pipe.hdel(PATH_MAP_KEY, stored_path)
        pipe.hset(PATH_MAP_KEY, file_path, pcap_key.rsplit(":", 1)[-1])
        pipe.set(REBUILD_DIRTY, 1)
        await asyncio.to_thread(pipe.execute)
        return False

    async def is_unchanged_since_index(
        self,
        *,
        redis_client,
        file_path: str,
        file_size: int,
        mtime: float,
        current_scan_mode: ScanMode,
        current_pebc: Optional[float],
        current_config_version: str,
    ) -> bool:
        """Cheap pre-check that avoids reading the whole file to hash it.

        True when this path was indexed before with the same size and mtime and
        the scan settings do not ask for a rescan.
        """
        known_hash = await asyncio.to_thread(redis_client.hget, PATH_MAP_KEY, file_path)
        if not known_hash:
            return False

        pcap_key = f"{PCAP_FILE_KEY_PREFIX}:{known_hash}"
        stored = await asyncio.to_thread(redis_client.hgetall, pcap_key)
        if not stored or stored.get("path") != file_path:
            return False
        if _parse_int(stored.get("size_bytes")) != file_size:
            return False
        if _parse_float(stored.get("last_modified")) != mtime:
            return False
        if should_rescan_file(
            current_scan_mode=current_scan_mode.value,
            current_pebc=current_pebc,
            current_config_version=current_config_version,
            stored_scan_mode=stored.get("scan_mode"),
            stored_pebc=_parse_float(stored.get("pebc")),
            stored_config_version=stored.get("config_version"),
        ):
            return False

        await asyncio.to_thread(redis_client.hset, pcap_key, "last_scanned", time.time())
        return True

    # Collect the list of files to scan
    async def collect_files(
        self,
        root_directory: str,
        exclude_files: List[str],
        allowed_extensions: tuple,
        target_folder: Optional[str],
    ) -> Tuple[List[str], bool]:
        extensions = tuple(e.lower() for e in allowed_extensions)

        def walk() -> Tuple[List[str], bool]:
            # The whole walk runs in a worker thread: iterating os.walk on the
            # event loop blocked the API for as long as the directory tree took.
            collected: List[str] = []
            found_matching_folder = False
            for root, dirs, files in os.walk(root_directory):
                check_cancellation(self.scan_cancel_event)

                if target_folder:
                    if os.path.basename(root) != target_folder:
                        continue
                    found_matching_folder = True

                for filename in files:
                    # .PCAP and .pcap alike
                    if filename in exclude_files or not filename.lower().endswith(extensions):
                        continue
                    collected.append(os.path.join(root, filename))
            return collected, found_matching_folder

        return await asyncio.to_thread(walk)

    # Process a single file
    async def process_one_file(
        self,
        file_path: str,
        *,
        semaphore: asyncio.Semaphore,
        large_semaphore: asyncio.Semaphore,
        large_file_bytes: int,
        **kwargs,
    ) -> None:
        file_size = await asyncio.to_thread(_file_size_or_none, file_path)
        if file_size is None:
            logger.warning("Skipping %s: it disappeared before it could be scanned", file_path)
            self.scan_status["processed_files"] += 1
            return
        # Large captures share a small number of slots (LARGE_FILE_PARALLEL_SCANS).
        # They queue for that slot before taking a general one, so waiting
        # large files never hold up small ones.
        large_gate = large_semaphore if file_size >= large_file_bytes else contextlib.nullcontext()
        async with large_gate:
            async with semaphore:
                current = self.scan_status["current_files"]
                current.append(file_path)
                try:
                    await self._process_one_file(file_path, **kwargs)
                finally:
                    with contextlib.suppress(ValueError):
                        current.remove(file_path)
                    self.scan_status["processed_files"] += 1

    async def _process_one_file(
        self,
        file_path: str,
        *,
        seen_hashes: Set[str],
        seen_hashes_lock: asyncio.Lock,
        counter_lock: asyncio.Lock,
        files_indexed_container: List[int],
        redis_client,
        config,
        context: AppContext,
    ) -> None:
        # Scan and index a single pcap file
        check_cancellation(self.scan_cancel_event)

        filename = os.path.basename(file_path)

        stat = await asyncio.to_thread(os.stat, file_path)
        file_size, mtime = stat.st_size, stat.st_mtime

        # Determine scan mode
        base_scan_mode = config.pcap.scan_mode

        qs = config.pcap.quick_scan
        quick_min_size_bytes = parse_size_bytes(qs.min_file_size, default=0)

        current_scan_mode, current_pebc, current_config_version = get_effective_scan_mode(
            file_size,
            base_scan_mode,
            quick_scan_pebc=qs.pebc,
            quick_scan_min_file_size_bytes=quick_min_size_bytes,
            quick_scan_config_version=qs.config_version,
        )

        # Skip unchanged files before hashing: hashing reads the whole file.
        if await self.is_unchanged_since_index(
            redis_client=redis_client,
            file_path=file_path,
            file_size=file_size,
            mtime=mtime,
            current_scan_mode=current_scan_mode,
            current_pebc=current_pebc,
            current_config_version=current_config_version,
        ):
            logger.info("Skipping %s (same size and mtime as indexed)", file_path)
            return

        file_hash = await calculate_sha256(file_path)

        # The content at this path changed (new hash): the entry for the old
        # content describes a file that no longer exists, and used to stay in
        # the catalog next to the new one.
        previous_hash = await asyncio.to_thread(redis_client.hget, PATH_MAP_KEY, file_path)
        if previous_hash and previous_hash != file_hash:
            previous = await asyncio.to_thread(
                redis_client.hgetall, f"{PCAP_FILE_KEY_PREFIX}:{previous_hash}"
            )
            if previous.get("path") == file_path:
                logger.info("%s changed since it was indexed; removing the old entry", file_path)
                old_protocols = await asyncio.to_thread(
                    remove_catalog_entry, redis_client, previous_hash, previous
                )
                await asyncio.to_thread(drop_unused_protocols, redis_client, old_protocols)
            else:
                await asyncio.to_thread(redis_client.hdel, PATH_MAP_KEY, file_path)

        async with seen_hashes_lock:
            if file_hash in seen_hashes:
                logger.info(
                    f"Skipping {file_path} (duplicate hash already processed in this scan)"
                )
                return
            seen_hashes.add(file_hash)

        pcap_key = f"{PCAP_FILE_KEY_PREFIX}:{file_hash}"

        should_scan_now = await self.should_process_file(
            redis_client=redis_client,
            pcap_key=pcap_key,
            file_path=file_path,
            current_scan_mode=current_scan_mode,
            current_pebc=current_pebc,
            current_config_version=current_config_version,
        )

        if not should_scan_now:
            return

        quick_threshold_bytes: Optional[int] = None
        if current_scan_mode == ScanMode.QUICK and current_pebc is not None:
            quick_threshold_bytes = int(file_size * current_pebc)

        logger.info("Processing file: %s (scan_mode: %s)", file_path, current_scan_mode.value)

        # Call fastscan
        check_cancellation(self.scan_cancel_event)
        protocol_result = await self.get_protocols_from_pcap(
            file_path,
            excluded_protocols=None,
            scan_mode=current_scan_mode,
            quick_threshold_bytes=quick_threshold_bytes,
        )

        if protocol_result is None:
            logger.warning(f"Skipping file {filename} from index due to processing error.")
            return

        protocol_data, packets_scanned = protocol_result

        if current_scan_mode == ScanMode.FAST and set(protocol_data) <= {"eth"}:
            # fastscan only understands Ethernet/IP and raw IP. For anything
            # else (MTP2, Linux cooked, PPPoE, VLAN, ...) it finds nothing past
            # the link layer, so let tshark decode the file instead.
            logger.info("fastscan found nothing past the link layer in %s; falling back to tshark", file_path)
            current_scan_mode = ScanMode.FULL
            protocol_result = await self.get_protocols_from_pcap(
                file_path, excluded_protocols=None, scan_mode=ScanMode.FULL
            )
            if protocol_result is None:
                logger.warning(f"Skipping file {filename} from index due to processing error.")
                return
            protocol_data, packets_scanned = protocol_result

        if not protocol_data:
            logger.warning(f"No protocols found in {filename}. Skipping from index.")
            return

        # Compute metadata
        protocol_percentages = calculate_protocol_percentages(protocol_data, packets_scanned)

        # A file still being written (e.g. a running capture) changes while it
        # is scanned. The protocols read describe neither the old nor the new
        # content, so do not store them: leave the file for the next scan.
        # (Storing them with the new size and mtime meant it was never rescanned.)
        try:
            stat_after = await asyncio.to_thread(os.stat, file_path)
        except OSError:
            logger.warning("%s disappeared while it was scanned; not indexing it", file_path)
            return
        if (stat_after.st_size, stat_after.st_mtime) != (file_size, mtime):
            logger.warning("%s changed while it was scanned; it will be scanned again next time", file_path)
            return

        protocols = sorted(list(protocol_data.keys()))
        download_url = f"{context.config.public_url}/pcaps/download/{file_hash}"

        if current_scan_mode == ScanMode.QUICK:
            # A quick scan stops early, so count the whole file separately.
            total_packets = await get_total_packets_from_pcap(file_path)
            if total_packets is None:
                logger.warning(f"capinfos failed for {file_path}; continuing without total_packets")
                total_packets = 0
        else:
            # fast and full modes emit one line per packet: the scan already
            # counted every packet, no need to read the file again.
            total_packets = packets_scanned

        filename_norm = filename.lower()
        path_norm = file_path.lower()
        current_time = time.time()

        # Protocols an earlier scan of this content found but this one did not
        # (typically: guessed from ports in fast mode, absent in a full decode).
        old_protocols = _split_protocols(
            await asyncio.to_thread(redis_client.hget, pcap_key, "protocols")
        )
        stale_protocols = sorted(set(old_protocols) - set(protocols))

        # Write to Redis
        pipe = redis_client.pipeline()
        for proto in stale_protocols:
            pipe.srem(_protocol_key(proto), file_hash)

        pipe.hset(
            pcap_key,
            mapping={
                "filename": filename,
                "filename_sort": filename_norm,
                "source_directory": os.path.dirname(file_path),
                "path": file_path,
                "path_sort": path_norm,
                "size_bytes": file_size,
                "download_url": download_url,
                "protocols": ",".join(protocols),
                "total_packets": total_packets,
                "protocol_counts": json.dumps(protocol_data),
                "protocol_percentages": json.dumps(protocol_percentages),
                "packets_scanned": packets_scanned,
                "last_modified": mtime,
                "last_scanned": current_time,
                "scan_mode": current_scan_mode.value,
                "pebc": "" if current_pebc is None else current_pebc,
                "config_version": current_config_version,
            }
        )
        pipe.hset(PATH_MAP_KEY, file_path, file_hash)

        autocomplete_payload = {proto: 0 for proto in protocols}

        if autocomplete_payload:
            pipe.zadd(AUTOCOMPLETE_KEY, autocomplete_payload)

        for proto in protocols:
            pipe.sadd(_protocol_key(proto), file_hash)

        # Lexicographical indexes
        pipe.zadd(LEX_INDEX_FILENAME, {filename_norm: 0}, nx=True)
        pipe.zadd(LEX_INDEX_PATH, {path_norm: 0}, nx=True)

        # Sort indexes
        pipe.zadd(SORT_INDEX_SIZE, {file_hash: file_size})
        pipe.zadd(SORT_INDEX_PACKET_COUNT, {file_hash: total_packets or 0})
        pipe.zadd(SORT_INDEX_FILENAME, {file_hash: 0})
        pipe.zadd(SORT_INDEX_PATH, {file_hash: 0})

        await asyncio.to_thread(pipe.execute)
        if stale_protocols:
            await asyncio.to_thread(drop_unused_protocols, redis_client, stale_protocols)

        logger.info(
            "Indexed file %s (hash: %s) with protocols: %s",
            filename,
            file_hash,
            ", ".join(protocols),
        )

        async with counter_lock:
            files_indexed_container[0] += 1

    @with_app_context
    async def scan_and_index(
        self,
        exclude_files: List[str] = None,
        target_folder: Optional[str] = None,
        *,
        context: AppContext = None,
    ) -> dict:
        if exclude_files is None:
            exclude_files = []

        redis_client = context.redis_client
        config = context.config

        if not redis_client:
            return {"error": "Redis connection is not available."}

        large_file_bytes = parse_size_bytes(config.pcap.large_file_size, default=512 * 1024**2)

        logger.info(
            "Starting PARALLEL scan for: %s (max_concurrent=%d, files >= %d bytes %d at a time, exclusions=%s)",
            config.pcap.root_directory,
            config.pcap.max_parallel_scans,
            large_file_bytes,
            config.pcap.large_file_parallel_scans,
            exclude_files,
        )

        try:
            check_cancellation(self.scan_cancel_event)

            if not await asyncio.to_thread(os.path.isdir, config.pcap.root_directory):
                logger.warning(f"Directory '{config.pcap.root_directory}' does not exist. Skipping.")
                return { "status": "warning", "message": f"Directory '{config.pcap.root_directory}' does not exist.", "indexed_files": 0 }

            # Collect all file paths
            all_files, found_matching_folder = await self.collect_files(
                root_directory=config.pcap.root_directory,
                exclude_files=exclude_files,
                allowed_extensions=tuple(config.pcap.allowed_file_extensions),
                target_folder=target_folder,
            )

            if target_folder and not found_matching_folder:
                logger.warning(f"No folder named '{target_folder}' found under {config.pcap.root_directory}.")
                return { "status": "warning", "message": f"No folder named '{target_folder}' found.", "indexed_files": 0 }

            logger.info(f"Collected {len(all_files)} files to scan after applying exclusions.")

            # Smallest first, so a few multi-GB captures do not delay the rest
            # from becoming searchable.
            # A file that vanished since the walk (or a dangling symlink) is
            # dropped here; one such file used to fail the whole scan.
            sizes = await asyncio.to_thread(
                lambda: {p: _file_size_or_none(p) for p in all_files}
            )
            all_files = sorted((p for p in all_files if sizes[p] is not None), key=sizes.__getitem__)
            self.scan_status["total_files"] = len(all_files)
            self.scan_status["message"] = f"Scanning {len(all_files)} files..."

            # Prepare shared state
            semaphore = asyncio.Semaphore(config.pcap.max_parallel_scans)
            large_semaphore = asyncio.Semaphore(config.pcap.large_file_parallel_scans)
            seen_hashes_lock = asyncio.Lock() # protect seen_hashes
            seen_hashes : Set[str] = set()
            counter_lock = asyncio.Lock() # protect files_indexed
            files_indexed_container : List[int] = [0]

            # Create all tasks and run them concurrently
            tasks = [
                self.process_one_file(
                    file_path,
                    semaphore=semaphore,
                    large_semaphore=large_semaphore,
                    large_file_bytes=large_file_bytes,
                    seen_hashes_lock=seen_hashes_lock,
                    seen_hashes=seen_hashes,
                    counter_lock=counter_lock,
                    files_indexed_container=files_indexed_container,
                    redis_client=redis_client,
                    config=config,
                    context=context,
                )
                for file_path in all_files
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Check if cancelled
            if self.scan_cancel_event.is_set():
                logger.info(f"Scan cancelled. Indexed {files_indexed_container[0]} files before cancellation.")
                return {"status": "cancelled", "indexed_files": files_indexed_container[0]}

            # Log any unhandled exceptions from individual file tasks
            for i, result in enumerate(results):
                if isinstance(result, asyncio.CancelledError):
                    pass
                elif isinstance(result, Exception):
                    logger.error(f"Error processing file {all_files[i]}: {result}")

            logger.info("Parallel scan completed successfully. Indexed %d / %d files.", files_indexed_container[0], len(all_files))

            removed = 0
            if target_folder is None:
                removed = await asyncio.to_thread(
                    self.prune_missing_files, redis_client, config.pcap.root_directory, set(all_files)
                )
            self.scan_status["removed_files"] = removed

            return {"status": "success", "indexed_files": files_indexed_container[0], "removed_files": removed}

        except asyncio.CancelledError:
            logger.info(f"Scan cancelled")
            return {"status": "cancelled", "indexed_files": 0}

    def prune_missing_files(self, redis_client, root_directory: str, scanned: Set[str]) -> int:
        """Remove catalog entries whose file is gone from disk.

        Runs after a complete scan. Entries for deleted files used to stay
        searchable forever, and downloading them failed with a 500.
        """
        if not scanned:
            # Nothing at all on disk usually means a missing or mistyped mount,
            # not that every capture was deleted: keep the catalog.
            logger.warning("No pcap files found under %s; not removing anything from the catalog", root_directory)
            return 0
        root = os.path.normpath(root_directory)
        removed = 0
        touched: List[str] = []
        keys = list(redis_client.scan_iter(f"{PCAP_FILE_KEY_PREFIX}:*", count=1000))
        for start in range(0, len(keys), 1000):
            batch = keys[start:start + 1000]
            pipe = redis_client.pipeline(transaction=False)
            for key in batch:
                pipe.hgetall(key)
            for key, stored in zip(batch, pipe.execute()):
                path = stored.get("path")
                if not path or path in scanned:
                    continue
                inside = os.path.commonpath([root, os.path.normpath(path)]) == root
                if inside and os.path.lexists(path):
                    continue  # still there, e.g. excluded from this scan
                file_hash = key.rsplit(":", 1)[-1]
                logger.info("Removing %s from the catalog: the file no longer exists", path)
                touched += remove_catalog_entry(redis_client, file_hash, stored)
                removed += 1

        # Path map entries left behind by deleted files.
        stale_paths = [
            path for path, _ in redis_client.hscan_iter(PATH_MAP_KEY, count=1000)
            if path not in scanned and not os.path.lexists(path)
        ]
        for start in range(0, len(stale_paths), 1000):
            redis_client.hdel(PATH_MAP_KEY, *stale_paths[start:start + 1000])

        drop_unused_protocols(redis_client, touched)
        if removed:
            logger.info("Removed %d deleted files from the catalog", removed)
        return removed

    @with_app_context
    def scan_wrapper(self, exclude_files=None, target_folder: Optional[str] = None, *, context: AppContext = None):
        redis = context.redis_client
        if not redis:
            logger.error("Redis connection is not available. Scan aborted.")
            return

        if self.scan_status["state"] != ScanState.RUNNING:
            # Called directly rather than after try_begin_scan().
            if not self.try_begin_scan():
                logger.info("A scan is already running; not starting another one.")
                return

        try:
            # dirty the lex indexes
            redis.set(REBUILD_DIRTY, 1)

            self.scan_status["message"] = "Scanning in progress..."
            logger.info("Background scan started.")

            result = asyncio.run(
                self.scan_and_index(exclude_files=exclude_files, target_folder=target_folder)
            )
            self.scan_status["indexed_files"] = result.get("indexed_files", 0)

            if result.get("status") == "cancelled":
                self.scan_status["state"] = ScanState.IDLE
                self.scan_status["message"] = (
                    f"Scan cancelled. Indexed {self.scan_status['indexed_files']} files before cancellation."
                )
                logger.info("Background scan cancelled.")
            elif result.get("status") == "warning":
                self.scan_status["state"] = ScanState.COMPLETED
                self.scan_status["message"] = result.get("message", "Nothing to scan.")
            else:
                self.scan_status["state"] = ScanState.COMPLETED
                message = f"Completed successfully. Indexed {self.scan_status['indexed_files']} files."
                if result.get("removed_files"):
                    message += f" Removed {result['removed_files']} deleted files."
                self.scan_status["message"] = message
                logger.info("Background scan completed.")
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            self.scan_status["state"] = ScanState.FAILED
            self.scan_status["message"] = f"Last scan failed: {e}"
        finally:
            self.scan_status["current_files"] = []
            if self.scan_status["state"] == ScanState.RUNNING:
                self.scan_status["state"] = ScanState.IDLE
            # Totals on the dashboard are cached for a few minutes; drop them.
            with contextlib.suppress(Exception):
                redis.delete(DASHBOARD_SUMMARY_KEY)

            self.__schedule_lex_rebuild__()

    async def backfill_total_packets(self, redis_client: Redis) -> dict:
        if not redis_client:
            return {"error": "Redis connection is not available."}

        # SCAN instead of KEYS: KEYS blocks Redis for the whole walk.
        keys = await asyncio.to_thread(
            lambda: list(redis_client.scan_iter(f"{PCAP_FILE_KEY_PREFIX}:*", count=1000))
        )
        processed = 0
        updated = 0
        total = len(keys)

        for key in keys:
            data = await asyncio.to_thread(redis_client.hgetall, key)
            if not data:
                continue

            processed += 1
            existing_total = data.get("total_packets")
            if existing_total not in (None, ""):
                continue

            file_path = data.get("path")
            if not file_path or not await asyncio.to_thread(os.path.exists, file_path):
                logger.warning("Missing file for total_packets backfill: %s", file_path)
                continue

            total_packets = await get_total_packets_from_pcap(file_path)
            if total_packets is None:
                logger.warning(
                    f"capinfos failed for {file_path}; continuing without total_packets"
                )
                total_packets = ""

            await asyncio.to_thread(redis_client.hset, key, "total_packets", total_packets)
            updated += 1

        return {"processed": processed, "updated": updated, "total": total}

    @with_app_context
    def backfill_wrapper(self, *, context: AppContext = None):
        redis = context.redis_client
        if not redis:
            logger.error("Redis connection is not available. Backfill aborted.")
            return

        try:
            self.backfill_status["state"] = BackfillState.RUNNING
            self.backfill_status["processed"] = 0
            self.backfill_status["updated"] = 0
            self.backfill_status["total"] = 0
            self.backfill_status["message"] = "Backfill in progress..."
            logger.info("Background total_packets backfill started.")

            result = asyncio.run(self.backfill_total_packets(redis))
            self.backfill_status["processed"] = result.get("processed", 0)
            self.backfill_status["updated"] = result.get("updated", 0)
            self.backfill_status["total"] = result.get("total", 0)

            self.backfill_status["state"] = BackfillState.COMPLETED
            self.backfill_status["message"] = (
                "Completed successfully. "
                f"Updated {self.backfill_status['updated']} of {self.backfill_status['processed']} keys."
            )
            logger.info("Background total_packets backfill completed.")

        except Exception as e:
            logger.error("Backfill failed: %s", e)
            self.backfill_status["state"] = BackfillState.FAILED
            self.backfill_status["message"] = str(e)
        finally:
            if self.backfill_status["state"] != BackfillState.FAILED:
                self.backfill_status["state"] = BackfillState.IDLE

    def rebuild_search_indexes_sync(self, redis_client: Redis) -> dict:
        if not redis_client:
            return {"error": "Redis connection is not available."}

        rebuild_protocol_index_sync(redis_client)

        keys = list(redis_client.scan_iter(f"{PCAP_FILE_KEY_PREFIX}:*"))
        total = len(keys)
        if total == 0:
            redis_client.delete(
                LEX_INDEX_FILENAME,
                LEX_INDEX_PATH,
                SORT_INDEX_FILENAME,
                SORT_INDEX_PATH,
                SORT_INDEX_SIZE,
                SORT_INDEX_PACKET_COUNT,
            )
            return {"processed": 0, "backfilled": 0, "total": 0}

        filename_map: Dict[str, List[str]] = {}
        path_map: Dict[str, List[str]] = {}
        size_map: Dict[str, int] = {}
        packet_map: Dict[str, int] = {}

        processed = 0
        backfilled = 0

        for key in keys:
            processed += 1
            data = redis_client.hgetall(key)
            if not data:
                continue

            file_hash = key.split(":")[-1]

            filename_sort = _normalize_scan_param(data.get("filename_sort"))
            if not filename_sort:
                raw = _normalize_scan_param(data.get("filename"))
                if raw:
                    filename_sort = raw.lower()
                    redis_client.hset(key, "filename_sort", filename_sort)
                    backfilled += 1

            path_sort = _normalize_scan_param(data.get("path_sort"))
            if not path_sort:
                raw = _normalize_scan_param(data.get("path"))
                if raw:
                    path_sort = raw.lower()
                    redis_client.hset(key, "path_sort", path_sort)
                    backfilled += 1

            if filename_sort:
                filename_map.setdefault(filename_sort, []).append(file_hash)
            if path_sort:
                path_map.setdefault(path_sort, []).append(file_hash)

            size_bytes = _parse_int(data.get("size_bytes"))
            if size_bytes is not None:
                size_map[file_hash] = max(size_bytes, 0)

            # The score used by SORT_INDEX_PACKET_COUNT has drifted historically;
            # prefer `total_packets`, fall back to `protocol_packet_count`.
            packet_count = _parse_int(data.get("total_packets"))
            if packet_count is None:
                packet_count = _parse_int(data.get("protocol_packet_count"))
            packet_map[file_hash] = max(packet_count or 0, 0)

        lex_filename_new = f"{LEX_INDEX_FILENAME}:new"
        lex_path_new = f"{LEX_INDEX_PATH}:new"
        filename_new = f"{SORT_INDEX_FILENAME}:new"
        path_new = f"{SORT_INDEX_PATH}:new"
        size_new = f"{SORT_INDEX_SIZE}:new"
        packet_new = f"{SORT_INDEX_PACKET_COUNT}:new"

        pipe = redis_client.pipeline()
        pipe.delete(lex_filename_new, lex_path_new, filename_new, path_new, size_new, packet_new)

        # Rebuild lex sets (score=0 => zrange is lexicographic)
        if filename_map:
            pipe.zadd(lex_filename_new, {k: 0 for k in filename_map.keys()})
        if path_map:
            pipe.zadd(lex_path_new, {k: 0 for k in path_map.keys()})

        # Numeric sorts
        if size_map:
            pipe.zadd(size_new, size_map)
        if packet_map:
            pipe.zadd(packet_new, packet_map)

        # Lex-derived sorts for file hashes
        for rank, fname in enumerate(sorted(filename_map.keys())):
            hashes = filename_map.get(fname)
            if hashes:
                pipe.zadd(filename_new, {h: rank for h in hashes})

        for rank, fpath in enumerate(sorted(path_map.keys())):
            hashes = path_map.get(fpath)
            if hashes:
                pipe.zadd(path_new, {h: rank for h in hashes})

        pipe.execute()

        # Swap in rebuilt indexes atomically
        pipe = redis_client.pipeline()
        pipe.rename(lex_filename_new, LEX_INDEX_FILENAME)
        pipe.rename(lex_path_new, LEX_INDEX_PATH)
        pipe.rename(filename_new, SORT_INDEX_FILENAME)
        pipe.rename(path_new, SORT_INDEX_PATH)
        pipe.rename(size_new, SORT_INDEX_SIZE)
        pipe.rename(packet_new, SORT_INDEX_PACKET_COUNT)
        pipe.execute()

        return {"processed": processed, "backfilled": backfilled, "total": total}

    @with_app_context
    def rebuild_searchindex_wrapper(self, *, context: AppContext = None):
        redis = context.redis_client
        if not redis:
            logger.error("Redis connection is not available. Rebuild aborted.")
            return

        try:
            self.rebuild_searchindex_status["state"] = RebuildSearchIndexState.RUNNING
            self.rebuild_searchindex_status["processed"] = 0
            self.rebuild_searchindex_status["backfilled"] = 0
            self.rebuild_searchindex_status["total"] = 0
            self.rebuild_searchindex_status["message"] = "Rebuild in progress..."
            logger.info("Background rebuild-searchindex started.")

            result = self.rebuild_search_indexes_sync(redis)
            self.rebuild_searchindex_status["processed"] = result.get("processed", 0)
            self.rebuild_searchindex_status["backfilled"] = result.get("backfilled", 0)
            self.rebuild_searchindex_status["total"] = result.get("total", 0)

            self.rebuild_searchindex_status["state"] = RebuildSearchIndexState.COMPLETED
            self.rebuild_searchindex_status["message"] = (
                "Completed successfully. "
                f"Rebuilt sort indexes from {self.rebuild_searchindex_status['processed']} keys "
                f"(backfilled={self.rebuild_searchindex_status['backfilled']})."
            )
            logger.info("Background rebuild-searchindex completed.")

        except Exception as e:
            logger.error("Rebuild-searchindex failed: %s", e)
            self.rebuild_searchindex_status["state"] = RebuildSearchIndexState.FAILED
            self.rebuild_searchindex_status["message"] = str(e)
        finally:
            if self.rebuild_searchindex_status["state"] != RebuildSearchIndexState.FAILED:
                self.rebuild_searchindex_status["state"] = RebuildSearchIndexState.IDLE

    @with_app_context
    def __schedule_lex_rebuild__(self, delay_seconds: int = 10, *, context: AppContext = None):

        def worker():
            redis = context.redis_client
            if not redis:
                return

            time.sleep(delay_seconds)
            # if new changes happened, abort (another worker will handle it)
            if redis.get(REBUILD_DIRTY) is None:
                return

            # acquire rebuild lock
            if not redis.set(REBUILD_LOCK, 1, nx=True, ex=300):
                return

            try:
                redis.delete(REBUILD_DIRTY)
                asyncio.run(rebuild_lex_sort_indexes())
            finally:
                redis.delete(REBUILD_LOCK)

        threading.Thread(target=worker, daemon=True).start()

    def _stream_protocol_counts(
        self,
        command: List[str],
        tool: str,
        pcap_file: str,
        excluded_protocols: Optional[set[str]] = None,
    ) -> Optional[Tuple[Dict[str, int], int]]:
        """Run a tool that prints one colon-separated protocol stack per packet
        ("eth:ip:sctp:m3ua") and count packets per protocol while reading.

        Only distinct stacks are kept in memory (usually a few hundred), so a
        capture with tens of millions of packets costs the same as a small one.
        The previous version collected every output line first and ran the
        backend out of memory on 1 GB+ files.
        """
        cancel_event = self.scan_cancel_event
        try:
            # Binary mode with a big buffer: decoding and stripping ~17M text
            # lines per GB made Python, not the scanner, the bottleneck (the
            # tool spent most of its time blocked on a full pipe). Lines are
            # counted as raw bytes; only the few hundred distinct stacks are
            # decoded at the end.
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1 << 20,
            )
        except FileNotFoundError:
            logger.error("%s not found - please install it.", tool)
            return None

        self.scan_process[tool] = process

        # Drain stderr in the background so a chatty tool can never block on
        # a full pipe; only the last lines are needed for the error message.
        stderr_tail: deque = deque(maxlen=20)

        def drain_stderr():
            for line in process.stderr:
                stderr_tail.append(line.decode("utf-8", "replace").rstrip())

        stderr_thread = threading.Thread(target=drain_stderr, daemon=True)
        stderr_thread.start()

        raw_stacks: Counter = Counter()
        cancelled = False
        try:
            while True:
                # Counter.update on a list counts in C, several times faster
                # than a Python loop over the lines.
                batch = list(islice(process.stdout, CANCEL_CHECK_EVERY_LINES))
                if not batch:
                    break
                raw_stacks.update(batch)
                if cancel_event.is_set():
                    cancelled = True
                    break
        except Exception as e:
            logger.error("Unexpected error while reading %s output for %s: %s", tool, pcap_file, e)
            cancelled = True
        finally:
            if cancelled and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
            process.wait()
            stderr_thread.join(timeout=5)
            self.scan_process[tool] = None

        if cancelled or cancel_event.is_set():
            logger.info("Scan cancelled while %s was reading %s.", tool, pcap_file)
            return None

        stacks: Counter = Counter()
        for raw, n in raw_stacks.items():
            stacks[raw.decode("utf-8", "replace").strip()] += n

        packets_scanned = sum(stacks.values())
        if process.returncode != 0:
            message = "\n".join(stderr_tail)
            if packets_scanned == 0:
                logger.error("%s exited with error for %s: %s", tool, pcap_file, message)
                return None
            # e.g. a capture cut off mid-packet: everything before the cut is valid.
            logger.warning(
                "%s exited with code %s for %s; keeping the %d packets read. %s",
                tool, process.returncode, pcap_file, packets_scanned, message,
            )

        excluded = excluded_protocols or set()
        protocol_counts: Dict[str, int] = {}
        for stack, n in stacks.items():
            if not stack:
                continue  # a packet the tool could not decode
            for proto in set(stack.split(":")) - excluded:
                protocol_counts[proto] = protocol_counts.get(proto, 0) + n

        return protocol_counts, packets_scanned

    def get_protocols_from_pcap_fast_sync(
        self,
        pcap_file: str,
        excluded_protocols: Optional[set[str]] = None,
    ) -> Optional[Tuple[Dict[str, int], int]]:
        """Fast protocol scan using the fastscan binary (/usr/local/bin/fastscan)."""
        return self._stream_protocol_counts(
            ["fastscan", pcap_file], "fastscan", pcap_file, excluded_protocols
        )

    def get_protocols_from_pcap_quick_sync(
        self,
        pcap_file: str,
        *,
        quick_threshold_bytes: Optional[int],
        excluded_protocols: Optional[set[str]] = None,
    ) -> Optional[Tuple[Dict[str, int], int]]:
        """Quick scan via tshark, stopping after threshold bytes."""
        scan_cancel_event = self.scan_cancel_event
        scan_process = self.scan_process

        threshold = quick_threshold_bytes or 0
        if threshold <= 0:
            logger.warning("Quick scan threshold is <= 0 for %s; skipping", pcap_file)
            return {}, 0

        command = [
            "tshark",
            "-r",
            pcap_file,
            "-T",
            "fields",
            "-e",
            "frame.len",
            "-e",
            "frame.protocols",
            "-E",
            "separator=\t",
        ]

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
            )
            scan_process["tshark"] = process

            # Drain stderr while reading stdout: a tshark that writes many
            # warnings would otherwise fill the pipe and stall.
            stderr_tail: deque = deque(maxlen=20)
            stderr_thread = threading.Thread(
                target=lambda: stderr_tail.extend(process.stderr), daemon=True
            )
            stderr_thread.start()

            protocol_counts: Dict[str, int] = {}
            bytes_scanned = 0
            packets_scanned = 0
            threshold_reached = False

            logger.info(
                "Quick scan tshark started for %s (threshold_bytes=%s)",
                pcap_file,
                threshold,
            )

            while True:
                if scan_cancel_event.is_set():
                    logger.info(
                        "Scan cancellation requested. Terminating tshark for %s.",
                        pcap_file,
                    )
                    process.terminate()
                    break

                line = process.stdout.readline() if process.stdout else ""
                if line == "":
                    break

                line = line.strip()
                if not line:
                    continue

                parts = line.split("\t", 1)
                if len(parts) != 2:
                    continue

                size_str, protocols_str = parts
                try:
                    packet_size = int(size_str)
                except ValueError:
                    continue

                if bytes_scanned + packet_size > threshold:
                    threshold_reached = True
                    logger.info(
                        "Quick scan threshold reached for %s (bytes_scanned=%s, next_packet=%s, threshold=%s)",
                        pcap_file,
                        bytes_scanned,
                        packet_size,
                        threshold,
                    )
                    break

                bytes_scanned += packet_size
                packets_scanned += 1
                if not protocols_str:
                    continue

                protocols = protocols_str.split(":")
                unique_protocols = set(protocols) - (excluded_protocols or set())
                for proto in unique_protocols:
                    protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()  # reap it, so no zombie is left behind
            stderr_thread.join(timeout=5)

            if scan_cancel_event.is_set():
                return None

            stderr_output = "".join(stderr_tail)
            if process.returncode not in (0, None) and not threshold_reached:
                stderr_output = stderr_output.strip()
                if stderr_output:
                    logger.error(
                        "tshark exited with error for %s: %s",
                        pcap_file,
                        stderr_output,
                    )
                return None

            logger.info(
                "Quick scan finished for %s (bytes_scanned=%s, packets_scanned=%s)",
                pcap_file,
                bytes_scanned,
                packets_scanned,
            )
            return protocol_counts, packets_scanned

        except FileNotFoundError:
            logger.error("tshark not found — please install it.")
            return None
        except Exception as e:
            logger.error(
                "Unexpected error while analyzing %s with quickscan: %s",
                pcap_file,
                e,
            )
            return None
        finally:
            scan_process["tshark"] = None

    def get_protocols_from_pcap_sync(
        self, pcap_file: str, excluded_protocols: Optional[set[str]] = None
    ) -> Optional[Tuple[Dict[str, int], int]]:
        # Full mode: tshark decodes every packet.
        # -n: no name resolution (slow, and would leak DNS lookups for capture IPs).
        command = ["tshark", "-n", "-r", pcap_file, "-T", "fields", "-e", "frame.protocols"]
        for pref in TSHARK_LEAN_PREFS:
            command += ["-o", pref]

        session_reset = get_app_context().config.pcap.tshark_session_reset
        if session_reset > 0:
            # Without this, tshark keeps state for every flow in the file: a 1.2 GB
            # backbone capture pushed it past 6 GB RSS. -M drops that state every
            # N packets.
            command += ["-M", str(session_reset)]

        return self._stream_protocol_counts(command, "tshark", pcap_file, excluded_protocols)


    async def get_protocols_from_pcap(
        self,
        pcap_file: str,
        excluded_protocols: Optional[set[str]] = None,
        scan_mode: ScanMode = ScanMode.FULL,
        quick_threshold_bytes: Optional[int] = None,
    ) -> Optional[Tuple[Dict[str, int], int]]:
        match scan_mode:
            case ScanMode.FAST:
                return await asyncio.to_thread(
                    self.get_protocols_from_pcap_fast_sync,
                    pcap_file,
                    excluded_protocols=excluded_protocols,
                )
            case ScanMode.FULL:
                return await asyncio.to_thread(
                    self.get_protocols_from_pcap_sync,
                    pcap_file,
                    excluded_protocols=excluded_protocols,
                )
            case ScanMode.QUICK:
                return await asyncio.to_thread(
                    self.get_protocols_from_pcap_quick_sync,
                    pcap_file,
                    quick_threshold_bytes=quick_threshold_bytes,
                    excluded_protocols=excluded_protocols,
                )
            case _:
                logger.error(f"Unknown scan mode: {scan_mode}")
                return None



@with_app_context
def get_scan_service(*, context: AppContext = None) -> ScanService:
    if not hasattr(context, "_scan_service"):
        context._scan_service = ScanService()
    return context._scan_service

@with_app_context
async def rebuild_lex_sort_indexes(*, context: AppContext = None):
    redis = context.redis_client
    if not redis:
        return

    logger.info("Rebuilding lexicographic sort indexes (atomic)")

    filename_new = f"{SORT_INDEX_FILENAME}:new"
    path_new = f"{SORT_INDEX_PATH}:new"

    filename_map: dict[str, list[str]] = {}
    path_map: dict[str, list[str]] = {}

    # One round trip per 1000 files instead of one per file.
    keys = list(redis.scan_iter(f"{PCAP_FILE_KEY_PREFIX}:*", count=1000))
    for start in range(0, len(keys), 1000):
        batch = keys[start:start + 1000]
        pipe = redis.pipeline(transaction=False)
        for key in batch:
            pipe.hmget(key, "filename_sort", "path_sort")
        for key, (fname, fpath) in zip(batch, pipe.execute()):
            file_hash = key.split(":")[-1]
            if fname:
                filename_map.setdefault(fname, []).append(file_hash)
            if fpath:
                path_map.setdefault(fpath, []).append(file_hash)

    # filename sort index
    filenames = await asyncio.to_thread(
        redis.zrange, LEX_INDEX_FILENAME, 0, -1
    )

    pipe = redis.pipeline()
    pipe.delete(filename_new)

    for rank, fname in enumerate(filenames):
        hashes = filename_map.get(fname)
        if hashes:
            pipe.zadd(
                filename_new,
                {h: rank for h in hashes}
            )

    pipe.execute()

    # path sort index
    paths = await asyncio.to_thread(
        redis.zrange, LEX_INDEX_PATH, 0, -1
    )

    pipe = redis.pipeline()
    pipe.delete(path_new)

    for rank, fpath in enumerate(paths):
        hashes = path_map.get(fpath)
        if hashes:
            pipe.zadd(
                path_new,
                {h: rank for h in hashes}
            )

    pipe.execute()

    pipe = redis.pipeline()
    if await asyncio.to_thread(redis.exists, filename_new):
        pipe.rename(filename_new, SORT_INDEX_FILENAME)
    else:
        pipe.delete(SORT_INDEX_FILENAME)

    if await asyncio.to_thread(redis.exists, path_new):
        pipe.rename(path_new, SORT_INDEX_PATH)
    else:
        pipe.delete(SORT_INDEX_PATH)
    pipe.execute()

    logger.info("Lexicographic sort indexes rebuilt successfully.")
