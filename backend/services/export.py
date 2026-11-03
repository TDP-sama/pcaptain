"""Filtered exports: write only the packets matching a Wireshark display filter.

A display filter needs a full tshark decode of the source file, which takes
minutes on a 1 GB+ capture. So exports run as background jobs (with progress),
and every finished extract is kept on disk keyed by (source sha256, filter):
asking for the same extract again is served straight from the cache. Keying on
the content hash means an edited source file never returns a stale extract.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, Optional

from .logger import get_logger
from .scan import parse_size_bytes

logger = get_logger(__name__)

EXTRACT_SUFFIX = ".pcapng"
# A pcap with a header and no packets: lets tshark compile a filter in well
# under a second, so a typo is reported before a long job starts.
EMPTY_PCAP = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


class JobState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    READY = "ready"
    EMPTY = "empty"      # finished, but no packet matched
    FAILED = "failed"


@dataclass
class ExportJob:
    id: str
    file_hash: str
    source_path: str
    source_name: str
    filter: str
    state: JobState = JobState.QUEUED
    progress: float = 0.0        # 0..1, how far tshark has read the source
    cached: bool = False         # served from an earlier run
    packets: Optional[int] = None
    size_bytes: Optional[int] = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["state"] = self.state.value
        d.pop("source_path")
        return d


def normalize_filter(display_filter: str) -> str:
    return re.sub(r"\s+", " ", display_filter.strip())


def export_id(file_hash: str, display_filter: str) -> str:
    return hashlib.sha256(f"{file_hash}\0{display_filter}".encode()).hexdigest()[:32]


def download_name(source_name: str, display_filter: str) -> str:
    stem = re.sub(r"\.(pcapng|pcap|cap)(\.gz)?$", "", source_name, flags=re.I)
    slug = re.sub(r"[^A-Za-z0-9]+", "-", display_filter).strip("-")[:40] or "filtered"
    return f"{stem}__{slug}{EXTRACT_SUFFIX}"


class ExportService:
    def __init__(self, cache_dir: str, cache_max_size: int | str, max_jobs: int, session_reset: int):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_max_bytes = (
            cache_max_size if isinstance(cache_max_size, int)
            else parse_size_bytes(str(cache_max_size), default=5 * 1024**3)
        )
        self.session_reset = session_reset
        self._pool = ThreadPoolExecutor(max_workers=max_jobs, thread_name_prefix="export")
        self._jobs: Dict[str, ExportJob] = {}
        self._lock = threading.Lock()
        self._empty_pcap = self.cache_dir / ".empty.pcap"
        self._empty_pcap.write_bytes(EMPTY_PCAP)
        # Leftovers from a run that was killed mid-export.
        for tmp in self.cache_dir.glob("*.part"):
            tmp.unlink(missing_ok=True)

    # --- filter validation ---
    def validate(self, display_filter: str) -> Optional[str]:
        """Return None if tshark accepts the filter, else its error message."""
        if not display_filter:
            return "The filter is empty."
        try:
            proc = subprocess.run(
                ["tshark", "-n", "-r", str(self._empty_pcap), "-Y", display_filter],
                capture_output=True, text=True, timeout=20,
            )
        except subprocess.TimeoutExpired:
            return "tshark took too long to check the filter."
        if proc.returncode == 0:
            return None
        lines = [
            ln for ln in proc.stderr.splitlines()
            if ln.strip() and not ln.startswith("Running as user")
        ]
        return "\n".join(lines) or f"tshark rejected the filter (exit code {proc.returncode})."

    # --- cache ---
    def _extract_path(self, job_id: str) -> Path:
        return self.cache_dir / f"{job_id}{EXTRACT_SUFFIX}"

    def _evict(self) -> None:
        extracts = sorted(self.cache_dir.glob(f"*{EXTRACT_SUFFIX}"), key=lambda p: p.stat().st_mtime)
        total = sum(p.stat().st_size for p in extracts)
        for p in extracts:
            if total <= self.cache_max_bytes:
                break
            total -= p.stat().st_size
            p.unlink(missing_ok=True)
            with self._lock:
                self._jobs.pop(p.stem, None)
            logger.info("Evicted cached extract %s", p.name)

    # --- jobs ---
    def has_result(self, file_hash: str, display_filter: str) -> bool:
        """True if this export already exists (running, finished or cached on disk)."""
        job_id = export_id(file_hash, display_filter)
        with self._lock:
            if job_id in self._jobs and self._jobs[job_id].state != JobState.FAILED:
                return True
        return self._extract_path(job_id).exists()

    def get(self, job_id: str) -> Optional[ExportJob]:
        with self._lock:
            return self._jobs.get(job_id)

    def extract_file(self, job: ExportJob) -> Path:
        path = self._extract_path(job.id)
        if path.exists():
            os.utime(path)  # mark as recently used for eviction
        return path

    def start(self, *, file_hash: str, source_path: str, source_name: str, display_filter: str) -> ExportJob:
        """Return the job for this file + filter, starting it if needed."""
        job_id = export_id(file_hash, display_filter)
        with self._lock:
            job = self._jobs.get(job_id)
            if job and job.state in (JobState.QUEUED, JobState.RUNNING, JobState.READY, JobState.EMPTY):
                if job.state == JobState.READY and not self._extract_path(job_id).exists():
                    job = None  # evicted or removed by hand; rebuild it
                else:
                    if job.state in (JobState.READY, JobState.EMPTY):
                        job.cached = True  # answered from an earlier run
                    return job

            job = ExportJob(
                id=job_id, file_hash=file_hash, source_path=source_path,
                source_name=source_name, filter=display_filter,
            )
            cached = self._extract_path(job_id)
            if cached.exists():
                # Finished by an earlier process (e.g. before a restart).
                job.state, job.cached, job.progress = JobState.READY, True, 1.0
                job.size_bytes = cached.stat().st_size
                job.packets = _count_packets(cached)
                job.finished_at = time.time()
                self._jobs[job_id] = job
                return job

            self._jobs[job_id] = job

        self._pool.submit(self._run, job)
        return job

    def _run(self, job: ExportJob) -> None:
        final = self._extract_path(job.id)
        tmp = final.with_suffix(".part")
        cmd = ["tshark", "-n", "-r", job.source_path, "-Y", job.filter, "-w", str(tmp), "-F", "pcapng"]
        if self.session_reset > 0:
            # Bound memory on captures with millions of flows. Reassembly stays
            # on (unlike scanning) so filters on SIP/HTTP over TCP still match.
            cmd += ["-M", str(self.session_reset)]

        job.state = JobState.RUNNING
        logger.info("Export %s started: %s | %s", job.id, job.source_name, job.filter)
        try:
            source_size = os.path.getsize(job.source_path)
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            stderr_lines: list[str] = []
            reader = threading.Thread(
                target=lambda: stderr_lines.extend(proc.stderr), daemon=True
            )
            reader.start()
            while proc.poll() is None:
                pos = _read_position(proc.pid, job.source_path)
                if pos is not None and source_size:
                    job.progress = min(pos / source_size, 0.99)
                time.sleep(0.5)
            reader.join(timeout=5)

            message = "".join(ln for ln in stderr_lines if not ln.startswith("Running as user")).strip()
            wrote = tmp.exists() and tmp.stat().st_size > 0
            if proc.returncode != 0 and not wrote:
                raise RuntimeError(message or f"tshark exited with code {proc.returncode}")
            if proc.returncode != 0:
                # A capture cut off mid-packet: what was read before the cut is valid.
                logger.warning("Export %s: tshark exit %s, keeping output. %s", job.id, proc.returncode, message)

            packets = _count_packets(tmp) if wrote else 0
            if not packets:
                tmp.unlink(missing_ok=True)
                job.state, job.packets = JobState.EMPTY, 0
            else:
                tmp.replace(final)
                job.packets, job.size_bytes = packets, final.stat().st_size
                job.state = JobState.READY
                self._evict()
            job.progress = 1.0
            logger.info("Export %s finished: %s, %s packets", job.id, job.state.value, job.packets)
        except Exception as e:
            tmp.unlink(missing_ok=True)
            job.state, job.error = JobState.FAILED, str(e)
            logger.error("Export %s failed: %s", job.id, e)
        finally:
            job.finished_at = time.time()


def _read_position(pid: int, path: str) -> Optional[int]:
    """How far a process has read into `path`, from /proc (Linux only)."""
    fd_dir = f"/proc/{pid}/fd"
    try:
        for fd in os.listdir(fd_dir):
            try:
                if os.readlink(f"{fd_dir}/{fd}") == path:
                    with open(f"/proc/{pid}/fdinfo/{fd}") as f:
                        for line in f:
                            if line.startswith("pos:"):
                                return int(line.split()[1])
            except OSError:
                continue
    except OSError:
        return None
    return None


def _count_packets(path: Path) -> Optional[int]:
    try:
        out = subprocess.run(["capinfos", "-M", "-c", str(path)], capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"Number of packets:\s*(\d+)", out.stdout)
    return int(m.group(1)) if m else None


_service: Optional[ExportService] = None
_service_lock = threading.Lock()


def get_export_service() -> ExportService:
    from .context import get_app_context

    global _service
    with _service_lock:
        if _service is None:
            config = get_app_context().config
            _service = ExportService(
                cache_dir=config.export.cache_dir,
                cache_max_size=config.export.cache_max_size,
                max_jobs=config.export.max_jobs,
                session_reset=config.pcap.tshark_session_reset,
            )
        return _service
