import asyncio
import os
import re
import subprocess
import tempfile

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import FileResponse

from services.context import AppContext, get_app_context
from services.export import count_packets, get_export_service, normalize_filter
from services.logger import get_logger
from services.scan import PCAP_FILE_KEY_PREFIX

router = APIRouter(tags=["Pcaps"])
logger = get_logger(__name__)

PCAP_MEDIA_TYPE = "application/vnd.tcpdump.pcap"
# The legacy one-shot filter routes below decode the whole file inside the
# request. Bound how many run at once and for how long; POST /exports is the
# way to filter large captures (background job, progress, cache).
LEGACY_FILTER_TIMEOUT_SECONDS = 15 * 60
_legacy_filter_slots = asyncio.Semaphore(2)


def resolve_catalog_file(context: AppContext, metadata: dict) -> str:
    """Path of an indexed capture, checked to lie under the pcap root.

    The path comes from the catalog (the scanner found it by walking the root),
    so it is normalised, not resolved: a capture that is a symlink still works.
    404 when it is no longer on disk (it used to fail with a 500).
    """
    root = os.path.normpath(context.config.pcap.root_directory)
    path = os.path.normpath(metadata.get("path") or "")
    if not os.path.isabs(path) or os.path.commonpath([root, path]) != root:
        raise HTTPException(status_code=403, detail="Forbidden: Access is denied.")
    if not os.path.isfile(path):
        raise HTTPException(
            status_code=404,
            detail="The capture is no longer on disk. It will leave the catalog with the next scan.",
        )
    return path


async def _catalog_entry(context: AppContext, file_hash: str) -> dict:
    metadata = await asyncio.to_thread(
        context.redis_client.hgetall, f"{PCAP_FILE_KEY_PREFIX}:{file_hash}"
    )
    if not metadata:
        raise HTTPException(status_code=404, detail="File not found")
    return metadata


def remove_file(path: str):
    try:
        os.remove(path)
        logger.info(f"Cleaned up temporary file: {path}")
    except OSError as e:
        logger.error(f"Error deleting temporary file {path}: {e}")


def _filter_to_temp_file(source: str, display_filter: str, session_reset: int) -> str:
    """Write the packets of `source` matching `display_filter` to a temp file
    and return its path. Raises HTTPException on a bad filter or no match."""
    error = get_export_service().validate(display_filter)
    if error:
        raise HTTPException(status_code=400, detail=f"Invalid display filter: {error}")

    fd, temp_path = tempfile.mkstemp(prefix="filtered_", suffix=".pcap")
    os.close(fd)
    cmd = ["tshark", "-n", "-r", source, "-Y", display_filter, "-w", temp_path, "-F", "pcap"]
    if session_reset > 0:  # 0 means "never reset", as in the scanner
        cmd += ["-M", str(session_reset)]
    logger.info("Starting one-shot filtered download: %s", " ".join(cmd))
    try:
        try:
            proc = subprocess.run(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
                timeout=LEGACY_FILTER_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            raise HTTPException(
                status_code=504,
                detail="Filtering took too long. Use POST /exports for large captures.",
            )
        wrote = os.path.exists(temp_path) and os.path.getsize(temp_path) > 0
        if proc.returncode != 0 and not wrote:
            logger.error("tshark filter failed: %s", proc.stderr)
            raise HTTPException(status_code=500, detail="Failed to filter the pcap file.")
        # tshark always writes a file header, so "no match" is a file with no
        # packets, not an empty file (which used to be returned with a 200).
        if not count_packets(temp_path):
            raise HTTPException(status_code=404, detail=f"No packets match the filter '{display_filter}'")
        return temp_path
    except BaseException:
        remove_file(temp_path)
        raise


async def _filtered_response(context, metadata, display_filter, background_tasks, download_name):
    source = resolve_catalog_file(context, metadata)
    async with _legacy_filter_slots:
        temp_path = await asyncio.to_thread(
            _filter_to_temp_file, source, display_filter, context.config.pcap.tshark_session_reset
        )
    background_tasks.add_task(remove_file, temp_path)
    return FileResponse(temp_path, media_type=PCAP_MEDIA_TYPE, filename=download_name)


@router.get(
    "/pcaps/download/{file_hash}", summary="Download a specific pcap file by hash"
)
async def download_pcap_by_hash(
    file_hash: str,
    background_tasks: BackgroundTasks,
    # display filter
    filter: str | None = Query(default=None, max_length=2000,
                               description="Filter to apply when downloading a subset of the pcap"),
    context: AppContext = Depends(get_app_context)
):
    metadata = await _catalog_entry(context, file_hash)
    filename = metadata.get("filename")

    # No filter -> return original file
    if not filter or not filter.strip():
        path = resolve_catalog_file(context, metadata)
        return FileResponse(path, media_type=PCAP_MEDIA_TYPE, filename=filename)

    # Kept for old links; the UI now uses POST /exports (background job + cache).
    return await _filtered_response(context, metadata, normalize_filter(filter), background_tasks, filename)


@router.get(
    "/pcaps/download/{file_hash}/filter", summary="Download a filtered subset of a pcap"
)
async def download_filtered_pcap(
    file_hash: str,
    protocol: str,
    background_tasks: BackgroundTasks,
    context: AppContext = Depends(get_app_context),
):
    if not re.match(r"^[a-zA-Z0-9_.-]+$", protocol):
        raise HTTPException(status_code=400, detail="Invalid protocol format")
    metadata = await _catalog_entry(context, file_hash)
    return await _filtered_response(
        context, metadata, protocol, background_tasks,
        f"subset_{protocol}_{metadata.get('filename')}",
    )
