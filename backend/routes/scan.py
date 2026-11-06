from fastapi import APIRouter
from pydantic import BaseModel
from services.config import ScanMode, save_runtime_scan_mode
from services.context import get_app_context, AppContext
from typing import Optional, List
from fastapi import Depends, Query, Request, HTTPException
from fastapi.responses import JSONResponse
import asyncio

from services.scan import BackfillState, RebuildSearchIndexState, ScanState, get_scan_service
from services.logger import get_logger

router = APIRouter(tags=["Scan"])

logger = get_logger(__name__)


@router.post("/reindex", summary="Rescan pcap directories and rebuild the index")
async def reindex_pcaps(
    request: Request,
    exclude: Optional[List[str]] = Query(None),
    context: AppContext = Depends(get_app_context),
):

    return await _start_scan(context, exclude=exclude)


async def _start_scan(context: AppContext, *, exclude=None, target_folder: Optional[str] = None):
    # A scan cannot do anything without Redis: say so now instead of answering
    # "started" and failing in the background.
    state = await asyncio.to_thread(context.redis_state)
    if state != "ready":
        detail = ("The catalog is still loading, try again in a few seconds."
                  if state == "loading" else "The catalog database (Redis) is not reachable.")
        return JSONResponse(content={"status": "unavailable", "detail": detail}, status_code=503)

    scan_service = get_scan_service()
    # Checked and marked "running" in one step, so two quick clicks cannot
    # start two scans.
    if not scan_service.try_begin_scan():
        return JSONResponse(
            content={"status": "busy", "message": "A scan is already running."},
            status_code=409,
        )

    asyncio.get_running_loop().run_in_executor(
        context.thread_executor,
        lambda: scan_service.scan_wrapper(exclude_files=exclude, target_folder=target_folder),
    )
    return JSONResponse(content={"status": "started"})


@router.get("/scan-status")
async def scan_status_endpoint():
    """State of the current or last scan. While a scan runs, total_files,
    processed_files and current_files (being scanned right now) show progress."""
    return get_scan_service().status_snapshot()


@router.post("/backfill/total-packets", summary="Backfill total packet counts for existing pcaps")
async def backfill_total_packets_endpoint(
    context: AppContext = Depends(get_app_context),
):
    scan_service = get_scan_service()
    if scan_service.backfill_status.get("state") == BackfillState.RUNNING:
        return JSONResponse(
            content={"status": "busy", "message": "A backfill is already running."},
            status_code=409,
        )

    loop = asyncio.get_event_loop()
    loop.run_in_executor(
        context.thread_executor,
        lambda: scan_service.backfill_wrapper(),
    )
    return JSONResponse(content={"status": "started"})


@router.get("/backfill-status")
async def backfill_status_endpoint():
    scan_service = get_scan_service()
    return scan_service.backfill_status


@router.post(
    "/backfill/rebuild-searchindex",
    summary="Rebuild all sort indexes from existing Redis data",
)
async def rebuild_searchindex_endpoint(
    context: AppContext = Depends(get_app_context),
):
    scan_service = get_scan_service()
    if scan_service.rebuild_searchindex_status.get("state") == RebuildSearchIndexState.RUNNING:
        return JSONResponse(
            content={
                "status": "busy",
                "message": "A rebuild-searchindex job is already running.",
            },
            status_code=409,
        )

    loop = asyncio.get_event_loop()
    loop.run_in_executor(
        context.thread_executor,
        lambda: scan_service.rebuild_searchindex_wrapper(),
    )
    return JSONResponse(content={"status": "started"})


@router.get("/backfill/rebuild-searchindex-status")
async def rebuild_searchindex_status_endpoint():
    scan_service = get_scan_service()
    return scan_service.rebuild_searchindex_status

@router.post("/scan-cancel", summary="Cancel the currently running scan")
async def cancel_scan():
    scan_service = get_scan_service()
    if scan_service.scan_status["state"] != ScanState.RUNNING:
        return JSONResponse(
            content={"status": "no_scan", "message": "No scan is currently running."},
            status_code=400,
        )

    scan_service.scan_cancel_event.set()
    logger.info("Scan cancellation requested by user")
    return JSONResponse(
        content={
            "status": "cancelling",
            "message": "Scan cancellation has been triggered.",
        }
    )

@router.get("/scan-config", summary="Get current scan configuration")
async def scan_config(*, context: AppContext = Depends(get_app_context)):
    """Expose current runtime scan configuration."""
    pcap_config = context.config.pcap
    return {
        "scan_mode": pcap_config.scan_mode.value,
        "pebc": pcap_config.quick_scan.pebc if pcap_config.scan_mode == ScanMode.QUICK else None,
        "min_file_size": pcap_config.quick_scan.min_file_size if pcap_config.scan_mode == ScanMode.QUICK else None,
        "config_version": pcap_config.quick_scan.config_version,
    }

class ScanConfigUpdate(BaseModel):
    scan_mode: ScanMode


@router.put("/scan-config", summary="Change the scan mode used by the next scan")
async def update_scan_config(
    body: ScanConfigUpdate,
    context: AppContext = Depends(get_app_context),
):
    scan_service = get_scan_service()
    if scan_service.scan_status["state"] == ScanState.RUNNING:
        raise HTTPException(status_code=409, detail="A scan is running. Change the mode after it finishes.")

    previous = context.config.pcap.scan_mode
    # Stored in Redis (survives restarts with the catalog), not in a config file:
    # the image's config.yaml is read-only defaults and is not mounted.
    await asyncio.to_thread(save_runtime_scan_mode, context.redis_client, body.scan_mode)
    context.config.pcap.scan_mode = body.scan_mode
    logger.info("Scan mode changed from %s to %s", ScanMode(previous).value, body.scan_mode.value)

    return {**(await scan_config(context=context)), "persisted": True}


@router.post(
    "/reindex/{folder_name}", summary="Reindex a specific folder under PCAP directories"
)
async def reindex_specific_folder(
    folder_name: str,
    request: Request,
    exclude: Optional[List[str]] = Query(None),
    context: AppContext = Depends(get_app_context),
):
    # Runs in the background like /reindex, under the same "one scan at a
    # time" rule (it used to run inside the request, next to any other scan).
    return await _start_scan(context, exclude=exclude, target_folder=folder_name)
