import asyncio
import os

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from services.context import AppContext, get_app_context
from services.export import JobState, download_name, get_export_service, normalize_filter
from services.logger import get_logger
from services.scan import PCAP_FILE_KEY_PREFIX
from routes.pcaps import resolve_catalog_file

router = APIRouter(tags=["Exports"])
logger = get_logger(__name__)


class ExportRequest(BaseModel):
    file_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    filter: str = Field(..., min_length=1, max_length=2000, description="Wireshark display filter")


def _job_payload(job, context: AppContext) -> dict:
    data = job.to_dict()
    if job.state == JobState.READY:
        data["download_url"] = f"{context.config.public_url}/exports/{job.id}/download"
    return data


@router.get("/exports/validate", summary="Check a Wireshark display filter without running it")
async def validate_filter(filter: str = Query(..., min_length=1, max_length=2000)):
    error = await asyncio.to_thread(get_export_service().validate, normalize_filter(filter))
    return {"valid": error is None, "error": error}


@router.post("/exports", summary="Extract the packets of one capture that match a display filter")
async def create_export(body: ExportRequest, context: AppContext = Depends(get_app_context)):
    redis = context.redis_client
    if not redis:
        raise HTTPException(503, "Redis unavailable")

    meta = await asyncio.to_thread(redis.hgetall, f"{PCAP_FILE_KEY_PREFIX}:{body.file_hash}")
    if not meta:
        raise HTTPException(404, "File not found in the catalog")

    # Same check as a plain download. The catalog path is normalised, not
    # resolved, so a capture that is a symlink can be exported too.
    source = await asyncio.to_thread(resolve_catalog_file, context, meta)

    service = get_export_service()
    display_filter = normalize_filter(body.filter)
    # A filter that already produced an export was valid; skip the tshark check
    # so cache hits answer immediately.
    if not service.has_result(body.file_hash, display_filter):
        error = await asyncio.to_thread(service.validate, display_filter)
        if error:
            raise HTTPException(400, f"Invalid display filter: {error}")

    job = await asyncio.to_thread(
        service.start,
        file_hash=body.file_hash,
        source_path=source,
        source_name=meta.get("filename") or os.path.basename(source),
        display_filter=display_filter,
    )
    return _job_payload(job, context)


@router.get("/exports/{job_id}", summary="Progress and result of an export")
async def get_export(job_id: str, context: AppContext = Depends(get_app_context)):
    job = get_export_service().get(job_id)
    if not job:
        raise HTTPException(404, "Unknown export. Start it again with POST /exports.")
    return _job_payload(job, context)


@router.get("/exports/{job_id}/download", summary="Download a finished export")
async def download_export(job_id: str):
    service = get_export_service()
    job = service.get(job_id)
    if not job or job.state != JobState.READY:
        raise HTTPException(404, "This export is not ready")
    path = await asyncio.to_thread(service.extract_file, job)
    if not path.exists():
        raise HTTPException(404, "This export was removed from the cache. Start it again.")
    return FileResponse(
        path,
        media_type="application/x-pcapng",  # extracts are written as pcapng
        filename=download_name(job.source_name, job.filter),
    )
