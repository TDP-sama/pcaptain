# Apply asynchronous processing (done)
# Apply incremental redis update (done)
# Apply CPU/memory usage limitation for scanning (done)
# Use backoff to check redis status for initial scanning (done)
# Fix some environment errors (done)
# Apply status health check api (done)
# Apply packets per protocol counting, using t-shark (done)
# Apply fuzzy searching (done)
# Apply configurable mounted directory

import redis
import contextlib
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import JSONResponse
import asyncio

from services.context import init_app_context
from services.logger import get_logger, setup_logging
from services.scan import ensure_index_version, get_scan_service
from services.config import apply_runtime_settings, load_config

from routes.scan import router as scan_router
from routes.protocols import router as protocols_router
from routes.pcaps import router as pcaps_router
from routes.search import router as search_router
from routes.dashboard import router as dashboard_router
from routes.exports import router as exports_router

config = load_config()
setup_logging(config.log.level)
logger = get_logger(__name__)
context = init_app_context(config)

# SCAN SCHEDULER
async def scheduled_scan_loop():
    """Runs in the background and triggers a scan every X seconds."""
    while True:
        try:
            interval = config.pcap.scan_interval_seconds
            scan_service = get_scan_service()

            await asyncio.sleep(interval)

            # Any state but "running": a scan that failed or was cancelled
            # must not stop the scheduled ones for good.
            if scan_service.try_begin_scan():
                logger.info(f"Starting scheduled scan (Interval: {interval}s)...")
                loop = asyncio.get_running_loop()

                await loop.run_in_executor(
                    context.thread_executor,
                    lambda: scan_service.scan_wrapper(
                        exclude_files=None
                    ),
                )
            else:
                logger.info("Scheduled scan skipped: Scanner is currently busy.")

        except Exception as e:
            logger.error(f"Error in scheduled scan loop: {e}")
            await asyncio.sleep(60)

async def start_when_redis_is_ready():
    """Wait for Redis in the background, then restore UI settings and run the
    initial scan if the catalog is empty. The API is up meanwhile; /health
    reports the Redis state and catalog requests answer 503 until it is ready."""
    while not await asyncio.to_thread(context.wait_for_redis, config.redis.wait_seconds):
        logger.error("Still waiting for Redis; scans and searches are unavailable until it is ready")
    redis_client = context.redis_client
    try:
        await asyncio.to_thread(apply_runtime_settings, redis_client, config)
        # Repairs protocol sets left inconsistent by older versions (once).
        await asyncio.to_thread(ensure_index_version, redis_client)
        # Only need to know whether anything is indexed: one SCAN step, not a
        # blocking KEYS over the whole catalog.
        existing_pcap_key = await asyncio.to_thread(
            lambda: next(redis_client.scan_iter("pcap:file:*", count=1000), None)
        )
    except redis.exceptions.RedisError as e:
        logger.error(f"Startup Redis check failed: {e}")
        return

    if existing_pcap_key:
        logger.info("Found indexed pcaps in Redis. Skipping initial scan.")
        return
    logger.info("No indexed pcaps found in Redis. Starting initial scan...")
    scan_service = get_scan_service()
    if not scan_service.try_begin_scan():
        return  # someone already pressed Scan
    asyncio.get_running_loop().run_in_executor(
        context.thread_executor, lambda: scan_service.scan_wrapper(exclude_files=None)
    )


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    await context.initialize_async()
    startup_task = asyncio.create_task(start_when_redis_is_ready())
    scan_task = asyncio.create_task(scheduled_scan_loop())

    try:
        yield
    finally:
        logger.info("Shutting down background tasks...")
        for task in (startup_task, scan_task):
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

app = FastAPI(
    title="Pcap Catalog Service",
    description="A service to index and search pcap files by protocol using a Redis-native inverted index.",
    lifespan=lifespan,
    docs_url=None,
)


@app.get("/docs", include_in_schema=False)
async def swagger_ui():
    # A relative schema URL, so the page works both at :7000/docs and behind
    # the web UI's proxy at /api/docs (the default "/openapi.json" pointed at
    # the frontend, which has no such file).
    return get_swagger_ui_html(openapi_url="openapi.json", title=f"{app.title} - API docs")

app.include_router(scan_router)
app.include_router(protocols_router)
app.include_router(pcaps_router)
app.include_router(search_router)
app.include_router(dashboard_router)
app.include_router(exports_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(redis.exceptions.ConnectionError)
@app.exception_handler(redis.exceptions.TimeoutError)
async def redis_unavailable(request: Request, exc: redis.exceptions.RedisError):
    # BusyLoadingError is a ConnectionError: Redis is up but still reading its dump.
    # TimeoutError: Redis accepted the connection but did not answer in time.
    loading = isinstance(exc, redis.exceptions.BusyLoadingError)
    detail = ("The catalog is still loading, try again in a few seconds."
              if loading else "The catalog database (Redis) is not reachable.")
    return JSONResponse(status_code=503, content={"detail": detail})


@app.get("/health")
async def health_check():
    redis_state = await asyncio.to_thread(context.redis_state)
    return {"status": "OK" if redis_state == "ready" else "DEGRADED", "redis": redis_state}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=config.port)
