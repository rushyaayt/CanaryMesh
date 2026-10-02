"""CanaryMesh - Honeytoken-as-a-Service Application Entrypoint"""

import asyncio
import logging
import os
import sqlite3
import sys
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from redis.exceptions import RedisError
from app.api import alerts, gateway, seed, tokens
from app.config import get_settings
from app.database import get_db
from app.routers import breaches, traps, webhooks, ws
from app.services.alert_engine import alert_connections, notification_worker

logger = logging.getLogger("canarymesh")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Ensure database schema is primed
    db = get_db()
    settings = get_settings()
    notification_task = asyncio.create_task(notification_worker())
    retention_task = None
    if settings.redis_url:
        try:
            await alert_connections.start_redis(settings.redis_url)
        except RedisError as exc:
            logger.warning(
                "Redis alert feed unavailable; using process-local WebSockets (%s)",
                type(exc).__name__,
            )
    if settings.retention_days > 0:
        db.purge_old_events(settings.retention_days)
        retention_task = asyncio.create_task(_retention_worker())

    print("\n" + "=" * 65)
    print(r"""
   ____                            __  __          _     
  / ___|__ _ _ __   __ _ _ __ _   |  \/  | ___ ___| |__  
 | |   / _` | '_ \ / _` | '__| | | | |\/| |/ _ \ __| '_ \ 
 | |__| (_| | | | | (_| | |  | |_| | |  | |  __\__ \ | | |
  \____\__,_|_| |_|\__,_|_|   \__, |_|  |_|\___|___/_| |_|
                              |___/                        
    """)
    print("   [+] CanaryMesh - Honeytoken-as-a-Service Engine")
    print(f"   [+] Server: {settings.public_url}")
    print(f"   [+] Dashboard: {settings.public_url}/")
    print("   [+] Decoy Trap Gateway: Ready")
    print("   [+] CI/CD Seeder: Ready")
    print("=" * 65 + "\n")
    try:
        yield
    finally:
        notification_task.cancel()
        if retention_task:
            retention_task.cancel()
        try:
            await notification_task
        except asyncio.CancelledError:
            pass
        if retention_task:
            try:
                await retention_task
            except asyncio.CancelledError:
                pass
        await alert_connections.stop_redis()


async def _retention_worker() -> None:
    while True:
        await asyncio.sleep(24 * 60 * 60)
        settings = get_settings()
        if settings.retention_days > 0:
            try:
                removed = get_db().purge_old_events(settings.retention_days)
            except sqlite3.Error as exc:
                logger.error("Scheduled event retention failed (%s)", type(exc).__name__)
            else:
                logger.info("Scheduled event retention removed %s records", removed)


app = FastAPI(
    title="CanaryMesh - Honeytoken-as-a-Service",
    description=(
        "Active cyber deception platform that deploys realistic, low-cost honeytokens "
        "into code, cloud, and CI/CD pipelines to detect suspicious credential use."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware for open integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(tokens.router)
app.include_router(seed.router)
app.include_router(alerts.router)
app.include_router(gateway.router)
app.include_router(breaches.router)
app.include_router(traps.router)
app.include_router(webhooks.router)
app.include_router(ws.router)

# Mount Static Files
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(os.path.join(STATIC_DIR, "css"), exist_ok=True)
os.makedirs(os.path.join(STATIC_DIR, "js"), exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
async def serve_dashboard():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "CanaryMesh API is online. Static dashboard index.html not yet installed."}


@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "healthy",
        "service": "CanaryMesh Deception Platform",
        "version": "0.1.0",
    }
