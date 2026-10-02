"""Decoy routes that imitate commonly scraped configuration files."""

from fastapi import APIRouter, BackgroundTasks, Request

from app.core.forensics import extract_client_ip
from app.services.alert_engine import register_breach

router = APIRouter(tags=["Decoy Traps"])


@router.get("/.env", summary="Decoy environment file")
@router.get("/config.json", summary="Decoy application configuration")
async def trap_env_file(request: Request, background_tasks: BackgroundTasks):
    await register_breach(
        token_type="Environment File Scrape",
        source_ip=extract_client_ip(request),
        user_agent=request.headers.get("user-agent", "Unknown"),
        path=str(request.url),
        background_tasks=background_tasks,
    )
    return {
        "DB_HOST": "10.0.0.50",
        "DB_USER": "admin",
        "DB_PASS": "Canary_Trap_9823!",
    }
