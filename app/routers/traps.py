"""Decoy routes that imitate commonly scraped configuration files."""

from fastapi import APIRouter, Request

from app.core.forensics import extract_client_ip
from app.services.alert_engine import register_breach

router = APIRouter(tags=["Decoy Traps"])


@router.get("/.env", summary="Decoy environment file")
@router.get("/config.json", summary="Decoy application configuration")
async def trap_env_file(request: Request):
    await register_breach(
        token_type="Environment File Scrape",
        source_ip=extract_client_ip(request),
        user_agent=request.headers.get("user-agent", "Unknown"),
        path=request.url.path,
    )
    return {
        "DB_HOST": "db.canarymesh.invalid",
        "DB_USER": "canary-decoy",
        "DB_PASS": "NOT_A_REAL_CREDENTIAL",
    }
