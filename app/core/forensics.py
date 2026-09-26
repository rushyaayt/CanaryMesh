"""CanaryMesh Forensic Telemetry & Adversary Fingerprinting Engine"""

import ipaddress
import re
from typing import Any, Dict, Optional, Tuple
import httpx
from starlette.requests import Request
from app.config import get_settings


KNOWN_OFFENSIVE_TOOLS = [
    (r"sqlmap", "Automated SQL Injection Scanner (SQLMap)"),
    (r"nikto", "Web Vulnerability Scanner (Nikto)"),
    (r"nuclei", "Vulnerability Scanner (Nuclei)"),
    (r"curl", "Command-line HTTP Client (cURL)"),
    (r"python-requests", "Python Automation / Script (requests)"),
    (r"httpx", "Python HTTPX Client"),
    (r"go-http-client", "Golang Binary / Microservice"),
    (r"postman", "API Testing Tool (Postman)"),
    (r"aws-cli", "AWS Command Line Interface"),
    (r"boto3", "AWS SDK for Python (Boto3)"),
    (r"wget", "Command-line Downloader (wget)"),
    (r"masscan|zgrab|nmap", "Port / Service Reconnaissance Scanner"),
    (r"burp", "Burp Suite Security Proxy"),
]


def extract_client_ip(request: Request) -> str:
    """Extracts client IP, respecting trusted proxy headers if configured."""
    settings = get_settings()

    if settings.trust_proxy_headers:
        # Check CF-Connecting-IP (Cloudflare)
        cf_ip = request.headers.get("cf-connecting-ip")
        if cf_ip:
            return cf_ip.strip()

        # Check X-Real-IP
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()

        # Check X-Forwarded-For
        x_forwarded = request.headers.get("x-forwarded-for")
        if x_forwarded:
            # Client IP is the first in comma-separated list
            first_ip = x_forwarded.split(",")[0].strip()
            if first_ip:
                return first_ip

    if request.client and request.client.host:
        return request.client.host

    return "127.0.0.1"


def analyze_user_agent(user_agent: str) -> Dict[str, Any]:
    """Inspects User-Agent string for reconnaissance tools and automation scripts."""
    ua_lower = user_agent.lower()
    tool_detected = "Unknown Browser / Custom Client"
    is_automated = False

    for pattern, label in KNOWN_OFFENSIVE_TOOLS:
        if re.search(pattern, ua_lower):
            tool_detected = label
            is_automated = True
            break

    if not is_automated and any(x in ua_lower for x in ["bot", "spider", "crawler", "scrape"]):
        tool_detected = "Automated Crawler / Scanner Bot"
        is_automated = True

    return {
        "raw_user_agent": user_agent,
        "tool_detected": tool_detected,
        "is_automated_tool": is_automated,
    }


def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return True


async def resolve_ip_geo(ip_str: str) -> Dict[str, Any]:
    """Resolves IP Geolocation & ASN with graceful offline/local fallback."""
    settings = get_settings()

    if is_private_ip(ip_str):
        return {
            "status": "success",
            "country": "Internal / Local Network",
            "countryCode": "LOCAL",
            "region": "Intranet",
            "city": "Private Subnet",
            "isp": "Localhost / Enterprise VPC",
            "org": "Internal Infrastructure",
            "as": "AS0 (Internal)",
            "query": ip_str,
        }

    if not settings.geoip_enabled:
        return {"status": "disabled", "query": ip_str}

    # Public IP lookup via free IP-API endpoint with short timeout
    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip_str}?fields=status,message,country,countryCode,regionName,city,isp,org,as,query"
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        "status": "success",
                        "country": data.get("country", "Unknown"),
                        "countryCode": data.get("countryCode", "XX"),
                        "region": data.get("regionName", "Unknown"),
                        "city": data.get("city", "Unknown"),
                        "isp": data.get("isp", "Unknown"),
                        "org": data.get("org", "Unknown"),
                        "as": data.get("as", "Unknown"),
                        "query": ip_str,
                    }
    except Exception:
        pass

    return {
        "status": "fallback",
        "country": "External Internet",
        "countryCode": "WAN",
        "city": "Unknown",
        "isp": "Public Route",
        "query": ip_str,
    }


def calculate_threat_severity(token_type: str, is_expired: bool, is_automated: bool) -> str:
    """Calculates risk severity score based on token type and timing context."""
    if is_expired:
        # An expired token being queried means someone discovered a decommissioned/historical leak!
        return "HIGH"

    if token_type in ["aws_iam", "database_url", "stripe_secret"]:
        return "CRITICAL"

    if token_type == "ci_ephemeral":
        # Ephemeral CI key being used outside normal build implies active CI compromise
        return "CRITICAL"

    return "HIGH"
