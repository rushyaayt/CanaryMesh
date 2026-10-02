"""SSRF-resistant HTTPS webhook validation and delivery."""

import asyncio
import ipaddress
import logging
import socket
from urllib.parse import urlsplit

import aiohttp
from aiohttp.abc import AbstractResolver
from fastapi import HTTPException, status

from app.config import get_settings

logger = logging.getLogger("canarymesh.webhook_security")
METADATA_ADDRESSES = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("168.63.129.16"),
    ipaddress.ip_address("fd00:ec2::254"),
}


def _is_public_address(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global


def _is_metadata_address(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip in METADATA_ADDRESSES


class PublicAddressResolver(AbstractResolver):
    async def resolve(self, host, port=0, family=socket.AF_INET):
        allowed_hosts = set(get_settings().webhook_allowed_hosts)
        allowlisted = host.lower().rstrip(".") in allowed_hosts
        try:
            ip = ipaddress.ip_address(host)
            addresses = [(str(ip), ip.version)]
        except ValueError:
            loop = asyncio.get_running_loop()
            records = await loop.getaddrinfo(
                host, port, family=family, type=socket.SOCK_STREAM
            )
            addresses = list(dict.fromkeys((record[4][0], 4 if record[0] == socket.AF_INET else 6)
                                           for record in records))
        if not addresses:
            raise OSError("Webhook hostname did not resolve")
        if any(_is_metadata_address(address) for address, _ in addresses):
            raise OSError("Webhook hostname resolves to a cloud metadata address")
        if not allowlisted and any(not _is_public_address(address) for address, _ in addresses):
            raise OSError("Webhook hostname resolves to a non-public address")
        return [
            {
                "hostname": host,
                "host": address,
                "port": port,
                "family": socket.AF_INET if version == 4 else socket.AF_INET6,
                "proto": 0,
                "flags": 0,
            }
            for address, version in addresses
        ]

    async def close(self):
        return None


async def validate_webhook_url(url: str) -> None:
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Webhook URL is malformed",
        ) from exc
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port not in (None, 443)
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Webhook URL must be an HTTPS URL on port 443 without embedded credentials",
        )
    resolver = PublicAddressResolver()
    try:
        await asyncio.wait_for(
            resolver.resolve(host, 443, family=socket.AF_UNSPEC), timeout=3
        )
    except (OSError, ValueError, asyncio.TimeoutError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Webhook hostname is not permitted or could not be safely resolved",
        ) from exc
    finally:
        await resolver.close()


async def post_webhook(url: str, payload: dict) -> bool:
    try:
        await validate_webhook_url(url)
        timeout = aiohttp.ClientTimeout(total=5)
        connector = aiohttp.TCPConnector(
            resolver=PublicAddressResolver(),
            use_dns_cache=False,
            ssl=True,
        )
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            async with session.post(
                url,
                json=payload,
                allow_redirects=False,
                headers={"Content-Type": "application/json"},
            ) as response:
                return 200 <= response.status < 300
    except HTTPException as exc:
        logger.warning("Webhook destination rejected (HTTP %s)", exc.status_code)
        return False
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError) as exc:
        logger.warning("Webhook delivery failed (%s)", type(exc).__name__)
        return False
