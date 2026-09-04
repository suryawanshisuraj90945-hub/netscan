import hashlib
import hmac
import ipaddress
import json
import logging
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse

import httpx
from sqlmodel import Session, select

from netscan.config import settings
from netscan.models import Webhook

logger = logging.getLogger(__name__)

# SSRF-safe blocked IP ranges and addresses
_BLOCKED_RANGES: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.IPv4Network("127.0.0.0/8"),       # localhost
    ipaddress.IPv4Network("10.0.0.0/8"),        # private-Class A
    ipaddress.IPv4Network("172.16.0.0/12"),     # private-Class B
    ipaddress.IPv4Network("192.168.0.0/16"),    # private-Class C
    ipaddress.IPv4Network("169.254.0.0/16"),    # link-local (APIPA)
    ipaddress.IPv4Network("0.0.0.0/8"),         # reserved
    ipaddress.IPv4Network("255.255.255.255/32"), # broadcast
]

_BLOCKED_IPV6_RANGES: list[ipaddress.IPv6Network] = [
    ipaddress.IPv6Network("::1/128"),             # localhost
    ipaddress.IPv6Network("fc00::/7"),            # unique local (ULA)
    ipaddress.IPv6Network("fe80::/10"),           # link-local
]

SAFE_SCHEMES = {"http", "https"}


def _is_private_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP address is in a private/reserved/metadata range."""
    for network in _BLOCKED_RANGES:
        if ip in network:
            return True
    for network in _BLOCKED_IPV6_RANGES:
        if ip in network:
            return True
    if ip.is_private:
        return True
    return False


def _parse_url_hostname(url: str) -> str | None:
    """Extract the hostname from a URL."""
    try:
        parsed = urlparse(url)
        return parsed.hostname
    except Exception:
        return None


def _check_url_ssrf(url: str) -> bool:
    """
    Check if a URL is safe from SSRF.
    Returns True if the URL is safe (OK to request), False if it should be blocked.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    scheme = (parsed.scheme or "").lower()
    if scheme not in SAFE_SCHEMES:
        return False

    hostname = parsed.hostname
    if not hostname:
        # No hostname; try to check if it's a direct IP
        try:
            ip = ipaddress.ip_address(parsed.path or "")
            if ip.version == 4 and ip in ipaddress.IPv4Network("0.0.0.0/8"):
                return False
        except Exception:
            pass
        return True

    # Resolve hostname via DNS and check resolved IPs
    try:
        addr_info = socket.gethostbyname_ex(hostname)
        resolved_ips = addr_info[2]
    except Exception:
        # DNS resolution failed → fail closed: reject the destination
        return False

    # Check all resolved IPs against blocked ranges
    for resolved_ip_str in resolved_ips:
        try:
            resolved_ip = ipaddress.ip_address(resolved_ip_str)
            if _is_private_ip(resolved_ip):
                return False
        except ValueError:
            continue

    # Also check direct IP in hostname
    try:
        direct_ip = ipaddress.ip_address(hostname)
        if _is_private_ip(direct_ip):
            return False
    except ValueError:
        pass

    return True


def _sanitize_url(url: str) -> str:
    """Extract host info from URL for logging (no security purpose)."""
    try:
        parsed = urlparse(url)
        return parsed.hostname or "unknown"
    except Exception:
        return "unknown"


class WebhookDispatcher:
    """Dispatches webhook events with full object snapshots and HMAC signatures."""

    @staticmethod
    def generate_signature(secret: str, payload_bytes: bytes) -> str:
        return hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()

    @classmethod
    async def dispatch_event(
        cls,
        event_name: str,
        data: Dict[str, Any],
        session: Session,
    ) -> None:
        statement = select(Webhook).where(Webhook.is_active == True)
        webhooks = session.exec(statement).all()

        if not webhooks:
            return

        payload = {
            "event": event_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }
        payload_json = json.dumps(payload, default=str)
        payload_bytes = payload_json.encode("utf-8")

        async with httpx.AsyncClient(
            timeout=settings.WEBHOOK_TIMEOUT_SECONDS, follow_redirects=False
        ) as client:
            for wh in webhooks:
                # Check if webhook is subscribed to this event
                if wh.events and event_name not in wh.events and "*" not in wh.events:
                    continue

                # SSRF: validate destination before making HTTP request
                if not _check_url_ssrf(wh.url):
                    logger.warning(
                        "Webhook delivery blocked by SSRF protection",
                        extra={
                            "webhook_id": str(wh.id),
                            "webhook_name": wh.name,
                            "event": event_name,
                            "blocked_url": wh.url,
                        },
                    )
                    continue

                signature = cls.generate_signature(wh.secret, payload_bytes)
                headers = {
                    "Content-Type": "application/json",
                    "X-NetScan-Event": event_name,
                    "X-NetScan-Signature": signature,
                }

                safe_host = _sanitize_url(wh.url)

                for attempt in range(settings.WEBHOOK_MAX_RETRIES):
                    attempt_start = datetime.now(timezone.utc)
                    try:
                        response = await client.post(
                            wh.url, content=payload_bytes, headers=headers
                        )
                        attempt_duration_ms = int(
                            (datetime.now(timezone.utc) - attempt_start).total_seconds() * 1000
                        )

                        # SSRF: check redirect targets to prevent bypass
                        # Use status_code check instead of response.is_redirect
                        # (test mocks may not have is_redirect attribute)
                        status_code = response.status_code
                        if 300 <= status_code < 400:
                            location = response.headers.get("location")
                            if location:
                                try:
                                    if not _check_url_ssrf(location):
                                        logger.warning(
                                            "Webhook delivery blocked by SSRF protection on redirect",
                                            extra={
                                                "webhook_id": str(wh.id),
                                                "webhook_name": wh.name,
                                                "event": event_name,
                                                "redirect_url": location,
                                            },
                                        )
                                        break
                                except Exception:
                                    pass

                        if response.is_success:
                            logger.info(
                                "Webhook delivered successfully",
                                extra={
                                    "webhook_id": str(wh.id),
                                    "webhook_name": wh.name,
                                    "event": event_name,
                                    "attempt": attempt + 1,
                                    "status_code": response.status_code,
                                    "duration_ms": attempt_duration_ms,
                                    "target_host": safe_host,
                                },
                            )
                            break
                        else:
                            logger.warning(
                                "Webhook returned non-success status",
                                extra={
                                    "webhook_id": str(wh.id),
                                    "webhook_name": wh.name,
                                    "event": event_name,
                                    "attempt": attempt + 1,
                                    "status_code": response.status_code,
                                    "duration_ms": attempt_duration_ms,
                                    "target_host": safe_host,
                                },
                            )
                    except Exception as e:
                        attempt_duration_ms = int(
                            (datetime.now(timezone.utc) - attempt_start).total_seconds() * 1000
                        )
                        logger.error(
                            "Webhook delivery error",
                            extra={
                                "webhook_id": str(wh.id),
                                "webhook_name": wh.name,
                                "event": event_name,
                                "attempt": attempt + 1,
                                "error_type": type(e).__name__,
                                "error_message": str(e),
                                "duration_ms": attempt_duration_ms,
                                "target_host": safe_host,
                            },
                            exc_info=True,
                        )

                else:
                    # Max retries exhausted
                    logger.error(
                        "Webhook delivery failed after max retries",
                        extra={
                            "webhook_id": str(wh.id),
                            "webhook_name": wh.name,
                            "event": event_name,
                            "attempts": settings.WEBHOOK_MAX_RETRIES,
                            "target_host": safe_host,
                        },
                    )