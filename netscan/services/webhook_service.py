import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse
import httpx
from sqlmodel import Session, select
from netscan.config import settings
from netscan.models import Webhook

logger = logging.getLogger(__name__)


def _sanitize_url(url: str) -> str:
    """Extract safe host info from URL for logging."""
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

        async with httpx.AsyncClient(timeout=settings.WEBHOOK_TIMEOUT_SECONDS) as client:
            for wh in webhooks:
                # Check if webhook is subscribed to this event
                if wh.events and event_name not in wh.events and "*" not in wh.events:
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
                        response = await client.post(wh.url, content=payload_bytes, headers=headers)
                        attempt_duration_ms = int((datetime.now(timezone.utc) - attempt_start).total_seconds() * 1000)

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
                        attempt_duration_ms = int((datetime.now(timezone.utc) - attempt_start).total_seconds() * 1000)
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
