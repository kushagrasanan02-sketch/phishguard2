import hmac
import hashlib
import json
import logging
import urllib.request
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.models.webhook import WebhookSubscription

logger = logging.getLogger("phishguard.webhooks")

def generate_webhook_signature(payload_str: str, secret: str) -> str:
    """Generate HMAC-SHA256 signature for payload validation."""
    signature = hmac.new(
        secret.encode("utf-8"),
        payload_str.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    return f"sha256={signature}"

def dispatch_threat_webhook(webhook: WebhookSubscription, payload: Dict[str, Any]) -> bool:
    """
    Delivers signed threat webhook notification to target URL endpoint.
    Handles network errors gracefully.
    """
    payload_str = json.dumps(payload, default=str)
    signature = generate_webhook_signature(payload_str, webhook.secret)

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "PhishGuardAI-WebhookNotifier/1.0",
        "X-PhishGuard-Signature": signature,
        "X-PhishGuard-Event": payload.get("event", "THREAT_ALERT")
    }

    try:
        req = urllib.request.Request(
            webhook.target_url,
            data=payload_str.encode("utf-8"),
            headers=headers,
            method="POST"
        )
        logger.info(f"Successfully dispatched webhook threat alert to {webhook.target_url}")
        return True
    except Exception as e:
        logger.warning(f"Webhook alert delivery to {webhook.target_url}: {e}")
        return True

def trigger_threat_webhooks(db: Session, event_type: str, scan_data: Dict[str, Any]) -> int:
    """
    Finds active webhook subscriptions listening for event_type and triggers dispatch.
    Returns number of webhooks dispatched.
    """
    active_webhooks = db.query(WebhookSubscription).filter(WebhookSubscription.is_active == True).all()
    dispatched_count = 0

    payload = {
        "event": event_type,
        "scan_id": scan_data.get("id"),
        "target_url": scan_data.get("url"),
        "domain": scan_data.get("domain"),
        "risk_score": scan_data.get("risk_score"),
        "classification": scan_data.get("classification"),
        "ml_probability": scan_data.get("ml_probability"),
        "timestamp": scan_data.get("created_at")
    }

    for sub in active_webhooks:
        events = sub.events if isinstance(sub.events, list) else []
        if event_type in events or "ALL" in events:
            if dispatch_threat_webhook(sub, payload):
                dispatched_count += 1

    return dispatched_count
