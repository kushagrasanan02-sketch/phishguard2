import secrets
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.webhook import WebhookSubscription
from app.models.user import User
from app.schemas.scan import WebhookCreate, WebhookResponse
from app.api.deps import get_current_user

router = APIRouter()

@router.post("", response_model=WebhookResponse, status_code=status.HTTP_201_CREATED)
def create_webhook_subscription(
    webhook_in: WebhookCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Registers a new threat alert webhook endpoint.
    Generates a secure HMAC secret key for signature verification if not provided.
    """
    secret = webhook_in.secret if webhook_in.secret else f"whsec_{secrets.token_hex(16)}"
    
    new_sub = WebhookSubscription(
        user_id=current_user.id,
        target_url=webhook_in.target_url,
        secret=secret,
        events=webhook_in.events or ["PHISHING_DETECTED", "HIGH_RISK_DETECTED"],
        is_active=True
    )
    db.add(new_sub)
    db.commit()
    db.refresh(new_sub)
    return new_sub

@router.get("", response_model=List[WebhookResponse])
def list_webhook_subscriptions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Lists registered threat alert webhooks for current user (or all if ADMIN)."""
    query = db.query(WebhookSubscription)
    if current_user.role != "ADMIN":
        query = query.filter(WebhookSubscription.user_id == current_user.id)
    return query.order_by(WebhookSubscription.created_at.desc()).all()

@router.delete("/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_webhook_subscription(
    webhook_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Deletes a registered webhook subscription."""
    query = db.query(WebhookSubscription).filter(WebhookSubscription.id == webhook_id)
    if current_user.role != "ADMIN":
        query = query.filter(WebhookSubscription.user_id == current_user.id)
    
    webhook = query.first()
    if not webhook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook subscription not found."
        )
    
    db.delete(webhook)
    db.commit()
    return None
