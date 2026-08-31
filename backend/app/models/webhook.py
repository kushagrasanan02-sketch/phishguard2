import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, JSON
from app.database.session import Base

class WebhookSubscription(Base):
    __tablename__ = "webhook_subscriptions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    target_url = Column(String(500), nullable=False)
    secret = Column(String(255), nullable=False) # Secret key for HMAC signature verification
    events = Column(JSON, nullable=False, default=["PHISHING_DETECTED", "HIGH_RISK_DETECTED"])
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
