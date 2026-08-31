import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, JSON
from app.database.session import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), nullable=True)
    action = Column(String(100), nullable=False) # e.g. "USER_LOGIN", "URL_SCAN", "AUTH_FAILURE"
    ip_address = Column(String(45), nullable=True)
    details = Column(JSON, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
