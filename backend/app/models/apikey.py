import uuid
import secrets
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database.session import Base

class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    name = Column(String(100), nullable=False) # e.g. "SIEM Production Key"
    key_prefix = Column(String(12), nullable=False, index=True) # e.g. "pg_live_a1b2"
    hashed_key = Column(String(255), nullable=False, index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    last_used = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User", backref="api_keys")

    @staticmethod
    def generate_key() -> tuple[str, str, str]:
        """Generates (full_key, key_prefix, hashed_key_repr)."""
        raw_token = secrets.token_hex(20)
        full_key = f"pg_live_{raw_token}"
        key_prefix = full_key[:12]
        return full_key, key_prefix, full_key
