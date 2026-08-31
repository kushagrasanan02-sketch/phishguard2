import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from app.database.session import Base

class ScanClassification(str):
    SAFE = "SAFE"
    GUARDED = "GUARDED"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING = "PHISHING"

class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True) # Nullable for guest/demo scans
    url = Column(Text, nullable=False)
    normalized_url = Column(Text, nullable=False)
    domain = Column(String(255), index=True, nullable=False)
    risk_score = Column(Integer, nullable=False) # 0 to 100
    classification = Column(String(50), nullable=False) # SAFE, GUARDED, SUSPICIOUS, PHISHING
    ml_probability = Column(Float, nullable=False) # 0.0 to 1.0
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    features = relationship("URLFeatures", back_populates="scan", uselist=False, cascade="all, delete-orphan")
    risk_factors = relationship("RiskFactor", back_populates="scan", cascade="all, delete-orphan")

class URLFeatures(Base):
    __tablename__ = "url_features"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    
    url_length = Column(Integer, nullable=False, default=0)
    hostname_length = Column(Integer, nullable=False, default=0)
    subdomain_count = Column(Integer, nullable=False, default=0)
    dot_count = Column(Integer, nullable=False, default=0)
    hyphen_count = Column(Integer, nullable=False, default=0)
    special_char_count = Column(Integer, nullable=False, default=0)
    has_ip = Column(Boolean, nullable=False, default=False)
    has_at_symbol = Column(Boolean, nullable=False, default=False)
    has_punycode = Column(Boolean, nullable=False, default=False)
    parameter_count = Column(Integer, nullable=False, default=0)
    has_suspicious_keywords = Column(Boolean, nullable=False, default=False)
    detected_keywords = Column(JSON, nullable=True) # list of matched keywords
    domain_age_days = Column(Integer, nullable=True)
    https_enabled = Column(Boolean, nullable=False, default=False)
    redirect_count = Column(Integer, nullable=False, default=0)
    ssl_valid = Column(Boolean, nullable=True)
    brand_impersonated = Column(String(100), nullable=True)

    scan = relationship("Scan", back_populates="features")

class RiskFactor(Base):
    __tablename__ = "risk_factors"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    factor = Column(String(100), nullable=False) # e.g. "Brand Impersonation"
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    score_contribution = Column(Integer, nullable=False) # e.g. +20

    scan = relationship("Scan", back_populates="risk_factors")

class EmailScan(Base):
    __tablename__ = "email_scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    sender = Column(String(255), nullable=True)
    recipient = Column(String(255), nullable=True)
    subject = Column(Text, nullable=True)
    risk_score = Column(Integer, nullable=False)
    classification = Column(String(50), nullable=False)
    spf_result = Column(String(50), nullable=True)
    dkim_result = Column(String(50), nullable=True)
    dmarc_result = Column(String(50), nullable=True)
    reply_to_mismatch = Column(Boolean, default=False)
    extracted_urls = Column(JSON, nullable=True)
    indicators = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

class ModelVersion(Base):
    __tablename__ = "model_versions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    version = Column(String(50), nullable=False, unique=True)
    algorithm = Column(String(100), nullable=False) # e.g. "Random Forest Classifier"
    training_date = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    metrics = Column(JSON, nullable=False) # accuracy, precision, recall, f1, roc_auc
    is_active = Column(Boolean, default=True)
