from datetime import datetime
from typing import List, Optional, Any, Dict
from pydantic import BaseModel, HttpUrl

class RiskFactorSchema(BaseModel):
    factor: str
    description: str
    severity: str
    score_contribution: int

    class Config:
        from_attributes = True

class URLFeaturesSchema(BaseModel):
    url_length: int
    hostname_length: int
    subdomain_count: int
    dot_count: int
    hyphen_count: int
    special_char_count: int
    has_ip: bool
    has_at_symbol: bool
    has_punycode: bool
    parameter_count: int
    has_suspicious_keywords: bool
    detected_keywords: Optional[List[str]] = []
    domain_age_days: Optional[int] = None
    https_enabled: bool
    redirect_count: int
    ssl_valid: Optional[bool] = None
    brand_impersonated: Optional[str] = None

    class Config:
        from_attributes = True

class URLScanRequest(BaseModel):
    url: str

class ScanResponse(BaseModel):
    id: str
    url: str
    normalized_url: str
    domain: str
    risk_score: int
    classification: str
    ml_probability: float
    created_at: datetime
    features: Optional[URLFeaturesSchema] = None
    risk_factors: List[RiskFactorSchema] = []

    class Config:
        from_attributes = True

class DashboardStatsResponse(BaseModel):
    total_scans: int
    phishing_detected: int
    safe_urls: int
    high_risk_urls: int
    average_risk_score: float
    threat_distribution: Dict[str, int]

class BatchURLScanRequest(BaseModel):
    urls: List[str]

class BatchScanResponse(BaseModel):
    total_processed: int
    safe_count: int
    phishing_count: int
    average_risk_score: float
    scans: List[ScanResponse]

class WebhookCreate(BaseModel):
    target_url: str
    secret: Optional[str] = None
    events: Optional[List[str]] = ["PHISHING_DETECTED", "HIGH_RISK_DETECTED"]

class WebhookResponse(BaseModel):
    id: str
    target_url: str
    secret: str
    events: List[str]
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

class IOCItem(BaseModel):
    indicator: str # domain or url
    type: str # DOMAIN, URL
    risk_score: int
    classification: str
    first_seen: datetime

class IOCFeedResponse(BaseModel):
    feed_title: str
    generated_at: datetime
    total_indicators: int
    indicators: List[IOCItem]

