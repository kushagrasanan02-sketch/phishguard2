from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

class EmailScanRequest(BaseModel):
    raw_email: str = Field(..., description="Raw email text content (RFC 822 / body / headers)")

class EmbeddedURLScan(BaseModel):
    url: str
    domain: str
    risk_score: int
    classification: str

class EmailScanResponse(BaseModel):
    id: str
    sender: Optional[str] = None
    recipient: Optional[str] = None
    subject: Optional[str] = None
    risk_score: int
    classification: str
    spf_result: Optional[str] = "PASS"
    dkim_result: Optional[str] = "PASS"
    dmarc_result: Optional[str] = "PASS"
    reply_to_mismatch: bool = False
    extracted_urls: Optional[List[str]] = []
    url_scans: Optional[List[EmbeddedURLScan]] = []
    indicators: Optional[List[str]] = []
    created_at: datetime

    class Config:
        from_attributes = True
