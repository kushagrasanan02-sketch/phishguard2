from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.services.email_parser import evaluate_email_security
from app.models.scan import EmailScan
from app.models.user import User
from app.models.audit import AuditLog
from app.schemas.email import EmailScanRequest, EmailScanResponse, EmbeddedURLScan
from app.api.deps import get_current_user_optional

router = APIRouter()

@router.post("", response_model=EmailScanResponse, status_code=status.HTTP_201_CREATED)
def scan_email_text(
    scan_in: EmailScanRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """
    Parses and inspects raw email text headers, authentication checks, BEC spoofing,
    and embedded URL risk.
    """
    if not scan_in.raw_email.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Raw email text content cannot be empty."
        )

    eval_result = evaluate_email_security(scan_in.raw_email)
    user_id = current_user.id if current_user else None

    email_scan = EmailScan(
        user_id=user_id,
        sender=eval_result["sender"],
        recipient=eval_result["recipient"],
        subject=eval_result["subject"],
        risk_score=eval_result["risk_score"],
        classification=eval_result["classification"],
        spf_result=eval_result["spf_result"],
        dkim_result=eval_result["dkim_result"],
        dmarc_result=eval_result["dmarc_result"],
        reply_to_mismatch=eval_result["reply_to_mismatch"],
        extracted_urls=eval_result["extracted_urls"],
        indicators=eval_result["indicators"]
    )
    db.add(email_scan)

    audit = AuditLog(
        user_id=user_id,
        action="EMAIL_SCAN",
        details={
            "sender": eval_result["sender"],
            "subject": eval_result["subject"],
            "risk_score": eval_result["risk_score"]
        }
    )
    db.add(audit)
    db.commit()
    db.refresh(email_scan)

    # Convert transient url_scans dicts to EmbeddedURLScan model instances
    url_scans_models = [EmbeddedURLScan(**us) for us in eval_result["url_scans"]]
    response_data = EmailScanResponse.model_validate(email_scan)
    response_data.url_scans = url_scans_models
    return response_data

@router.post("/file", response_model=EmailScanResponse, status_code=status.HTTP_201_CREATED)
async def scan_email_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Upload and inspect a .eml or .msg email file for security indicators."""
    content_bytes = await file.read()
    try:
        raw_email_str = content_bytes.decode('utf-8', errors='ignore')
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read file encoding: {str(e)}"
        )

    return scan_email_text(EmailScanRequest(raw_email=raw_email_str), db, current_user)

@router.get("", response_model=List[EmailScanResponse])
def list_email_scans(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """List historical email security scans."""
    query = db.query(EmailScan)
    if current_user and current_user.role != "ADMIN":
        query = query.filter(EmailScan.user_id == current_user.id)

    scans = query.order_by(EmailScan.created_at.desc()).offset(skip).limit(limit).all()
    return scans

@router.get("/{scan_id}", response_model=EmailScanResponse)
def get_email_scan_report(
    scan_id: str,
    db: Session = Depends(get_db)
):
    """Retrieve an email scan report by ID."""
    scan = db.query(EmailScan).filter(EmailScan.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Email scan report not found."
        )
    return scan
