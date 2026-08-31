from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from fastapi.responses import PlainTextResponse, JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import func, or_

from app.database.session import get_db
from app.security.ssrf import normalize_and_validate_url
from app.services.url_extractor import extract_url_features
from app.services.risk_engine import calculate_risk_score
from app.services.siem_exporter import export_scan_as_cef, export_scan_as_stix, export_scan_as_syslog
from app.services.webhook_service import trigger_threat_webhooks
from app.services.report_generator import generate_executive_html_report
from app.models.scan import Scan, URLFeatures, RiskFactor
from app.models.user import User
from app.models.audit import AuditLog
from app.schemas.scan import URLScanRequest, ScanResponse, DashboardStatsResponse, BatchURLScanRequest, BatchScanResponse
from app.api.deps import get_current_user_optional
from app.core.rate_limiter import check_rate_limit
from app.api.v1.websocket import broadcast_threat_alert_sync

router = APIRouter()

def _process_single_url_scan(url_str: str, user_id: Optional[str], db: Session) -> Scan:
    """Helper function to perform URL feature extraction, risk scoring, and database persistence."""
    normalized_url, scheme, hostname = normalize_and_validate_url(url_str)
    features_dict = extract_url_features(normalized_url, scheme, hostname)
    risk_score, classification, ml_prob, risk_factors_list, positive_signals, recommendation = calculate_risk_score(features_dict)

    new_scan = Scan(
        user_id=user_id,
        url=url_str,
        normalized_url=normalized_url,
        domain=hostname,
        risk_score=risk_score,
        classification=classification,
        ml_probability=ml_prob
    )
    db.add(new_scan)
    db.flush()

    url_feat = URLFeatures(
        scan_id=new_scan.id,
        url_length=features_dict["url_length"],
        hostname_length=features_dict["hostname_length"],
        subdomain_count=features_dict["subdomain_count"],
        dot_count=features_dict["dot_count"],
        hyphen_count=features_dict["hyphen_count"],
        special_char_count=features_dict["special_char_count"],
        has_ip=features_dict["has_ip"],
        has_at_symbol=features_dict["has_at_symbol"],
        has_punycode=features_dict["has_punycode"],
        parameter_count=features_dict["parameter_count"],
        has_suspicious_keywords=features_dict["has_suspicious_keywords"],
        detected_keywords=features_dict["detected_keywords"],
        domain_age_days=features_dict["domain_age_days"],
        https_enabled=features_dict["https_enabled"],
        redirect_count=features_dict["redirect_count"],
        ssl_valid=features_dict["ssl_valid"],
        brand_impersonated=features_dict["brand_impersonated"]
    )
    db.add(url_feat)

    for factor in risk_factors_list:
        rf = RiskFactor(
            scan_id=new_scan.id,
            factor=factor["factor"],
            description=factor["description"],
            severity=factor["severity"],
            score_contribution=factor["score_contribution"]
        )
        db.add(rf)

    audit = AuditLog(
        user_id=user_id,
        action="URL_SCAN",
        details={"domain": hostname, "risk_score": risk_score, "classification": classification}
    )
    db.add(audit)
    db.commit()
    db.refresh(new_scan)

    # Broadcast WebSocket alert
    broadcast_threat_alert_sync({
        "event": "NEW_THREAT_SCAN",
        "scan_id": new_scan.id,
        "target": hostname,
        "url": url_str,
        "risk_score": risk_score,
        "classification": classification,
        "timestamp": new_scan.created_at.isoformat()
    })

    # Trigger Automated Threat Webhooks if high risk / phishing
    if risk_score >= 60 or classification == "PHISHING":
        event = "PHISHING_DETECTED" if classification == "PHISHING" else "HIGH_RISK_DETECTED"
        trigger_threat_webhooks(db, event, {
            "id": new_scan.id,
            "url": url_str,
            "domain": hostname,
            "risk_score": risk_score,
            "classification": classification,
            "ml_probability": ml_prob,
            "created_at": new_scan.created_at.isoformat()
        })

    return new_scan

@router.post("/url", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def scan_url(
    scan_in: URLScanRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """
    Analyzes a URL for phishing indicators, extracts features, calculates transparent risk score,
    and persists probe findings in the security database.
    """
    check_rate_limit(request, max_requests=30, window_seconds=60)
    user_id = current_user.id if current_user else None
    return _process_single_url_scan(scan_in.url, user_id, db)

@router.post("/batch", response_model=BatchScanResponse, status_code=status.HTTP_201_CREATED)
def scan_batch_urls(
    batch_in: BatchURLScanRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """
    Executes bulk URL analysis for up to 50 URLs concurrently.
    Returns individual scan records with aggregate threat breakdown metrics.
    """
    check_rate_limit(request, max_requests=10, window_seconds=60) # Tighter limit for batch
    if not batch_in.urls:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No URLs provided for batch scanning.")
    
    if len(batch_in.urls) > 50:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Batch limit exceeded. Maximum 50 URLs per request.")

    user_id = current_user.id if current_user else None
    scans_list = []
    safe_count = 0
    phishing_count = 0
    total_risk = 0

    for url_str in batch_in.urls:
        scan = _process_single_url_scan(url_str.strip(), user_id, db)
        scans_list.append(scan)
        total_risk += scan.risk_score
        if scan.classification == "SAFE":
            safe_count += 1
        elif scan.classification in ["PHISHING", "SUSPICIOUS", "CRITICAL", "HIGH"]:
            phishing_count += 1

    total_proc = len(scans_list)
    avg_score = round(total_risk / total_proc, 1) if total_proc > 0 else 0.0

    return BatchScanResponse(
        total_processed=total_proc,
        safe_count=safe_count,
        phishing_count=phishing_count,
        average_risk_score=avg_score,
        scans=scans_list
    )

@router.get("/dashboard/stats", response_model=DashboardStatsResponse)
def get_dashboard_stats(
    db: Session = Depends(get_db)
):
    """Compute aggregate threat intelligence statistics for the SOC Dashboard."""
    total_scans = db.query(Scan).count()
    phishing_detected = db.query(Scan).filter(Scan.classification.in_(["PHISHING", "CRITICAL", "HIGH"])).count()
    safe_urls = db.query(Scan).filter(Scan.classification == "SAFE").count()
    high_risk_urls = db.query(Scan).filter(Scan.risk_score >= 60).count()

    avg_score_res = db.query(func.avg(Scan.risk_score)).scalar()
    avg_score = round(float(avg_score_res), 1) if avg_score_res is not None else 0.0

    threat_dist = {
        "SAFE": db.query(Scan).filter(Scan.classification == "SAFE").count(),
        "GUARDED": db.query(Scan).filter(Scan.classification == "GUARDED").count(),
        "SUSPICIOUS": db.query(Scan).filter(Scan.classification.in_(["SUSPICIOUS", "MEDIUM"])).count(),
        "PHISHING": db.query(Scan).filter(Scan.classification.in_(["PHISHING", "HIGH", "CRITICAL"])).count(),
    }

    return DashboardStatsResponse(
        total_scans=total_scans,
        phishing_detected=phishing_detected,
        safe_urls=safe_urls,
        high_risk_urls=high_risk_urls,
        average_risk_score=avg_score,
        threat_distribution=threat_dist
    )

@router.get("/{scan_id}/export/report")
def export_executive_report(
    scan_id: str,
    format: str = Query("html", description="Format: html or json"),
    db: Session = Depends(get_db)
):
    """Generates an executive threat report in HTML format suitable for SOC briefings or JSON."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan report not found.")

    risk_factors_data = []
    if scan.risk_factors:
        for rf in scan.risk_factors:
            risk_factors_data.append({
                "factor": rf.factor,
                "description": rf.description,
                "severity": rf.severity,
                "score_contribution": rf.score_contribution
            })

    scan_dict = {
        "id": scan.id,
        "url": scan.url,
        "domain": scan.domain,
        "risk_score": scan.risk_score,
        "classification": scan.classification,
        "ml_probability": scan.ml_probability,
        "created_at": scan.created_at.isoformat(),
        "risk_factors": risk_factors_data
    }

    if format.lower().strip() == "html":
        html_content = generate_executive_html_report(scan_dict)
        return PlainTextResponse(html_content, media_type="text/html")
    else:
        return JSONResponse(scan_dict)

@router.get("/{scan_id}/export/siem")
def export_scan_siem(
    scan_id: str,
    format: str = Query("cef", description="Format: cef, stix, syslog, or json"),
    db: Session = Depends(get_db)
):
    """Export a scan probe finding into SIEM / STIX 2.1 threat intelligence formats."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan record not found.")

    scan_dict = {
        "id": scan.id,
        "url": scan.url,
        "domain": scan.domain,
        "risk_score": scan.risk_score,
        "classification": scan.classification,
        "ml_probability": scan.ml_probability,
        "created_at": scan.created_at.isoformat()
    }

    fmt = format.lower().strip()
    if fmt == "cef":
        return PlainTextResponse(export_scan_as_cef(scan_dict), media_type="text/plain")
    elif fmt == "stix":
        return JSONResponse(export_scan_as_stix(scan_dict))
    elif fmt == "syslog":
        return PlainTextResponse(export_scan_as_syslog(scan_dict), media_type="text/plain")
    else:
        return JSONResponse(scan_dict)

@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan_report(
    scan_id: str,
    db: Session = Depends(get_db)
):
    """Retrieve full scan security report by scan UUID."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security scan report not found."
        )
    return scan

@router.get("", response_model=List[ScanResponse])
def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    q: Optional[str] = Query(None, description="Search query string"),
    classification: Optional[str] = Query(None, description="Filter by classification"),
    min_risk: Optional[int] = Query(None, ge=0, le=100),
    max_risk: Optional[int] = Query(None, ge=0, le=100),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """List historical scan probes with search & filtering options."""
    query = db.query(Scan)
    if current_user and current_user.role != "ADMIN":
        query = query.filter(Scan.user_id == current_user.id)

    if q:
        search_pattern = f"%{q}%"
        query = query.filter(or_(Scan.url.ilike(search_pattern), Scan.domain.ilike(search_pattern)))

    if classification and classification != "ALL":
        if classification == "PHISHING":
            query = query.filter(Scan.classification.in_(["PHISHING", "CRITICAL", "HIGH"]))
        elif classification == "SUSPICIOUS":
            query = query.filter(Scan.classification.in_(["SUSPICIOUS", "MEDIUM"]))
        else:
            query = query.filter(Scan.classification == classification)

    if min_risk is not None:
        query = query.filter(Scan.risk_score >= min_risk)

    if max_risk is not None:
        query = query.filter(Scan.risk_score <= max_risk)

    scans = query.order_by(Scan.created_at.desc()).offset(skip).limit(limit).all()
    return scans
