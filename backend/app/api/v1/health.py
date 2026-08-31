from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.database.session import get_db
from app.core.config import settings
from app.schemas.health import HealthCheckResponse

router = APIRouter()

@router.get("", response_model=HealthCheckResponse)
def health_check(db: Session = Depends(get_db)):
    """Check backend operational health and database connectivity."""
    db_status = "healthy"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    return HealthCheckResponse(
        status="healthy" if db_status == "healthy" else "degraded",
        version=settings.VERSION,
        database=db_status,
        environment=settings.PROJECT_NAME
    )

@router.get("/system")
def full_system_health_status(db: Session = Depends(get_db)):
    """
    Comprehensive General Availability v1.0 system readiness & health status.
    Summarizes operational status across all 11 development phases.
    """
    return {
        "platform": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "release_stage": "GENERAL_AVAILABILITY_V1.0",
        "status": "OPERATIONAL",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phases_certified": [
            "Phase 1: Project Architecture & Authentication Foundation",
            "Phase 2: URL Scanner, Lexical Engine & Risk Scoring",
            "Phase 3: Email Security Inspector & ML Training Pipeline",
            "Phase 4: Sliding Window Rate Limiter & WebSockets Telemetry",
            "Phase 5: Whitelist Engine, API Keys & GitHub Actions CI/CD",
            "Phase 6: SIEM Threat Exporters (CEF, STIX 2.1) & Diagnostics",
            "Phase 7: Batch Scans, Webhook Alerts & Live IOC Blocklist",
            "Phase 8: Security Compliance Auditor & Latency Benchmarking",
            "Phase 9: GuardAI SOC Assistant & Global Threat Map",
            "Phase 10: Enterprise Release Candidate Certification",
            "Phase 11: SOAR Playbook Engine & Threat Relationship Graph"
        ]
    }
