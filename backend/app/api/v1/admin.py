from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.user import User
from app.models.scan import Scan, EmailScan, ModelVersion
from app.models.audit import AuditLog
from app.schemas.admin import ModelVersionResponse, UserManagementResponse, AuditLogResponse, AdminSystemStats
from app.services.ml_engine import train_and_persist_model
from app.services.security_auditor import perform_security_audit
from app.services.benchmark_engine import run_system_performance_benchmark
from app.services.release_certifier import certifier_system_release_candidate
from app.api.deps import get_current_active_admin

router = APIRouter()

@router.get("/stats", response_model=AdminSystemStats)
def get_admin_system_stats(
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_active_admin)
):
    """Retrieve system stats for the Admin Dashboard."""
    total_users = db.query(User).count()
    active_scans = db.query(Scan).count()
    email_scans = db.query(EmailScan).count()

    active_model_obj = db.query(ModelVersion).filter(ModelVersion.is_active == True).first()
    if not active_model_obj:
        # Guarantee an active model exists
        train_and_persist_model(db)
        active_model_obj = db.query(ModelVersion).filter(ModelVersion.is_active == True).first()

    version_str = active_model_obj.version if active_model_obj else "RandomForest v1.0"
    precision_val = active_model_obj.metrics.get("precision", 0.96) if (active_model_obj and active_model_obj.metrics) else 0.96

    return AdminSystemStats(
        total_users=total_users,
        active_scans=active_scans,
        email_scans=email_scans,
        active_model=f"RandomForest {version_str}",
        active_model_precision=precision_val,
        system_status="OPERATIONAL"
    )

@router.get("/security-audit")
def get_security_compliance_audit(
    admin: User = Depends(get_current_active_admin)
):
    """Executes automated security posture checks (CORS, OWASP headers, SSRF filters, JWT entropy)."""
    return perform_security_audit()

@router.post("/benchmark")
def run_performance_benchmark(
    iterations: int = Query(10, ge=1, le=100),
    admin: User = Depends(get_current_active_admin)
):
    """Executes system performance benchmark measuring millisecond scan latency and throughput."""
    return run_system_performance_benchmark(iterations)

@router.get("/certification")
def get_enterprise_release_certification(
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_active_admin)
):
    """Master Enterprise Release Candidate v1.0 Certification Endpoint."""
    return certifier_system_release_candidate(db)

@router.get("/models", response_model=List[ModelVersionResponse])
def list_model_versions(
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_active_admin)
):
    """List all registered ML model versions and performance metrics."""
    models = db.query(ModelVersion).order_by(ModelVersion.training_date.desc()).all()
    if not models:
        train_and_persist_model(db)
        models = db.query(ModelVersion).order_by(ModelVersion.training_date.desc()).all()
    return models

@router.post("/models/retrain", response_model=ModelVersionResponse, status_code=status.HTTP_201_CREATED)
def retrain_ml_model(
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_active_admin)
):
    """Trigger online retraining of the Random Forest model and register new model version."""
    model_data = train_and_persist_model(db)
    active_model = db.query(ModelVersion).filter(ModelVersion.is_active == True).first()

    audit = AuditLog(
        user_id=admin.id,
        action="MODEL_RETRAIN",
        details={"version": model_data["version"], "metrics": model_data["metrics"]}
    )
    db.add(audit)
    db.commit()

    return active_model

@router.post("/models/{model_id}/activate", response_model=ModelVersionResponse)
def activate_model_version(
    model_id: str,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_active_admin)
):
    """Activate a specific model version."""
    target_model = db.query(ModelVersion).filter(ModelVersion.id == model_id).first()
    if not target_model:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Model version not found.")

    db.query(ModelVersion).update({"is_active": False})
    target_model.is_active = True

    audit = AuditLog(
        user_id=admin.id,
        action="MODEL_ACTIVATE",
        details={"version": target_model.version, "model_id": target_model.id}
    )
    db.add(audit)
    db.commit()
    db.refresh(target_model)
    return target_model

@router.get("/users", response_model=List[UserManagementResponse])
def list_system_users(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_active_admin)
):
    """List registered platform users for admin console."""
    users = db.query(User).order_by(User.created_at.desc()).offset(skip).limit(limit).all()
    return users

@router.get("/audit-logs", response_model=List[AuditLogResponse])
def list_audit_logs(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_active_admin)
):
    """List audit log events for system administration."""
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit).all()
    return logs
