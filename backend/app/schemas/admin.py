from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from datetime import datetime

class ModelMetrics(BaseModel):
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    roc_auc: float

class ModelVersionResponse(BaseModel):
    id: str
    version: str
    algorithm: str
    metrics: Dict[str, float]
    is_active: bool
    training_date: datetime

    class Config:
        from_attributes = True

class UserManagementResponse(BaseModel):
    id: str
    email: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None

    class Config:
        from_attributes = True

class AuditLogResponse(BaseModel):
    id: str
    user_id: Optional[str] = None
    action: str
    details: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    timestamp: datetime

    class Config:
        from_attributes = True

class AdminSystemStats(BaseModel):
    total_users: int
    active_scans: int
    email_scans: int
    active_model: str
    active_model_precision: float
    system_status: str
