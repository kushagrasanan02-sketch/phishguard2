from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.services.soar_engine import dispatch_soar_mitigation_playbook
from app.api.deps import get_current_active_admin
from app.models.user import User

router = APIRouter()

class SOARDispatchRequest(BaseModel):
    scan_id: str
    action: str = "firewall_sinkhole" # firewall_sinkhole, dns_blocklist, endpoint_quarantine, notify_users

@router.post("/dispatch")
def dispatch_soar_playbook(
    req: SOARDispatchRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_active_admin)
):
    """
    Executes automated SOAR incident response playbooks for high-risk threat scans.
    Requires ADMIN privileges.
    """
    return dispatch_soar_mitigation_playbook(req.scan_id, req.action, db)
