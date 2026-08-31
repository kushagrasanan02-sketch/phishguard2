from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.services.chat_assistant import analyze_threat_query_with_guard_ai
from app.api.deps import get_current_user_optional
from app.models.user import User

router = APIRouter()

class ChatAnalysisRequest(BaseModel):
    query: str
    scan_context: Optional[Dict[str, Any]] = None

class ChatAnalysisResponse(BaseModel):
    query: str
    response: str
    mitigation_playbook: list[str]
    suggested_actions: list[str]
    model_version: str

@router.post("/analyze", response_model=ChatAnalysisResponse)
def analyze_threat_chat(
    chat_in: ChatAnalysisRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """
    AI SOC Security Analyst Chat Assistant endpoint.
    Receives security analyst queries and scan context, returning structured GuardAI response and playbooks.
    """
    res = analyze_threat_query_with_guard_ai(chat_in.query, chat_in.scan_context)
    return ChatAnalysisResponse(**res)
