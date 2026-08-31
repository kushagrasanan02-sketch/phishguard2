from typing import Optional
from pydantic import BaseModel, Field
from datetime import datetime

class APIKeyCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100, description="Name or description for API Key")

class APIKeyCreatedResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    api_key: str # Secret raw key returned ONLY ONCE upon creation
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

class APIKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    is_active: bool
    created_at: datetime
    last_used: Optional[datetime] = None

    class Config:
        from_attributes = True
