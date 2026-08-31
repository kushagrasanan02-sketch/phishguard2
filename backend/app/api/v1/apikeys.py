from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.user import User
from app.models.apikey import APIKey
from app.schemas.apikey import APIKeyCreateRequest, APIKeyCreatedResponse, APIKeyResponse
from app.api.deps import get_current_user

router = APIRouter()

@router.post("", response_model=APIKeyCreatedResponse, status_code=status.HTTP_201_CREATED)
def create_api_key(
    key_in: APIKeyCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Generates a new programmatic API Key for external SIEM / CLI integrations."""
    full_key, key_prefix, hashed_repr = APIKey.generate_key()

    new_key = APIKey(
        user_id=current_user.id,
        name=key_in.name,
        key_prefix=key_prefix,
        hashed_key=hashed_repr,
        is_active=True
    )
    db.add(new_key)
    db.commit()
    db.refresh(new_key)

    return APIKeyCreatedResponse(
        id=new_key.id,
        name=new_key.name,
        key_prefix=new_key.key_prefix,
        api_key=full_key,
        is_active=new_key.is_active,
        created_at=new_key.created_at
    )

@router.get("", response_model=List[APIKeyResponse])
def list_api_keys(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all registered API keys for the authenticated user."""
    keys = db.query(APIKey).filter(APIKey.user_id == current_user.id).order_by(APIKey.created_at.desc()).all()
    return keys

@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_api_key(
    key_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Revokes an API Key."""
    key = db.query(APIKey).filter(APIKey.id == key_id, APIKey.user_id == current_user.id).first()
    if not key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API Key not found.")

    key.is_active = False
    db.commit()
    return None
