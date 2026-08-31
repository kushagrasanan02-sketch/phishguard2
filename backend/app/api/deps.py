from typing import Generator, Optional
from fastapi import Depends, HTTPException, status, Header
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.core.security import decode_jwt_token
from app.models.user import User, UserRole
from app.models.apikey import APIKey

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)

def get_current_user_optional(
    db: Session = Depends(get_db),
    token: Optional[str] = Depends(oauth2_scheme),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key")
) -> Optional[User]:
    """Retrieve user if valid JWT bearer token OR valid X-API-Key is present."""
    if token:
        payload = decode_jwt_token(token)
        if payload and payload.get("type") == "access":
            user_id: Optional[str] = payload.get("sub")
            if user_id:
                user = db.query(User).filter(User.id == user_id).first()
                if user and user.is_active:
                    return user

    if x_api_key and x_api_key.startswith("pg_live_"):
        key_record = db.query(APIKey).filter(APIKey.hashed_key == x_api_key, APIKey.is_active == True).first()
        if key_record:
            user = db.query(User).filter(User.id == key_record.user_id).first()
            if user and user.is_active:
                return user

    return None

def get_current_user(
    db: Session = Depends(get_db),
    token: Optional[str] = Depends(oauth2_scheme),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key")
) -> User:
    """Retrieve user from JWT bearer token or X-API-Key header. Raises 401 if unauthenticated."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate security credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    user = get_current_user_optional(db, token, x_api_key)
    if user is None:
        raise credentials_exception

    return user

def get_current_active_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    """Validate that the current user possesses ADMIN privileges."""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The operation requires administrator privileges"
        )
    return current_user
