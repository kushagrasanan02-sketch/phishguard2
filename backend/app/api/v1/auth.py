from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Body
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.core.security import (
    get_password_hash,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_jwt_token
)
from app.models.user import User, UserRole
from app.models.audit import AuditLog
from app.schemas.auth import UserRegister, UserLogin, Token
from app.schemas.user import UserResponse
from app.api.deps import get_current_user

router = APIRouter()

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(
    user_in: UserRegister,
    db: Session = Depends(get_db)
):
    """Register a new user account."""
    existing_user = db.query(User).filter(User.email == user_in.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists."
        )

    # First user registered automatically gets ADMIN privileges
    is_first_user = db.query(User).count() == 0
    role = UserRole.ADMIN if is_first_user else UserRole.USER

    new_user = User(
        email=user_in.email,
        hashed_password=get_password_hash(user_in.password),
        full_name=user_in.full_name,
        role=role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Audit Log
    audit = AuditLog(
        user_id=new_user.id,
        action="USER_REGISTER",
        details={"email": new_user.email, "role": new_user.role.value}
    )
    db.add(audit)
    db.commit()

    return new_user

@router.post("/login", response_model=Token)
def login_user(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """Authenticate user with OAuth2 form data and return JWT tokens."""
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        # Audit failed login attempt
        audit = AuditLog(
            action="AUTH_FAILURE",
            details={"attempted_email": form_data.username}
        )
        db.add(audit)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive"
        )

    user.last_login = datetime.now(timezone.utc)
    db.commit()

    access_token = create_access_token(subject=user.id)
    refresh_token = create_refresh_token(subject=user.id)

    # Audit login success
    audit = AuditLog(
        user_id=user.id,
        action="USER_LOGIN",
        details={"email": user.email}
    )
    db.add(audit)
    db.commit()

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )

@router.post("/login/json", response_model=Token)
def login_user_json(
    user_in: UserLogin,
    db: Session = Depends(get_db)
):
    """Authenticate user with JSON payload."""
    user = db.query(User).filter(User.email == user_in.email).first()
    if not user or not verify_password(user_in.password, user.hashed_password):
        audit = AuditLog(
            action="AUTH_FAILURE",
            details={"attempted_email": user_in.email}
        )
        db.add(audit)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive"
        )

    user.last_login = datetime.now(timezone.utc)
    db.commit()

    access_token = create_access_token(subject=user.id)
    refresh_token = create_refresh_token(subject=user.id)

    audit = AuditLog(
        user_id=user.id,
        action="USER_LOGIN",
        details={"email": user.email}
    )
    db.add(audit)
    db.commit()

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )

@router.get("/me", response_model=UserResponse)
def get_current_user_profile(
    current_user: User = Depends(get_current_user)
):
    """Retrieve details for current authenticated user."""
    return current_user

@router.post("/refresh", response_model=Token)
def refresh_token(
    refresh_token: str = Body(..., embed=True),
    db: Session = Depends(get_db)
):
    """Obtain a new access token using a valid refresh token."""
    payload = decode_jwt_token(refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )

    user_id = payload.get("sub")
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )

    new_access_token = create_access_token(subject=user.id)
    new_refresh_token = create_refresh_token(subject=user.id)

    return Token(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer"
    )
