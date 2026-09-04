"""
Authentication & Role-Based Access Control (RBAC)
Provides JWT security, user management, password hashing, and role enforcement (ADMIN, OPERATOR, ANALYST, REVIEWER).
"""

import datetime
import hashlib
import hmac
from typing import Any

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from ulpf.packages.config.settings import get_settings
from ulpf.packages.schemas.models import UserRole

security = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    """Generates a secure salted bcrypt password hash (with sha256 pre-hashing for length bounds)."""
    # Pre-hash with sha256 to ensure byte length is always <= 64 bytes (preventing bcrypt 72 byte limit error)
    prehashed = hashlib.sha256(password.encode("utf-8")).digest()
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(prehashed, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies plain password against hash (supports bcrypt and legacy sha256 for backward compatibility)."""
    if hashed_password.startswith("$2b$") or hashed_password.startswith("$2a$"):
        prehashed = hashlib.sha256(plain_password.encode("utf-8")).digest()
        try:
            return bcrypt.checkpw(prehashed, hashed_password.encode("utf-8"))
        except Exception:
            return False
    # Legacy SHA-256 fallback
    plain_hash = hashlib.sha256(plain_password.encode("utf-8")).hexdigest()
    return hmac.compare_digest(plain_hash, hashed_password)


# Built-in Default Users (pre-computed bcrypt hashes for instant startup)
USERS_DB: dict[str, dict[str, Any]] = {
    "admin": {
        "username": "admin",
        "password_hash": hash_password("admin123"),
        "role": UserRole.ADMIN,
        "full_name": "NTRO Lead Architect (Admin)",
    },
    "reviewer": {
        "username": "reviewer",
        "password_hash": hash_password("reviewer123"),
        "role": UserRole.REVIEWER,
        "full_name": "Security Schema Reviewer",
    },
    "operator": {
        "username": "operator",
        "password_hash": hash_password("operator123"),
        "role": UserRole.OPERATOR,
        "full_name": "Pipeline Ingestion Operator",
    },
    "analyst": {
        "username": "analyst",
        "password_hash": hash_password("analyst123"),
        "role": UserRole.ANALYST,
        "full_name": "SOC Cyber Threat Analyst",
    },
}


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    username: str
    role: str
    full_name: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


def create_access_token(
    data: dict, expires_delta: datetime.timedelta | None = None
) -> str:
    settings = get_settings()
    to_encode = data.copy()
    expire_minutes = settings.ULPF_ACCESS_TOKEN_EXPIRE_MINUTES
    expire = datetime.datetime.now(datetime.timezone.utc) + (
        expires_delta or datetime.timedelta(minutes=expire_minutes)
    )
    to_encode.update({"exp": expire, "token_type": "access"})
    return jwt.encode(
        to_encode, settings.ULPF_SECRET_KEY, algorithm=settings.ULPF_JWT_ALGORITHM
    )


def create_refresh_token(data: dict) -> str:
    settings = get_settings()
    to_encode = data.copy()
    expire_minutes = settings.ULPF_REFRESH_TOKEN_EXPIRE_MINUTES
    expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        minutes=expire_minutes
    )
    to_encode.update({"exp": expire, "token_type": "refresh"})
    return jwt.encode(
        to_encode, settings.ULPF_SECRET_KEY, algorithm=settings.ULPF_JWT_ALGORITHM
    )


def verify_user(credentials: LoginRequest) -> dict[str, Any] | None:
    settings = get_settings()
    # Built-in demo credentials cannot be used when DEMO_MODE is disabled in production
    if not settings.ULPF_DEMO_MODE:
        return None
    user = USERS_DB.get(credentials.username)
    if not user:
        return None
    if verify_password(credentials.password, user["password_hash"]):
        return user
    return None


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Security(security),
) -> dict[str, Any]:
    settings = get_settings()

    if not credentials or not credentials.credentials:
        # Check if DEMO mode is explicitly active
        if settings.ULPF_DEMO_MODE:
            return USERS_DB["admin"]
        # Production non-demo mode: strictly require bearer token
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided. Set Authorization: Bearer <token>.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        payload = jwt.decode(
            token, settings.ULPF_SECRET_KEY, algorithms=[settings.ULPF_JWT_ALGORITHM]
        )
        if payload.get("token_type") == "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type: refresh token cannot be used as an access token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        username: str = payload.get("sub")
        if not settings.ULPF_DEMO_MODE and username in USERS_DB:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Built-in demo accounts are disabled in production mode.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if username is None or username not in USERS_DB:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or unrecognized user in token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return USERS_DB[username]
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please refresh your session.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate token signature",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_roles(allowed_roles: list[UserRole]):
    def role_checker(user: dict[str, Any] = Depends(get_current_user)):
        user_role = user.get("role")
        if user_role not in allowed_roles and user_role != UserRole.ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires one of roles: {[r.value for r in allowed_roles]}. Current role: {user_role.value if hasattr(user_role, 'value') else user_role}",
            )
        return user

    return role_checker
