"""
Authentication API Endpoints
Login, Token Refresh, and Current User Profile.
"""

from typing import Any

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status

from ulpf.apps.api.auth import (
    USERS_DB,
    LoginRequest,
    RefreshTokenRequest,
    TokenResponse,
    create_access_token,
    create_refresh_token,
    get_current_user,
    verify_user,
)
from ulpf.packages.config.settings import get_settings
from ulpf.packages.security.sanitization import auth_rate_limiter

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse)
def login(credentials: LoginRequest, request: Request):
    """Authenticates user credentials and issues signed access and refresh tokens."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    if not auth_rate_limiter.check_rate_limit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please wait before retrying.",
        )

    user = verify_user(credentials)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    role_val = (
        user["role"].value if hasattr(user["role"], "value") else str(user["role"])
    )
    access_token = create_access_token(data={"sub": user["username"], "role": role_val})
    refresh_token = create_refresh_token(
        data={"sub": user["username"], "role": role_val}
    )
    settings = get_settings()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ULPF_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        username=user["username"],
        role=role_val,
        full_name=user["full_name"],
    )


@router.post("/refresh", response_model=dict[str, Any])
def refresh_token(request: RefreshTokenRequest):
    """Exchanges a valid refresh token for a newly signed access token."""
    settings = get_settings()
    try:
        payload = jwt.decode(
            request.refresh_token,
            settings.ULPF_SECRET_KEY,
            algorithms=[settings.ULPF_JWT_ALGORITHM],
        )
        if payload.get("token_type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Provided token is not a refresh token",
            )
        username = payload.get("sub")
        if not username or username not in USERS_DB:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User associated with refresh token not found",
            )

        user = USERS_DB[username]
        role_val = (
            user["role"].value if hasattr(user["role"], "value") else str(user["role"])
        )
        new_access_token = create_access_token(data={"sub": username, "role": role_val})

        return {
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in": settings.ULPF_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "username": username,
            "role": role_val,
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired. Please log in again.",
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token signature",
        )


@router.get("/me", response_model=dict[str, Any])
def get_my_info(user: dict[str, Any] = Depends(get_current_user)):
    """Returns currently authenticated user profile and active role."""
    role_val = (
        user["role"].value if hasattr(user["role"], "value") else str(user["role"])
    )
    return {
        "username": user["username"],
        "role": role_val,
        "full_name": user["full_name"],
    }
