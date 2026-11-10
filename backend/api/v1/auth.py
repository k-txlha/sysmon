"""Administrator setup, login, and server-managed session endpoints."""

from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, SecretStr

from backend.config.settings import settings
from backend.services.auth_service import (
    AUTH_SESSION_COOKIE,
    CSRF_HEADER,
    SESSION_TTL,
    AdministratorAlreadyExists,
    AuthenticatedAdmin,
    AuthenticationInputError,
    auth_service,
)
from backend.utils.rate_limiter import RateLimiter

router = APIRouter(prefix="/api/v1/auth", tags=["Administrator Authentication"])
login_rate_limiter = RateLimiter(
    requests_limit=5,
    window_seconds=60,
    key_by_client_ip=True,
)


class CredentialsRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: SecretStr = Field(min_length=1, max_length=128)


class PasswordChangeRequest(BaseModel):
    new_password: SecretStr = Field(min_length=1, max_length=128)


def _set_session_cookies(response: Response, session_token: str) -> None:
    cookie_options = {
        "max_age": int(SESSION_TTL.total_seconds()),
        "secure": settings.AUTH_SESSION_COOKIE_SECURE,
        "samesite": "strict",
        "path": "/",
    }
    response.set_cookie(
        AUTH_SESSION_COOKIE,
        session_token,
        httponly=True,
        **cookie_options,
    )


def _clear_session_cookies(response: Response) -> None:
    response.delete_cookie(
        AUTH_SESSION_COOKIE,
        path="/",
        secure=settings.AUTH_SESSION_COOKIE_SECURE,
        httponly=True,
        samesite="strict",
    )


def _is_local_client(request: Request) -> bool:
    if request.client is None:
        return False
    if "forwarded" in request.headers or "x-real-ip" in request.headers or any(
        header.lower().startswith("x-forwarded-") for header in request.headers
    ):
        return False
    try:
        return ipaddress.ip_address(request.client.host).is_loopback
    except ValueError:
        return False


async def require_admin(
    request: Request,
    csrf_header: str | None = Header(default=None, alias=CSRF_HEADER),
) -> AuthenticatedAdmin:
    session_token = request.cookies.get(AUTH_SESSION_COOKIE)
    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Administrator authentication required.",
        )
    admin = auth_service.get_session(session_token)
    if admin is None or admin.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Administrator authentication required.",
        )
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        if (
            not csrf_header
            or not auth_service.validate_csrf(admin, csrf_header)
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF validation failed.",
            )
    return admin


@router.get("/status")
async def authentication_status():
    return {"setup_required": auth_service.is_setup_required()}


@router.post("/setup", status_code=status.HTTP_201_CREATED)
async def setup_admin(
    payload: CredentialsRequest,
    request: Request,
    response: Response,
) -> dict[str, object]:
    response.headers["Cache-Control"] = "no-store"
    if not _is_local_client(request):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Initial administrator setup is only available from localhost.",
        )
    try:
        admin = auth_service.create_admin(
            payload.username, payload.password.get_secret_value()
        )
    except AdministratorAlreadyExists:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Initial administrator setup has already been completed.",
        )
    except AuthenticationInputError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session_token, csrf_token, _ = auth_service.create_session(admin["id"])
    _set_session_cookies(response, session_token)
    return {"user": admin, "csrf_token": csrf_token}


@router.post("/login", dependencies=[Depends(login_rate_limiter)])
async def login(
    payload: CredentialsRequest,
    response: Response,
) -> dict[str, object]:
    response.headers["Cache-Control"] = "no-store"
    admin = auth_service.authenticate(
        payload.username, payload.password.get_secret_value()
    )
    if admin is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )
    session_token, csrf_token, _ = auth_service.create_session(admin["id"])
    _set_session_cookies(response, session_token)
    return {"user": admin, "csrf_token": csrf_token}


@router.get("/me")
async def current_admin(
    response: Response,
    admin: AuthenticatedAdmin = Depends(require_admin),
) -> dict[str, object]:
    response.headers["Cache-Control"] = "no-store"
    csrf_token = auth_service.rotate_csrf(admin.session_id)
    return {
        "user": {"id": admin.id, "username": admin.username, "role": admin.role},
        "csrf_token": csrf_token,
    }


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    admin: AuthenticatedAdmin = Depends(require_admin),
) -> dict[str, str]:
    del admin
    session_token = request.cookies.get(AUTH_SESSION_COOKIE)
    if session_token:
        auth_service.revoke_session(session_token)
    _clear_session_cookies(response)
    return {"status": "logged_out"}


@router.post("/password")
async def change_password(
    payload: PasswordChangeRequest,
    response: Response,
    admin: AuthenticatedAdmin = Depends(require_admin),
) -> dict[str, str]:
    try:
        auth_service.change_password(
            admin.id, payload.new_password.get_secret_value()
        )
    except AuthenticationInputError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    _clear_session_cookies(response)
    return {"status": "password_changed"}
