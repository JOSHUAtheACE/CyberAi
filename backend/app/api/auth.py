from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..deps import get_current_user, record_audit
from ..models import RuntimeSetting, User, Workspace
from ..security import (
    create_session_token,
    hash_password,
    new_csrf_token,
    rate_limiter,
    utc_now,
    verify_password,
)
from ..serializers import iso, user_payload

router = APIRouter(prefix="/auth", tags=["Authentication"])

DEMO_ACCOUNT = "analyst@sentinela.ai"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=200)
    remember: bool = True


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=12, max_length=200)


def _set_session_cookies(response: Response, token: str, csrf: str, remember: bool) -> None:
    max_age = settings.access_token_ttl_minutes * 60 if remember else None
    response.set_cookie(
        settings.cookie_name,
        token,
        max_age=max_age,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )
    response.set_cookie(
        settings.csrf_cookie,
        csrf,
        max_age=max_age,
        httponly=False,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )


def _auth_response(response: Response, request: Request, db: Session, user: User, remember: bool) -> dict:
    csrf = new_csrf_token()
    token = create_session_token(
        user_id=user.id,
        email=user.email,
        role=user.role.code,
        csrf_token=csrf,
        ttl_minutes=(settings.access_token_ttl_minutes if remember else 60),
    )
    _set_session_cookies(response, token, csrf, remember)
    user.last_login_at = utc_now()
    record_audit(
        db,
        actor=user,
        action="auth.login",
        resource_type="user",
        resource_id=user.id,
        request=request,
        meta={"demo": user.is_demo, "role": user.role.code},
    )
    db.commit()
    workspaces = db.query(Workspace).order_by(Workspace.id).all()
    return {
        "user": user_payload(user),
        "csrf_token": csrf,
        "expires_in_minutes": settings.access_token_ttl_minutes if remember else 60,
        "workspaces": [
            {
                "id": ws.id,
                "slug": ws.slug,
                "name": ws.name,
                "environment": ws.environment,
                "description": ws.description,
            }
            for ws in workspaces
        ],
    }


@router.post("/login")
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    email = payload.email.lower().strip()
    key = f"login:{client_ip}:{email}"
    if not rate_limiter.check(key, limit=8, window_seconds=300):
        record_audit(
            db, actor=None, action="auth.rate_limited", resource_type="user", resource_id=email,
            request=request, meta={"reason": "too_many_attempts"},
        )
        db.commit()
        raise HTTPException(status_code=429, detail="Too many sign-in attempts. Try again in a few minutes.")
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        record_audit(
            db, actor=None, action="auth.failed", resource_type="user", resource_id=email, request=request,
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="This account has been deactivated.")
    if user.is_demo:
        demo_setting = db.get(RuntimeSetting, "demo_mode")
        if demo_setting and not (demo_setting.value or {}).get("enabled", True):
            raise HTTPException(status_code=403, detail="Demo access is disabled for this deployment.")
    rate_limiter.reset(key)
    return _auth_response(response, request, db, user, payload.remember)


@router.post("/demo-login")
def demo_login(request: Request, response: Response, db: Session = Depends(get_db)):
    if not settings.demo_mode_enabled:
        raise HTTPException(status_code=403, detail="Demo access is disabled.")
    demo_setting = db.get(RuntimeSetting, "demo_mode")
    if demo_setting and not (demo_setting.value or {}).get("enabled", True):
        raise HTTPException(status_code=403, detail="Demo access is disabled for this deployment.")
    client_ip = request.client.host if request.client else "unknown"
    if not rate_limiter.check(f"demo-login:{client_ip}", limit=12, window_seconds=300):
        raise HTTPException(status_code=429, detail="Too many demo sessions. Try again shortly.")
    user = db.query(User).filter(User.email == DEMO_ACCOUNT).first()
    if not user:
        raise HTTPException(status_code=503, detail="Demo workspace is not initialised.")
    return _auth_response(response, request, db, user, remember=False)


@router.post("/logout")
def logout(request: Request, response: Response, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    record_audit(db, actor=user, action="auth.logout", resource_type="user", resource_id=user.id, request=request)
    db.commit()
    response.delete_cookie(settings.cookie_name, path="/")
    response.delete_cookie(settings.csrf_cookie, path="/")
    return {"ok": True}


@router.get("/me")
def me(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    payload = getattr(request.state, "session", {}) or {}
    workspaces = db.query(Workspace).order_by(Workspace.id).all()
    return {
        "user": user_payload(user),
        "csrf_token": payload.get("csrf"),
        "demo_mode_enabled": settings.demo_mode_enabled,
        "workspaces": [
            {
                "id": ws.id,
                "slug": ws.slug,
                "name": ws.name,
                "environment": ws.environment,
                "description": ws.description,
            }
            for ws in workspaces
        ],
        "session_expires_at": iso(
            __import__("datetime").datetime.fromtimestamp(payload.get("exp", 0), tz=__import__("datetime").timezone.utc)
        )
        if payload.get("exp")
        else None,
    }


@router.post("/change-password")
def change_password(
    payload: PasswordChange,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect.")
    user.password_hash = hash_password(payload.new_password)
    record_audit(db, actor=user, action="auth.password_changed", resource_type="user", resource_id=user.id, request=request)
    db.commit()
    return {"ok": True}
