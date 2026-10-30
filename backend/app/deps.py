from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .models import AuditLog, User, Workspace
from .security import decode_session_token, require_csrf


def _token_from_request(request: Request) -> str | None:
    token = request.cookies.get(settings.cookie_name)
    if token:
        return token
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header.split(" ", 1)[1].strip()
    return None


def get_session_payload(request: Request) -> dict:
    token = _token_from_request(request)
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")
    return decode_session_token(token)


def get_current_user(
    request: Request, db: Session = Depends(get_db)
) -> User:
    payload = get_session_payload(request)
    user = db.get(User, int(payload["sub"]))
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Account is not active")
    request.state.user = user
    request.state.session = payload
    return user


def require_permissions(*permissions: str):
    def dependency(request: Request, user: User = Depends(get_current_user)) -> User:
        granted = set(user.role.permissions or [])
        missing = [p for p in permissions if p not in granted]
        if missing:
            raise HTTPException(
                status_code=403,
                detail=f"Missing permission: {', '.join(missing)}",
            )
        return user

    return dependency


def require_csrf_for(request: Request) -> None:
    payload = get_session_payload(request)
    require_csrf(request, payload)


def csrf_protected(user: User = Depends(get_current_user)) -> User:
    """Dependency for mutating authenticated endpoints. Request is validated in middleware."""
    return user


def get_workspace(
    workspace_id: int | None = None,
    workspace: str | None = None,
    db: Session = Depends(get_db),
) -> Workspace:
    if workspace:
        ws = db.query(Workspace).filter(Workspace.slug == workspace).first()
    elif workspace_id:
        ws = db.get(Workspace, workspace_id)
    else:
        ws = db.query(Workspace).filter(Workspace.environment == "LIVE").first()
    if not ws:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return ws


def record_audit(
    db: Session,
    *,
    actor: User | None,
    action: str,
    resource_type: str = "",
    resource_id: str | int = "",
    request: Request | None = None,
    meta: dict | None = None,
) -> AuditLog:
    entry = AuditLog(
        actor_id=actor.id if actor else None,
        actor_email=actor.email if actor else "system",
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id),
        ip_address=(request.client.host if request and request.client else ""),
        meta=meta or {},
    )
    db.add(entry)
    return entry


def paginate(query, page: int, page_size: int):
    total = query.count()
    rows = query.offset((page - 1) * page_size).limit(page_size).all()
    return rows, total
