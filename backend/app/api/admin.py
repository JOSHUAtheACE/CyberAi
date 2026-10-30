from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import record_audit, require_permissions
from ..models import (
    AuditLog,
    FlowRecord,
    GeneratedReport,
    ReplaySession,
    RuntimeSetting,
    SecurityAlert,
    SystemEvent,
    User,
    Workspace,
    utcnow,
)
from ..security import PERMISSIONS, ROLE_DEFINITIONS, hash_password
from ..serializers import iso, user_payload

router = APIRouter(prefix="/admin", tags=["Administration"])


@router.get("/roles")
def roles(
    user: User = Depends(require_permissions("users.manage")),
    db: Session = Depends(get_db),
):
    counts = dict(
        db.query(User.role_id, func.count(User.id)).group_by(User.role_id).all()
    )
    from ..models import Role

    mapping = {role.code: role.id for role in db.query(Role).all()}
    payload = []
    for definition in ROLE_DEFINITIONS:
        payload.append(
            {
                **definition,
                "users": counts.get(mapping.get(definition["code"]), 0),
            }
        )
    return {
        "roles": payload,
        "permissions": [{"code": k, "label": v} for k, v in PERMISSIONS.items()],
        "note": "Role permissions are enforced server-side on every request.",
    }


@router.get("/users")
def list_users(
    user: User = Depends(require_permissions("users.manage")),
    db: Session = Depends(get_db),
):
    rows = db.query(User).order_by(User.id).all()
    return {"items": [user_payload(row) for row in rows], "total": len(rows)}


class UserCreate(BaseModel):
    email: EmailStr
    name: str = Field(min_length=2, max_length=160)
    role_code: str
    password: str = Field(min_length=12, max_length=200)


@router.post("/users", status_code=201)
def create_user(
    payload: UserCreate,
    actor: User = Depends(require_permissions("users.manage")),
    db: Session = Depends(get_db),
):
    from ..models import Role

    if db.query(User).filter(User.email == payload.email.lower()).first():
        raise HTTPException(status_code=409, detail="A user with this email already exists")
    role = db.query(Role).filter(Role.code == payload.role_code).first()
    if not role:
        raise HTTPException(status_code=400, detail="Unknown role")
    user = User(
        email=payload.email.lower(),
        name=payload.name.strip(),
        password_hash=hash_password(payload.password),
        role_id=role.id,
        is_active=True,
        is_demo=False,
    )
    db.add(user)
    db.flush()
    record_audit(
        db,
        actor=actor,
        action="user.created",
        resource_type="user",
        resource_id=user.id,
        meta={"role": role.code, "email": user.email},
    )
    db.commit()
    db.refresh(user)
    return user_payload(user)


class UserUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=160)
    role_code: str | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=200)


@router.patch("/users/{user_id}")
def update_user(
    user_id: int,
    payload: UserUpdate,
    actor: User = Depends(require_permissions("users.manage")),
    db: Session = Depends(get_db),
):
    from ..models import Role

    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == actor.id and payload.is_active is False:
        raise HTTPException(status_code=400, detail="You cannot deactivate your own account")
    changes: dict = {}
    if payload.name:
        target.name = payload.name.strip()
        changes["name"] = target.name
    if payload.role_code:
        role = db.query(Role).filter(Role.code == payload.role_code).first()
        if not role:
            raise HTTPException(status_code=400, detail="Unknown role")
        if target.id == actor.id and role.code != actor.role.code:
            raise HTTPException(status_code=400, detail="You cannot change your own role")
        target.role_id = role.id
        changes["role"] = role.code
    if payload.is_active is not None:
        target.is_active = payload.is_active
        changes["is_active"] = payload.is_active
    if payload.password:
        target.password_hash = hash_password(payload.password)
        changes["password_reset"] = True
    if not changes:
        raise HTTPException(status_code=400, detail="No supported changes supplied")
    record_audit(
        db,
        actor=actor,
        action="user.updated",
        resource_type="user",
        resource_id=target.id,
        meta=changes,
    )
    db.commit()
    db.refresh(target)
    return user_payload(target)


@router.get("/audit")
def audit_logs(
    q: str | None = Query(None, max_length=120),
    action: str | None = Query(None),
    actor: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(30, ge=1, le=100),
    user: User = Depends(require_permissions("audit.view")),
    db: Session = Depends(get_db),
):
    query = db.query(AuditLog)
    if q:
        like = f"%{q.strip()}%"
        query = query.filter(
            or_(
                AuditLog.action.ilike(like),
                AuditLog.resource_type.ilike(like),
                AuditLog.resource_id.ilike(like),
                AuditLog.actor_email.ilike(like),
            )
        )
    if action:
        query = query.filter(AuditLog.action == action)
    if actor:
        query = query.filter(AuditLog.actor_email == actor)
    total = query.count()
    rows = (
        query.order_by(AuditLog.ts.desc(), AuditLog.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    actions = [
        {"value": value, "count": count}
        for value, count in db.query(AuditLog.action, func.count(AuditLog.id))
        .group_by(AuditLog.action)
        .order_by(func.count(AuditLog.id).desc())
        .limit(20)
        .all()
    ]
    return {
        "items": [
            {
                "id": row.id,
                "ts": iso(row.ts),
                "actor": row.actor_email,
                "action": row.action,
                "resource_type": row.resource_type,
                "resource_id": row.resource_id,
                "ip_address": row.ip_address,
                "meta": row.meta,
            }
            for row in rows
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
        "actions": actions,
    }


@router.get("/settings")
def platform_settings(
    user: User = Depends(require_permissions("settings.view")),
    db: Session = Depends(get_db),
):
    demo = db.get(RuntimeSetting, "demo_mode")
    workspaces = db.query(Workspace).order_by(Workspace.id).all()
    return {
        "runtime": {
            "demo_mode": {
                "key": "demo_mode",
                "enabled": bool((demo.value or {}).get("enabled", True)) if demo else True,
                "description": "Controls whether the synthetic demo workspace and demo sign-in are available.",
                "updated_at": iso(demo.updated_at) if demo else None,
            }
        },
        "workspaces": [
            {
                "id": ws.id,
                "slug": ws.slug,
                "name": ws.name,
                "environment": ws.environment,
                "description": ws.description,
                "internal_cidrs": ws.internal_cidrs,
            }
            for ws in workspaces
        ],
        "limits": {
            "upload_mb": 50,
            "max_preview_records": 25,
            "collector_records_per_request": 5000,
            "retention_days": 90,
        },
        "notes": [
            "External enrichment is controlled by the server environment and is disabled by default.",
            "Investigation actions never modify network infrastructure.",
        ],
    }


class SettingsUpdate(BaseModel):
    demo_mode: bool | None = None


@router.patch("/settings")
def update_settings(
    payload: SettingsUpdate,
    actor: User = Depends(require_permissions("users.manage")),
    db: Session = Depends(get_db),
):
    changes: dict = {}
    if payload.demo_mode is not None:
        row = db.get(RuntimeSetting, "demo_mode")
        if not row:
            row = RuntimeSetting(key="demo_mode", value={"enabled": payload.demo_mode})
            db.add(row)
        else:
            row.value = {"enabled": payload.demo_mode}
        row.updated_at = utcnow()
        row.updated_by = actor.id
        changes["demo_mode"] = payload.demo_mode
        db.add(
            SystemEvent(
                category="configuration",
                message=f"Demo mode {'enabled' if payload.demo_mode else 'disabled'} by {actor.email}.",
            )
        )
    if not changes:
        raise HTTPException(status_code=400, detail="No supported changes supplied")
    record_audit(
        db,
        actor=actor,
        action="system.settings_updated",
        resource_type="runtime_setting",
        resource_id=",".join(changes),
        meta=changes,
    )
    db.commit()
    return platform_settings(actor, db)


@router.get("/overview")
def admin_overview(
    user: User = Depends(require_permissions("settings.view")),
    db: Session = Depends(get_db),
):
    user_counts = dict(
        db.query(User.is_active, func.count(User.id)).group_by(User.is_active).all()
    )
    return {
        "users": {
            "total": (user_counts.get(True, 0) + user_counts.get(False, 0)),
            "active": user_counts.get(True, 0),
            "disabled": user_counts.get(False, 0),
        },
        "records": {
            "flows": db.query(func.count(FlowRecord.id)).scalar() or 0,
            "alerts": db.query(func.count(SecurityAlert.id)).scalar() or 0,
            "reports": db.query(func.count(GeneratedReport.id)).scalar() or 0,
            "replay_sessions": db.query(func.count(ReplaySession.id)).scalar() or 0,
        },
        "audit_events": db.query(func.count(AuditLog.id)).scalar() or 0,
        "recent_events": [
            {
                "id": row.id,
                "ts": iso(row.ts),
                "level": row.level,
                "category": row.category,
                "message": row.message,
            }
            for row in db.query(SystemEvent).order_by(SystemEvent.ts.desc()).limit(12).all()
        ],
    }
