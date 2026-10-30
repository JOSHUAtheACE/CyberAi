from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import record_audit, require_permissions
from ..models import GeneratedReport, User, Workspace
from ..pdf_report import render_report_pdf
from ..reports import REPORT_KINDS, create_report, report_csv
from ..serializers import iso, user_payload
from .dashboard import get_workspace_or_404
from ..models import User as UserModel

router = APIRouter(prefix="/reports", tags=["Reports"])


def _report_payload(report: GeneratedReport, workspace: Workspace | None = None, with_summary: bool = False) -> dict:
    payload = {
        "id": report.id,
        "reference": report.reference,
        "kind": report.kind,
        "kind_label": REPORT_KINDS.get(report.kind, report.kind),
        "title": report.title,
        "environment": report.environment,
        "workspace_id": report.workspace_id,
        "workspace": workspace.name if workspace else None,
        "period": {
            "start": iso(report.period_start),
            "end": iso(report.period_end),
        },
        "status": report.status,
        "created_at": iso(report.created_at),
        "params": report.params,
        "summary": report.summary if with_summary else None,
        "peek": {
            "alerts": (report.summary or {}).get("totals", {}).get("alerts"),
            "flows": (report.summary or {}).get("totals", {}).get("flows"),
            "critical": (report.summary or {}).get("totals", {}).get("critical"),
        },
    }
    if report.created_by:
        creator = report.summary.get("created_by") if report.summary else None
        payload["created_by"] = creator
    return payload


@router.get("")
def list_reports(
    workspace: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(12, ge=1, le=50),
    user: User = Depends(require_permissions("reports.view")),
    db: Session = Depends(get_db),
):
    query = db.query(GeneratedReport)
    if workspace:
        ws = get_workspace_or_404(db, workspace)
        query = query.filter(GeneratedReport.workspace_id == ws.id)
    total = query.count()
    rows = (
        query.order_by(GeneratedReport.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    workspace_map = {
        ws.id: ws for ws in db.query(Workspace).filter(Workspace.id.in_({r.workspace_id for r in rows} or {-1})).all()
    }
    return {
        "items": [_report_payload(row, workspace_map.get(row.workspace_id)) for row in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "kinds": [{"value": key, "label": value} for key, value in REPORT_KINDS.items()],
    }


class ReportCreate(BaseModel):
    workspace: str = "live-ops"
    kind: str = Field(default="security_summary")
    period: str = Field(default="24h", pattern="^(24h|7d|30d|custom)$")
    start: str | None = None
    end: str | None = None


@router.post("", status_code=201)
def generate_report(
    payload: ReportCreate,
    user: User = Depends(require_permissions("reports.view")),
    db: Session = Depends(get_db),
):
    if payload.kind not in REPORT_KINDS:
        raise HTTPException(status_code=400, detail="Unsupported report kind")
    ws = get_workspace_or_404(db, payload.workspace)
    start = end = None
    if payload.period == "custom":
        try:
            start = datetime.fromisoformat((payload.start or "").replace("Z", "+00:00")).replace(tzinfo=None)
            end = datetime.fromisoformat((payload.end or "").replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            raise HTTPException(status_code=400, detail="Custom reports require ISO-8601 start and end")
        if start >= end:
            raise HTTPException(status_code=400, detail="Start must precede end")
    report = create_report(
        db,
        workspace=ws,
        environment=ws.environment,
        kind=payload.kind,
        period=payload.period,
        start=start,
        end=end,
        created_by=user.id,
    )
    summary = dict(report.summary or {})
    summary["created_by"] = user_payload(user)["name"]
    report.summary = summary
    record_audit(
        db,
        actor=user,
        action="report.generated",
        resource_type="generated_report",
        resource_id=report.id,
        meta={"kind": payload.kind, "period": payload.period, "workspace": ws.slug},
    )
    db.commit()
    db.refresh(report)
    return _report_payload(report, ws, with_summary=True)


@router.get("/{report_id}")
def report_detail(
    report_id: int,
    user: User = Depends(require_permissions("reports.view")),
    db: Session = Depends(get_db),
):
    report = db.get(GeneratedReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    ws = db.get(Workspace, report.workspace_id)
    payload = _report_payload(report, ws, with_summary=True)
    summary = report.summary or {}
    payload["linkage"] = {
        "query": summary.get("query"),
        "environment": summary.get("environment"),
        "limitations": summary.get("limitations", []),
        "note": (
            "Report values are computed from stored flow records and alerts at generation time. "
            "Re-generating with a different period may yield different totals."
        ),
    }
    return payload


@router.get("/{report_id}/export")
def export_report(
    report_id: int,
    format: str = Query("pdf", pattern="^(pdf|csv|json)$"),
    user: User = Depends(require_permissions("reports.export")),
    db: Session = Depends(get_db),
):
    report = db.get(GeneratedReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    summary = report.summary or {}
    if not summary:
        raise HTTPException(status_code=409, detail="Report has no stored summary to export")
    record_audit(
        db,
        actor=user,
        action="report.exported",
        resource_type="generated_report",
        resource_id=report.id,
        meta={"format": format},
    )
    db.commit()

    filename = f"{report.reference}.{format}"
    if format == "csv":
        body = report_csv(summary).encode("utf-8")
        media = "text/csv; charset=utf-8"
    elif format == "json":
        import json

        body = json.dumps(
            {
                "report": _report_payload(report, with_summary=True),
                "exported_at": iso(datetime.utcnow()),
                "exported_by": user.email,
            },
            indent=2,
            default=str,
        ).encode("utf-8")
        media = "application/json"
    else:
        body = render_report_pdf(summary)
        media = "application/pdf"
    return Response(
        content=body,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
