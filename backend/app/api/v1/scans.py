from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db_session, require_user
from app.core.logging import get_logger
from app.core.security import get_client_ip, validate_target_url
from app.core.telemetry import metrics
from app.models.user import User
from app.queue.handlers import execute_scan
from app.repositories.scan import scan_repo
from app.schemas.scan import (
    ScanCreate,
    ScanDetail,
    ScanListResponse,
    ScanProgress,
    ScanRead,
    ScanReport,
    ScanStats,
)
from app.services.scan_service import ScanService

logger = get_logger("scans_router")

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanRead, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    scan_in: ScanCreate,
    db: AsyncSession = Depends(get_db_session),
    current_user: User | None = Depends(get_current_user),
) -> Any:
    target_url = validate_target_url(scan_in.target_url)
    logger.info("scan_requested", url=target_url, user_id=current_user.id if current_user else None)
    metrics.increment("scan_requests_total")

    scan = await ScanService.create_scan(
        db, scan_in, user_id=current_user.id if current_user else None
    )

    execute_scan.delay(scan.id)

    return scan


@router.get("", response_model=ScanListResponse)
async def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db_session),
    current_user: User | None = Depends(get_current_user),
) -> dict:
    scans, total = await ScanService.list_scans(
        db, skip=skip, limit=limit, user_id=current_user.id if current_user else None
    )
    return {
        "items": scans,
        "total": total,
        "page": skip // limit + 1,
        "page_size": limit,
    }


@router.get("/stats", response_model=ScanStats)
async def get_scan_stats(
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    return await ScanService.get_stats(db)


@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db_session),
) -> Any:
    scan = await ScanService.get_scan_detail(db, scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    return scan


@router.get("/{scan_id}/progress", response_model=ScanProgress)
async def get_scan_progress(
    scan_id: str,
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    scan = await scan_repo.get(db, scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    progress = 0.0
    if scan.status == "pending":
        progress = 0.0
    elif scan.status == "running":
        progress = 50.0
    elif scan.status in ("completed", "failed"):
        progress = 100.0

    return {
        "scan_id": scan_id,
        "status": scan.status,
        "progress": progress,
        "current_scanner": None,
        "findings_so_far": scan.findings_count,
        "estimated_remaining_seconds": None,
    }


@router.post("/{scan_id}/rescan", response_model=ScanRead, status_code=status.HTTP_202_ACCEPTED)
async def rescan(
    scan_id: str,
    db: AsyncSession = Depends(get_db_session),
    current_user: User | None = Depends(get_current_user),
) -> Any:
    scan = await scan_repo.get(db, scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    new_scan = await ScanService.create_scan(
        db, ScanCreate(target_url=scan.target_url), user_id=current_user.id if current_user else None
    )
    execute_scan.delay(new_scan.id)
    return new_scan


@router.get("/{scan_id}/report", response_model=ScanReport)
async def get_scan_report(
    scan_id: str,
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    scan = await ScanService.get_scan_detail(db, scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    metadata = scan.metadata or {}
    score_breakdown = metadata.get("score_breakdown", [])
    summary = metadata.get("summary", {})
    risk_level = metadata.get("risk_level", "unknown")

    return {
        "scan": scan,
        "score_breakdown": score_breakdown,
        "summary": summary,
        "risk_level": risk_level,
    }
