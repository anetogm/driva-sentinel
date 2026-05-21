from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.core.security import validate_target_url
from app.models.scan import Finding, Scan
from app.repositories.scan import finding_repo, scan_repo
from app.scanner_engine.engine import scan_engine
from app.score_engine.engine import score_engine
from app.schemas.scan import FindingCreate, ScanCreate, ScanStats

logger = get_logger("scan_service")


class ScanService:
    @staticmethod
    async def create_scan(db: AsyncSession, scan_in: ScanCreate, user_id: str | None = None) -> Scan:
        target_url = validate_target_url(scan_in.target_url)

        scan_data = {
            "target_url": target_url,
            "status": "pending",
            "user_id": user_id,
        }
        scan = await scan_repo.create(db, obj_in=scan_data)
        logger.info("scan_created", scan_id=scan.id, url=target_url)
        return scan

    @staticmethod
    async def get_scan(db: AsyncSession, scan_id: str) -> Scan | None:
        return await scan_repo.get_with_findings(db, scan_id)

    @staticmethod
    async def get_scan_detail(db: AsyncSession, scan_id: str) -> Scan | None:
        scan = await scan_repo.get_with_findings(db, scan_id)
        if scan and scan.findings:
            pass
        return scan

    @staticmethod
    async def list_scans(
        db: AsyncSession, *, skip: int = 0, limit: int = 100, user_id: str | None = None
    ) -> tuple[Sequence[Scan], int]:
        if user_id:
            scans = await scan_repo.get_multi_by_user(db, user_id, skip=skip, limit=limit)
        else:
            scans = await scan_repo.get_multi(db, skip=skip, limit=limit)
        total = await scan_repo.count(db)
        return scans, total

    @staticmethod
    async def get_stats(db: AsyncSession) -> dict:
        total = await scan_repo.count(db)
        by_status = await scan_repo.count_by_status(db)
        by_rating = await scan_repo.count_by_rating(db)
        avg_score = await scan_repo.get_average_score(db)
        recent = await scan_repo.get_recent(db, limit=10)

        return {
            "total_scans": total,
            "completed_scans": by_status.get("completed", 0),
            "failed_scans": by_status.get("failed", 0),
            "average_score": round(avg_score, 2) if avg_score else None,
            "rating_distribution": by_rating,
            "recent_scans": recent,
        }

    @staticmethod
    async def execute_scan(db: AsyncSession, scan_id: str) -> Scan:
        scan = await scan_repo.get(db, scan_id)
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        scan = await scan_repo.update(
            db,
            db_obj=scan,
            obj_in={
                "status": "running",
                "started_at": datetime.now(timezone.utc),
            },
        )

        try:
            results = await scan_engine.run_scan(scan.target_url)

            score_data = score_engine.calculate(results)

            findings_data = []
            for result in results:
                for finding in result.findings:
                    findings_data.append({
                        "scan_id": scan_id,
                        "scanner": finding.scanner,
                        "category": finding.category,
                        "title": finding.title,
                        "description": finding.description,
                        "severity": finding.severity,
                        "confidence": finding.confidence,
                        "evidence": finding.evidence,
                        "recommendation": finding.recommendation,
                        "score_impact": finding.score_impact,
                    })

            if findings_data:
                await finding_repo.create_many(db, findings_data)

            metadata = {
                "scanners_executed": len(results),
                "score_breakdown": score_data["score_breakdown"],
                "summary": score_data["summary"],
                "risk_level": score_data["risk_level"],
            }

            scan = await scan_repo.update(
                db,
                db_obj=scan,
                obj_in={
                    "status": "completed",
                    "score": score_data["score"],
                    "rating": score_data["rating"],
                    "completed_at": datetime.now(timezone.utc),
                    "findings_count": score_data["findings_count"],
                    "metadata": metadata,
                },
            )

            logger.info(
                "scan_completed",
                scan_id=scan_id,
                score=score_data["score"],
                rating=score_data["rating"],
                findings=score_data["findings_count"],
            )

        except Exception as e:
            logger.error("scan_failed", scan_id=scan_id, error=str(e))
            scan = await scan_repo.update(
                db,
                db_obj=scan,
                obj_in={
                    "status": "failed",
                    "completed_at": datetime.now(timezone.utc),
                    "metadata": {"error": str(e)},
                },
            )

        return scan
