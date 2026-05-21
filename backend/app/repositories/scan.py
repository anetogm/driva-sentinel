from typing import Sequence

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Finding, Scan
from app.repositories.base import BaseRepository


class ScanRepository(BaseRepository[Scan]):
    def __init__(self) -> None:
        super().__init__(Scan)

    async def get_multi_by_user(
        self, db: AsyncSession, user_id: str, *, skip: int = 0, limit: int = 100
    ) -> Sequence[Scan]:
        result = await db.execute(
            select(Scan)
            .where(Scan.user_id == user_id)
            .order_by(desc(Scan.created_at))
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()

    async def get_with_findings(self, db: AsyncSession, scan_id: str) -> Scan | None:
        result = await db.execute(
            select(Scan).where(Scan.id == scan_id)
        )
        return result.scalar_one_or_none()

    async def get_recent(self, db: AsyncSession, limit: int = 10) -> Sequence[Scan]:
        result = await db.execute(
            select(Scan).order_by(desc(Scan.created_at)).limit(limit)
        )
        return result.scalars().all()

    async def count_by_status(self, db: AsyncSession) -> dict[str, int]:
        result = await db.execute(
            select(Scan.status, func.count(Scan.id)).group_by(Scan.status)
        )
        return {status: count for status, count in result.all()}

    async def count_by_rating(self, db: AsyncSession) -> dict[str, int]:
        result = await db.execute(
            select(Scan.rating, func.count(Scan.id))
            .where(Scan.rating.isnot(None))
            .group_by(Scan.rating)
        )
        return {rating: count for rating, count in result.all()}

    async def get_average_score(self, db: AsyncSession) -> float | None:
        result = await db.execute(
            select(func.avg(Scan.score)).where(Scan.score.isnot(None))
        )
        return result.scalar()


class FindingRepository(BaseRepository[Finding]):
    def __init__(self) -> None:
        super().__init__(Finding)

    async def get_by_scan(
        self, db: AsyncSession, scan_id: str
    ) -> Sequence[Finding]:
        result = await db.execute(
            select(Finding)
            .where(Finding.scan_id == scan_id)
            .order_by(
                func.case(
                    (Finding.severity == "critical", 1),
                    (Finding.severity == "high", 2),
                    (Finding.severity == "medium", 3),
                    (Finding.severity == "low", 4),
                    (Finding.severity == "info", 5),
                    else_=6,
                )
            )
        )
        return result.scalars().all()

    async def create_many(
        self, db: AsyncSession, findings: list[dict]
    ) -> Sequence[Finding]:
        db_findings = [Finding(**f) for f in findings]
        db.add_all(db_findings)
        await db.commit()
        for f in db_findings:
            await db.refresh(f)
        return db_findings


scan_repo = ScanRepository()
finding_repo = FindingRepository()
