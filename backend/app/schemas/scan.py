from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class ScanCreate(BaseModel):
    target_url: str = Field(..., min_length=1, max_length=2048)


class FindingEvidence(BaseModel):
    request: str | None = None
    response: str | None = None
    headers: dict[str, str] | None = None
    detail: str | None = None


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scanner: str
    category: str
    title: str
    description: str
    severity: str
    confidence: str
    evidence: dict[str, Any] | None = None
    recommendation: str | None = None
    score_impact: float
    created_at: datetime


class FindingCreate(BaseModel):
    scanner: str
    category: str
    title: str
    description: str
    severity: str
    confidence: str = "high"
    evidence: dict[str, Any] | None = None
    recommendation: str | None = None
    score_impact: float = 0.0


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    target_url: str
    status: str
    score: float | None = None
    rating: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    findings_count: int
    user_id: str | None = None
    metadata: dict[str, Any] | None = None
    created_at: datetime
    updated_at: datetime


class ScanDetail(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    target_url: str
    status: str
    score: float | None = None
    rating: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    findings_count: int
    user_id: str | None = None
    metadata: dict[str, Any] | None = None
    created_at: datetime
    updated_at: datetime
    findings: list[FindingRead] = []


class ScanListResponse(BaseModel):
    items: list[ScanRead]
    total: int
    page: int
    page_size: int


class ScanProgress(BaseModel):
    scan_id: str
    status: str
    progress: float = Field(..., ge=0.0, le=100.0)
    current_scanner: str | None = None
    findings_so_far: int
    estimated_remaining_seconds: int | None = None


class ScoreBreakdown(BaseModel):
    category: str
    score: float
    max_score: float
    findings_count: int


class ScanReport(BaseModel):
    scan: ScanDetail
    score_breakdown: list[ScoreBreakdown]
    summary: dict[str, int]
    risk_level: str


class ExportFormat(str, Enum):
    JSON = "json"
    PDF = "pdf"


class ScanStats(BaseModel):
    total_scans: int
    completed_scans: int
    failed_scans: int
    average_score: float | None = None
    rating_distribution: dict[str, int]
    recent_scans: list[ScanRead]
