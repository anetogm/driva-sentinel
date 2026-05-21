from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Category(str, Enum):
    HEADERS = "headers"
    TLS = "tls"
    DNS = "dns"
    WEB = "web"
    TECH = "tech"
    EXPOSURE = "exposure"
    FINGERPRINT = "fingerprint"


@dataclass
class ScanTarget:
    url: str
    hostname: str = ""
    scheme: str = "https"
    port: int = 443
    path: str = "/"

    def __post_init__(self) -> None:
        from urllib.parse import urlparse

        parsed = urlparse(self.url)
        self.hostname = parsed.hostname or ""
        self.scheme = parsed.scheme or "https"
        self.port = parsed.port or (443 if self.scheme == "https" else 80)
        self.path = parsed.path or "/"


@dataclass
class Finding:
    scanner: str
    category: str
    title: str
    description: str
    severity: str
    confidence: str = "high"
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    score_impact: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "score_impact": self.score_impact,
        }


@dataclass
class ScanResult:
    scanner_name: str
    category: str
    findings: list[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0
    raw_data: dict[str, Any] = field(default_factory=dict)

    def add_finding(
        self,
        title: str,
        description: str,
        severity: str,
        recommendation: str = "",
        evidence: dict[str, Any] | None = None,
        score_impact: float = 0.0,
        confidence: str = "high",
    ) -> None:
        self.findings.append(
            Finding(
                scanner=self.scanner_name,
                category=self.category,
                title=title,
                description=description,
                severity=severity,
                confidence=confidence,
                evidence=evidence or {},
                recommendation=recommendation,
                score_impact=score_impact,
            )
        )


class BaseScanner(ABC):
    name: str = "base"
    category: str = "unknown"
    timeout_seconds: int = 30

    @abstractmethod
    async def scan(self, target: ScanTarget) -> ScanResult:
        ...

    def create_result(self) -> ScanResult:
        return ScanResult(scanner_name=self.name, category=self.category)
