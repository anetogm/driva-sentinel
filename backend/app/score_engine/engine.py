from app.core.logging import get_logger
from app.scanner_engine.base import ScanResult

logger = get_logger("score_engine")

SEVERITY_WEIGHTS = {
    "critical": -15.0,
    "high": -10.0,
    "medium": -5.0,
    "low": -2.0,
    "info": -0.0,
}

CATEGORY_WEIGHTS = {
    "headers": 1.0,
    "tls": 1.2,
    "dns": 0.8,
    "web": 1.1,
    "tech": 0.5,
    "exposure": 1.3,
    "fingerprint": 0.3,
}

RATING_THRESHOLDS = [
    (95, "A+"),
    (85, "A"),
    (70, "B"),
    (55, "C"),
    (40, "D"),
    (0, "F"),
]


class ScoreEngine:
    def calculate(self, results: list[ScanResult]) -> dict:
        total_score = 100.0
        findings_count = 0
        category_scores = {}
        severity_counts = {}

        for result in results:
            cat = result.category
            cat_weight = CATEGORY_WEIGHTS.get(cat, 1.0)
            cat_score_impact = 0.0
            cat_findings = 0

            for finding in result.findings:
                severity = finding.severity.lower()
                weight = SEVERITY_WEIGHTS.get(severity, 0.0)

                adjusted_impact = finding.score_impact if finding.score_impact != 0.0 else weight
                adjusted_impact *= cat_weight

                cat_score_impact += adjusted_impact
                findings_count += 1
                cat_findings += 1
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            category_scores[cat] = {
                "score_impact": round(cat_score_impact, 2),
                "findings_count": cat_findings,
                "max_score": 20.0 * cat_weight,
            }
            total_score += cat_score_impact

        total_score = max(0.0, min(100.0, total_score))
        total_score = round(total_score, 2)

        rating = "F"
        for threshold, r in RATING_THRESHOLDS:
            if total_score >= threshold:
                rating = r
                break

        score_breakdown = []
        for cat, data in category_scores.items():
            cat_max = data["max_score"]
            cat_impact = data["score_impact"]
            cat_score = max(0.0, cat_max + cat_impact)
            score_breakdown.append({
                "category": cat,
                "score": round(cat_score, 2),
                "max_score": round(cat_max, 2),
                "findings_count": data["findings_count"],
            })

        summary = {
            "total_findings": findings_count,
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "info": severity_counts.get("info", 0),
        }

        risk_level = self._calculate_risk_level(total_score, severity_counts)

        logger.info(
            "score_calculated",
            score=total_score,
            rating=rating,
            findings=findings_count,
        )

        return {
            "score": total_score,
            "rating": rating,
            "findings_count": findings_count,
            "score_breakdown": score_breakdown,
            "summary": summary,
            "risk_level": risk_level,
        }

    def _calculate_risk_level(self, score: float, severity_counts: dict) -> str:
        critical = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)

        if critical >= 2 or (critical >= 1 and high >= 3):
            return "critical"
        if critical >= 1 or high >= 3:
            return "high"
        if high >= 1 or score < 70:
            return "medium"
        if score < 85:
            return "low"
        return "minimal"


score_engine = ScoreEngine()
