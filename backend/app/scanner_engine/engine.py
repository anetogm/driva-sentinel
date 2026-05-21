import asyncio
import time
from typing import Any

from app.core.logging import get_logger
from app.core.telemetry import metrics, timed
from app.scanner_engine.base import ScanResult, ScanTarget
from app.scanner_engine.registry import scanner_registry

logger = get_logger("scanner_engine")


class ScanEngine:
    def __init__(self, max_concurrent: int = 7) -> None:
        self.max_concurrent = max_concurrent
        self.registry = scanner_registry

    async def run_scan(self, url: str) -> list[ScanResult]:
        target = ScanTarget(url=url)
        scanners = self.registry.get_all()
        semaphore = asyncio.Semaphore(self.max_concurrent)

        metrics.gauge("scan_scanners_total", len(scanners))
        logger.info(
            "scan_started",
            url=url,
            scanner_count=len(scanners),
        )

        async def run_with_timeout(scanner) -> ScanResult:
            async with semaphore:
                start = time.perf_counter()
                scanner_name = scanner.name
                try:
                    result = await asyncio.wait_for(
                        scanner.scan(target),
                        timeout=scanner.timeout_seconds,
                    )
                    elapsed = time.perf_counter() - start
                    result.execution_time_seconds = elapsed
                    metrics.observe(
                        "scanner_duration_seconds",
                        elapsed,
                        {"scanner": scanner_name},
                    )
                    metrics.increment(
                        "scanner_findings_total",
                        len(result.findings),
                        {"scanner": scanner_name, "category": scanner.category},
                    )
                    logger.info(
                        "scanner_completed",
                        scanner=scanner_name,
                        findings=len(result.findings),
                        elapsed=round(elapsed, 3),
                    )
                    return result
                except asyncio.TimeoutError:
                    elapsed = time.perf_counter() - start
                    logger.warning(
                        "scanner_timeout",
                        scanner=scanner_name,
                        timeout=scanner.timeout_seconds,
                    )
                    result = ScanResult(
                        scanner_name=scanner_name,
                        category=scanner.category,
                        execution_time_seconds=elapsed,
                    )
                    result.add_finding(
                        title=f"{scanner_name} scanner timeout",
                        description=f"The {scanner_name} scanner exceeded the timeout of {scanner.timeout_seconds}s.",
                        severity="low",
                        confidence="high",
                        recommendation="Consider increasing scanner timeout or check target responsiveness.",
                        score_impact=-0.5,
                    )
                    return result
                except Exception as e:
                    elapsed = time.perf_counter() - start
                    logger.error(
                        "scanner_error",
                        scanner=scanner_name,
                        error=str(e),
                        error_type=type(e).__name__,
                    )
                    result = ScanResult(
                        scanner_name=scanner_name,
                        category=scanner.category,
                        execution_time_seconds=elapsed,
                    )
                    result.add_finding(
                        title=f"{scanner_name} scanner error",
                        description=f"The {scanner_name} scanner encountered an error: {str(e)}",
                        severity="info",
                        confidence="medium",
                        recommendation="This may be due to network issues or target protection mechanisms.",
                        score_impact=0.0,
                    )
                    return result

        tasks = [run_with_timeout(s) for s in scanners]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        final_results = []
        for r in results:
            if isinstance(r, Exception):
                logger.error("scan_task_exception", error=str(r))
                continue
            final_results.append(r)

        total_findings = sum(len(r.findings) for r in final_results)
        logger.info(
            "scan_completed",
            url=url,
            results=len(final_results),
            total_findings=total_findings,
        )
        metrics.increment("scan_completed_total")
        metrics.gauge("scan_findings_total", total_findings)

        return final_results


scan_engine = ScanEngine()
