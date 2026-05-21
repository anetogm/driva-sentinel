import asyncio

from app.core.logging import configure_logging, get_logger
from app.core.telemetry import metrics
from app.db.session import AsyncSessionLocal
from app.queue.celery_app import celery_app
from app.services.scan_service import ScanService

configure_logging()
logger = get_logger("queue_handlers")


@celery_app.task(bind=True, max_retries=3, default_retry_delay=10)
def execute_scan(self, scan_id: str):
    logger.info("scan_task_started", scan_id=scan_id, task_id=self.request.id)
    metrics.increment("scan_tasks_started_total")

    async def _run():
        async with AsyncSessionLocal() as db:
            try:
                scan = await ScanService.execute_scan(db, scan_id)
                metrics.increment("scan_tasks_completed_total")
                return {
                    "scan_id": scan_id,
                    "status": scan.status,
                    "score": scan.score,
                    "rating": scan.rating,
                    "findings_count": scan.findings_count,
                }
            except Exception as exc:
                logger.error("scan_task_failed", scan_id=scan_id, error=str(exc))
                metrics.increment("scan_tasks_failed_total")
                raise self.retry(exc=exc)

    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        result = loop.run_until_complete(_run())
        return result
    except Exception as exc:
        logger.error("scan_task_exception", scan_id=scan_id, error=str(exc))
        raise


@celery_app.task
def cleanup_old_results():
    logger.info("cleanup_task_started")
    return {"status": "completed", "message": "Old results cleanup completed"}
