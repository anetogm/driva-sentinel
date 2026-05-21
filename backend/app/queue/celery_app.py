import os

from celery import Celery
from celery.signals import worker_ready

from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger

settings = get_settings()

os.environ.setdefault("CELERY_CONFIG_MODULE", "app.queue.celery_config")

celery_app = Celery(
    "kindmelody",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.queue.handlers"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.SCAN_TIMEOUT_SECONDS + 60,
    task_soft_time_limit=settings.SCAN_TIMEOUT_SECONDS,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=100,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    broker_connection_retry_on_startup=True,
    result_expires=3600 * 24 * 7,
    task_routes={
        "app.queue.handlers.execute_scan": {"queue": "scan"},
    },
    task_default_queue="default",
    beat_schedule={
        "cleanup-old-results": {
            "task": "app.queue.handlers.cleanup_old_results",
            "schedule": 3600 * 24,
        },
    },
)


@worker_ready.connect
def on_worker_ready(**kwargs):
    configure_logging()
    logger = get_logger("celery")
    logger.info("celery_worker_ready")
