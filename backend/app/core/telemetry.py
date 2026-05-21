from functools import wraps
from typing import Any, Callable, TypeVar

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger("telemetry")

F = TypeVar("F", bound=Callable[..., Any])


class MetricsCollector:
    _instance: "MetricsCollector | None" = None

    def __new__(cls) -> "MetricsCollector":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        self._initialized = True
        self._counters: dict[str, int] = {}
        self._histograms: dict[str, list[float]] = {}
        self._gauges: dict[str, float] = {}

    def increment(self, name: str, value: int = 1, labels: dict[str, str] | None = None) -> None:
        key = self._key(name, labels)
        self._counters[key] = self._counters.get(key, 0) + value

    def observe(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        key = self._key(name, labels)
        if key not in self._histograms:
            self._histograms[key] = []
        self._histograms[key].append(value)

    def gauge(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        key = self._key(name, labels)
        self._gauges[key] = value

    def _key(self, name: str, labels: dict[str, str] | None = None) -> str:
        if not labels:
            return name
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"

    def get_metrics(self) -> dict[str, Any]:
        return {
            "counters": dict(self._counters),
            "histograms": {k: {"count": len(v), "sum": sum(v)} for k, v in self._histograms.items()},
            "gauges": dict(self._gauges),
        }


metrics = MetricsCollector()


def timed(metric_name: str, labels: dict[str, str] | None = None) -> Callable[[F], F]:
    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            import time

            start = time.perf_counter()
            try:
                return func(*args, **kwargs)
            finally:
                elapsed = time.perf_counter() - start
                metrics.observe(metric_name, elapsed, labels)

        @wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            import asyncio
            import time

            start = time.perf_counter()
            try:
                return await func(*args, **kwargs)
            finally:
                elapsed = time.perf_counter() - start
                metrics.observe(metric_name, elapsed, labels)

        if hasattr(func, "__wrapped__"):
            return async_wrapper  # type: ignore[return-value]
        from inspect import iscoroutinefunction

        if iscoroutinefunction(func):
            return async_wrapper  # type: ignore[return-value]
        return wrapper  # type: ignore[return-value]

    return decorator
