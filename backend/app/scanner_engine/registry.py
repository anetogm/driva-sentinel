from app.scanner_engine.base import BaseScanner
from app.scanner_engine.plugins.dns_scanner import DNSScanner
from app.scanner_engine.plugins.exposure_scanner import ExposureScanner
from app.scanner_engine.plugins.fingerprint_scanner import FingerprintScanner
from app.scanner_engine.plugins.headers_scanner import HeadersScanner
from app.scanner_engine.plugins.tech_scanner import TechScanner
from app.scanner_engine.plugins.tls_scanner import TLSScanner
from app.scanner_engine.plugins.web_scanner import WebScanner


class ScannerRegistry:
    def __init__(self) -> None:
        self._scanners: dict[str, BaseScanner] = {}
        self._register_default_scanners()

    def _register_default_scanners(self) -> None:
        scanners = [
            HeadersScanner(),
            TLSScanner(),
            DNSScanner(),
            WebScanner(),
            TechScanner(),
            ExposureScanner(),
            FingerprintScanner(),
        ]
        for scanner in scanners:
            self.register(scanner)

    def register(self, scanner: BaseScanner) -> None:
        self._scanners[scanner.name] = scanner

    def get(self, name: str) -> BaseScanner | None:
        return self._scanners.get(name)

    def get_all(self) -> list[BaseScanner]:
        return list(self._scanners.values())

    def list_scanners(self) -> list[dict]:
        return [
            {
                "name": s.name,
                "category": s.category,
                "timeout_seconds": s.timeout_seconds,
            }
            for s in self._scanners.values()
        ]


scanner_registry = ScannerRegistry()
