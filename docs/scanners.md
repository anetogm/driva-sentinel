# Scanner Documentation

## Plugin Architecture

All scanners implement the `BaseScanner` abstract class:

```python
class BaseScanner(ABC):
    name: str = "base"
    category: str = "unknown"
    timeout_seconds: int = 30

    @abstractmethod
    async def scan(self, target: ScanTarget) -> ScanResult:
        ...
```

## Adding a New Scanner

1. Create a new file in `backend/app/scanner_engine/plugins/`
2. Implement the `BaseScanner` interface
3. Register in `backend/app/scanner_engine/registry.py`

Example:

```python
from app.scanner_engine.base import BaseScanner, ScanResult, ScanTarget

class MyScanner(BaseScanner):
    name = "myscanner"
    category = "custom"

    async def scan(self, target: ScanTarget) -> ScanResult:
        result = self.create_result()
        # Perform checks
        result.add_finding(
            title="Issue found",
            description="Description of the issue",
            severity="high",
            recommendation="How to fix it",
            score_impact=-10.0,
        )
        return result
```

## Scanner Details

### Headers Scanner
- **File**: `headers_scanner.py`
- **Checks**: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CORS, Cookie flags, Cache-Control, Server leakage
- **Max Impact**: -20 points (missing HTTPS)

### TLS Scanner
- **File**: `tls_scanner.py`
- **Checks**: Certificate validity, expiration, self-signed, hostname mismatch, weak protocols (TLSv1.0/1.1), weak ciphers, HSTS preload
- **Max Impact**: -20 points (no HTTPS)

### DNS Scanner
- **File**: `dns_scanner.py`
- **Checks**: SPF, DMARC, DKIM, DNSSEC, CAA, MX, wildcard detection, subdomain enumeration
- **Max Impact**: -8 points (SPF +all)

### Web Scanner
- **File**: `web_scanner.py`
- **Checks**: Exposed .git, .env, backups, admin panels, robots.txt, HTTP methods, CORS misconfiguration, clickjacking, open redirect, error leakage
- **Max Impact**: -15 points (exposed .git or .env)

### Technology Scanner
- **File**: `tech_scanner.py`
- **Checks**: Frameworks, CMS, WAF, CDN, JavaScript libraries, cloud providers
- **Max Impact**: -1 point (outdated technology)

### Exposure Scanner
- **File**: `exposure_scanner.py`
- **Checks**: Sensitive files, directory listing, API docs, Spring Boot actuators, debug consoles, Docker files
- **Max Impact**: -15 points (Terraform state or debug console)

### Fingerprint Scanner
- **File**: `fingerprint_scanner.py`
- **Checks**: Server headers, cookie analysis, HTML body signatures, information disclosure assessment
- **Max Impact**: -2 points (excessive header disclosure)
