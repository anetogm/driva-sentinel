# KindMelody Security Scanner

## Project Overview

KindMelody is an enterprise-grade website security analysis platform built with Python/FastAPI backend, Next.js frontend, and Celery workers. It performs deep security scans across 7 categories and provides actionable recommendations.

## Architecture

### Backend (`backend/`)
- **FastAPI** async API server at `app/main.py`
- **SQLAlchemy 2.0** with asyncpg for PostgreSQL
- **Models**: `Scan`, `Finding`, `User` in `app/models/`
- **Repositories**: Data access layer in `app/repositories/`
- **Services**: Business logic in `app/services/`
- **Scanner Engine**: Plugin-based architecture in `app/scanner_engine/`
- **Queue**: Celery with Redis broker in `app/queue/`

### Scanners (7 total)
All in `app/scanner_engine/plugins/`:
1. `headers_scanner.py` - Security headers analysis
2. `tls_scanner.py` - TLS/SSL certificate and cipher analysis
3. `dns_scanner.py` - DNS records (SPF, DMARC, DKIM, DNSSEC, CAA)
4. `web_scanner.py` - Web exposure (git, env, backups, admin panels)
5. `tech_scanner.py` - Technology detection (frameworks, CMS, WAF, CDN)
6. `exposure_scanner.py` - Sensitive file and endpoint exposure
7. `fingerprint_scanner.py` - Server and technology fingerprinting

### Score Engine (`app/score_engine/engine.py`)
- Weighted scoring based on severity and category
- Critical: -15, High: -10, Medium: -5, Low: -2
- Ratings: A+ (95+), A (85+), B (70+), C (55+), D (40+), F (<40)

### Frontend (`frontend/`)
- Next.js 15 with App Router
- Dark mode first design (bg: #0a0f1a)
- Glassmorphism UI components
- Pages: Landing, Scan Detail, History

### Workers (`workers/`)
- Celery worker consuming scan tasks
- Executes scanners asynchronously
- Retry logic with exponential backoff

## Key Files

| Purpose | Path |
|---------|------|
| API Entry | `backend/app/main.py` |
| Config | `backend/app/core/config.py` |
| Security | `backend/app/core/security.py` |
| Scan Router | `backend/app/api/v1/scans.py` |
| Auth Router | `backend/app/api/v1/auth.py` |
| Scan Service | `backend/app/services/scan_service.py` |
| Scan Engine | `backend/app/scanner_engine/engine.py` |
| Score Engine | `backend/app/score_engine/engine.py` |
| Celery App | `backend/app/queue/celery_app.py` |
| Frontend Entry | `frontend/app/page.tsx` |
| Scan Detail | `frontend/app/scans/[id]/page.tsx` |
| History | `frontend/app/history/page.tsx` |
| Docker Compose | `infrastructure/docker/docker-compose.yml` |
| K8s Base | `infrastructure/k8s/base/` |
| Helm Chart | `infrastructure/helm/kindmelody/` |

## Development Commands

```bash
# Start all services locally
make setup

# Docker Compose
make dev        # Start
make dev-logs   # View logs
make dev-down   # Stop

# Build images
make build-all

# Kubernetes
make k3d-create     # Create k3d cluster
make k8s-deploy     # Deploy to k8s
make k8s-delete     # Remove deployment

# Helm
make helm-install   # Install Helm chart
make helm-delete    # Uninstall

# Linting
make lint-backend
make lint-frontend
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | postgresql+asyncpg://... | PostgreSQL connection |
| `REDIS_URL` | redis://redis:6379/0 | Redis connection |
| `CELERY_BROKER_URL` | redis://redis:6379/1 | Celery broker |
| `SECRET_KEY` | change-me | JWT signing key |
| `SCAN_TIMEOUT_SECONDS` | 300 | Max scan duration |
| `RATE_LIMIT_PER_MINUTE` | 10 | API rate limit |

## Testing a Scan

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com"}'
```
