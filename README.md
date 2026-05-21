# KindMelody Security Scanner

Enterprise-grade website security analysis platform. Deep security scans, real-time scoring, and actionable recommendations.

## Overview

KindMelody is a comprehensive web security scanner inspired by the concepts of Top.nic.br and Security Headers, but built with modern architecture, enterprise scalability, and a SOC-dashboard-style interface.

### Features

- **7 Specialized Scanners**: Headers, TLS/SSL, DNS, Web Exposure, Technology Detection, Fingerprinting, and Exposure Analysis
- **A+ to F Rating**: Weighted scoring with severity-based impact
- **Real-time Scanning**: Asynchronous execution with progress tracking
- **Dark Mode UI**: Modern cybersecurity SaaS interface with glassmorphism design
- **RESTful API**: OpenAPI/Swagger documentation
- **JWT Authentication**: Secure user management
- **Horizontal Scaling**: Kubernetes-ready with HPA, PDB, and multi-environment support

## Architecture

```
kindmelody/
├── backend/          # FastAPI + SQLAlchemy + Celery
├── frontend/         # Next.js 15 + TypeScript + Tailwind
├── workers/          # Celery workers for scan execution
├── infrastructure/   # Docker, K8s, Helm, NGINX
├── monitoring/       # Prometheus, Grafana, Loki, OpenTelemetry
├── scripts/          # Setup and deploy scripts
├── docs/             # Documentation
└── .github/          # CI/CD workflows
```

## Quick Start

### Docker Compose (Local Development)

```bash
make setup
# or
bash scripts/setup.sh
```

Access:
- Frontend: http://localhost:3000
- API: http://localhost:8000
- API Docs: http://localhost:8000/api/docs
- Grafana: http://localhost:3001 (admin/admin)
- Prometheus: http://localhost:9090

### Kubernetes (Local with k3d)

```bash
make k3d-create
make build-all
make k8s-deploy
```

### Helm (Production)

```bash
helm upgrade --install kindmelody infrastructure/helm/kindmelody \
  --namespace kindmelody --create-namespace \
  --values infrastructure/helm/kindmelody/values.yaml
```

## Scanners

| Scanner | Category | Checks |
|---------|----------|--------|
| Headers | Security Headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CORS, Cookie Flags |
| TLS | TLS/SSL | Certificate validity, cipher suites, protocol versions, HSTS preload |
| DNS | DNS Security | SPF, DMARC, DKIM, DNSSEC, CAA, MX, wildcard detection, subdomain enumeration |
| Web | Web Exposure | Exposed .git, .env, backups, admin panels, robots.txt, HTTP methods, CORS misconfig, open redirect, error leakage |
| Tech | Technology Detection | Frameworks, CMS, WAF, CDN, JavaScript libraries, cloud providers |
| Exposure | Exposure | Sensitive files, directory listing, API docs, Spring Boot actuators, debug consoles |
| Fingerprint | Fingerprinting | Server headers, cookie analysis, HTML body signatures, information disclosure |

## Scoring System

- **Base Score**: 100
- **Critical**: -15 points
- **High**: -10 points
- **Medium**: -5 points
- **Low**: -2 points
- **Info**: 0 points

| Score | Rating |
|-------|--------|
| 95-100 | A+ |
| 85-94 | A |
| 70-84 | B |
| 55-69 | C |
| 40-54 | D |
| <40 | F |

## API Endpoints

### Authentication
- `POST /api/v1/auth/register` - Register new user
- `POST /api/v1/auth/login` - Login
- `GET /api/v1/auth/me` - Get current user

### Scans
- `POST /api/v1/scans` - Create new scan
- `GET /api/v1/scans` - List scans
- `GET /api/v1/scans/{id}` - Get scan detail
- `GET /api/v1/scans/{id}/progress` - Get scan progress
- `GET /api/v1/scans/{id}/report` - Get scan report
- `POST /api/v1/scans/{id}/rescan` - Re-scan target
- `GET /api/v1/scans/stats` - Get scan statistics

### Health
- `GET /api/v1/health` - Health check
- `GET /api/v1/health/ready` - Readiness check
- `GET /api/v1/health/metrics` - Prometheus metrics

## Technology Stack

### Backend
- Python 3.12, FastAPI, SQLAlchemy 2.0, Pydantic v2
- Celery, Redis, asyncpg
- structlog, prometheus-client, OpenTelemetry

### Frontend
- Next.js 15, TypeScript 5, TailwindCSS
- shadcn/ui, Framer Motion, Recharts, TanStack Query

### Infrastructure
- Docker, Kubernetes, Helm
- NGINX Ingress Controller
- Prometheus, Grafana, Loki, OpenTelemetry

## Security

- SSRF protection with IP blocklist (RFC1918, localhost)
- Input validation and URL sanitization
- Rate limiting (SlowAPI)
- JWT authentication with expiration
- Correlation IDs in all logs
- Resource limits on all containers
- Non-root container execution
- Security headers in NGINX

## License

MIT License
