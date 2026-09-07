# Driva Sentinel — Security Scanner

Plataforma de análise de segurança para aplicações web, com múltiplos scanners especializados, pontuação de risco em tempo real e recomendações acionáveis.

## Principais recursos

- Análise de headers de segurança, TLS/SSL, DNS e exposição web
- Detecção de tecnologias e fingerprinting
- Classificação de segurança de A+ a F
- Execução assíncrona de scans com acompanhamento de progresso
- API REST documentada com OpenAPI/Swagger
- Autenticação com JWT
- Infraestrutura preparada para Docker, Kubernetes e Helm
- Observabilidade com Prometheus, Grafana, Loki e OpenTelemetry

## Arquitetura

```text
kindmelody/
├── backend/          # FastAPI + SQLAlchemy + Celery
├── frontend/         # Next.js + TypeScript + Tailwind
├── workers/          # Execução assíncrona dos scans
├── infrastructure/   # Docker, Kubernetes, Helm e NGINX
├── monitoring/       # Prometheus, Grafana, Loki e OpenTelemetry
├── scripts/
├── docs/
└── .github/          # CI/CD
```

## Scanners

| Scanner | Exemplos de verificações |
| --- | --- |
| Headers | CSP, HSTS, X-Frame-Options, CORS e cookies |
| TLS | Certificado, protocolos e cipher suites |
| DNS | SPF, DMARC, DKIM, DNSSEC, CAA e MX |
| Web | `.git`, `.env`, backups, painéis administrativos e métodos HTTP |
| Tech | Frameworks, CMS, WAF, CDN e bibliotecas JavaScript |
| Exposure | Arquivos sensíveis, diretórios, APIs e consoles de debug |
| Fingerprint | Headers, cookies e assinaturas do corpo HTML |

## Tech Stack

**Backend:** Python 3.12, FastAPI, SQLAlchemy, Pydantic, Celery, Redis e asyncpg  
**Frontend:** Next.js, TypeScript e Tailwind CSS  
**Infraestrutura:** Docker, Kubernetes, Helm e NGINX  
**Observabilidade:** Prometheus, Grafana, Loki e OpenTelemetry

## Execução local

### Docker Compose

```bash
make setup
```

ou:

```bash
bash scripts/setup.sh
```

Serviços principais:

- Frontend: `http://localhost:3000`
- API: `http://localhost:8000`
- Documentação da API: `http://localhost:8000/api/docs`
- Grafana: `http://localhost:3001`
- Prometheus: `http://localhost:9090`

### Kubernetes com k3d

```bash
make k3d-create
make build-all
make k8s-deploy
```

## Segurança

O projeto inclui proteção contra SSRF, validação de entrada, sanitização de URLs, rate limiting, autenticação JWT, execução de containers sem root, limites de recursos e headers de segurança no NGINX.

## Licença

MIT.
