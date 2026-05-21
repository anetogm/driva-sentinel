# Development Guide

## Prerequisites

- Python 3.12+
- Node.js 22+
- Docker & Docker Compose
- PostgreSQL 16 (or use Docker)
- Redis 7 (or use Docker)

## Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Environment Variables

Create a `.env` file:

```
DATABASE_URL=postgresql+asyncpg://kindmelody:kindmelody@localhost:5432/kindmelody
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/1
CELERY_RESULT_BACKEND=redis://localhost:6379/2
SECRET_KEY=dev-secret-key
DEBUG=true
```

### Run Backend

```bash
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Run Worker

```bash
cd backend
celery -A app.queue.celery_app worker -l info -c 2
```

## Frontend Setup

```bash
cd frontend
npm install --legacy-peer-deps
npm run dev
```

Frontend will be available at http://localhost:3000

## Running Tests

### Backend

```bash
cd backend
pytest tests/ -v --cov=app
```

### Frontend

```bash
cd frontend
npm run test
```

## Code Style

### Python
- Use `ruff` for linting
- Use `mypy` for type checking
- Follow PEP 8
- All functions must have type hints

### TypeScript
- Use ESLint for linting
- Strict TypeScript mode
- Functional components with explicit return types

## Git Workflow

1. Create feature branch: `git checkout -b feature/my-feature`
2. Make changes and commit
3. Push branch and create PR
4. CI runs linting, tests, and security scans
5. After approval, merge to main
6. Docker images built and pushed automatically
