# Architecture Documentation

## System Architecture

KindMelody follows a microservices-style architecture with clear separation of concerns:

```
                    +-------------+
                    |   User      |
                    +------+------+
                           |
                           v
                    +-------------+
                    |   NGINX     |
                    |  Ingress    |
                    +------+------+
                           |
              +------------+------------+
              |                         |
              v                         v
      +---------------+        +---------------+
      |   Frontend    |        |   Backend     |
      |   Next.js     |        |   FastAPI     |
      |   (Port 3000) |        |   (Port 8000) |
      +---------------+        +-------+-------+
                                       |
                          +------------+------------+
                          |                         |
                          v                         v
                   +-------------+          +-------------+
                   |  PostgreSQL |          |    Redis    |
                   |   (Data)    |          | (Queue/Cache|
                   +-------------+          +------+------+
                                                   |
                                                   v
                                          +---------------+
                                          |    Worker     |
                                          |    Celery     |
                                          +---------------+
```

## Data Flow

1. User submits URL via Frontend
2. Backend validates URL, creates scan record, enqueues Celery task
3. Worker picks up task, executes all 7 scanners in parallel
4. Each scanner performs its checks and returns findings
5. Score engine calculates weighted score and rating
6. Results saved to PostgreSQL
7. Frontend polls progress and displays results

## Security Model

- **SSRF Protection**: Blocked IP ranges (RFC1918, localhost)
- **Input Validation**: URL format validation, scheme whitelist
- **Rate Limiting**: Per-minute and per-hour limits via SlowAPI
- **Authentication**: JWT tokens with configurable expiration
- **Container Security**: Non-root user, read-only root FS, dropped capabilities
- **Network Policy**: Restricted inter-service communication
