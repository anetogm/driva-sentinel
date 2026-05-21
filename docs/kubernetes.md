# Kubernetes Deployment Guide

## Prerequisites

- Kubernetes cluster (1.28+)
- kubectl configured
- Helm 3.16+
- NGINX Ingress Controller installed

## Quick Deploy

### Using Kustomize (Base)

```bash
cd infrastructure/k8s/base
kubectl apply -k .
```

### Using Environment Overlays

```bash
# Development
cd infrastructure/k8s/overlays/dev
kubectl apply -k .

# Staging
cd infrastructure/k8s/overlays/staging
kubectl apply -k .

# Production
cd infrastructure/k8s/overlays/production
kubectl apply -k .
```

### Using Helm

```bash
helm install kindmelody infrastructure/helm/kindmelody \
  --namespace kindmelody --create-namespace \
  --values infrastructure/helm/kindmelody/values.yaml
```

## Resource Requirements

| Component | CPU Request | CPU Limit | Memory Request | Memory Limit |
|-----------|-------------|-----------|----------------|--------------|
| Backend | 200m | 1000m | 512Mi | 1Gi |
| Frontend | 100m | 500m | 256Mi | 512Mi |
| Worker | 300m | 2000m | 1Gi | 4Gi |
| PostgreSQL | 500m | 2000m | 1Gi | 4Gi |
| Redis | 100m | 500m | 256Mi | 1Gi |

## Scaling

### Horizontal Pod Autoscaler

All stateless components have HPA configured:
- Backend: 3-20 replicas (CPU 70%)
- Frontend: 2-10 replicas (CPU 70%)
- Worker: 3-50 replicas (CPU 60%)

### Manual Scaling

```bash
kubectl scale deployment kindmelody-worker --replicas=10 -n kindmelody
```

## Health Checks

- **Liveness**: HTTP GET /api/v1/health (10s interval)
- **Readiness**: HTTP GET /api/v1/health/ready (5s interval)
- **Worker**: Celery inspect ping (30s interval)
