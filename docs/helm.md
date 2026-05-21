# Helm Chart Guide

## Chart Structure

```
infrastructure/helm/kindmelody/
├── Chart.yaml
├── values.yaml
├── values-dev.yaml
├── values-staging.yaml
├── values-prod.yaml
└── templates/
    ├── _helpers.tpl
    ├── deployment.yaml
    ├── service.yaml
    ├── hpa.yaml
    ├── ingress.yaml
    ├── configmap.yaml
    ├── secret.yaml
    └── pdb.yaml
```

## Installation

### Default (Production-like)

```bash
helm install kindmelody infrastructure/helm/kindmelody \
  --namespace kindmelody --create-namespace
```

### Development

```bash
helm install kindmelody-dev infrastructure/helm/kindmelody \
  --namespace kindmelody-dev --create-namespace \
  --values infrastructure/helm/kindmelody/values-dev.yaml
```

### Staging

```bash
helm install kindmelody-staging infrastructure/helm/kindmelody \
  --namespace kindmelody-staging --create-namespace \
  --values infrastructure/helm/kindmelody/values-staging.yaml
```

### Production

```bash
helm install kindmelody-prod infrastructure/helm/kindmelody \
  --namespace kindmelody --create-namespace \
  --values infrastructure/helm/kindmelody/values-prod.yaml \
  --set backend.secrets.SECRET_KEY=$(openssl rand -hex 32)
```

## Upgrade

```bash
helm upgrade kindmelody infrastructure/helm/kindmelody \
  --namespace kindmelody \
  --values infrastructure/helm/kindmelody/values.yaml
```

## Uninstall

```bash
helm uninstall kindmelody --namespace kindmelody
```

## Configuration

Key values in `values.yaml`:

| Key | Description | Default |
|-----|-------------|---------|
| `backend.replicaCount` | Backend replicas | 3 |
| `backend.autoscaling.enabled` | Enable HPA | true |
| `backend.autoscaling.maxReplicas` | Max backend replicas | 20 |
| `frontend.replicaCount` | Frontend replicas | 2 |
| `worker.replicaCount` | Worker replicas | 3 |
| `worker.autoscaling.maxReplicas` | Max worker replicas | 50 |
| `ingress.enabled` | Enable ingress | true |
| `ingress.hosts[0].host` | Main hostname | kindmelody.dev |
