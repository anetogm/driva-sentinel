#!/bin/bash
set -e

echo "KindMelody - Local Kubernetes Deploy"
echo "====================================="

if ! command -v kubectl &> /dev/null; then
    echo "kubectl is required. Please install it first."
    exit 1
fi

cd "$(dirname "$0")/../infrastructure/k8s/base"

echo "Applying Kubernetes manifests..."
kubectl apply -k .

echo ""
echo "Waiting for deployments..."
kubectl wait --for=condition=available --timeout=120s deployment/kindmelody-backend -n kindmelody || true
kubectl wait --for=condition=available --timeout=120s deployment/kindmelody-frontend -n kindmelody || true
kubectl wait --for=condition=available --timeout=120s deployment/kindmelody-worker -n kindmelody || true

echo ""
echo "Deployment complete!"
echo ""
kubectl get pods -n kindmelody
