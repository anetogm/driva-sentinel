.PHONY: setup dev build test lint docker-up docker-down k8s-deploy k8s-delete helm-install helm-delete

setup:
	bash scripts/setup.sh

dev:
	cd infrastructure/docker && docker compose up -d

dev-logs:
	cd infrastructure/docker && docker compose logs -f

dev-down:
	cd infrastructure/docker && docker compose down

dev-build:
	cd infrastructure/docker && docker compose up -d --build

test-backend:
	cd backend && pytest tests/ -v

test-frontend:
	cd frontend && npm test

lint-backend:
	cd backend && ruff check app/
	cd backend && mypy app/

lint-frontend:
	cd frontend && npm run lint

build-backend:
	docker build -t kindmelody/backend:latest backend/

build-frontend:
	docker build -t kindmelody/frontend:latest frontend/

build-worker:
	docker build -t kindmelody/worker:latest workers/

build-all: build-backend build-frontend build-worker

k8s-deploy:
	bash scripts/deploy-local.sh

k8s-delete:
	kubectl delete namespace kindmelody

helm-install:
	helm upgrade --install kindmelody infrastructure/helm/kindmelody \
		--namespace kindmelody --create-namespace \
		--values infrastructure/helm/kindmelody/values.yaml

helm-delete:
	helm uninstall kindmelody --namespace kindmelody

k3d-create:
	k3d cluster create kindmelody --agents 2 --port "8080:80@loadbalancer"

k3d-delete:
	k3d cluster delete kindmelody
