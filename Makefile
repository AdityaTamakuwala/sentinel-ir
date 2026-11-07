.PHONY: help init-env up down restart logs ps migrate seed generate-client check-client test test-backend test-frontend test-e2e lint security-check

PYTHON ?= python3

help:
	@echo "SENTINEL IR — Operational Make Targets"
	@echo "  make init-env         Generate local .env from .env.example with fresh keys"
	@echo "  make up               Build and start full Docker Compose stack in background"
	@echo "  make down             Stop Docker Compose stack"
	@echo "  make logs             Tail logs across all containers"
	@echo "  make ps               Show container health and ports"
	@echo "  make migrate          Run Alembic database migrations inside api container"
	@echo "  make seed             Run dev/demo seed inside api container (dev mode only)"
	@echo "  make generate-client  Export OpenAPI schema and regenerate TypeScript API client"
	@echo "  make check-client     Verify committed TypeScript API client matches OpenAPI schema"
	@echo "  make test-backend     Run pytest suite against PostgreSQL & Redis"
	@echo "  make test-frontend    Run frontend unit/component tests"
	@echo "  make test-e2e         Run Playwright E2E tests against live stack"
	@echo "  make test             Run all backend + frontend unit/integration tests"
	@echo "  make lint             Run ruff, mypy, ESLint, and tsc checks"
	@echo "  make security-check   Run bandit, pip-audit, and npm audit"

init-env:
	$(PYTHON) scripts/init_dev_env.py

up: init-env
	docker compose up -d --build

down:
	docker compose down

restart:
	docker compose restart

logs:
	docker compose logs -f --tail=100

ps:
	docker compose ps

migrate:
	docker compose exec -T api alembic upgrade head

seed:
	docker compose exec -T api python -m scripts.seed_dev_data

generate-client:
	$(PYTHON) scripts/generate_openapi_client.py

check-client:
	$(PYTHON) scripts/generate_openapi_client.py --check

test-backend:
	cd backend && ../.venv/bin/pytest -v

test-frontend:
	cd frontend && npm test

test-e2e:
	cd frontend && npx playwright test

test: test-backend test-frontend

lint:
	cd backend && ../.venv/bin/ruff check app tests scripts
	cd backend && ../.venv/bin/mypy app
	cd frontend && npm run lint && npm run typecheck

security-check:
	cd backend && ../.venv/bin/bandit -r app -ll -q
	cd backend && ../.venv/bin/pip-audit
	cd frontend && npm audit --omit=dev --audit-level=high

