# SENTINEL IR — Production Deployment & Operations Guide

## 1. System Requirements & Topology

### 1.1 Minimum Hardware Specifications
- **CPU:** 4 vCPUs (x86_64 or ARM64 / Apple Silicon)
- **RAM:** 8 GB minimum (16 GB recommended for high alert volume)
- **Disk:** 50 GB SSD storage (for PostgreSQL database, Redis persistence, and forensic evidence vault)
- **OS:** Linux (Ubuntu 22.04 LTS / Debian 12 / RHEL 9) or macOS 13+

### 1.2 Container Architecture
SENTINEL IR is orchestrated via Docker Compose across six specialized services:

| Container Name | Base Image | Role | Exposed Ports | Internal Network |
|---|---|---|---|---|
| `sentinel_postgres` | `postgres:16-alpine` | Primary transactional relational database | `127.0.0.1:5432:5432` | `sentinel_net` |
| `sentinel_redis` | `redis:7-alpine` | Celery broker, token-bucket limiter & SSE Pub/Sub | `127.0.0.1:6379:6379` | `sentinel_net` |
| `sentinel_api` | `python:3.12-slim` | FastAPI async REST API server | `127.0.0.1:8000:8000` | `sentinel_net` |
| `sentinel_worker` | `python:3.12-slim` | Celery execution worker (playbooks, enrichments) | None | `sentinel_net` |
| `sentinel_beat` | `python:3.12-slim` | Celery Beat periodic task scheduler | None | `sentinel_net` |
| `sentinel_web` | `node:20-alpine` | Next.js App Router UI & Reverse Proxy | `0.0.0.0:3000:3000` | `sentinel_net` |

---

## 2. Quickstart Deployment (Local Development)

### Step 1: Clone Repository & Generate Cryptographic Secrets
```bash
git clone <repository_url>
cd "SOC INCIDENT AND RESPONSE"

# Generate cryptographically secure .env with high-entropy keys
python3 scripts/init_dev_env.py
```

### Step 2: Launch the Complete Stack
```bash
docker compose up -d --build --wait
```
All six containers will start and wait until their respective health checks report `healthy`.

### Step 3: Access the Platform
- **SOC Web Console:** `http://127.0.0.1:3001` (or `http://localhost:3000`)
- **FastAPI OpenAPI Documentation:** `http://127.0.0.1:8000/docs`
- **API Health Check:** `http://127.0.0.1:8000/health/live` and `http://127.0.0.1:8000/health/ready`

---

## 3. Production Deployment Hardening

For production environments, utilize `docker-compose.prod.yml`, which enforces strict container isolation and security baselines.

```bash
docker compose -f docker-compose.prod.yml up -d --build --wait
```

### 3.1 Security Hardening Invariants Enforced
1. **Production Secret Rejection:**
   If `APP_ENV=production` is set, `Settings` validation rejects default demo secrets (`secret`, `dev_secret`, `insecure`, etc.) and halts startup with a fatal configuration error.
2. **Dual-Role PostgreSQL Privileges:**
   - Database migrations run under `sentinel_owner`.
   - The runtime application connects as `sentinel_app`, which is explicitly forbidden from running DDL (`CREATE/ALTER/DROP`) and cannot run `UPDATE/DELETE/TRUNCATE` on `audit_logs` or `response_approvals`.
3. **Non-Root Execution:**
   All application containers drop root privileges upon startup and run as unprivileged service users (`uid=10001` or `node`).
4. **Read-Only Root Filesystem:**
   Container root filesystems are mounted read-only where practical, with designated temporary directories mapped to `tmpfs`.
5. **Resource Limits:**
   Explicit CPU and memory reservation and limit caps prevent noisy neighbor or resource exhaustion denial-of-service conditions.

---

## 4. Key Environment Variables (`.env`)

| Variable | Description | Production Requirement |
|---|---|---|
| `APP_ENV` | Application environment (`development`, `testing`, `production`) | Must be `production` |
| `SECRET_KEY` | HMAC secret for signing JWTs and session tokens | 64+ hex chars, high entropy |
| `WAZUH_WEBHOOK_SECRET` | Shared secret for verifying Wazuh HMAC-SHA256 signatures | 64+ hex chars, high entropy |
| `POSTGRES_USER` | DDL Owner username for migrations | Non-default identifier |
| `POSTGRES_PASSWORD` | PostgreSQL owner password | 32+ characters |
| `APP_DB_USER` | Least-privilege runtime DML username (`sentinel_app`) | Non-default identifier |
| `APP_DB_PASSWORD` | Least-privilege runtime password | 32+ characters |
| `REDIS_PASSWORD` | Authentication password for Redis 7 | 32+ characters |
| `COOKIE_SECURE` | Enforces `Secure` flag on cookies | Must be `true` |
| `EVIDENCE_STORAGE_DIR` | Absolute path to the secure forensic evidence vault | Dedicated persistent volume |

---

## 5. Operations & Maintenance Runbook

### Database Migrations
```bash
# Apply pending migrations
docker compose exec api alembic upgrade head

# Rollback one migration
docker compose exec api alembic downgrade -1
```

### Viewing Real-Time Logs
```bash
# View structured JSON logs from API and workers
docker compose logs -f api worker beat
```

### Celery Worker Inspection
```bash
# Ping active Celery workers
docker compose exec api celery -A app.core.celery_app inspect ping

# Inspect currently executing tasks
docker compose exec api celery -A app.core.celery_app inspect active
```

### Backup & Disaster Recovery
```bash
# Backup PostgreSQL database
docker compose exec postgres pg_dump -U sentinel_owner sentinel_ir > sentinel_backup_$(date +%F).sql

# Restore PostgreSQL database
docker compose exec -T postgres psql -U sentinel_owner sentinel_ir < sentinel_backup.sql
```

