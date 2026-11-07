#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-api}"

# Always run production safety checks before starting any service
python -c "from app.core.config import get_settings; get_settings().validate_startup_safety()"

case "$MODE" in
  api)
    if [ -f "/app/alembic.ini" ] && [ -d "/app/alembic/versions" ]; then
      echo "[entrypoint] Applying Alembic database migrations..."
      alembic upgrade head
    fi
    if [ "${APP_ENV:-development}" = "development" ] && [ "${SEED_DEMO_DATA:-false}" = "true" ]; then
      if [ -f "/app/scripts/seed_dev_data.py" ]; then
        echo "[entrypoint] Ensuring idempotent development seed data..."
        python -m scripts.seed_dev_data
      fi
    fi
    echo "[entrypoint] Starting SENTINEL IR FastAPI server..."
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips="*"
    ;;
  worker)
    echo "[entrypoint] Starting SENTINEL IR Celery worker..."
    exec celery -A app.core.celery_app:celery_app worker --loglevel="${LOG_LEVEL:-INFO}" --concurrency=4
    ;;
  beat)
    echo "[entrypoint] Starting SENTINEL IR Celery beat scheduler..."
    rm -f /tmp/celerybeat.pid
    exec celery -A app.core.celery_app:celery_app beat --loglevel="${LOG_LEVEL:-INFO}" --schedule=/tmp/celerybeat-schedule --pidfile=/tmp/celerybeat.pid
    ;;
  *)
    exec "$@"
    ;;
esac

