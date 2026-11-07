# syntax=docker/dockerfile:1
FROM python:3.12.8-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY backend/pyproject.toml /build/pyproject.toml
COPY backend/app /build/app
RUN mkdir -p /build/scripts && touch /build/scripts/__init__.py && \
    python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip setuptools wheel && \
    /opt/venv/bin/pip install .

# --- Production Runtime Stage ---
FROM python:3.12.8-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH="/app"

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz-subset0 \
    libjpeg62-turbo \
    libopenjp2-7 \
    shared-mime-info \
    fonts-dejavu-core \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 sentinel \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin sentinel \
    && mkdir -p /app /var/lib/sentinel-ir/evidence \
    && chown -R sentinel:sentinel /app /var/lib/sentinel-ir

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=sentinel:sentinel backend/ /app/
COPY --chown=sentinel:sentinel playbooks/ /app/playbooks/
COPY --chown=sentinel:sentinel data/ /app/data/

RUN chmod +x /app/entrypoint.sh

USER sentinel

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["api"]

