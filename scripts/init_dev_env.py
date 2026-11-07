#!/usr/bin/env python3
"""Generate a local `.env` from `.env.example` with fresh cryptographic keys.

Idempotent: does not overwrite an existing `.env` unless `--force` is passed.
Never commits `.env` to git.
"""

from __future__ import annotations

import base64
import os
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV_EXAMPLE = ROOT / ".env.example"
ENV_FILE = ROOT / ".env"


def generate_fernet_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")


def main() -> int:
    force = "--force" in sys.argv
    if ENV_FILE.exists() and not force:
        print(f"[init_dev_env] {ENV_FILE} already exists; keeping existing configuration.")
        return 0

    content = ENV_EXAMPLE.read_text(encoding="utf-8")

    secret_key = secrets.token_urlsafe(48)
    fernet_key = generate_fernet_key()
    metrics_token = secrets.token_urlsafe(32)
    owner_pw = secrets.token_hex(16)
    app_pw = secrets.token_hex(16)
    # Deterministic documented local-dev demo password ONLY for local dev seed convenience,
    # still changeable via DEMO_USER_PASSWORD and completely rejected in production mode.
    demo_pw = "SentinelDemo!2026#SOC"

    replacements = {
        "CHANGE_ME_GENERATE_WITH_INIT_DEV_ENV": secret_key,
        "CHANGE_ME_GENERATE_FERNET_KEY_WITH_INIT_DEV_ENV": fernet_key,
        "CHANGE_ME_GENERATE_METRICS_TOKEN": metrics_token,
        "CHANGE_ME_DEV_OWNER_PASSWORD": owner_pw,
        "CHANGE_ME_DEV_APP_PASSWORD": app_pw,
        "CHANGE_ME_DEV_DEMO_PASSWORD": demo_pw,
    }

    for placeholder, value in replacements.items():
        content = content.replace(placeholder, value)

    ENV_FILE.write_text(content, encoding="utf-8")
    os.chmod(ENV_FILE, 0o600)
    print(f"[init_dev_env] Generated local development {ENV_FILE} with fresh random keys.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

