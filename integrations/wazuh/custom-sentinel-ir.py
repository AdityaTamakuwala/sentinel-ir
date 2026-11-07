#!/usr/bin/env python3
"""Wazuh Manager Custom Integrator Script for SENTINEL IR (`/var/ossec/integrations/custom-sentinel-ir`).

Configure in `/var/ossec/etc/ossec.conf` (see `ossec.conf.snippet`).
Signs the raw Wazuh alert JSON body using HMAC-SHA256 + Unix epoch timestamp for replay protection,
and POSTs to `/api/v1/ingest/wazuh`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import time
import urllib.request


def main() -> int:
    if len(sys.argv) < 4:
        sys.stderr.write("Usage: custom-sentinel-ir <alert_file> <api_key> <webhook_url>\n")
        return 1

    alert_file_path = sys.argv[1]
    api_key = sys.argv[2]
    webhook_url = sys.argv[3]
    hmac_secret = os.environ.get("SENTINEL_WEBHOOK_HMAC_SECRET", "")

    if not hmac_secret:
        sys.stderr.write("SENTINEL_WEBHOOK_HMAC_SECRET environment variable must be set.\n")
        return 1

    with open(alert_file_path, encoding="utf-8") as fh:
        alert_json = json.load(fh)

    raw_bytes = json.dumps(alert_json, separators=(",", ":")).encode("utf-8")
    ts_str = str(int(time.time()))
    signing_input = ts_str.encode("utf-8") + b"." + raw_bytes
    signature = hmac.new(hmac_secret.encode("utf-8"), signing_input, hashlib.sha256).hexdigest()

    req = urllib.request.Request(
        webhook_url,
        data=raw_bytes,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Sentinel-API-Key": api_key,
            "X-Sentinel-Timestamp": ts_str,
            "X-Sentinel-Signature": f"sha256={signature}",
            "User-Agent": "Wazuh-SentinelIR-Integrator/1.0",
        },
    )

    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
        if resp.status not in (200, 201, 202):
            sys.stderr.write(f"SENTINEL IR webhook returned unexpected HTTP {resp.status}\n")
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

