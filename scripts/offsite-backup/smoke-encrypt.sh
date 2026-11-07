#!/usr/bin/env bash
# Local check: AES-256-GCM roundtrip, and tampered ciphertext is rejected.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export BACKUP_ENCRYPTION_KEY="${BACKUP_ENCRYPTION_KEY:-sec1-local-smoke-key-not-for-prod}"
python3 "$SCRIPT_DIR/crypto.py" self-test
