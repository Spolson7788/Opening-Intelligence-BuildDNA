#!/usr/bin/env bash
# Email Stephan via Resend when a backup/restore workflow fails.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

require_env RESEND_API_KEY
require_env BACKUP_ALERT_TO

FROM_ADDR="${BACKUP_ALERT_FROM:-noreply@mail.oipoweredbybuilddna.com}"
SUBJECT="${BACKUP_ALERT_SUBJECT:-OI backup FAILED}"
BODY="${BACKUP_ALERT_BODY:-A SEC-1 backup or restore workflow failed. Check the GitHub Actions run. No secrets in this message.}"
RUN_URL="${GITHUB_SERVER_URL:-}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-}"

payload=$(python3 - << PY
import json, os
body = os.environ.get("BACKUP_ALERT_BODY", """$BODY""")
run = """$RUN_URL"""
text = body + "\n\nRun: " + run
print(json.dumps({
  "from": """$FROM_ADDR""",
  "to": ["""$BACKUP_ALERT_TO"""],
  "subject": """$SUBJECT""",
  "text": text,
}))
PY
)

curl -sS -X POST "https://api.resend.com/emails" \
  -H "Authorization: Bearer ${RESEND_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "$payload" >/tmp/resend-out.json || die "Resend request failed"
log "failure alert submitted to Resend (response not printed)"
