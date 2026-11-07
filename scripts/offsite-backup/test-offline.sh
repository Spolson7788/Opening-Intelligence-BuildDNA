#!/usr/bin/env bash
# Offline proof for the SEC-1 backup. No production hosts and no real secrets.
# Needs a local Postgres (default 127.0.0.1:5432, user/password/db postgres)
# and MinIO (default 127.0.0.1:9000). Starts MinIO when MINIO_BIN is executable
# and nothing is already listening.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# Client tools must be PostgreSQL 17 when that prefix exists. A missing
# directory still fails the version check once Postgres is required.
PATH="/usr/lib/postgresql/17/bin:${HOME}/.local/bin:${PATH}"
export PATH

PASS_N=0
FAIL_N=0
LAST_LOG=""
MOCK_PID=""
MINIO_PID=""
STARTED_MINIO=0

ADMIN_URL="${SEC1_TEST_DATABASE_URL:-postgresql://postgres:postgres@127.0.0.1:5432/postgres}"
S3_ENDPOINT="${SEC1_TEST_S3_ENDPOINT:-http://127.0.0.1:9000}"
S3_ACCESS="${SEC1_TEST_S3_ACCESS_KEY:-minioadmin}"
S3_SECRET="${SEC1_TEST_S3_SECRET_KEY:-minioadmin}"
MOCK_PORT="${SEC1_MOCK_PORT:-8765}"
MOCK_KEY="offline-test-service-role"
ENC_KEY="offline-test-encryption-key"
ROLE_SECRET="role-secret-do-not-print"
FIXTURE=""
FAIL_FILE=""
MOCK_LOG=""

record_pass() { echo "PASS: $*"; PASS_N=$((PASS_N + 1)); }
record_fail() { echo "FAIL: $*"; FAIL_N=$((FAIL_N + 1)); }

scan_log() {
  SEC1_SECRET_SCAN="$(printf '%s\n' \
    "$ROLE_SECRET" \
    "$ENC_KEY" \
    "$MOCK_KEY" \
    "offline-guard-secret" \
    "$S3_SECRET")" \
    python3 "$SCRIPT_DIR/redact.py" --check "$1"
}

cleanup() {
  if [[ -n "$MOCK_PID" ]]; then
    kill "$MOCK_PID" >/dev/null 2>&1 || true
  fi
  if [[ "$STARTED_MINIO" == "1" && -n "$MINIO_PID" ]]; then
    kill "$MINIO_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "$FIXTURE" ]]; then
    rm -rf "$FIXTURE"
  fi
}
trap cleanup EXIT

run_ok() {
  local name="$1"
  shift
  local log rc
  log="$(mktemp)"
  set +e
  ( set -euo pipefail; "$@" ) >"$log" 2>&1
  rc=$?
  set -e
  LAST_LOG="$log"
  if [[ "$rc" -ne 0 ]]; then
    record_fail "$name (exit ${rc})"
    cat "$log"
    return 0
  fi
  if ! scan_log "$log"; then
    record_fail "$name leaked secret material"
    return 0
  fi
  record_pass "$name"
}

run_expect_fail() {
  local name="$1"
  shift
  local log rc
  log="$(mktemp)"
  set +e
  ( set -euo pipefail; "$@" ) >"$log" 2>&1
  rc=$?
  set -e
  LAST_LOG="$log"
  if [[ "$rc" -eq 0 ]]; then
    record_fail "$name (expected non-zero exit)"
    cat "$log"
    return 0
  fi
  if ! scan_log "$log"; then
    record_fail "$name leaked secret material"
    return 0
  fi
  record_pass "$name (exit ${rc})"
}

echo "STEP: encryption self-test"
run_ok "authenticated encryption roundtrip and tampered ciphertext rejected" \
  python3 "$SCRIPT_DIR/crypto.py" self-test

echo "STEP: restore-target guard matrix"
run_ok "local restore targets allowed and other hosts refused" \
  python3 "$SCRIPT_DIR/guards.py" self-test

echo "STEP: newest snapshot prefix"
run_ok "newest dated snapshot prefix chosen and invalid names ignored" \
  python3 "$SCRIPT_DIR/snapshot_prefix.py" self-test

echo "STEP: Supabase role and TOC filters"
run_ok "GRANTED BY is stripped and reserved role statements are skipped" \
  python3 "$SCRIPT_DIR/roles_restore.py" self-test
run_ok "Supabase schemas and missing extensions are removed from the restore list" \
  python3 "$SCRIPT_DIR/restore_toc.py" self-test

echo "STEP: restore workflow pins Postgres 17 and a real R2 snapshot"
workflow_pins_real_restore() {
  python3 - "$REPO_ROOT" <<'PY'
import sys
from pathlib import Path
root = Path(sys.argv[1])
wf = (root / ".github/workflows/oi-production-backup-restore-test.yml").read_text(encoding="utf-8")
offline = (root / ".github/workflows/oi-offsite-backup-offline-test.yml").read_text(encoding="utf-8")
script = (root / "scripts/offsite-backup/restore-test.sh").read_text(encoding="utf-8")
problems = []
def need(ok, message):
    if not ok:
        problems.append(message)
need("image: supabase/postgres:17.11.0.018\n" in wf, "restore service image is not supabase/postgres 17.11.0.018")
need("image: postgres:17\n" not in wf, "restore workflow still uses plain postgres:17")
need("supabase_admin:postgres@127.0.0.1:5432/postgres" in wf, "restore target is not the Supabase image database")
need("postgres:16" not in wf, "restore workflow still mentions postgres 16")
need("install-pg17-client.sh" in wf, "restore workflow does not install the PostgreSQL 17 client")
need("postgresql-client " not in wf and "postgresql-client\n" not in wf, "restore workflow installs the distro client metapackage")
need("default: r2\n" in wf, "workflow_dispatch default is not r2")
need("- r2\n" in wf and "- synthetic\n" in wf, "r2 and synthetic choices must both stay")
need("inputs.mode || 'r2'" in wf, "omitted workflow input does not fall back to r2")
need("alert-failure.sh" in wf, "Resend failure alert was removed")
need('BACKUP_ALERT_SUBJECT: "OI backup restore-test FAILED"' in wf, "restore failure alert subject changed")
need("OI_PROD_DATABASE_URL" not in wf, "restore workflow still receives the production database URL")
for name in ("R2_ACCOUNT_ID", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "R2_BUCKET", "BACKUP_ENCRYPTION_KEY"):
    need(f"secrets.{name}" in wf, f"restore workflow is missing {name}")
need('MODE="${SEC1_MODE:-r2}"' in script, "restore script default is not r2")
need("OI_PROD_DATABASE_URL" not in script, "restore script still queries the production database")
need("image: postgres:17\n" in offline, "offline test service image is not postgres:17")
need("install-pg17-client.sh" in offline, "offline workflow does not install the PostgreSQL 17 client")
backup = (root / ".github/workflows/oi-production-offsite-backup.yml").read_text(encoding="utf-8")
need("install-pg17-client.sh" in backup, "backup workflow does not install the PostgreSQL 17 client")
need("postgresql-client " not in backup and "postgresql-client\n" not in backup, "backup workflow installs the distro client metapackage")
if problems:
    sys.stderr.write("\n".join(problems) + "\n")
    raise SystemExit(1)
print("restore workflow pins Postgres 17 and defaults to the real snapshot")
PY
}
run_ok "workflow defaults to the newest R2 snapshot on Postgres 17" workflow_pins_real_restore

echo "STEP: R2 client settings match the backup bucket"
r2_endpoint_shape() {
  local out
  out="$(
    env -u R2_ENDPOINT -u R2_REGION \
      R2_ACCOUNT_ID='acct.example' \
      R2_ACCESS_KEY_ID='offline-access-key' \
      R2_SECRET_ACCESS_KEY='offline-secret-key' \
      R2_BUCKET='oi-production-backups' \
      bash -c 'source "$1"; configure_r2_aws_cli; printf "endpoint=%s\nregion=%s\nbucket=%s\n" "$R2_ENDPOINT" "$AWS_DEFAULT_REGION" "$R2_BUCKET"; cat "$AWS_CONFIG_FILE"' \
      _ "$SCRIPT_DIR/lib.sh"
  )"
  printf '%s\n' "$out"
  grep -q 'endpoint=https://acct.example.r2.cloudflarestorage.com' <<<"$out"
  grep -q 'region=auto' <<<"$out"
  grep -q 'bucket=oi-production-backups' <<<"$out"
  grep -q 'addressing_style = path' <<<"$out"
  if grep -q 'offline-secret-key' <<<"$out"; then
    echo "R2 config printed the secret access key" >&2
    return 1
  fi
}
run_ok "R2 endpoint is path-style, region auto, and derived from the account id" r2_endpoint_shape

echo "STEP: production guard stays on unless the offline flag is set"
prod_guard() {
  if env OI_PROD_DATABASE_URL='postgresql://postgres:postgres@127.0.0.1:5432/db' \
      bash -c 'source "$1"; assert_production_only' _ "$SCRIPT_DIR/lib.sh"; then
    echo "production guard allowed a URL without the project ref" >&2
    return 1
  fi
}
run_ok "production guard refuses a database URL without the project ref" prod_guard

offline_remote() {
  local log
  log="$(mktemp)"
  if env SEC1_OFFLINE_TEST=1 \
      OI_PROD_DATABASE_URL='postgresql://user:offline-guard-secret@db.example.supabase.co:5432/postgres' \
      OI_PROD_SUPABASE_URL='http://127.0.0.1:9' \
      bash -c 'source "$1"; assert_offline_test_sources' _ "$SCRIPT_DIR/lib.sh" >"$log" 2>&1; then
    echo "offline mode allowed a remote database" >&2
    return 1
  fi
  scan_log "$log"
  grep -q "refusing" "$log"
}
run_ok "offline mode refuses a non-local database URL" offline_remote

refuse_remote_restore() {
  local url="$1"
  local fake sentinel log rc
  fake="$(mktemp -d)"
  sentinel="$(mktemp)"
  rm -f "$sentinel"
  cat >"$fake/psql" <<'EOF'
#!/bin/sh
echo psql-was-invoked >"${SEC1_PSQL_SENTINEL:?}"
exit 0
EOF
  chmod +x "$fake/psql"
  cp "$fake/psql" "$fake/pg_dump"
  cp "$fake/psql" "$fake/pg_dumpall"
  cp "$fake/psql" "$fake/pg_restore"
  log="$(mktemp)"
  set +e
  env PATH="$fake:${PATH}" \
    SEC1_PSQL_SENTINEL="$sentinel" \
    SEC1_TARGET_DATABASE_URL="$url" \
    SEC1_MODE=synthetic \
    BACKUP_ENCRYPTION_KEY="$ENC_KEY" \
    bash "$SCRIPT_DIR/restore-test.sh" >"$log" 2>&1
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    echo "restore-test exited 0 for a non-local target" >&2
    return 1
  fi
  if [[ -s "$sentinel" ]]; then
    echo "psql was invoked for a refused restore target" >&2
    return 1
  fi
  if grep -q "synthetic mode" "$log"; then
    echo "restore continued past the host guard" >&2
    return 1
  fi
  grep -q "refusing restore target" "$log"
  scan_log "$log"
}
run_ok "supabase.co restore target refused before psql" \
  refuse_remote_restore "postgresql://postgres:postgres@db.bekaxmatcvxqpjixwsqn.supabase.co:5432/postgres"
run_ok "non-local restore target refused before psql" \
  refuse_remote_restore "postgresql://postgres:postgres@example.com:5432/db"
run_ok "host query override to a remote server refused" \
  refuse_remote_restore "postgresql://postgres:postgres@127.0.0.1:5432/db?host=db.example.supabase.co"

echo "STEP: local Postgres and MinIO"
if ! pg_isready -h 127.0.0.1 -p 5432 -q; then
  echo "FAIL: Postgres is not accepting connections on 127.0.0.1:5432" >&2
  exit 1
fi
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -tAc 'select 1' >/dev/null
server_num="$(psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -tAc 'SHOW server_version_num')"
server_num="${server_num//[[:space:]]/}"
client_major="$(pg_restore --version | sed -n 's/.*(PostgreSQL) \([0-9][0-9]*\)\..*/\1/p')"
if [[ "$server_num" != 17* || "$client_major" != "17" ]]; then
  echo "FAIL: restore tests need PostgreSQL 17 client and server (server=${server_num:-missing} client=${client_major:-missing})" >&2
  exit 1
fi

echo "STEP: default restore is the real snapshot, not the synthetic fixture"
mode_does_not_synthesize() {
  local mode_assignment="$1"
  local log rc
  log="$(mktemp)"
  set +e
  # shellcheck disable=SC2086
  env -u SEC1_SNAPSHOT_PREFIX \
      -u R2_ACCESS_KEY_ID -u R2_SECRET_ACCESS_KEY -u R2_ACCOUNT_ID \
      -u R2_BUCKET -u R2_ENDPOINT -u R2_REGION \
      -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_DEFAULT_REGION \
      -u AWS_CONFIG_FILE -u SEC1_AWS_CONFIG_FILE \
      $mode_assignment \
      SEC1_TARGET_DATABASE_URL="$ADMIN_URL" \
      BACKUP_ENCRYPTION_KEY="$ENC_KEY" \
      bash "$SCRIPT_DIR/restore-test.sh" >"$log" 2>&1
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    echo "restore-test succeeded without R2 credentials" >&2
    cat "$log" >&2
    return 1
  fi
  if grep -q "synthetic mode" "$log"; then
    echo "restore took the synthetic path" >&2
    cat "$log" >&2
    return 1
  fi
  if ! grep -q "missing required env/secret: R2_ACCESS_KEY_ID" "$log"; then
    echo "restore did not fail closed on the missing R2 credential" >&2
    cat "$log" >&2
    return 1
  fi
  scan_log "$log"
}
run_ok "omitted SEC1_MODE restores from R2 and fails closed without credentials" \
  mode_does_not_synthesize "-u SEC1_MODE"
run_ok "empty SEC1_MODE restores from R2 and fails closed without credentials" \
  mode_does_not_synthesize "SEC1_MODE="

unknown_mode_fails() {
  local log rc
  log="$(mktemp)"
  set +e
  env -u R2_ACCESS_KEY_ID \
    SEC1_MODE=bogus \
    SEC1_TARGET_DATABASE_URL="$ADMIN_URL" \
    BACKUP_ENCRYPTION_KEY="$ENC_KEY" \
    bash "$SCRIPT_DIR/restore-test.sh" >"$log" 2>&1
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    echo "unknown mode succeeded" >&2
    return 1
  fi
  if grep -q "synthetic mode" "$log"; then
    echo "unknown mode fell through to synthetic" >&2
    return 1
  fi
  grep -q "unknown SEC1_MODE: bogus" "$log"
  scan_log "$log"
}
run_ok "unknown restore mode fails closed" unknown_mode_fails

echo "STEP: pg_dump 17 transaction_timeout restores on Postgres 17"
pg17_transaction_timeout() {
  local url dump sql count
  psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS sec1_tx WITH (FORCE);"
  psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c "CREATE DATABASE sec1_tx;"
  url="postgresql://postgres:postgres@127.0.0.1:5432/sec1_tx"
  psql "$url" -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE public.sec1_tx (id integer PRIMARY KEY);
INSERT INTO public.sec1_tx VALUES (1);
SQL
  dump="$(mktemp)"
  pg_dump --format=custom --no-owner --no-acl --dbname="$url" --file="$dump"
  sql="$(pg_restore -f - "$dump")"
  grep -q 'SET transaction_timeout = 0;' <<<"$sql"
  psql "$url" -v ON_ERROR_STOP=1 <<'SQL'
DROP SCHEMA IF EXISTS public CASCADE;
CREATE SCHEMA public;
GRANT ALL ON SCHEMA public TO public;
SQL
  pg_restore --exit-on-error --single-transaction --no-owner --no-acl --dbname="$url" "$dump"
  count="$(psql "$url" -v ON_ERROR_STOP=1 -tAc 'SELECT count(*) FROM public.sec1_tx')"
  count="${count//[[:space:]]/}"
  [[ "$count" == "1" ]]
  rm -f "$dump"
  psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS sec1_tx WITH (FORCE);"
}
run_ok "pg_dump 17 transaction_timeout restores into Postgres 17" pg17_transaction_timeout

if ! curl -sf "${S3_ENDPOINT}/minio/health/live" >/dev/null; then
  MINIO_BIN="${MINIO_BIN:-}"
  if [[ -z "$MINIO_BIN" ]]; then
    if command -v minio >/dev/null 2>&1; then
      MINIO_BIN="$(command -v minio)"
    elif [[ -x /tmp/minio ]]; then
      MINIO_BIN=/tmp/minio
    fi
  fi
  if [[ ! -x "$MINIO_BIN" ]]; then
    echo "FAIL: MinIO is not running and no MinIO binary is available" >&2
    exit 1
  fi
  mkdir -p /tmp/sec1-minio-data
  MINIO_ROOT_USER="$S3_ACCESS" MINIO_ROOT_PASSWORD="$S3_SECRET" \
    "$MINIO_BIN" server /tmp/sec1-minio-data --address 127.0.0.1:9000 --console-address 127.0.0.1:9001 \
    >/tmp/sec1-minio.log 2>&1 &
  MINIO_PID=$!
  STARTED_MINIO=1
  ready=0
  for _ in $(seq 1 40); do
    if curl -sf "${S3_ENDPOINT}/minio/health/live" >/dev/null; then
      ready=1
      break
    fi
    sleep 0.25
  done
  if [[ "$ready" != "1" ]]; then
    echo "FAIL: MinIO did not become healthy" >&2
    cat /tmp/sec1-minio.log >&2 || true
    exit 1
  fi
fi

export AWS_ACCESS_KEY_ID="$S3_ACCESS"
export AWS_SECRET_ACCESS_KEY="$S3_SECRET"
export AWS_DEFAULT_REGION=us-east-1
export R2_ENDPOINT="$S3_ENDPOINT"
export R2_ACCESS_KEY_ID="$S3_ACCESS"
export R2_SECRET_ACCESS_KEY="$S3_SECRET"
export R2_ACCOUNT_ID=local
export R2_REGION=us-east-1
AWS_CFG="$(mktemp)"
cat >"$AWS_CFG" <<'EOF'
[default]
s3 =
    addressing_style = path
EOF
chmod 600 "$AWS_CFG"
export AWS_CONFIG_FILE="$AWS_CFG"
export SEC1_AWS_CONFIG_FILE="$AWS_CFG"

aws_cli() {
  aws --endpoint-url "$S3_ENDPOINT" "$@"
}

ensure_bucket() {
  local bucket="$1"
  if aws_cli s3 ls "s3://${bucket}" >/dev/null 2>&1; then
    aws_cli s3 rb "s3://${bucket}" --force >/dev/null
  fi
  aws_cli s3 mb "s3://${bucket}" >/dev/null
}

seed_dates() {
  local bucket="$1" kind="$2"
  shift 2
  local day
  for day in "$@"; do
    printf 'seed\n' | aws_cli s3 cp - "s3://${bucket}/${kind}/${day}/run.json" --only-show-errors >/dev/null
  done
}

count_dates() {
  local bucket="$1" kind="$2"
  aws_cli s3 ls "s3://${bucket}" --recursive \
    | python3 -c 'import sys
kind=sys.argv[1]
found=set()
prefix=kind.rstrip("/")+"/"
for line in sys.stdin:
    parts=line.split(maxsplit=3)
    if len(parts)!=4 or not parts[3].startswith(prefix):
        continue
    name=parts[3][len(prefix):].split("/",1)[0]
    found.add(name)
print(len(found))' "$kind"
}

echo "STEP: retention unit"
export SEC1_DATE_STAMP
SEC1_DATE_STAMP="$(TZ=America/Phoenix date +%F)"
export SEC1_MONTH_STAMP
SEC1_MONTH_STAMP="$(TZ=America/Phoenix date +%Y-%m-01)"

mapfile -t DAILY_35 < <(python3 - <<'PY'
import datetime, os
today = datetime.date.fromisoformat(os.environ["SEC1_DATE_STAMP"])
for offset in range(0, 35):
    print((today - datetime.timedelta(days=offset)).isoformat())
PY
)
mapfile -t MONTHLY_15 < <(python3 - <<'PY'
import datetime, os
today = datetime.date.fromisoformat(os.environ["SEC1_DATE_STAMP"])
index = today.year * 12 + (today.month - 1)
for delta in range(0, 15):
    cursor = index - delta
    year, month = divmod(cursor, 12)
    print(datetime.date(year, month + 1, 1).isoformat())
PY
)

ensure_bucket oi-retention-only
seed_dates oi-retention-only snapshots "${DAILY_35[@]}"
seed_dates oi-retention-only monthly "${MONTHLY_15[@]}"
export R2_BUCKET=oi-retention-only
run_ok "pruning keeps 30 daily and 12 monthly" python3 "$SCRIPT_DIR/retention.py"
if [[ -f "$LAST_LOG" ]]; then
  daily_left="$(count_dates oi-retention-only snapshots)"
  monthly_left="$(count_dates oi-retention-only monthly)"
  if [[ "$daily_left" == "30" && "$monthly_left" == "12" ]]; then
    oldest_daily="${DAILY_35[34]}"
    newest_daily="${DAILY_35[0]}"
    oldest_month="${MONTHLY_15[14]}"
    newest_month="${MONTHLY_15[0]}"
    if aws_cli s3 ls "s3://oi-retention-only/snapshots/${newest_daily}/run.json" >/dev/null \
      && aws_cli s3 ls "s3://oi-retention-only/monthly/${newest_month}/run.json" >/dev/null \
      && ! aws_cli s3 ls "s3://oi-retention-only/snapshots/${oldest_daily}/run.json" >/dev/null \
      && ! aws_cli s3 ls "s3://oi-retention-only/monthly/${oldest_month}/run.json" >/dev/null; then
      record_pass "pruned set keeps the newest 30 daily and 12 monthly prefixes"
    else
      record_fail "pruned set kept the wrong prefixes"
    fi
  else
    record_fail "retention counts daily=${daily_left} monthly=${monthly_left}"
  fi
fi

echo "STEP: databases, fixture storage, synthetic restore"
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 <<'SQL'
DROP DATABASE IF EXISTS sec1_synthetic WITH (FORCE);
DROP DATABASE IF EXISTS sec1_src WITH (FORCE);
DROP DATABASE IF EXISTS sec1_dst WITH (FORCE);
CREATE DATABASE sec1_synthetic;
CREATE DATABASE sec1_src;
CREATE DATABASE sec1_dst;
SQL

run_ok "synthetic restore roundtrip on local Postgres" \
  env SEC1_MODE=synthetic \
    SEC1_TARGET_DATABASE_URL="postgresql://postgres:postgres@127.0.0.1:5432/sec1_synthetic" \
    BACKUP_ENCRYPTION_KEY="$ENC_KEY" \
    bash "$SCRIPT_DIR/restore-test.sh"

FIXTURE="$(mktemp -d)"
mkdir -p "$FIXTURE/dir/nested/deep" "$FIXTURE/other" "$FIXTURE/v1.0"
printf 'aaa' >"$FIXTURE/a.txt"
printf 'bbb' >"$FIXTURE/b.txt"
printf 'ccc' >"$FIXTURE/c.txt"
printf 'readme' >"$FIXTURE/README"
printf 'da' >"$FIXTURE/dir/a.txt"
printf 'db' >"$FIXTURE/dir/nested/b.txt"
printf 'dc' >"$FIXTURE/dir/nested/deep/c.txt"
printf 'od' >"$FIXTURE/other/d.txt"
printf 'notes' >"$FIXTURE/v1.0/notes.txt"
FAIL_FILE="$(mktemp)"
MOCK_LOG="$(mktemp)"
: >"$FAIL_FILE"
: >"$MOCK_LOG"
python3 "$SCRIPT_DIR/mock_storage_server.py" \
  --port "$MOCK_PORT" \
  --root "$FIXTURE" \
  --bucket oi-production-media \
  --log "$MOCK_LOG" \
  --fail-file "$FAIL_FILE" \
  --api-key "$MOCK_KEY" \
  >/tmp/sec1-mock.log 2>&1 &
MOCK_PID=$!
ready=0
for _ in $(seq 1 40); do
  if curl -sf "http://127.0.0.1:${MOCK_PORT}/health" >/dev/null; then
    ready=1
    break
  fi
  sleep 0.1
done
if [[ "$ready" != "1" ]]; then
  echo "FAIL: mock storage did not start" >&2
  cat /tmp/sec1-mock.log >&2 || true
  exit 1
fi

psql "postgresql://postgres:postgres@127.0.0.1:5432/sec1_src" -v ON_ERROR_STOP=1 <<SQL
CREATE TABLE public.sec1_items (
  id integer PRIMARY KEY,
  note text NOT NULL
);
INSERT INTO public.sec1_items (id, note) VALUES
  (1, 'row-one'),
  (2, 'row-two'),
  (3, 'row-three'),
  (4, 'row-four');
SQL
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 <<SQL
DROP ROLE IF EXISTS sec1_writer;
DROP ROLE IF EXISTS sec1_reader;
CREATE ROLE sec1_reader NOLOGIN;
CREATE ROLE sec1_writer LOGIN PASSWORD '${ROLE_SECRET}';
GRANT sec1_reader TO sec1_writer;
CREATE TABLE IF NOT EXISTS public.sec1_bootstrap_guard (
  id integer PRIMARY KEY,
  hash text NOT NULL
);
INSERT INTO public.sec1_bootstrap_guard (id, hash)
SELECT 1, rolpassword FROM pg_authid WHERE rolname = current_user
ON CONFLICT (id) DO UPDATE SET hash = EXCLUDED.hash;
SQL

# Past dates only. The backup itself adds today and the current month.
mapfile -t DAILY_PAST < <(python3 - <<'PY'
import datetime, os
today = datetime.date.fromisoformat(os.environ["SEC1_DATE_STAMP"])
for offset in range(1, 35):
    print((today - datetime.timedelta(days=offset)).isoformat())
PY
)
mapfile -t MONTHLY_PAST < <(python3 - <<'PY'
import datetime, os
today = datetime.date.fromisoformat(os.environ["SEC1_DATE_STAMP"])
index = today.year * 12 + (today.month - 1)
for delta in range(1, 15):
    cursor = index - delta
    year, month = divmod(cursor, 12)
    print(datetime.date(year, month + 1, 1).isoformat())
PY
)

ensure_bucket oi-backup-flow
seed_dates oi-backup-flow snapshots "${DAILY_PAST[@]}"
seed_dates oi-backup-flow monthly "${MONTHLY_PAST[@]}"
: >"$MOCK_LOG"

full_flow() {
  env SEC1_OFFLINE_TEST=1 \
    SEC1_FORCE_MONTHLY=1 \
    SEC1_STORAGE_PAGE_LIMIT=2 \
    SEC1_DATE_STAMP="$SEC1_DATE_STAMP" \
    SEC1_MONTH_STAMP="$SEC1_MONTH_STAMP" \
    BACKUP_ENCRYPTION_KEY="$ENC_KEY" \
    OI_PROD_DATABASE_URL="postgresql://postgres:postgres@127.0.0.1:5432/sec1_src" \
    OI_PROD_SUPABASE_URL="http://127.0.0.1:${MOCK_PORT}" \
    OI_PROD_SUPABASE_SERVICE_ROLE_KEY="$MOCK_KEY" \
    OI_PROD_MEDIA_BUCKET=oi-production-media \
    R2_BUCKET=oi-backup-flow \
    bash "$SCRIPT_DIR/backup.sh"
  snap="snapshots/${SEC1_DATE_STAMP}"
  aws_cli s3 ls "s3://oi-backup-flow/${snap}/manifest.sha256" >/dev/null
  aws_cli s3 ls "s3://oi-backup-flow/${snap}/db/oi-production.roles.sql.enc" >/dev/null
  if aws_cli s3 ls "s3://oi-backup-flow" --recursive | awk '{print $4}' | grep -E '/oi-production\.(dump|roles\.sql)$'; then
    echo "plaintext dump or roles file was uploaded" >&2
    return 1
  fi
  work="$(mktemp -d)"
  aws_cli s3 sync "s3://oi-backup-flow/${snap}" "$work" --only-show-errors
  python3 "$SCRIPT_DIR/manifest.py" verify "$work"
  (
    cd "$work"
    sha256sum -c manifest.sha256
  )
  BACKUP_ENCRYPTION_KEY="$ENC_KEY" python3 "$SCRIPT_DIR/crypto.py" decrypt \
    "$work/db/oi-production.dump.enc" "$work/plain.dump"
  BACKUP_ENCRYPTION_KEY="$ENC_KEY" python3 "$SCRIPT_DIR/crypto.py" decrypt \
    "$work/db/oi-production.roles.sql.enc" "$work/plain.roles.sql"
  python3 - "$work" <<'PY'
import hashlib, pathlib, sys
root = pathlib.Path(sys.argv[1])
def expect(sidecar, filename):
    wanted = sidecar.read_text(encoding="utf-8").split()[0]
    digest = hashlib.sha256(filename.read_bytes()).hexdigest()
    if wanted != digest:
        raise SystemExit(f"plaintext hash mismatch for {filename.name}")
expect(root / "db/oi-production.dump.plaintext.sha256", root / "plain.dump")
expect(root / "db/oi-production.roles.sql.plaintext.sha256", root / "plain.roles.sql")
PY
  cmp "$FIXTURE/dir/nested/deep/c.txt" "$work/storage/dir/nested/deep/c.txt"
  cmp "$FIXTURE/v1.0/notes.txt" "$work/storage/v1.0/notes.txt"
  cmp "$FIXTURE/README" "$work/storage/README"
  python3 - "$work/run.json" <<'PY'
import json, sys
run = json.load(open(sys.argv[1], encoding="utf-8"))
if run["storage_file_count"] != 9:
    raise SystemExit(f"storage_file_count {run['storage_file_count']} != 9")
if run["encryption"] != "aes-256-gcm+pbkdf2-sha256":
    raise SystemExit("unexpected encryption label")
PY
  storage_count="$(find "$work/storage" -type f | wc -l | tr -d ' ')"
  [[ "$storage_count" == "9" ]]
  python3 - "$MOCK_LOG" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
lists = [row for row in rows if row.get("op") == "list"]
if not any(row["offset"] > 0 and row["limit"] == 2 for row in lists):
    raise SystemExit("storage listing did not paginate with limit 2")
if not any(str(row["prefix"]).startswith("dir/nested") for row in lists):
    raise SystemExit("storage listing did not recurse into nested folders")
PY
  daily_left="$(count_dates oi-backup-flow snapshots)"
  monthly_left="$(count_dates oi-backup-flow monthly)"
  [[ "$daily_left" == "30" ]]
  [[ "$monthly_left" == "12" ]]
  aws_cli s3 ls "s3://oi-backup-flow/snapshots/${SEC1_DATE_STAMP}/run.json" >/dev/null
  aws_cli s3 ls "s3://oi-backup-flow/monthly/${SEC1_MONTH_STAMP}/run.json" >/dev/null
  psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c "DROP ROLE IF EXISTS sec1_writer;"
  psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c "DROP ROLE IF EXISTS sec1_reader;"
  env SEC1_OFFLINE_TEST=1 \
    SEC1_MODE=r2 \
    SEC1_SNAPSHOT_PREFIX="snapshots/${SEC1_DATE_STAMP}" \
    SEC1_TARGET_DATABASE_URL="postgresql://postgres:postgres@127.0.0.1:5432/sec1_dst" \
    SEC1_EXPECT_TABLE=public.sec1_items \
    SEC1_EXPECT_COUNT=4 \
    BACKUP_ENCRYPTION_KEY="$ENC_KEY" \
    R2_BUCKET=oi-backup-flow \
    bash "$SCRIPT_DIR/restore-test.sh"
  note="$(psql "postgresql://postgres:postgres@127.0.0.1:5432/sec1_dst" -v ON_ERROR_STOP=1 -tAc "select note from public.sec1_items where id=1")"
  note="${note//[[:space:]]/}"
  [[ "$note" == "row-one" ]]
  count="$(psql "postgresql://postgres:postgres@127.0.0.1:5432/sec1_dst" -v ON_ERROR_STOP=1 -tAc "select count(*) from public.sec1_items")"
  count="${count//[[:space:]]/}"
  [[ "$count" == "4" ]]
  member="$(psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -tAc "select count(*) from pg_auth_members am join pg_roles member on member.oid=am.member join pg_roles role on role.oid=am.roleid where member.rolname='sec1_writer' and role.rolname='sec1_reader'")"
  member="${member//[[:space:]]/}"
  [[ "$member" == "1" ]]
  unchanged="$(psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -tAc "select (select hash from public.sec1_bootstrap_guard where id=1) is not distinct from (select rolpassword from pg_authid where rolname=current_user)")"
  unchanged="${unchanged//[[:space:]]/}"
  [[ "$unchanged" == "t" ]]
  PGPASSWORD="$ROLE_SECRET" psql "postgresql://sec1_writer@127.0.0.1:5432/sec1_dst" -v ON_ERROR_STOP=1 -tAc 'select 1' >/dev/null
  rm -rf "$work"
}
run_ok "full backup, encrypt, upload, download, decrypt, checksum, restore, and row count" full_flow

echo "STEP: default R2 restore picks the newest dated snapshot"
restore_newest_daily() {
  local out note count
  psql "$ADMIN_URL" -v ON_ERROR_STOP=1 <<'SQL'
DROP DATABASE IF EXISTS sec1_dst WITH (FORCE);
CREATE DATABASE sec1_dst;
SQL
  psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c "DROP ROLE IF EXISTS sec1_writer;"
  psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c "DROP ROLE IF EXISTS sec1_reader;"
  out="$(mktemp)"
  env -u SEC1_SNAPSHOT_PREFIX \
    SEC1_OFFLINE_TEST=1 \
    SEC1_MODE=r2 \
    SEC1_TARGET_DATABASE_URL="postgresql://postgres:postgres@127.0.0.1:5432/sec1_dst" \
    SEC1_EXPECT_TABLE=public.sec1_items \
    SEC1_EXPECT_COUNT=4 \
    BACKUP_ENCRYPTION_KEY="$ENC_KEY" \
    R2_BUCKET=oi-backup-flow \
    bash "$SCRIPT_DIR/restore-test.sh" >"$out" 2>&1
  cat "$out"
  grep -q "downloading snapshots/${SEC1_DATE_STAMP}" "$out"
  grep -q "restore-test PASS mode=r2 snapshot=snapshots/${SEC1_DATE_STAMP}" "$out"
  note="$(psql "postgresql://postgres:postgres@127.0.0.1:5432/sec1_dst" -v ON_ERROR_STOP=1 -tAc "select note from public.sec1_items where id=1")"
  note="${note//[[:space:]]/}"
  [[ "$note" == "row-one" ]]
  count="$(psql "postgresql://postgres:postgres@127.0.0.1:5432/sec1_dst" -v ON_ERROR_STOP=1 -tAc "select count(*) from public.sec1_items")"
  count="${count//[[:space:]]/}"
  [[ "$count" == "4" ]]
  rm -f "$out"
}
run_ok "omitted snapshot prefix restores the newest dated snapshot" restore_newest_daily

empty_snapshot_list_fails() {
  local out rc
  ensure_bucket oi-restore-empty
  out="$(mktemp)"
  set +e
  env -u SEC1_SNAPSHOT_PREFIX \
    SEC1_MODE=r2 \
    SEC1_TARGET_DATABASE_URL="postgresql://postgres:postgres@127.0.0.1:5432/sec1_dst" \
    BACKUP_ENCRYPTION_KEY="$ENC_KEY" \
    R2_BUCKET=oi-restore-empty \
    bash "$SCRIPT_DIR/restore-test.sh" >"$out" 2>&1
  rc=$?
  set -e
  cat "$out"
  if [[ "$rc" -eq 0 ]]; then
    echo "empty snapshot list restored" >&2
    return 1
  fi
  if grep -q "synthetic mode" "$out"; then
    echo "empty snapshot list fell through to synthetic" >&2
    return 1
  fi
  if ! grep -Eq "no dated snapshots found in the backup bucket|cannot list snapshots" "$out"; then
    echo "empty snapshot list did not fail closed" >&2
    return 1
  fi
  rm -f "$out"
}
run_ok "R2 restore with no dated snapshot fails closed" empty_snapshot_list_fails

echo "STEP: Supabase-shaped roles and schemas"
supabase_shaped_restore() {
  local src dst work bad bad_rc count users staff auth storage crypto flags member anon_member second_rc
  psql "$ADMIN_URL" -v ON_ERROR_STOP=1 <<'SQL'
DROP DATABASE IF EXISTS sec1_supa_src WITH (FORCE);
DROP DATABASE IF EXISTS sec1_supa_dst WITH (FORCE);
CREATE DATABASE sec1_supa_src;
CREATE DATABASE sec1_supa_dst;
SQL
  psql "$ADMIN_URL" -v ON_ERROR_STOP=0 -c "REVOKE oi_pr2_api FROM postgres;" >/dev/null 2>&1 || true
  psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c "DROP ROLE IF EXISTS oi_pr2_api;"
  src="postgresql://postgres:postgres@127.0.0.1:5432/sec1_supa_src"
  dst="postgresql://postgres:postgres@127.0.0.1:5432/sec1_supa_dst"
  psql "$src" -v ON_ERROR_STOP=1 <<'SQL'
CREATE SCHEMA auth;
CREATE SCHEMA storage;
CREATE SCHEMA extensions;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE public.organizations (id integer PRIMARY KEY, name text NOT NULL);
CREATE TABLE public.users (
  id integer PRIMARY KEY,
  organization_id integer NOT NULL REFERENCES public.organizations (id)
);
CREATE TABLE public.platform_staff (id integer PRIMARY KEY);
INSERT INTO public.organizations VALUES (1, 'Acme');
INSERT INTO public.users VALUES (1, 1);
INSERT INTO public.platform_staff VALUES (7);
CREATE TABLE auth.users (id integer PRIMARY KEY, email text);
CREATE TABLE storage.objects (id integer PRIMARY KEY);
INSERT INTO auth.users VALUES (1, 'should-not-restore@example.com');
INSERT INTO storage.objects VALUES (1);
CREATE FUNCTION auth.uid() RETURNS integer LANGUAGE sql AS 'SELECT 1';
SQL
  work="$(mktemp -d)"
  mkdir -p "$work/gen" "$work/snap/db" "$work/snap/storage"
  pg_dump --format=custom --no-owner --no-acl --dbname="$src" --file="$work/gen/plain.dump"
  cat >"$work/gen/roles.sql" <<SQL
SET default_transaction_read_only = off;
CREATE ROLE supabase_admin;
ALTER ROLE supabase_admin WITH SUPERUSER INHERIT CREATEROLE CREATEDB LOGIN REPLICATION BYPASSRLS PASSWORD '${ROLE_SECRET}';
CREATE ROLE anon;
ALTER ROLE anon WITH NOSUPERUSER NOLOGIN;
CREATE ROLE authenticator;
ALTER ROLE authenticator WITH LOGIN PASSWORD '${ROLE_SECRET}';
CREATE ROLE supabase_read_only_user;
ALTER ROLE supabase_read_only_user WITH LOGIN BYPASSRLS PASSWORD '${ROLE_SECRET}';
CREATE ROLE oi_pr2_api;
ALTER ROLE oi_pr2_api WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION NOBYPASSRLS PASSWORD '${ROLE_SECRET}';
GRANT anon TO authenticator WITH INHERIT TRUE GRANTED BY supabase_admin;
GRANT oi_pr2_api TO postgres WITH INHERIT TRUE GRANTED BY supabase_admin;
GRANT pg_read_all_data TO supabase_read_only_user GRANTED BY supabase_admin;
SQL
  chmod 600 "$work/gen/roles.sql" "$work/gen/plain.dump"
  BACKUP_ENCRYPTION_KEY="$ENC_KEY" python3 "$SCRIPT_DIR/crypto.py" encrypt \
    "$work/gen/plain.dump" "$work/snap/db/oi-production.dump.enc"
  BACKUP_ENCRYPTION_KEY="$ENC_KEY" python3 "$SCRIPT_DIR/crypto.py" encrypt \
    "$work/gen/roles.sql" "$work/snap/db/oi-production.roles.sql.enc"
  python3 - "$work" <<'PY'
import hashlib, pathlib, sys
root = pathlib.Path(sys.argv[1])
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
pairs = [
    (root / "gen/plain.dump", root / "snap/db/oi-production.dump.plaintext.sha256", "plaintext-oi-production.dump"),
    (root / "gen/roles.sql", root / "snap/db/oi-production.roles.sql.plaintext.sha256", "plaintext-oi-production.roles.sql"),
    (root / "snap/db/oi-production.dump.enc", root / "snap/db/oi-production.dump.enc.sha256", "db/oi-production.dump.enc"),
    (root / "snap/db/oi-production.roles.sql.enc", root / "snap/db/oi-production.roles.sql.enc.sha256", "db/oi-production.roles.sql.enc"),
]
for source, dest, label in pairs:
    dest.write_text(f"{sha(source)}  {label}\n", encoding="utf-8")
PY
  echo fixture >"$work/snap/storage/fixture.txt"
  python3 "$SCRIPT_DIR/manifest.py" write "$work/snap" >/dev/null
  ensure_bucket oi-supabase-restore
  aws_cli s3 sync "$work/snap" "s3://oi-supabase-restore/snapshots/2026-01-15" --only-show-errors
  bad="$(mktemp)"
  cat "$work/gen/roles.sql" >"$bad"
  printf '\nGRANT no_such_app_role TO oi_pr2_api;\n' >>"$bad"
  chmod 600 "$bad"
  set +e
  env SEC1_TARGET_DATABASE_URL="$dst" \
    python3 "$SCRIPT_DIR/roles_restore.py" "$bad" >"$work/bad.log" 2>&1
  bad_rc=$?
  set -e
  cat "$work/bad.log"
  if [[ "$bad_rc" -eq 0 ]]; then
    echo "bad app-role grant was accepted" >&2
    return 1
  fi
  if ! grep -q "roles restore statement failed" "$work/bad.log"; then
    echo "bad grant was not a hard failure" >&2
    return 1
  fi
  psql "$ADMIN_URL" -v ON_ERROR_STOP=0 -c "REVOKE oi_pr2_api FROM postgres;" >/dev/null 2>&1 || true
  psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c "DROP ROLE IF EXISTS oi_pr2_api;"
  psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS sec1_supa_dst WITH (FORCE);"
  psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c "CREATE DATABASE sec1_supa_dst;"
  env SEC1_MODE=r2 \
    SEC1_SNAPSHOT_PREFIX=snapshots/2026-01-15 \
    SEC1_TARGET_DATABASE_URL="$dst" \
    BACKUP_ENCRYPTION_KEY="$ENC_KEY" \
    R2_BUCKET=oi-supabase-restore \
    bash "$SCRIPT_DIR/restore-test.sh"
  count="$(psql "$dst" -v ON_ERROR_STOP=1 -tAc 'select count(*) from public.organizations')"
  users="$(psql "$dst" -v ON_ERROR_STOP=1 -tAc 'select count(*) from public.users')"
  staff="$(psql "$dst" -v ON_ERROR_STOP=1 -tAc 'select count(*) from public.platform_staff')"
  auth="$(psql "$dst" -v ON_ERROR_STOP=1 -tAc "select to_regclass('auth.users') is null")"
  storage="$(psql "$dst" -v ON_ERROR_STOP=1 -tAc "select to_regclass('storage.objects') is null")"
  crypto="$(psql "$dst" -v ON_ERROR_STOP=1 -tAc "select count(*) from pg_extension where extname = 'pgcrypto'")"
  [[ "${count//[[:space:]]/}" == "1" ]]
  [[ "${users//[[:space:]]/}" == "1" ]]
  [[ "${staff//[[:space:]]/}" == "1" ]]
  [[ "${auth//[[:space:]]/}" == "t" ]]
  [[ "${storage//[[:space:]]/}" == "t" ]]
  [[ "${crypto//[[:space:]]/}" == "1" ]]
  flags="$(psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -tAc "select (not rolcanlogin and not rolsuper and not rolbypassrls) from pg_roles where rolname = 'supabase_admin'")"
  [[ "${flags//[[:space:]]/}" == "t" ]]
  member="$(psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -tAc "select count(*) from pg_auth_members am join pg_roles member on member.oid = am.member join pg_roles role on role.oid = am.roleid where member.rolname = 'postgres' and role.rolname = 'oi_pr2_api'")"
  anon_member="$(psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -tAc "select count(*) from pg_auth_members am join pg_roles member on member.oid = am.member join pg_roles role on role.oid = am.roleid where member.rolname = 'authenticator' and role.rolname = 'anon'")"
  [[ "${member//[[:space:]]/}" == "1" ]]
  [[ "${anon_member//[[:space:]]/}" == "1" ]]
  PGPASSWORD="$ROLE_SECRET" psql "postgresql://oi_pr2_api@127.0.0.1:5432/sec1_supa_dst" -v ON_ERROR_STOP=1 -tAc 'select 1' >/dev/null
  pg_restore -l "$work/gen/plain.dump" >"$work/again.list"
  psql "$dst" -v ON_ERROR_STOP=1 -tA -c "SELECT name FROM pg_available_extensions" >"$work/ext.txt"
  : >"$work/installed.txt"
  python3 "$SCRIPT_DIR/restore_toc.py" "$work/again.list" "$work/ext.txt" "$work/installed.txt" >/dev/null
  set +e
  pg_restore --exit-on-error --single-transaction --no-owner --no-acl \
    --use-list="$work/again.list" --dbname="$dst" "$work/gen/plain.dump" >"$work/second.log" 2>&1
  second_rc=$?
  set -e
  if [[ "$second_rc" -eq 0 ]]; then
    echo "repeating the filtered public restore was treated as success" >&2
    return 1
  fi
  if ! grep -q "already exists" "$work/second.log"; then
    echo "repeat restore failed for an unexpected reason" >&2
    cat "$work/second.log" >&2
    return 1
  fi
  rm -rf "$work"
  rm -f "$bad"
}
run_ok "Supabase roles fixture restores app roles and public data, and still fails closed" supabase_shaped_restore

echo "STEP: tampered ciphertext on the restore path"
tamper_restore() {
  work="$(mktemp -d)"
  aws_cli s3 sync "s3://oi-backup-flow/snapshots/${SEC1_DATE_STAMP}/db" "$work/db" --only-show-errors
  python3 - "$work/db/oi-production.dump.enc" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
blob = bytearray(path.read_bytes())
# The last four bytes are the end marker. Flip a tag byte inside the ciphertext.
if len(blob) < 8:
    raise SystemExit("ciphertext too short to tamper")
blob[-5] ^= 0x5A
path.write_bytes(blob)
PY
  mkdir -p "$work/snap/db" "$work/snap/storage"
  cp "$work/db/oi-production.dump.enc" "$work/snap/db/oi-production.dump.enc"
  # Keep a valid roles payload so the failure is specifically the database ciphertext.
  aws_cli s3 cp "s3://oi-backup-flow/snapshots/${SEC1_DATE_STAMP}/db/oi-production.roles.sql.enc" \
    "$work/snap/db/oi-production.roles.sql.enc" --only-show-errors >/dev/null
  aws_cli s3 cp "s3://oi-backup-flow/snapshots/${SEC1_DATE_STAMP}/db/oi-production.roles.sql.enc.sha256" \
    "$work/snap/db/oi-production.roles.sql.enc.sha256" --only-show-errors >/dev/null
  aws_cli s3 cp "s3://oi-backup-flow/snapshots/${SEC1_DATE_STAMP}/db/oi-production.roles.sql.plaintext.sha256" \
    "$work/snap/db/oi-production.roles.sql.plaintext.sha256" --only-show-errors >/dev/null
  aws_cli s3 cp "s3://oi-backup-flow/snapshots/${SEC1_DATE_STAMP}/db/oi-production.dump.plaintext.sha256" \
    "$work/snap/db/oi-production.dump.plaintext.sha256" --only-show-errors >/dev/null
  sha256sum "$work/snap/db/oi-production.dump.enc" | awk '{print $1 "  db/oi-production.dump.enc"}' \
    >"$work/snap/db/oi-production.dump.enc.sha256"
  printf 'tampered\n' >"$work/snap/storage/tampered.txt"
  python3 "$SCRIPT_DIR/manifest.py" write "$work/snap" >/dev/null
  ensure_bucket oi-backup-tamper
  aws_cli s3 sync "$work/snap" "s3://oi-backup-tamper/snapshots/tamper-test" --only-show-errors
  set +e
  env SEC1_OFFLINE_TEST=1 \
    SEC1_MODE=r2 \
    SEC1_SNAPSHOT_PREFIX=snapshots/tamper-test \
    SEC1_TARGET_DATABASE_URL="postgresql://postgres:postgres@127.0.0.1:5432/sec1_dst" \
    BACKUP_ENCRYPTION_KEY="$ENC_KEY" \
    R2_BUCKET=oi-backup-tamper \
    bash "$SCRIPT_DIR/restore-test.sh" >"$work/restore.log" 2>&1
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    echo "tampered snapshot restored" >&2
    return 1
  fi
  if ! grep -q "authentication failed" "$work/restore.log"; then
    echo "tampered snapshot was not rejected as ciphertext" >&2
    cat "$work/restore.log" >&2
    return 1
  fi
  scan_log "$work/restore.log"
  rm -rf "$work"
}
run_ok "tampered ciphertext rejected on restore" tamper_restore

echo "STEP: injected download failure"
printf 'dir/nested/deep/c.txt\n' >"$FAIL_FILE"
: >"$MOCK_LOG"
ensure_bucket oi-backup-fail
download_failure() {
  set +e
  env SEC1_OFFLINE_TEST=1 \
    SEC1_STORAGE_PAGE_LIMIT=2 \
    SEC1_DATE_STAMP="$SEC1_DATE_STAMP" \
    SEC1_MONTH_STAMP="$SEC1_MONTH_STAMP" \
    BACKUP_ENCRYPTION_KEY="$ENC_KEY" \
    OI_PROD_DATABASE_URL="postgresql://postgres:postgres@127.0.0.1:5432/sec1_src" \
    OI_PROD_SUPABASE_URL="http://127.0.0.1:${MOCK_PORT}" \
    OI_PROD_SUPABASE_SERVICE_ROLE_KEY="$MOCK_KEY" \
    OI_PROD_MEDIA_BUCKET=oi-production-media \
    R2_BUCKET=oi-backup-fail \
    bash "$SCRIPT_DIR/backup.sh" >"$1" 2>&1
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    echo "backup succeeded despite a forced download error" >&2
    return 1
  fi
  if grep -q "backup complete" "$1"; then
    echo "backup reported completion after a download error" >&2
    return 1
  fi
  if ! grep -q "HTTP 500" "$1"; then
    echo "backup did not report the download HTTP failure" >&2
    cat "$1" >&2
    return 1
  fi
  if aws_cli s3 ls "s3://oi-backup-fail" --recursive | grep -q .; then
    echo "failed backup still uploaded objects" >&2
    return 1
  fi
  scan_log "$1"
}
fail_log="$(mktemp)"
run_ok "injected download failure fails the run" download_failure "$fail_log"

echo "STEP: full restore on supabase/postgres:17.11.0.018"
hosted_image_restore() {
  local docker_cmd src work baseline
  if docker info >/dev/null 2>&1; then
    docker_cmd=(docker)
  elif sudo docker info >/dev/null 2>&1; then
    docker_cmd=(sudo docker)
  else
    echo "docker is required to test the Supabase Postgres image" >&2
    return 1
  fi
  "${docker_cmd[@]}" rm -f sec1-supabase sec1-supabase-restore >/dev/null 2>&1 || true
  "${docker_cmd[@]}" run -d --name sec1-supabase-restore \
    -p 127.0.0.1:5433:5432 \
    -e POSTGRES_PASSWORD=postgres \
    supabase/postgres:17.11.0.018 >/dev/null
  local i ready=0
  for i in $(seq 1 60); do
    if PGPASSWORD=postgres psql "postgresql://supabase_admin@127.0.0.1:5433/postgres" -tAc 'select 1' >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  [[ "$ready" == "1" ]]
  src="postgresql://supabase_admin:postgres@127.0.0.1:5433/postgres"
  baseline="$(psql "$src" -v ON_ERROR_STOP=1 -tAc "SELECT (to_regclass('auth.users') IS NOT NULL AND EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'realtime'))::text")"
  [[ "${baseline//[[:space:]]/}" == "t" || "${baseline//[[:space:]]/}" == "true" ]]
  psql "$src" -v ON_ERROR_STOP=1 <<SQL
CREATE SCHEMA oi_private;
CREATE TABLE public.organizations (id integer PRIMARY KEY, name text NOT NULL);
CREATE TABLE public.users (
  id integer PRIMARY KEY,
  organization_id integer NOT NULL REFERENCES public.organizations (id)
);
CREATE TABLE public.platform_staff (id integer PRIMARY KEY);
CREATE TABLE oi_private.notes (id integer PRIMARY KEY, body text NOT NULL);
INSERT INTO public.organizations VALUES (1, 'Acme');
INSERT INTO public.users VALUES (1, 1);
INSERT INTO public.platform_staff VALUES (7);
INSERT INTO oi_private.notes VALUES (1, 'kept');
ALTER PUBLICATION supabase_realtime ADD TABLES IN SCHEMA public;
CREATE TABLE realtime.messages (
  id integer PRIMARY KEY,
  payload jsonb,
  binary_payload bytea
);
ALTER TABLE realtime.messages ADD CONSTRAINT messages_payload_exclusive
  CHECK (((payload IS NULL) OR (binary_payload IS NULL))) NOT VALID;
CREATE FUNCTION auth.sec1_touch() RETURNS trigger LANGUAGE plpgsql AS \$func\$
BEGIN RETURN NEW; END \$func\$;
CREATE TRIGGER sec1_auth_users_guard BEFORE UPDATE ON auth.users
  FOR EACH ROW EXECUTE FUNCTION auth.sec1_touch();
DROP ROLE IF EXISTS oi_pr2_api;
CREATE ROLE oi_pr2_api LOGIN PASSWORD '${ROLE_SECRET}';
GRANT oi_pr2_api TO postgres GRANTED BY supabase_admin;
SQL
  work="$(mktemp -d)"
  mkdir -p "$work/gen" "$work/snap/db" "$work/snap/storage"
  pg_dump --format=custom --no-owner --no-acl --dbname="$src" --file="$work/gen/plain.dump"
  pg_dumpall --roles-only --dbname="$src" >"$work/gen/roles.sql"
  chmod 600 "$work/gen/plain.dump" "$work/gen/roles.sql"
  if ! grep -q "GRANTED BY supabase_admin" "$work/gen/roles.sql"; then
    echo "roles dump is missing GRANTED BY supabase_admin" >&2
    return 1
  fi
  BACKUP_ENCRYPTION_KEY="$ENC_KEY" python3 "$SCRIPT_DIR/crypto.py" encrypt \
    "$work/gen/plain.dump" "$work/snap/db/oi-production.dump.enc"
  BACKUP_ENCRYPTION_KEY="$ENC_KEY" python3 "$SCRIPT_DIR/crypto.py" encrypt \
    "$work/gen/roles.sql" "$work/snap/db/oi-production.roles.sql.enc"
  python3 - "$work" <<'PY'
import hashlib, pathlib, sys
root = pathlib.Path(sys.argv[1])
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
pairs = [
    (root / "gen/plain.dump", root / "snap/db/oi-production.dump.plaintext.sha256", "plaintext-oi-production.dump"),
    (root / "gen/roles.sql", root / "snap/db/oi-production.roles.sql.plaintext.sha256", "plaintext-oi-production.roles.sql"),
    (root / "snap/db/oi-production.dump.enc", root / "snap/db/oi-production.dump.enc.sha256", "db/oi-production.dump.enc"),
    (root / "snap/db/oi-production.roles.sql.enc", root / "snap/db/oi-production.roles.sql.enc.sha256", "db/oi-production.roles.sql.enc"),
]
for source, dest, label in pairs:
    dest.write_text(f"{sha(source)}  {label}\n", encoding="utf-8")
PY
  echo fixture >"$work/snap/storage/fixture.txt"
  python3 "$SCRIPT_DIR/manifest.py" write "$work/snap" >/dev/null
  ensure_bucket oi-supabase-image
  aws_cli s3 sync "$work/snap" "s3://oi-supabase-image/snapshots/2026-11-07" --only-show-errors
  pg_restore -l "$work/gen/plain.dump" >"$work/toc.list"
  psql "$src" -v ON_ERROR_STOP=1 -tA -c "SELECT name FROM pg_available_extensions" >"$work/available.txt"
  psql "$src" -v ON_ERROR_STOP=1 -tA -c "SELECT extname FROM pg_extension" >"$work/installed.txt"
  echo "---- TOC inventory (restored versus skipped) ----"
  python3 "$SCRIPT_DIR/restore_toc.py" inventory "$work/toc.list" "$work/available.txt" "$work/installed.txt" | tee "$work/inventory.txt"
  python3 - "$work/inventory.txt" <<'PY'
import sys
text = open(sys.argv[1], encoding="utf-8").read()
restored, skipped = text.split("SKIPPED", 1)
checks = {
    "public table data restored": "TABLE DATA schema=public" in restored,
    "app schema restored": "TABLE schema=oi_private" in restored,
    "realtime check constraint skipped": "CHECK CONSTRAINT schema=realtime" in skipped and "CHECK CONSTRAINT schema=realtime" not in restored,
    "auth trigger skipped": "TRIGGER schema=auth" in skipped and "TRIGGER schema=auth" not in restored,
    "event triggers skipped": "EVENT TRIGGER schema=-" in skipped,
    "supabase publication skipped": "PUBLICATION schema=-" in skipped,
    "publication tables in public skipped": "PUBLICATION TABLES IN SCHEMA schema=public" in skipped,
    "auth table data skipped": "TABLE DATA schema=auth" in skipped and "TABLE DATA schema=auth" not in restored,
}
failed = [name for name, ok in checks.items() if not ok]
if failed:
    raise SystemExit("TOC inventory mismatch: " + ", ".join(failed))
PY
  psql "$src" -v ON_ERROR_STOP=1 <<'SQL'
ALTER TABLE realtime.messages DROP CONSTRAINT messages_payload_exclusive;
DROP TRIGGER sec1_auth_users_guard ON auth.users;
DROP TABLE public.users;
DROP TABLE public.organizations;
DROP TABLE public.platform_staff;
DROP SCHEMA oi_private CASCADE;
SQL
  psql "$src" -v ON_ERROR_STOP=1 -c "REVOKE oi_pr2_api FROM postgres;"
  psql "$src" -v ON_ERROR_STOP=1 -c "DROP ROLE oi_pr2_api;"
  env SEC1_MODE=r2 \
    SEC1_SNAPSHOT_PREFIX=snapshots/2026-11-07 \
    SEC1_TARGET_DATABASE_URL="$src" \
    BACKUP_ENCRYPTION_KEY="$ENC_KEY" \
    R2_BUCKET=oi-supabase-image \
    bash "$SCRIPT_DIR/restore-test.sh"
  local org users staff notes auth_ok constraint trigger admin_super
  org="$(psql "$src" -v ON_ERROR_STOP=1 -tAc 'select count(*) from public.organizations')"
  users="$(psql "$src" -v ON_ERROR_STOP=1 -tAc 'select count(*) from public.users')"
  staff="$(psql "$src" -v ON_ERROR_STOP=1 -tAc 'select count(*) from public.platform_staff')"
  notes="$(psql "$src" -v ON_ERROR_STOP=1 -tAc 'select count(*) from oi_private.notes')"
  auth_ok="$(psql "$src" -v ON_ERROR_STOP=1 -tAc "select to_regclass('auth.users') is not null")"
  constraint="$(psql "$src" -v ON_ERROR_STOP=1 -tAc "select count(*) from pg_constraint where conname = 'messages_payload_exclusive'")"
  trigger="$(psql "$src" -v ON_ERROR_STOP=1 -tAc "select count(*) from pg_trigger where tgname = 'sec1_auth_users_guard'")"
  admin_super="$(psql "$src" -v ON_ERROR_STOP=1 -tAc "select rolsuper from pg_roles where rolname = 'supabase_admin'")"
  [[ "${org//[[:space:]]/}" == "1" ]]
  [[ "${users//[[:space:]]/}" == "1" ]]
  [[ "${staff//[[:space:]]/}" == "1" ]]
  [[ "${notes//[[:space:]]/}" == "1" ]]
  [[ "${auth_ok//[[:space:]]/}" == "t" || "${auth_ok//[[:space:]]/}" == "true" ]]
  [[ "${constraint//[[:space:]]/}" == "0" ]]
  [[ "${trigger//[[:space:]]/}" == "0" ]]
  [[ "${admin_super//[[:space:]]/}" == "t" || "${admin_super//[[:space:]]/}" == "true" ]]
  PGPASSWORD="$ROLE_SECRET" psql "postgresql://oi_pr2_api@127.0.0.1:5433/postgres" -v ON_ERROR_STOP=1 -tAc 'select 1' >/dev/null
  "${docker_cmd[@]}" rm -f sec1-supabase-restore >/dev/null 2>&1 || true
  rm -rf "$work"
}
run_ok "hosted Supabase image restores app data and skips realtime, auth, and publications" hosted_image_restore

echo
echo "==== offline backup results: ${PASS_N} passed, ${FAIL_N} failed ===="
if [[ "$FAIL_N" -ne 0 ]]; then
  exit 1
fi
