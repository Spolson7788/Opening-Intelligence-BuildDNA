#!/usr/bin/env bash
# Offline proof for the SEC-1 backup. No production hosts and no real secrets.
# Needs a local Postgres (default 127.0.0.1:5432, user/password/db postgres)
# and MinIO (default 127.0.0.1:9000). Starts MinIO when MINIO_BIN is executable
# and nothing is already listening.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATH="${HOME}/.local/bin:${PATH}"
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

echo
echo "==== offline backup results: ${PASS_N} passed, ${FAIL_N} failed ===="
if [[ "$FAIL_N" -ne 0 ]]; then
  exit 1
fi
