#!/usr/bin/env bash
# SEC-1 restore test into a throwaway Postgres 17 (CI service container).
# The target host must be localhost, 127.0.0.1, ::1, or a local socket.
# supabase.co and every other host are refused before any connection.
# This script never connects to the production database.
#
# Modes:
#   SEC1_MODE=r2         — newest snapshots/YYYY-MM-DD from the backup bucket (default)
#   SEC1_MODE=synthetic  — explicit opt-in: build a tiny dump locally
set -euo pipefail
umask 077
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

# Prefer the pinned PostgreSQL 17 client over a newer distro metapackage.
if [[ -d /usr/lib/postgresql/17/bin ]]; then
  PATH="/usr/lib/postgresql/17/bin:${PATH}"
  export PATH
fi

# Empty and unset both mean the real snapshot. Synthetic is opt-in only.
MODE="${SEC1_MODE:-r2}"
WORK="${SEC1_WORK_DIR:-$(mktemp -d /tmp/sec1-restore.XXXXXX)}"
TARGET_DB_URL="${SEC1_TARGET_DATABASE_URL:-postgresql://postgres:postgres@127.0.0.1:5432/oi_restore_test}"
SNAPSHOT_PREFIX=""
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# Refuse a remote target before requiring secrets or touching the network.
assert_restore_target_local "$TARGET_DB_URL"
export SEC1_TARGET_DATABASE_URL="$TARGET_DB_URL"

require_cmd python3
require_cmd psql
require_cmd pg_restore
require_cmd pg_dump
require_cmd pg_dumpall
require_cmd sha256sum
require_env BACKUP_ENCRYPTION_KEY
mkdir -p "$WORK"

pg_client_major() {
  local cmd="$1" line major
  line="$("$cmd" --version 2>/dev/null || true)"
  major="$(printf '%s\n' "$line" | sed -n 's/.*(PostgreSQL) \([0-9][0-9]*\)\..*/\1/p' | head -n 1)"
  if [[ ! "$major" =~ ^[0-9]+$ ]]; then
    die "${cmd} version is not PostgreSQL 17"
  fi
  printf '%s' "$major"
}

assert_postgres_17() {
  local tool major server_num err rc
  for tool in psql pg_restore pg_dump pg_dumpall; do
    major="$(pg_client_major "$tool")"
    [[ "$major" == "17" ]] || die "${tool} must be PostgreSQL 17, found major ${major}"
  done
  err="$WORK/server-version.err"
  set +e
  server_num="$(psql "$TARGET_DB_URL" -v ON_ERROR_STOP=1 -tAc 'SHOW server_version_num' 2>"$err")"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    python3 "$LIB_DIR/redact.py" "$err" >&2 || true
    die "could not read restore target server version"
  fi
  server_num="${server_num//[[:space:]]/}"
  [[ "$server_num" =~ ^[0-9]+$ ]] || die "could not read restore target server version"
  major=$((10#$server_num / 10000))
  [[ "$major" -eq 17 ]] || die "restore target must be PostgreSQL 17, found major ${major}"
  log "postgres client and server are major version 17"
}

assert_restored_key_tables() {
  local tables count present t
  tables="$(psql "$TARGET_DB_URL" -v ON_ERROR_STOP=1 -tAc \
    "SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind = 'r'")" \
    || die "could not count restored tables"
  tables="${tables//[[:space:]]/}"
  [[ "$tables" =~ ^[1-9][0-9]*$ ]] || die "restored database has no public tables"
  log "restored public tables=${tables}"
  for t in organizations users platform_staff; do
    present="$(psql "$TARGET_DB_URL" -v ON_ERROR_STOP=1 -tAc \
      "SELECT to_regclass('public.${t}') IS NOT NULL")" \
      || die "could not check key table public.${t}"
    present="${present//[[:space:]]/}"
    [[ "$present" == "t" ]] || die "key table public.${t} is missing"
    count="$(psql "$TARGET_DB_URL" -v ON_ERROR_STOP=1 -tAc \
      "SELECT count(*) FROM public.${t}")" \
      || die "row count failed for public.${t}"
    count="${count//[[:space:]]/}"
    [[ "$count" =~ ^[0-9]+$ ]] || die "row count for public.${t} is not a number"
    if [[ "$t" == "organizations" || "$t" == "users" ]]; then
      [[ "$count" -ge 1 ]] || die "key table public.${t} is empty after restore"
    fi
    log "restored public.${t} count=${count}"
  done
}

assert_postgres_17

dump_roles_to() {
  local dest="$1" err="$2" rc
  set +e
  pg_dumpall --roles-only --dbname="$TARGET_DB_URL" >"$dest" 2>"$err"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    python3 "$LIB_DIR/redact.py" "$err" >&2 || die "roles dump failed and redaction failed"
    die "pg_dumpall --roles-only failed (exit ${rc})"
  fi
  if [[ -s "$err" ]]; then
    python3 "$LIB_DIR/redact.py" "$err" >&2
  fi
  chmod 600 "$dest"
  if ! grep -q "CREATE ROLE" "$dest"; then
    die "roles dump contained no CREATE ROLE statements"
  fi
}

if [[ "$MODE" == "r2" ]]; then
  require_cmd aws
  configure_r2_aws_cli
  SNAPSHOT_PREFIX="${SEC1_SNAPSHOT_PREFIX:-}"
  if [[ -z "$SNAPSHOT_PREFIX" ]]; then
    listing="$(aws s3 ls "s3://${R2_BUCKET}/snapshots/" --endpoint-url "$R2_ENDPOINT")" \
      || die "cannot list snapshots"
    SNAPSHOT_PREFIX="$(printf '%s\n' "$listing" | python3 "$LIB_DIR/snapshot_prefix.py")" \
      || die "no dated snapshots found in the backup bucket"
  fi
  [[ -n "$SNAPSHOT_PREFIX" ]] || die "snapshot prefix is empty"
  log "downloading ${SNAPSHOT_PREFIX}"
  mkdir -p "$WORK/snap"
  aws s3 sync "s3://${R2_BUCKET}/${SNAPSHOT_PREFIX}" "$WORK/snap" --endpoint-url "$R2_ENDPOINT" --only-show-errors \
    || die "snapshot download failed"
  [[ -f "$WORK/snap/manifest.sha256" ]] || die "manifest.sha256 missing — incomplete snapshot"
  [[ -f "$WORK/snap/db/oi-production.dump.enc" ]] || die "encrypted dump missing"
  [[ -f "$WORK/snap/db/oi-production.roles.sql.enc" ]] || die "encrypted roles dump missing"
elif [[ "$MODE" == "synthetic" ]]; then
  require_cmd pg_dump
  require_cmd pg_dumpall
  log "synthetic mode: building a tiny encrypted dump for CI"
  mkdir -p "$WORK/snap/db" "$WORK/gen"
  psql "$TARGET_DB_URL" -v ON_ERROR_STOP=1 <<'SQL'
DROP SCHEMA IF EXISTS public CASCADE;
CREATE SCHEMA public;
CREATE TABLE public.sec1_smoke (id int primary key, note text);
INSERT INTO public.sec1_smoke VALUES (1, 'hello-sec1');
SQL
  pg_dump --format=custom --no-owner --no-acl --dbname="$TARGET_DB_URL" --file="$WORK/gen/plain.dump"
  dump_roles_to "$WORK/gen/roles.sql" "$WORK/roles-dump.err"
  PLAIN_SHA="$(sha256_file "$WORK/gen/plain.dump")"
  ROLES_PLAIN_SHA="$(sha256_file "$WORK/gen/roles.sql")"
  encrypt_file "$WORK/gen/plain.dump" "$WORK/snap/db/oi-production.dump.enc"
  encrypt_file "$WORK/gen/roles.sql" "$WORK/snap/db/oi-production.roles.sql.enc"
  ENC_SHA="$(sha256_file "$WORK/snap/db/oi-production.dump.enc")"
  ROLES_ENC_SHA="$(sha256_file "$WORK/snap/db/oi-production.roles.sql.enc")"
  printf '%s  db/oi-production.dump.enc\n' "$ENC_SHA" >"$WORK/snap/db/oi-production.dump.enc.sha256"
  printf '%s  plaintext-oi-production.dump\n' "$PLAIN_SHA" >"$WORK/snap/db/oi-production.dump.plaintext.sha256"
  printf '%s  db/oi-production.roles.sql.enc\n' "$ROLES_ENC_SHA" >"$WORK/snap/db/oi-production.roles.sql.enc.sha256"
  printf '%s  plaintext-oi-production.roles.sql\n' "$ROLES_PLAIN_SHA" >"$WORK/snap/db/oi-production.roles.sql.plaintext.sha256"
  mkdir -p "$WORK/snap/storage"
  echo 'fixture' >"$WORK/snap/storage/fixture.txt"
  python3 "$LIB_DIR/manifest.py" write "$WORK/snap" >/dev/null
else
  die "unknown SEC1_MODE: ${MODE}"
fi

log "verifying manifest checksums"
python3 "$LIB_DIR/manifest.py" verify "$WORK/snap"
(
  cd "$WORK/snap"
  sha256sum -c manifest.sha256
)
log "manifest OK"

if [[ -f "$WORK/snap/run.json" ]]; then
  python3 - "$WORK/snap" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
run = json.loads((root / "run.json").read_text(encoding="utf-8"))
storage = root / "storage"
files = [p for p in storage.rglob("*") if p.is_file()] if storage.is_dir() else []
listed = int(run["storage_file_count"])
if listed != len(files):
    sys.stderr.write(f"ERROR: storage count {len(files)} != run.json {listed}\n")
    raise SystemExit(1)
manifest_lines = [line for line in (root / "manifest.sha256").read_text(encoding="utf-8").splitlines() if line.strip()]
if "manifest_file_count" in run and int(run["manifest_file_count"]) != len(manifest_lines):
    sys.stderr.write("ERROR: manifest_file_count does not match manifest.sha256\n")
    raise SystemExit(1)
print(f"run.json counts OK storage_files={listed} manifest_files={len(manifest_lines)}")
PY
fi

log "decrypting database dump"
decrypt_file "$WORK/snap/db/oi-production.dump.enc" "$WORK/plain.dump"
verify_plaintext_hash "$WORK/snap/db/oi-production.dump.plaintext.sha256" "$WORK/plain.dump" "database dump"
log "decrypt OK database"
log "decrypting roles dump"
decrypt_file "$WORK/snap/db/oi-production.roles.sql.enc" "$WORK/plain.roles.sql"
verify_plaintext_hash "$WORK/snap/db/oi-production.roles.sql.plaintext.sha256" "$WORK/plain.roles.sql" "roles dump"
chmod 600 "$WORK/plain.dump" "$WORK/plain.roles.sql"
log "decrypt OK roles"

log "restoring roles into throwaway Postgres"
python3 "$LIB_DIR/roles_restore.py" "$WORK/plain.roles.sql"

log "restoring database into throwaway Postgres"
# pg_dump omits CREATE SCHEMA public. Recreate it, and skip a TOC entry that
# would create it again. Every other restore error still fails the run.
psql "$TARGET_DB_URL" -v ON_ERROR_STOP=1 <<'SQL'
DROP SCHEMA IF EXISTS public CASCADE;
CREATE SCHEMA public;
GRANT ALL ON SCHEMA public TO public;
SQL
pg_restore -l "$WORK/plain.dump" >"$WORK/restore.list"
python3 - "$WORK/restore.list" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
out = []
for line in path.read_text(encoding="utf-8").splitlines():
    body = line[1:] if line.startswith(";") else line
    if " SCHEMA - public " in f" {body} ":
        if not line.startswith(";"):
            line = ";" + line
    out.append(line)
path.write_text("\n".join(out) + "\n", encoding="utf-8")
PY
pg_restore --exit-on-error --single-transaction --no-owner --no-acl \
  --use-list="$WORK/restore.list" --dbname="$TARGET_DB_URL" "$WORK/plain.dump"

if [[ -n "${SEC1_EXPECT_COUNT:-}" ]]; then
  [[ "${SEC1_EXPECT_TABLE:-}" =~ ^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$ ]] \
    || die "SEC1_EXPECT_TABLE must be schema.table"
  COUNT="$(psql "$TARGET_DB_URL" -v ON_ERROR_STOP=1 -tAc "select count(*) from ${SEC1_EXPECT_TABLE}")" \
    || die "row count query failed"
  COUNT="${COUNT//[[:space:]]/}"
  [[ "$COUNT" == "$SEC1_EXPECT_COUNT" ]] \
    || die "row count for ${SEC1_EXPECT_TABLE} expected ${SEC1_EXPECT_COUNT} got ${COUNT}"
  log "row count OK ${SEC1_EXPECT_TABLE}=${COUNT}"
elif [[ "$MODE" == "synthetic" ]]; then
  COUNT="$(psql "$TARGET_DB_URL" -v ON_ERROR_STOP=1 -tAc 'select count(*) from public.sec1_smoke')"
  COUNT="${COUNT//[[:space:]]/}"
  [[ "$COUNT" == "1" ]] || die "expected sec1_smoke count 1, got ${COUNT}"
  NOTE="$(psql "$TARGET_DB_URL" -v ON_ERROR_STOP=1 -tAc "select note from public.sec1_smoke where id=1")"
  NOTE="${NOTE//[[:space:]]/}"
  [[ "$NOTE" == "hello-sec1" ]] || die "row content mismatch"
  log "synthetic restore PASS (row count + content)"
else
  assert_restored_key_tables
  log "r2 restore PASS (key tables present)"
fi

if [[ "$MODE" == "r2" ]]; then
  log "restore-test PASS mode=r2 snapshot=${SNAPSHOT_PREFIX}"
else
  log "restore-test PASS mode=${MODE}"
fi
