#!/usr/bin/env bash
# SEC-1 nightly/manual off-site backup: oi-production DB + media → Cloudflare R2.
# Reads secrets from the environment (GitHub Actions). Never echoes secret values.
# Any dump, download, upload, checksum, or retention error fails the run.
set -euo pipefail
umask 077
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

WORK="${SEC1_WORK_DIR:-$(mktemp -d /tmp/sec1-backup.XXXXXX)}"
DATE_STAMP="${SEC1_DATE_STAMP:-$(today_phoenix)}"
MONTH_STAMP="${SEC1_MONTH_STAMP:-$(month_stamp_phoenix)}"
MEDIA_BUCKET="${OI_PROD_MEDIA_BUCKET:-$DEFAULT_MEDIA_BUCKET}"
SNAPSHOT_PREFIX="snapshots/${DATE_STAMP}"
MONTHLY_PREFIX="monthly/${MONTH_STAMP}"

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

require_cmd python3
require_cmd pg_dump
require_cmd pg_dumpall
require_cmd sha256sum
require_cmd aws

if [[ "${SEC1_OFFLINE_TEST:-}" == "1" ]]; then
  assert_offline_test_sources
  PROJECT_LABEL="offline-test"
else
  assert_production_only
  assert_production_supabase_url
  PROJECT_LABEL="$ALLOWED_PROJECT_REF"
fi

require_env BACKUP_ENCRYPTION_KEY
require_env OI_PROD_SUPABASE_URL
require_env OI_PROD_SUPABASE_SERVICE_ROLE_KEY
configure_r2_aws_cli

mkdir -p "$WORK/db" "$WORK/storage" "$WORK/out/db" "$WORK/out/storage"
export WORK MEDIA_BUCKET

log "dumping database (custom format) for ${PROJECT_LABEL}"
pg_dump --format=custom --no-owner --no-acl \
  --dbname="$OI_PROD_DATABASE_URL" \
  --file="$WORK/db/oi-production.dump"
chmod 600 "$WORK/db/oi-production.dump"

# Roles and membership GRANTs. The file contains password hashes; it is
# mode 0600, encrypted before upload, and never printed.
log "dumping roles and membership grants (roles-only; not printed)"
roles_err="$WORK/roles-dump.err"
set +e
pg_dumpall --roles-only --dbname="$OI_PROD_DATABASE_URL" \
  >"$WORK/db/oi-production.roles.sql" 2>"$roles_err"
roles_rc=$?
set -e
if [[ "$roles_rc" -ne 0 ]]; then
  python3 "$LIB_DIR/redact.py" "$roles_err" >&2 || die "roles dump failed and redaction failed"
  die "pg_dumpall --roles-only failed (exit ${roles_rc})"
fi
if [[ -s "$roles_err" ]]; then
  python3 "$LIB_DIR/redact.py" "$roles_err" >&2
fi
chmod 600 "$WORK/db/oi-production.roles.sql"
if ! grep -q "CREATE ROLE" "$WORK/db/oi-production.roles.sql"; then
  die "roles dump contained no CREATE ROLE statements"
fi

log "encrypting database dump"
encrypt_file "$WORK/db/oi-production.dump" "$WORK/out/db/oi-production.dump.enc"
log "encrypting roles dump"
encrypt_file "$WORK/db/oi-production.roles.sql" "$WORK/out/db/oi-production.roles.sql.enc"

PLAIN_SHA="$(sha256_file "$WORK/db/oi-production.dump")"
ENC_SHA="$(sha256_file "$WORK/out/db/oi-production.dump.enc")"
ROLES_PLAIN_SHA="$(sha256_file "$WORK/db/oi-production.roles.sql")"
ROLES_ENC_SHA="$(sha256_file "$WORK/out/db/oi-production.roles.sql.enc")"
printf '%s  db/oi-production.dump.enc\n' "$ENC_SHA" >"$WORK/out/db/oi-production.dump.enc.sha256"
printf '%s  plaintext-oi-production.dump\n' "$PLAIN_SHA" >"$WORK/out/db/oi-production.dump.plaintext.sha256"
printf '%s  db/oi-production.roles.sql.enc\n' "$ROLES_ENC_SHA" >"$WORK/out/db/oi-production.roles.sql.enc.sha256"
printf '%s  plaintext-oi-production.roles.sql\n' "$ROLES_PLAIN_SHA" >"$WORK/out/db/oi-production.roles.sql.plaintext.sha256"

log "listing and downloading storage (recursive, paginated) from ${MEDIA_BUCKET}"
python3 "$LIB_DIR/storage_copy.py" "$WORK/out/storage" "$WORK/storage-files.txt"
STORAGE_FILES="$(
  python3 - "$WORK/storage-files.txt" "$WORK/out/storage" <<'PY'
import sys
from pathlib import Path
listed = [line for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines() if line.strip()]
root = Path(sys.argv[2])
disk = sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())
if sorted(listed) != disk:
    sys.stderr.write(f"ERROR: storage object count listed={len(listed)} downloaded={len(disk)}\n")
    sys.exit(1)
print(len(disk))
PY
)" || die "storage object count does not match the listing"
STORAGE_BYTES="$(
  python3 -c 'import os,sys
total=0
for dirpath, _dirs, names in os.walk(sys.argv[1]):
    for name in names:
        total += os.path.getsize(os.path.join(dirpath, name))
print(total)' "$WORK/out/storage"
)" || die "could not measure storage bytes"
log "storage objects=${STORAGE_FILES} bytes=${STORAGE_BYTES}"

log "building manifest.sha256"
MANIFEST_COUNT="$(python3 "$LIB_DIR/manifest.py" write "$WORK/out")" || die "manifest write failed"
python3 "$LIB_DIR/manifest.py" verify "$WORK/out"
storage_in_manifest="$(python3 "$LIB_DIR/manifest.py" storage-count "$WORK/out/manifest.sha256")" \
  || die "could not count storage entries in the manifest"
[[ "$storage_in_manifest" == "$STORAGE_FILES" ]] \
  || die "storage object count ${STORAGE_FILES} does not match manifest ${storage_in_manifest}"
log "manifest OK files=${MANIFEST_COUNT} storage_files=${storage_in_manifest}"

export SEC1_PROJECT_LABEL="$PROJECT_LABEL"
export SEC1_MEDIA_BUCKET="$MEDIA_BUCKET"
export SEC1_DATE_STAMP="$DATE_STAMP"
export SEC1_PLAIN_SHA="$PLAIN_SHA"
export SEC1_ENC_SHA="$ENC_SHA"
export SEC1_ROLES_PLAIN_SHA="$ROLES_PLAIN_SHA"
export SEC1_ROLES_ENC_SHA="$ROLES_ENC_SHA"
export SEC1_STORAGE_FILES="$STORAGE_FILES"
export SEC1_STORAGE_BYTES="$STORAGE_BYTES"
export SEC1_MANIFEST_COUNT="$MANIFEST_COUNT"
export SEC1_RUN_JSON="$WORK/out/run.json"
python3 - <<'PY'
import datetime, json, os, re, sys
def need(name):
    value = os.environ.get(name, "")
    if not value:
        sys.stderr.write(f"ERROR: missing {name}\n")
        raise SystemExit(1)
    return value
payload = {
    "schema": "oi-sec1-backup-v2",
    "project_ref": need("SEC1_PROJECT_LABEL"),
    "media_bucket": need("SEC1_MEDIA_BUCKET"),
    "date_stamp_phoenix": need("SEC1_DATE_STAMP"),
    "created_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "db_plaintext_sha256": need("SEC1_PLAIN_SHA"),
    "db_ciphertext_sha256": need("SEC1_ENC_SHA"),
    "roles_plaintext_sha256": need("SEC1_ROLES_PLAIN_SHA"),
    "roles_ciphertext_sha256": need("SEC1_ROLES_ENC_SHA"),
    "storage_file_count": int(need("SEC1_STORAGE_FILES")),
    "storage_bytes": int(need("SEC1_STORAGE_BYTES")),
    "manifest_file_count": int(need("SEC1_MANIFEST_COUNT")),
    "encryption": "aes-256-gcm+pbkdf2-sha256",
    "github_run_id": os.environ.get("GITHUB_RUN_ID") or None,
    "github_sha": os.environ.get("GITHUB_SHA") or None,
}
for key in (
    "db_plaintext_sha256",
    "db_ciphertext_sha256",
    "roles_plaintext_sha256",
    "roles_ciphertext_sha256",
):
    if re.fullmatch(r"[0-9a-f]{64}", payload[key]) is None:
        sys.stderr.write("ERROR: run.json hash is not sha256\n")
        raise SystemExit(1)
with open(os.environ["SEC1_RUN_JSON"], "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2)
    fh.write("\n")
PY

count_local_files() {
  python3 -c 'import os,sys; print(sum(len(names) for _d, _s, names in os.walk(sys.argv[1])))' "$1"
}

count_remote() {
  local prefix="$1" out rc
  set +e
  out="$(aws s3 ls "s3://${R2_BUCKET}/${prefix}/" --recursive --endpoint-url "$R2_ENDPOINT" 2>"$WORK/aws-ls.err")"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    python3 "$LIB_DIR/redact.py" "$WORK/aws-ls.err" >&2 \
      || die "remote listing failed for ${prefix} and redaction failed"
    die "remote listing failed for ${prefix} (exit ${rc})"
  fi
  printf '%s' "$out" | python3 -c 'import sys; print(sum(1 for line in sys.stdin if line.strip()))'
}

upload_tree() {
  local prefix="$1" local_n remote_n
  r2_sync_dir "$WORK/out/db" "${prefix}/db"
  if [[ "$STORAGE_FILES" != "0" ]]; then
    r2_sync_dir "$WORK/out/storage" "${prefix}/storage"
  fi
  r2_cp "$WORK/out/run.json" "${prefix}/run.json"
  r2_cp "$WORK/out/manifest.sha256" "${prefix}/manifest.sha256"
  local_n="$(count_local_files "$WORK/out")" || die "local object count failed"
  remote_n="$(count_remote "$prefix")" || die "remote object count failed"
  [[ "$local_n" == "$remote_n" ]] \
    || die "uploaded object count ${remote_n} != local ${local_n} for ${prefix}"
  log "uploaded ${prefix} objects=${remote_n}"
}

log "uploading snapshot to s3://${R2_BUCKET}/${SNAPSHOT_PREFIX}/"
upload_tree "$SNAPSHOT_PREFIX"

DAY_NUM="$(TZ=America/Phoenix date +%d)"
if [[ "$DAY_NUM" == "01" || "${SEC1_FORCE_MONTHLY:-}" == "1" ]]; then
  log "also writing monthly snapshot ${MONTHLY_PREFIX}"
  upload_tree "$MONTHLY_PREFIX"
fi

log "retention: keep 30 daily snapshots and 12 monthly snapshots"
python3 "$LIB_DIR/retention.py"

log "backup complete: ${SNAPSHOT_PREFIX} (storage_files=${STORAGE_FILES})"
