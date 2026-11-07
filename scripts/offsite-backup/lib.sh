#!/usr/bin/env bash
# Shared helpers for SEC-1 off-site backup. Never prints secret values.
set -euo pipefail

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ALLOWED_PROJECT_REF="bekaxmatcvxqpjixwsqn"
DEFAULT_BUCKET="oi-production-backups"
# Used by backup.sh when OI_PROD_MEDIA_BUCKET is unset.
# shellcheck disable=SC2034
DEFAULT_MEDIA_BUCKET="oi-production-media"
FORBIDDEN_PROJECT_REFS=(
  fadihkhdwpfffpelqjtg
  ytqiulxtiharrplqnuir
  fdudsigbxumcpbxxxerb
  ioqfdcehnhnqpnqawwvo
  boaoedvyvifppuklbwad
)

die() { echo "ERROR: $*" >&2; exit 1; }
log() { echo "[sec1] $*"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    die "missing required env/secret: $name"
  fi
}

refuse_forbidden_project_refs() {
  local url="$1" label="$2" f
  for f in "${FORBIDDEN_PROJECT_REFS[@]}"; do
    if [[ "$url" == *"$f"* ]]; then
      die "refusing ${label}: mentions forbidden project ${f}"
    fi
  done
}

assert_production_only() {
  local url="${OI_PROD_DATABASE_URL:-}"
  [[ -n "$url" ]] || die "OI_PROD_DATABASE_URL is required"
  if [[ "$url" != *"$ALLOWED_PROJECT_REF"* ]]; then
    die "refusing to run: database URL does not name allowed project ref $ALLOWED_PROJECT_REF"
  fi
  refuse_forbidden_project_refs "$url" "database URL"
}

assert_production_supabase_url() {
  local url="${OI_PROD_SUPABASE_URL:-}"
  [[ -n "$url" ]] || die "OI_PROD_SUPABASE_URL is required"
  if [[ "$url" != *"$ALLOWED_PROJECT_REF"* ]]; then
    die "refusing to run: supabase URL does not name allowed project ref $ALLOWED_PROJECT_REF"
  fi
  refuse_forbidden_project_refs "$url" "supabase URL"
}

# SEC1_OFFLINE_TEST=1 is for the local CI harness only. It refuses every
# non-loopback database and storage URL, so it cannot be pointed at Supabase.
assert_offline_test_sources() {
  [[ "${SEC1_OFFLINE_TEST:-}" == "1" ]] || die "offline guard called without SEC1_OFFLINE_TEST=1"
  local url="${OI_PROD_DATABASE_URL:-}"
  [[ -n "$url" ]] || die "OI_PROD_DATABASE_URL is required"
  SEC1_GUARD_URL="$url" python3 "$LIB_DIR/guards.py" loopback-db
  refuse_forbidden_project_refs "$url" "database URL"
  url="${OI_PROD_SUPABASE_URL:-}"
  [[ -n "$url" ]] || die "OI_PROD_SUPABASE_URL is required"
  SEC1_GUARD_URL="$url" python3 "$LIB_DIR/guards.py" loopback-http
  refuse_forbidden_project_refs "$url" "supabase URL"
}

assert_restore_target_local() {
  local url="$1"
  [[ -n "$url" ]] || die "restore target URL is required"
  SEC1_GUARD_URL="$url" python3 "$LIB_DIR/guards.py" restore-target
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

encrypt_file() {
  local src="$1" dest="$2"
  require_env BACKUP_ENCRYPTION_KEY
  python3 "$LIB_DIR/crypto.py" encrypt "$src" "$dest"
}

decrypt_file() {
  local src="$1" dest="$2"
  require_env BACKUP_ENCRYPTION_KEY
  python3 "$LIB_DIR/crypto.py" decrypt "$src" "$dest"
}

verify_plaintext_hash() {
  local sidecar="$1" file="$2" label="$3" expect got
  [[ -f "$sidecar" ]] || die "missing plaintext hash sidecar for ${label}"
  expect="$(awk 'NR==1 {print $1}' "$sidecar")"
  [[ "$expect" =~ ^[0-9a-f]{64}$ ]] || die "plaintext sidecar for ${label} is not a sha256"
  got="$(sha256_file "$file")"
  [[ "$expect" == "$got" ]] || die "plaintext hash mismatch for ${label}"
}

configure_r2_aws_cli() {
  require_env R2_ACCESS_KEY_ID
  require_env R2_SECRET_ACCESS_KEY
  export AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID"
  export AWS_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY"
  export AWS_DEFAULT_REGION="${R2_REGION:-auto}"
  if [[ -z "${R2_ENDPOINT:-}" ]]; then
    require_env R2_ACCOUNT_ID
    R2_ENDPOINT="https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com"
    export R2_ENDPOINT
  fi
  export R2_BUCKET="${R2_BUCKET:-$DEFAULT_BUCKET}"
  local cfg="${SEC1_AWS_CONFIG_FILE:-${TMPDIR:-/tmp}/sec1-aws-config}"
  umask 077
  cat >"$cfg" <<'EOF'
[default]
s3 =
    addressing_style = path
EOF
  chmod 600 "$cfg"
  export AWS_CONFIG_FILE="$cfg"
  export AWS_REQUEST_CHECKSUM_CALCULATION="${AWS_REQUEST_CHECKSUM_CALCULATION:-WHEN_REQUIRED}"
  export AWS_RESPONSE_CHECKSUM_VALIDATION="${AWS_RESPONSE_CHECKSUM_VALIDATION:-WHEN_REQUIRED}"
}

r2_cp() {
  local src="$1" key="$2"
  aws s3 cp "$src" "s3://${R2_BUCKET}/${key}" --endpoint-url "$R2_ENDPOINT" --only-show-errors \
    || die "upload failed for ${key}"
}

r2_sync_dir() {
  local src="$1" prefix="$2"
  aws s3 sync "$src" "s3://${R2_BUCKET}/${prefix}" --endpoint-url "$R2_ENDPOINT" --only-show-errors \
    || die "upload failed for ${prefix}"
}

r2_rm_prefix() {
  local prefix="$1"
  aws s3 rm "s3://${R2_BUCKET}/${prefix}" --recursive --endpoint-url "$R2_ENDPOINT" \
    || die "delete failed for ${prefix}"
}

today_phoenix() {
  TZ=America/Phoenix date +%F
}

month_stamp_phoenix() {
  TZ=America/Phoenix date +%Y-%m-01
}
