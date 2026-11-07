#!/usr/bin/env bash
# Install PostgreSQL 17 client tools (psql, pg_dump, pg_restore, pg_dumpall).
# ubuntu-latest's postgresql-client metapackage is newer than 17. The R2
# snapshots are pg_dump 17 archives, so the restore client must be 17 too.
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  exec sudo -n bash "$0" "$@"
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg postgresql-common
if [[ ! -x /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh ]]; then
  echo "ERROR: PGDG apt setup script is missing" >&2
  exit 1
fi
/usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y
apt-get update -qq
apt-get install -y -qq postgresql-client-17

bin="/usr/lib/postgresql/17/bin"
if [[ ! -d "$bin" ]]; then
  echo "ERROR: PostgreSQL 17 client directory is missing" >&2
  exit 1
fi
for tool in psql pg_dump pg_restore pg_dumpall pg_isready; do
  if [[ ! -x "${bin}/${tool}" ]]; then
    echo "ERROR: missing ${bin}/${tool}" >&2
    exit 1
  fi
  if ! "${bin}/${tool}" --version | grep -q '(PostgreSQL) 17\.'; then
    echo "ERROR: ${tool} is not PostgreSQL 17" >&2
    "${bin}/${tool}" --version >&2 || true
    exit 1
  fi
done
echo "PostgreSQL 17 client tools ready in ${bin}"
