# SEC-1 off-site backup scripts

Backs up **oi-production only** (`bekaxmatcvxqpjixwsqn`) to Cloudflare R2 bucket `oi-production-backups`.

The database dump and the roles dump are encrypted with AES-256-GCM before upload. Storage objects are copied as-is and covered by the SHA-256 manifest. Any dump, download, upload, checksum, or restore error fails the job.

## GitHub Actions secrets (names only — paste values yourself)

| Secret name | Purpose |
|---|---|
| `OI_PROD_DATABASE_URL` | Postgres URI for project `bekaxmatcvxqpjixwsqn` only |
| `OI_PROD_SUPABASE_URL` | `https://bekaxmatcvxqpjixwsqn.supabase.co` |
| `OI_PROD_SUPABASE_SERVICE_ROLE_KEY` | Service role for **read** of Storage bucket `oi-production-media` |
| `BACKUP_ENCRYPTION_KEY` | Passphrase for AES-256-GCM. Read from the environment only; never put it on a command line |
| `R2_ACCOUNT_ID` | Cloudflare account id |
| `R2_ACCESS_KEY_ID` | R2 API token access key id |
| `R2_SECRET_ACCESS_KEY` | R2 API token secret |
| `R2_BUCKET` | Set to `oi-production-backups` |
| `RESEND_API_KEY` | For failure emails |
| `BACKUP_ALERT_TO` | Stephan’s alert email |
| `BACKUP_ALERT_FROM` | Optional; defaults to `noreply@mail.oipoweredbybuilddna.com` |

Never commit values. Never point these at other Supabase projects. Do not set `SEC1_OFFLINE_TEST` on the production workflows; that flag only accepts a loopback database and a loopback storage URL.

## What is in a snapshot

`snapshots/YYYY-MM-DD/` (America/Phoenix) and, on the 1st or when forced, `monthly/YYYY-MM-01/`:

- `db/oi-production.dump.enc` — custom-format `pg_dump` (`--no-owner --no-acl`), AES-256-GCM
- `db/oi-production.roles.sql.enc` — `pg_dumpall --roles-only` (roles and membership GRANTs, including password hashes), AES-256-GCM
- `db/*.plaintext.sha256` — hash of the plaintext, so a decrypt can be checked
- `storage/` — objects from bucket `oi-production-media`, every nested folder and every list page
- `manifest.sha256` — `sha256sum` of every file above
- `run.json` — counts and hashes; not itself listed in the manifest

Retention keeps 30 daily prefixes and 12 monthly prefixes. A failed delete fails the job.

## Decrypt

Download one snapshot, then decrypt with the passphrase in the environment (not in argv):

```bash
export BACKUP_ENCRYPTION_KEY
python3 scripts/offsite-backup/crypto.py decrypt \
  snap/db/oi-production.dump.enc oi-production.dump
python3 scripts/offsite-backup/crypto.py decrypt \
  snap/db/oi-production.roles.sql.enc oi-production.roles.sql
sha256sum oi-production.dump oi-production.roles.sql
# First field of snap/db/*.plaintext.sha256 must match.
```

A wrong key, a truncated file, or any modified ciphertext is rejected and no plaintext file is written. The previous unauthenticated AES-CBC snapshots cannot be decrypted with this tool.

Format details and the restore host rules are in `docs/ops/SEC1-OFFSITE-BACKUP.md`.

## Restore

Use `restore-test.sh`. It refuses every database host except `localhost`, `127.0.0.1`, `::1`, and a local unix socket. `supabase.co` and any other host, including a `?host=` or `?hostaddr=` override, are refused before `psql` runs.

```bash
export BACKUP_ENCRYPTION_KEY
export SEC1_TARGET_DATABASE_URL='postgresql://postgres@127.0.0.1:5432/oi_restore_test'
export SEC1_MODE=r2
export SEC1_SNAPSHOT_PREFIX=snapshots/YYYY-MM-DD   # optional; default is the newest daily snapshot
bash scripts/offsite-backup/restore-test.sh
```

The throwaway server's own bootstrap role (usually `postgres`) is left unchanged so the local connection keeps working. Every other role, membership GRANT, and password hash is restored. The roles SQL is never printed.

## Workflows

- `oi-production-offsite-backup.yml` — `workflow_dispatch` only (cron commented out).
- `oi-production-backup-restore-test.yml` — `workflow_dispatch`; modes `synthetic` or `r2`.
- `oi-offsite-backup-offline-test.yml` — push to `sec1/offsite-backup` and `workflow_dispatch`. No secrets and no cron. Runs `test-offline.sh`.

## Offline test

Requires local Postgres (`postgresql://postgres:postgres@127.0.0.1:5432/postgres`) and MinIO on `127.0.0.1:9000` (or `MINIO_BIN` so the script can start it). No production network and no real secrets.

```bash
bash scripts/offsite-backup/test-offline.sh
```
