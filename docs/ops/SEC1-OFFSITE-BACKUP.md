# SEC-1 ops notes

Branch `sec1/offsite-backup` from production commit `662c035`.

- Do **not** enable the nightly cron until approval gate A6. The schedule block in `oi-production-offsite-backup.yml` stays commented out, and both production workflows stay `workflow_dispatch` only.
- Do **not** run backup against any project other than `bekaxmatcvxqpjixwsqn`.
- Do **not** set `SEC1_OFFLINE_TEST` on a production workflow. That switch exists for `scripts/offsite-backup/test-offline.sh` and refuses any database or storage URL that is not loopback.
- Restore tests use a throwaway Postgres on `localhost`, `127.0.0.1`, or `::1`. `supabase.co` and every other host are refused before a connection is attempted. A `?host=` or `?hostaddr=` override is checked too, because libpq uses those instead of the URL host.
- See `scripts/offsite-backup/README.md` for secret names.

## What a run does

1. `pg_dump --format=custom --no-owner --no-acl` of the database.
2. `pg_dumpall --roles-only` for roles and membership `GRANT`s. The file contains password hashes. It is mode `0600`, encrypted before it leaves the runner, and never printed. stderr is redacted before it is logged.
3. List Storage bucket `oi-production-media` one folder at a time, following every subfolder and every `limit`/`offset` page. Download each file. The downloaded set must equal the listed set.
4. SHA-256 manifest. The number of manifest lines must equal the files on disk ( `run.json` is written after the manifest and is the only extra file allowed).
5. Encrypt the database dump and the roles dump with AES-256-GCM. Upload to R2. The remote object count must equal the local file count. The same check is repeated for the monthly copy.
6. Keep 30 newest `snapshots/YYYY-MM-DD/` prefixes and 12 newest `monthly/YYYY-MM-DD/` prefixes. A failed list or delete fails the job.

Object ACLs and ownership stay out of the data dump (`--no-acl --no-owner`) so a throwaway restore does not depend on Supabase owner roles. Membership GRANTs are in the roles dump.

## Encryption

`openssl enc` cannot authenticate AES-GCM, and `age --passphrase` prompts on a terminal. Snapshots use AES-256-GCM with a key derived from `BACKUP_ENCRYPTION_KEY`.

- KDF: PBKDF2-HMAC-SHA256, 200000 iterations, 16-byte random salt, 32-byte key
- Cipher: AES-256-GCM, 12-byte random nonce per chunk, 4 MiB plaintext chunks
- Associated data: `OISEC1GCM1` plus the chunk index, so reordered chunks fail
- Magic header: `OISEC1GCM1` version 1. Layout is documented in `scripts/offsite-backup/crypto.py`

The passphrase is read only from the `BACKUP_ENCRYPTION_KEY` environment variable.

### Decrypt

```bash
export BACKUP_ENCRYPTION_KEY   # GitHub secret value; do not pass it as an argument
python3 scripts/offsite-backup/crypto.py decrypt \
  snap/db/oi-production.dump.enc \
  oi-production.dump
python3 scripts/offsite-backup/crypto.py decrypt \
  snap/db/oi-production.roles.sql.enc \
  oi-production.roles.sql
sha256sum oi-production.dump
sha256sum oi-production.roles.sql
```

Compare each hash to the first field of `snap/db/oi-production.dump.plaintext.sha256` and `snap/db/oi-production.roles.sql.plaintext.sha256`. Also run `sha256sum -c manifest.sha256` from the snapshot directory before trusting the files.

A wrong key or any modified ciphertext raises an authentication error and the plaintext file is not written. Files produced by the old unauthenticated AES-CBC `openssl enc` command are refused.

### Restore

Supported path (host guard included):

```bash
export BACKUP_ENCRYPTION_KEY
export SEC1_MODE=r2
export SEC1_TARGET_DATABASE_URL='postgresql://postgres@127.0.0.1:5432/oi_restore_test'
export SEC1_SNAPSHOT_PREFIX='snapshots/YYYY-MM-DD'   # optional
bash scripts/offsite-backup/restore-test.sh
```

The script recreates `schema public`, restores roles, then `pg_restore --exit-on-error`. It does not change the throwaway server's bootstrap role (usually `postgres`), so the local password keeps working. Other roles are created with their password hashes.

The throwaway server must already provide any extensions the dump creates. A missing extension fails the restore instead of being ignored.

## Offline CI

`oi-offsite-backup-offline-test.yml` runs on pushes to `sec1/offsite-backup` only. It uses a Postgres service container and MinIO, with a local mock of the Storage list/download API. It does not use GitHub secrets and it has no schedule.

The harness covers a full backup, encrypt, upload, download, decrypt, manifest check, restore, and row-count check, plus tampered ciphertext, a non-local restore target, an injected download error, and retention of 30 daily / 12 monthly prefixes.
