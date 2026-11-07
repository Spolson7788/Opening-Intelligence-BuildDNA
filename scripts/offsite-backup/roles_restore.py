#!/usr/bin/env python3
"""Restore a pg_dumpall --roles-only script without printing passwords.

The bootstrap role of the throwaway server (usually postgres) is left
unchanged so the CI connection keeps working. Supabase-reserved roles are
pre-created NOLOGIN with safe defaults, and CREATE/ALTER for those roles
are not applied, so a hosted superuser such as supabase_admin is not
recreated. GRANTED BY clauses are removed because a local superuser cannot
grant as supabase_admin. App roles (for example oi_pr2_api) and their
membership GRANTs are applied. Duplicate CREATE ROLE ("already exists") is
the only error that is ignored, and only for that statement. Any other
error fails the process.

Passwords stay inside the SQL file. psql stderr is redacted before it is
shown. Statements are passed via a mode-0600 temp file, not argv.

Usage: roles_restore.py ROLES.sql
  SEC1_TARGET_DATABASE_URL must already be a local throwaway database.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from guards import GuardError, assert_local_postgres  # noqa: E402
from redact import redact  # noqa: E402

ROLE_STMT = re.compile(
    r"""^\s*(CREATE|ALTER)\s+ROLE\s+(?:"([^"]+)"|([A-Za-z_][\w$]*))""",
    re.IGNORECASE,
)
_GRANTED_BY = re.compile(
    r"""\s+GRANTED\s+BY\s+(?:"[^"]+"|[A-Za-z_][\w$]*)""",
    re.IGNORECASE,
)
# Hosted Supabase roles. A plain Postgres 17 cannot apply their SUPERUSER,
# REPLICATION, or GRANTED BY attributes. App roles are not in this set.
SUPABASE_RESERVED_ROLES = frozenset(
    {
        "anon",
        "authenticated",
        "authenticator",
        "dashboard_user",
        "pgbouncer",
        "pgsodium_keyholder",
        "pgsodium_keyiduser",
        "pgsodium_keymaker",
        "service_role",
        "supabase_admin",
        "supabase_auth_admin",
        "supabase_etl_admin",
        "supabase_functions_admin",
        "supabase_privileged_role",
        "supabase_read_only_user",
        "supabase_realtime_admin",
        "supabase_replication_admin",
        "supabase_storage_admin",
        "cli_login_postgres",
    }
)
_ROLE_IDENT = re.compile(r"[a-z_][a-z0-9_]*\Z")


def _fail(message: str) -> None:
    sys.stderr.write(f"ERROR: {message}\n")
    raise SystemExit(1)


def _split_statements(sql: str) -> list[str]:
    cleaned: list[str] = []
    for line in sql.splitlines(keepends=True):
        # pg_dumpall emits \restrict / \unrestrict. Those are psql meta
        # commands, not SQL, and they are not needed when each statement
        # is executed on its own.
        if line.lstrip().startswith("\\"):
            continue
        cleaned.append(line)
    text = "".join(cleaned)
    statements: list[str] = []
    buf: list[str] = []
    in_single = False
    i = 0
    while i < len(text):
        ch = text[i]
        if in_single:
            buf.append(ch)
            if ch == "'":
                if i + 1 < len(text) and text[i + 1] == "'":
                    buf.append(text[i + 1])
                    i += 2
                    continue
                in_single = False
            i += 1
            continue
        if ch == "'":
            in_single = True
            buf.append(ch)
            i += 1
            continue
        if ch == "-" and i + 1 < len(text) and text[i + 1] == "-":
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        if ch == ";":
            stmt = "".join(buf).strip()
            buf = []
            if stmt:
                statements.append(stmt)
            i += 1
            continue
        buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        statements.append(tail)
    return statements


def _role_name(stmt: str) -> str | None:
    match = ROLE_STMT.match(stmt)
    if not match:
        return None
    quoted = match.group(2)
    if quoted is not None:
        return quoted
    return match.group(3).lower()


def _is_create_or_alter(stmt: str) -> bool:
    return re.match(r"^\s*(CREATE|ALTER)\s+ROLE\b", stmt, re.IGNORECASE) is not None


def _is_duplicate_create(stmt: str, stderr: str) -> bool:
    if not re.match(r"^\s*CREATE\s+ROLE\b", stmt, re.IGNORECASE):
        return False
    lowered = stderr.lower()
    return "already exists" in lowered and "role" in lowered


def _is_reserved_role(name: str) -> bool:
    lowered = name.lower()
    return lowered in SUPABASE_RESERVED_ROLES or lowered.startswith("pg_")


def strip_granted_by(stmt: str) -> tuple[str, bool]:
    """Remove GRANTED BY outside string literals. Returns (sql, changed)."""
    out: list[str] = []
    i = 0
    in_single = False
    changed = False
    while i < len(stmt):
        ch = stmt[i]
        if in_single:
            out.append(ch)
            if ch == "'":
                if i + 1 < len(stmt) and stmt[i + 1] == "'":
                    out.append(stmt[i + 1])
                    i += 2
                    continue
                in_single = False
            i += 1
            continue
        if ch == "'":
            in_single = True
            out.append(ch)
            i += 1
            continue
        match = _GRANTED_BY.match(stmt, i)
        if match:
            changed = True
            i = match.end()
            continue
        out.append(ch)
        i += 1
    return "".join(out).strip(), changed


def prepare_statement(stmt: str, bootstrap: str) -> tuple[str | None, str]:
    """Return SQL to run, or None when the statement is intentionally skipped."""
    stripped, changed = strip_granted_by(stmt)
    role = _role_name(stripped)
    if role is not None and _is_create_or_alter(stripped):
        if role == bootstrap:
            return None, "bootstrap"
        if _is_reserved_role(role):
            return None, "reserved"
    if not stripped:
        return None, "empty"
    if changed:
        return stripped, "granted-by"
    return stripped, "apply"


def _precreate_reserved_roles(url: str) -> int:
    parts: list[str] = []
    for role in sorted(SUPABASE_RESERVED_ROLES):
        if _ROLE_IDENT.fullmatch(role) is None:
            _fail("refusing to pre-create an unsafe role name")
        parts.append(
            "IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = "
            f"'{role}') THEN "
            f"CREATE ROLE {role} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOREPLICATION NOBYPASSRLS INHERIT; "
            "END IF;"
        )
    sql = "DO $sec1$\nBEGIN\n" + "\n".join(parts) + "\nEND\n$sec1$;\n"
    proc = _exec_statement(url, sql)
    if proc.returncode != 0:
        sys.stderr.write(redact(proc.stderr))
        _fail("could not pre-create Supabase reserved roles")
    return len(SUPABASE_RESERVED_ROLES)


def _current_user(url: str) -> str:
    proc = subprocess.run(
        ["psql", "--no-password", "-X", "-q", "-tAc", "select current_user", "--dbname", url],
        capture_output=True,
        text=True,
        errors="replace",
    )
    if proc.returncode != 0:
        sys.stderr.write(redact(proc.stderr))
        _fail("could not read current_user on the restore target")
    user = proc.stdout.strip()
    if not user or any(ch.isspace() for ch in user):
        _fail("restore target returned an empty current_user")
    return user


def _exec_statement(url: str, stmt: str) -> subprocess.CompletedProcess[str]:
    fd, path = tempfile.mkstemp(prefix="sec1-role-", suffix=".sql")
    try:
        os.write(fd, stmt.encode("utf-8") + b"\n")
        os.close(fd)
        os.chmod(path, 0o600)
        return subprocess.run(
            [
                "psql",
                "--no-password",
                "-X",
                "-q",
                "-v",
                "ON_ERROR_STOP=1",
                "-f",
                path,
                "--dbname",
                url,
            ],
            capture_output=True,
            text=True,
            errors="replace",
        )
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def self_test() -> int:
    failures = 0

    def check(name: str, ok: bool) -> None:
        nonlocal failures
        if ok:
            print(f"PASS: {name}")
        else:
            failures += 1
            print(f"FAIL: {name}", file=sys.stderr)

    stripped, changed = strip_granted_by(
        'GRANT oi_pr2_api TO postgres WITH INHERIT TRUE GRANTED BY supabase_admin'
    )
    check(
        "GRANTED BY supabase_admin is removed",
        changed and stripped == "GRANT oi_pr2_api TO postgres WITH INHERIT TRUE",
    )
    quoted, quoted_changed = strip_granted_by(
        'GRANT anon TO authenticator GRANTED BY "supabase_admin"'
    )
    check(
        "quoted GRANTED BY is removed",
        quoted_changed and quoted == "GRANT anon TO authenticator",
    )
    literal = "ALTER ROLE oi_pr2_api WITH PASSWORD 'GRANTED BY supabase_admin'"
    literal_out, literal_changed = strip_granted_by(literal)
    check("GRANTED BY inside a password literal is kept", not literal_changed and literal_out == literal)
    app_sql, app_reason = prepare_statement(
        "ALTER ROLE oi_pr2_api WITH LOGIN PASSWORD 'secret'",
        "postgres",
    )
    check("app role alter is kept", app_reason == "apply" and app_sql is not None and "oi_pr2_api" in app_sql)
    reserved_sql, reserved_reason = prepare_statement(
        "ALTER ROLE supabase_admin WITH SUPERUSER LOGIN PASSWORD 'secret'",
        "postgres",
    )
    check("reserved role alter is skipped", reserved_sql is None and reserved_reason == "reserved")
    boot_sql, boot_reason = prepare_statement(
        "ALTER ROLE postgres WITH SUPERUSER PASSWORD 'secret'",
        "postgres",
    )
    check("bootstrap role alter is skipped", boot_sql is None and boot_reason == "bootstrap")
    grant_sql, grant_reason = prepare_statement(
        "GRANT oi_pr2_api TO postgres GRANTED BY supabase_admin",
        "postgres",
    )
    check(
        "app membership grant survives without GRANTED BY",
        grant_reason == "granted-by" and grant_sql == "GRANT oi_pr2_api TO postgres",
    )
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "self-test":
        return self_test()
    if len(argv) != 2:
        sys.stderr.write("usage: roles_restore.py ROLES.sql|self-test\n")
        return 2
    url = os.environ.get("SEC1_TARGET_DATABASE_URL", "")
    try:
        assert_local_postgres(url)
    except GuardError as exc:
        _fail(str(exc))
    sql_path = argv[1]
    try:
        sql = open(sql_path, "r", encoding="utf-8").read()
    except OSError:
        _fail("could not read roles dump")
    if not sql.strip():
        _fail("roles dump is empty")
    bootstrap = _current_user(url)
    _precreate_reserved_roles(url)
    applied = 0
    skipped_bootstrap = 0
    skipped_reserved = 0
    skipped_duplicate = 0
    stripped_grants = 0
    for stmt in _split_statements(sql):
        prepared, reason = prepare_statement(stmt, bootstrap)
        if prepared is None:
            if reason == "bootstrap":
                skipped_bootstrap += 1
            elif reason == "reserved":
                skipped_reserved += 1
            continue
        if reason == "granted-by":
            stripped_grants += 1
        proc = _exec_statement(url, prepared)
        if proc.returncode != 0:
            if _is_duplicate_create(prepared, proc.stderr):
                skipped_duplicate += 1
                continue
            sys.stderr.write(redact(proc.stderr))
            _fail("roles restore statement failed")
        applied += 1
    if applied == 0:
        _fail("roles restore applied no statements")
    print(
        f"roles restore applied={applied} "
        f"skipped_bootstrap={skipped_bootstrap} skipped_reserved={skipped_reserved} "
        f"skipped_duplicate={skipped_duplicate} stripped_granted_by={stripped_grants}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except SystemExit:
        raise
    except Exception as exc:
        sys.stderr.write(f"ERROR: roles restore failed: {type(exc).__name__}\n")
        sys.exit(1)
