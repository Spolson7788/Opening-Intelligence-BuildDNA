#!/usr/bin/env python3
"""Restore a pg_dumpall --roles-only script without printing passwords.

The bootstrap role of the throwaway server (usually postgres) is left
unchanged so the CI connection keeps working. Every other CREATE ROLE,
ALTER ROLE, and GRANT is applied. Duplicate CREATE ROLE (SQLSTATE-style
"already exists") is the only error that is ignored, and only for that
statement. Any other error fails the process.

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


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write("usage: roles_restore.py ROLES.sql\n")
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
    applied = 0
    skipped_bootstrap = 0
    skipped_duplicate = 0
    for stmt in _split_statements(sql):
        role = _role_name(stmt)
        if role is not None and role == bootstrap and _is_create_or_alter(stmt):
            skipped_bootstrap += 1
            continue
        proc = _exec_statement(url, stmt)
        if proc.returncode != 0:
            if _is_duplicate_create(stmt, proc.stderr):
                skipped_duplicate += 1
                continue
            sys.stderr.write(redact(proc.stderr))
            _fail("roles restore statement failed")
        applied += 1
    if applied == 0:
        _fail("roles restore applied no statements")
    print(
        f"roles restore applied={applied} "
        f"skipped_bootstrap={skipped_bootstrap} skipped_duplicate={skipped_duplicate}",
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
