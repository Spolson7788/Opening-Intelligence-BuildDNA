#!/usr/bin/env python3
"""Filter a pg_restore TOC for a plain Postgres 17.

Supabase-managed schemas (auth, storage, and the rest of the hosted
platform) are commented out. Extensions that are not installed on this
server are commented out. public data, constraints, and app schemas stay
in the list. pg_restore is still run with --exit-on-error, so a failure
in an entry that remains is a hard failure.

Usage: restore_toc.py LISTFILE EXTENSIONS.txt
  EXTENSIONS.txt is one available extension name per line.
  LISTFILE is rewritten in place.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Schemas owned by the Supabase platform, not by the application.
# `extensions` is kept so available extensions can be created there.
# `public` and application schemas such as oi_private are kept.
MANAGED_SCHEMAS = frozenset(
    {
        "_analytics",
        "_realtime",
        "auth",
        "cron",
        "graphql",
        "graphql_public",
        "net",
        "pgbouncer",
        "pgmq",
        "pgsodium",
        "pgsodium_masks",
        "realtime",
        "storage",
        "supabase_functions",
        "supabase_internal",
        "supabase_migrations",
        "vault",
    }
)

# Longest match first so "TABLE DATA" wins over "TABLE".
_DESCRIPTIONS = tuple(
    sorted(
        {
            "ACCESS METHOD",
            "ACL",
            "AGGREGATE",
            "CAST",
            "COLLATION",
            "COMMENT",
            "CONSTRAINT",
            "CONVERSION",
            "DEFAULT",
            "DEFAULT ACL",
            "DOMAIN",
            "EVENT TRIGGER",
            "EXTENSION",
            "FK CONSTRAINT",
            "FOREIGN DATA WRAPPER",
            "FOREIGN TABLE",
            "FUNCTION",
            "INDEX",
            "INDEX ATTACH",
            "LARGE OBJECT",
            "MATERIALIZED VIEW",
            "MATERIALIZED VIEW DATA",
            "OPERATOR",
            "OPERATOR CLASS",
            "OPERATOR FAMILY",
            "POLICY",
            "PROCEDURE",
            "PROCEDURAL LANGUAGE",
            "PUBLICATION",
            "PUBLICATION TABLE",
            "ROW SECURITY",
            "RULE",
            "SCHEMA",
            "SEQUENCE",
            "SEQUENCE OWNED BY",
            "SEQUENCE SET",
            "SERVER",
            "SHELL TYPE",
            "STATISTICS",
            "SUBSCRIPTION",
            "TABLE",
            "TABLE DATA",
            "TEXT SEARCH CONFIGURATION",
            "TEXT SEARCH DICTIONARY",
            "TEXT SEARCH PARSER",
            "TEXT SEARCH TEMPLATE",
            "TRANSFORM",
            "TRIGGER",
            "TYPE",
            "USER MAPPING",
            "VIEW",
        },
        key=len,
        reverse=True,
    )
)

_RESERVED_OWNERS = frozenset(
    {
        "anon",
        "authenticated",
        "authenticator",
        "dashboard_user",
        "pgbouncer",
        "service_role",
        "supabase_admin",
        "supabase_auth_admin",
        "supabase_etl_admin",
        "supabase_functions_admin",
        "supabase_read_only_user",
        "supabase_realtime_admin",
        "supabase_replication_admin",
        "supabase_storage_admin",
    }
)

_SUPABASE_EVENT_TRIGGERS = frozenset(
    {
        "grant_pg_cron_access",
        "grant_pg_graphql_access",
        "grant_pg_net_access",
        "issue_graphql_placeholder",
        "issue_pg_cron_access",
        "issue_pg_graphql_access",
        "issue_pg_net_access",
        "pgrst_ddl_watch",
        "pgrst_drop_watch",
    }
)


def _parse_entry(payload: str) -> tuple[str, str, str, str] | None:
    """Return (description, namespace, tag, owner) or None if unrecognized."""
    for desc in _DESCRIPTIONS:
        if payload == desc or payload.startswith(desc + " "):
            rest = payload[len(desc) :]
            if rest.startswith(" "):
                rest = rest[1:]
            if rest.endswith(" "):
                owner = ""
                core = rest.rstrip()
            elif " " in rest:
                core, owner = rest.rsplit(" ", 1)
            else:
                owner = ""
                core = rest
            namespace, sep, tag = core.partition(" ")
            if not sep:
                tag = ""
            return desc, namespace, tag, owner
    return None


def _skip(desc: str, namespace: str, tag: str, owner: str, available: set[str]) -> str | None:
    if namespace in MANAGED_SCHEMAS:
        return "schema"
    if desc == "SCHEMA" and tag in MANAGED_SCHEMAS:
        return "schema"
    # pg_dump sometimes emits CREATE SCHEMA public, which already exists.
    if desc == "SCHEMA" and tag == "public":
        return "public-schema"
    if desc == "EXTENSION":
        if tag not in available:
            return "extension"
        return None
    if desc == "COMMENT":
        if tag.startswith("SCHEMA "):
            name = tag.split(" ", 1)[1]
            if name in MANAGED_SCHEMAS or name == "public":
                return "comment"
        if tag.startswith("EXTENSION "):
            name = tag.split(" ", 1)[1].strip()
            if name not in available:
                return "extension"
        return None
    if desc == "EVENT TRIGGER":
        if owner.lower() in _RESERVED_OWNERS or tag in _SUPABASE_EVENT_TRIGGERS:
            return "event-trigger"
        return None
    if desc in {"PUBLICATION", "PUBLICATION TABLE"}:
        name = tag.split(" ", 1)[0] if tag else ""
        if name == "supabase_realtime" or name.startswith("supabase_"):
            return "publication"
        return None
    return None


def filter_lines(lines: list[str], available: set[str]) -> tuple[list[str], dict[str, object]]:
    entry = re.compile(r"^(\d+);\s+(\d+)\s+(\d+)\s+(.*)$")
    out: list[str] = []
    kept = 0
    skipped = 0
    skipped_extensions: set[str] = set()
    for raw in lines:
        text = raw[:-1] if raw.endswith("\n") else raw
        # Header comments and blank lines stay comments. A trailing space on a
        # TOC entry means the owner field is empty, so it must be preserved.
        if not text.strip() or text.lstrip().startswith(";"):
            out.append(text + "\n")
            continue
        match = entry.match(text)
        if match is None:
            out.append(text + "\n")
            kept += 1
            continue
        parsed = _parse_entry(match.group(4))
        if parsed is None:
            out.append(text + "\n")
            kept += 1
            continue
        desc, namespace, tag, owner = parsed
        reason = _skip(desc, namespace, tag, owner, available)
        if reason is None:
            out.append(text + "\n")
            kept += 1
            continue
        out.append(";" + text + "\n")
        skipped += 1
        if reason == "extension" and desc == "EXTENSION" and tag:
            skipped_extensions.add(tag)
    return out, {"kept": kept, "skipped": skipped, "extensions": skipped_extensions}


def filter_text(text: str, available: set[str]) -> tuple[str, dict[str, object]]:
    lines, info = filter_lines(text.splitlines(), available)
    return "".join(lines), info


def self_test() -> int:
    sample = "\n".join(
        [
            ";",
            "; Selected TOC Entries:",
            "7; 2615 16527 SCHEMA - auth postgres",
            "9; 2615 16529 SCHEMA - extensions postgres",
            "1; 2615 2200 SCHEMA - public postgres",
            "2; 3079 16530 EXTENSION - pgcrypto ",
            "3; 3079 16531 EXTENSION - supabase_vault ",
            "4; 0 0 COMMENT - EXTENSION pgcrypto ",
            "5; 0 0 COMMENT - EXTENSION supabase_vault ",
            "6; 0 0 COMMENT - SCHEMA auth postgres",
            "8; 0 0 COMMENT public TABLE organizations postgres",
            "10; 1259 1 TABLE auth users postgres",
            "11; 1259 2 TABLE public organizations postgres",
            "12; 0 2 TABLE DATA public organizations postgres",
            "13; 1255 3 FUNCTION auth uid() postgres",
            "14; 2606 4 FK CONSTRAINT public users users_organization_id_fkey postgres",
            "15; 3466 5 EVENT TRIGGER - pgrst_ddl_watch supabase_admin",
            "16; 3466 6 EVENT TRIGGER - app_evt postgres",
            "17; 6104 7 PUBLICATION - supabase_realtime postgres",
            "18; 6104 8 PUBLICATION - app_pub postgres",
            "19; 1259 9 TABLE storage objects postgres",
            "20; 1259 10 TABLE oi_private secrets postgres",
        ]
    )
    filtered, info = filter_text(sample, {"pgcrypto", "uuid-ossp"})
    failures = 0

    def need(label: str, ok: bool) -> None:
        nonlocal failures
        if ok:
            print(f"PASS: {label}")
        else:
            failures += 1
            print(f"FAIL: {label}", file=sys.stderr)

    def kept(token: str) -> bool:
        for line in filtered.splitlines():
            if token in line:
                return not line.startswith(";")
        return False

    need("auth schema skipped", not kept("SCHEMA - auth "))
    need("extensions schema kept", kept("SCHEMA - extensions "))
    need("public schema skipped", not kept("SCHEMA - public "))
    need("pgcrypto kept", kept("EXTENSION - pgcrypto"))
    need("supabase_vault skipped", not kept("EXTENSION - supabase_vault"))
    need("pgcrypto comment kept", kept("COMMENT - EXTENSION pgcrypto"))
    need("vault comment skipped", not kept("COMMENT - EXTENSION supabase_vault"))
    need("auth comment skipped", not kept("COMMENT - SCHEMA auth"))
    need("public comment kept", kept("COMMENT public TABLE organizations"))
    need("auth table skipped", not kept("TABLE auth users"))
    need("public table kept", kept("TABLE public organizations"))
    need("public table data kept", kept("TABLE DATA public organizations"))
    need("auth function skipped", not kept("FUNCTION auth uid()"))
    need("public fk kept", kept("FK CONSTRAINT public users"))
    need("supabase event trigger skipped", not kept("EVENT TRIGGER - pgrst_ddl_watch"))
    need("app event trigger kept", kept("EVENT TRIGGER - app_evt"))
    need("supabase publication skipped", not kept("PUBLICATION - supabase_realtime"))
    need("app publication kept", kept("PUBLICATION - app_pub"))
    need("storage table skipped", not kept("TABLE storage objects"))
    need("app schema kept", kept("TABLE oi_private secrets"))
    exts = info["extensions"]
    need("skipped extension recorded", exts == {"supabase_vault"})
    # A line we do not understand must stay active so the restore fails closed.
    unknown = "99; 1 2 NOT A REAL DESC public organizations postgres\n"
    unknown_out, _ = filter_text(unknown, set())
    need("unrecognized TOC entry is kept", unknown_out.startswith("99;"))
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "self-test":
        return self_test()
    if len(argv) != 3:
        sys.stderr.write("usage: restore_toc.py LISTFILE EXTENSIONS.txt\n")
        return 2
    list_path = Path(argv[1])
    ext_path = Path(argv[2])
    try:
        original = list_path.read_text(encoding="utf-8")
        available = {
            line.strip()
            for line in ext_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
    except OSError:
        sys.stderr.write("ERROR: could not read restore TOC\n")
        return 1
    filtered, info = filter_text(original, available)
    list_path.write_text(filtered, encoding="utf-8")
    names = ",".join(sorted(info["extensions"]))  # type: ignore[arg-type]
    print(
        f"toc filter kept={info['kept']} skipped={info['skipped']} "
        f"skipped_extensions={names}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
