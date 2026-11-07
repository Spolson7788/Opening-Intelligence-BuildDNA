#!/usr/bin/env python3
"""Filter a pg_restore TOC for a throwaway Supabase Postgres 17.

Every object in a Supabase-managed schema is commented out, including
CHECK CONSTRAINT, triggers, policies, and publications that hang off
those schemas. Extensions that are already installed, or not available
on this server, are commented out too. Application schemas (public and
any schema that is not part of the hosted platform) stay in the list.
pg_restore is still run with --exit-on-error, so a failure in an entry
that remains is a hard failure.

Usage: restore_toc.py LISTFILE AVAILABLE.txt INSTALLED.txt
  AVAILABLE.txt and INSTALLED.txt are one extension name per line.
  LISTFILE is rewritten in place.
  restore_toc.py inventory LISTFILE AVAILABLE.txt INSTALLED.txt
  prints restored versus skipped description/schema pairs.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Schemas owned by the Supabase platform, not by the application.
# `public` and application schemas such as oi_private are kept.
# `extensions` is hosted too: the image already creates it, and
# CREATE SCHEMA extensions fails with "already exists" there.
MANAGED_SCHEMAS = frozenset(
    {
        "_analytics",
        "_realtime",
        "auth",
        "cron",
        "extensions",
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
_MANAGED_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_])(?:"
    + "|".join(sorted(MANAGED_SCHEMAS, key=len, reverse=True))
    + r")(?![A-Za-z0-9_])"
)

# Longest match first so "TABLE DATA" wins over "TABLE".
_DESCRIPTIONS = tuple(
    sorted(
        {
            "ACCESS METHOD",
            "ACL",
            "AGGREGATE",
            "ACL LANGUAGE",
            "BLOB",
            "BLOB COMMENTS",
            "BLOB METADATA",
            "CAST",
            "CHECK CONSTRAINT",
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
            "FOREIGN SERVER",
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
            "PUBLICATION TABLES IN SCHEMA",
            "ROW SECURITY",
            "RULE",
            "SCHEMA",
            "SEQUENCE",
            "SEQUENCE OWNED BY",
            "SECURITY LABEL",
            "SEQUENCE SET",
            "SERVER",
            "SHELL TYPE",
            "STATISTICS",
            "SUBSCRIPTION",
            "SUBSCRIPTION TABLE",
            "TABLE",
            "TABLE ATTACH",
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


def _publication_name(tag: str) -> str:
    return tag.split(" ", 1)[0] if tag else ""


def _skip(
    desc: str,
    namespace: str,
    tag: str,
    owner: str,
    available: set[str],
    installed: set[str],
) -> str | None:
    if namespace in MANAGED_SCHEMAS:
        return "schema"
    if desc == "SCHEMA" and tag in MANAGED_SCHEMAS:
        return "schema"
    # pg_dump sometimes emits CREATE SCHEMA public, which already exists.
    if desc == "SCHEMA" and tag == "public":
        return "public-schema"
    if desc == "EXTENSION":
        # The image already installed the hosted extensions. Creating them
        # again fails, and an extension that is not shipped cannot be created.
        if tag in installed or tag not in available:
            return "extension"
        return None
    if desc == "COMMENT":
        if tag.startswith("SCHEMA "):
            name = tag.split(" ", 1)[1]
            if name in MANAGED_SCHEMAS or name == "public":
                return "comment"
        if tag.startswith("EXTENSION "):
            name = tag.split(" ", 1)[1].strip()
            if name in installed or name not in available:
                return "extension"
        return None
    if desc == "EVENT TRIGGER":
        if owner.lower() in _RESERVED_OWNERS or tag in _SUPABASE_EVENT_TRIGGERS:
            return "event-trigger"
        return None
    if desc in {"PUBLICATION", "PUBLICATION TABLE", "PUBLICATION TABLES IN SCHEMA"}:
        name = _publication_name(tag)
        if name == "supabase_realtime" or name.startswith("supabase_"):
            return "publication"
        return None
    return None


def _mentions_managed(payload: str) -> bool:
    return _MANAGED_TOKEN.search(payload) is not None


def filter_lines(
    lines: list[str],
    available: set[str],
    installed: set[str] | None = None,
) -> tuple[list[str], dict[str, object]]:
    entry = re.compile(r"^(\d+);\s+(\d+)\s+(\d+)\s+(.*)$")
    installed = installed or set()
    out: list[str] = []
    kept = 0
    skipped = 0
    skipped_extensions: set[str] = set()
    restored: list[tuple[str, str]] = []
    omitted: list[tuple[str, str]] = []
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
        payload = match.group(4)
        parsed = _parse_entry(payload)
        if parsed is None:
            if _mentions_managed(payload):
                out.append(";" + text + "\n")
                skipped += 1
                omitted.append(("UNPARSED", "managed"))
                continue
            out.append(text + "\n")
            kept += 1
            restored.append(("UNPARSED", "-"))
            continue
        desc, namespace, tag, owner = parsed
        reason = _skip(desc, namespace, tag, owner, available, installed)
        if reason is None:
            out.append(text + "\n")
            kept += 1
            restored.append((desc, namespace))
            continue
        out.append(";" + text + "\n")
        skipped += 1
        omitted.append((desc, namespace if namespace else "-"))
        if reason == "extension" and desc == "EXTENSION" and tag:
            skipped_extensions.add(tag)
    return out, {
        "kept": kept,
        "skipped": skipped,
        "extensions": skipped_extensions,
        "restored": restored,
        "skipped_entries": omitted,
    }


def filter_text(
    text: str,
    available: set[str],
    installed: set[str] | None = None,
) -> tuple[str, dict[str, object]]:
    lines, info = filter_lines(text.splitlines(), available, installed)
    return "".join(lines), info


def format_inventory(info: dict[str, object]) -> str:
    def lines_for(key: str, title: str) -> list[str]:
        pairs = info.get(key, [])
        counts: dict[tuple[str, str], int] = {}
        for desc, namespace in pairs:  # type: ignore[union-attr]
            counts[(desc, namespace)] = counts.get((desc, namespace), 0) + 1
        body = [title]
        for (desc, namespace), count in sorted(counts.items()):
            body.append(f"  {desc} schema={namespace} count={count}")
        if len(body) == 1:
            body.append("  (none)")
        return body

    return "\n".join(lines_for("restored", "RESTORED") + [""] + lines_for("skipped_entries", "SKIPPED"))


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
            "21; 2606 11 CHECK CONSTRAINT realtime messages messages_payload_exclusive postgres",
            "22; 6237 12 PUBLICATION TABLES IN SCHEMA public supabase_realtime public postgres",
            "23; 2620 13 TRIGGER auth users on_auth_user_created postgres",
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
    need("extensions schema skipped", not kept("SCHEMA - extensions "))
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
    need("realtime check constraint skipped", not kept("CHECK CONSTRAINT realtime"))
    need("realtime publication membership skipped", not kept("PUBLICATION TABLES IN SCHEMA"))
    need("auth trigger skipped", not kept("TRIGGER auth users"))
    exts = info["extensions"]
    need("skipped extension recorded", exts == {"supabase_vault"})
    # A line we do not understand must stay active so the restore fails closed,
    # unless it names a hosted schema.
    unknown = "99; 1 2 NOT A REAL DESC public organizations postgres\n"
    unknown_out, _ = filter_text(unknown, set())
    need("unrecognized public TOC entry is kept", unknown_out.startswith("99;"))
    hosted = "98; 1 2 NOT A REAL DESC realtime messages postgres\n"
    hosted_out, _ = filter_text(hosted, set())
    need("unrecognized hosted TOC entry is skipped", hosted_out.startswith(";98;"))
    installed_out, installed_info = filter_text(
        "2; 3079 16530 EXTENSION - pgcrypto \n",
        {"pgcrypto"},
        {"pgcrypto"},
    )
    need("already installed extension is skipped", installed_out.startswith(";"))
    need(
        "installed extension is recorded",
        installed_info["extensions"] == {"pgcrypto"},
    )
    return 1 if failures else 0


def _read_names(path: Path) -> set[str]:
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "self-test":
        return self_test()
    inventory = False
    args = argv[1:]
    if args and args[0] == "inventory":
        inventory = True
        args = args[1:]
    if len(args) != 3:
        sys.stderr.write(
            "usage: restore_toc.py [inventory] LISTFILE AVAILABLE.txt INSTALLED.txt\n"
        )
        return 2
    list_path = Path(args[0])
    try:
        original = list_path.read_text(encoding="utf-8")
        available = _read_names(Path(args[1]))
        installed = _read_names(Path(args[2]))
    except OSError:
        sys.stderr.write("ERROR: could not read restore TOC\n")
        return 1
    filtered, info = filter_text(original, available, installed)
    if inventory:
        sys.stdout.write(format_inventory(info) + "\n")
        return 0
    list_path.write_text(filtered, encoding="utf-8")
    names = ",".join(sorted(info["extensions"]))  # type: ignore[arg-type]
    print(
        f"toc filter kept={info['kept']} skipped={info['skipped']} "
        f"skipped_extensions={names}",
        flush=True,
    )
    print(format_inventory(info), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
