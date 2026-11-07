#!/usr/bin/env python3
"""Host guards for SEC-1 backup and restore.

Restore targets and offline-test sources may only be a local throwaway
Postgres: localhost, 127.0.0.1, ::1, a local unix socket, or an HTTP
service on those hosts. supabase.co and every other host are refused.

Error text never includes the URL, userinfo, or password.
"""

from __future__ import annotations

import os
import re
import sys
from urllib.parse import parse_qs, unquote, urlparse

LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_SAFE_HOST = re.compile(r"[A-Za-z0-9._:-]{1,200}\Z")
_SAFE_PATH = re.compile(r"/[A-Za-z0-9._/-]{0,200}\Z")


class GuardError(Exception):
    pass


def _label(host: str) -> str:
    if _SAFE_HOST.fullmatch(host) or _SAFE_PATH.fullmatch(host):
        return host
    return "unrecognized-host"


def _reject_supabase(url: str, what: str) -> None:
    if "supabase.co" in url.lower():
        raise GuardError(f"refusing {what}: supabase.co is not a local throwaway")


def _basic(url: str, what: str) -> str:
    if not isinstance(url, str) or not url or len(url) > 4096:
        raise GuardError(f"refusing {what}: missing or oversized URL")
    if any(ch.isspace() for ch in url):
        raise GuardError(f"refusing {what}: whitespace in URL")
    _reject_supabase(url, what)
    return url


def _normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def _is_local_postgres_target(token: str) -> bool:
    if token == "":
        return True
    host = _normalize_host(token)
    if host in LOCAL_HOSTS:
        return True
    # Unix-domain socket path. ".." would let a value pretend to be local
    # while pointing somewhere else, so those are refused.
    if token.startswith("/") and ".." not in token.split("/"):
        return True
    return False


def _targets(parsed) -> list[str]:
    netloc = unquote(parsed.netloc or "")
    if "," in netloc:
        raise GuardError("refusing database URL: multiple hosts")
    targets: list[str] = []
    if parsed.hostname:
        targets.append(parsed.hostname)
    query = parse_qs(parsed.query, keep_blank_values=True)
    for key in ("host", "hostaddr"):
        for value in query.get(key, []):
            for part in unquote(value).split(","):
                targets.append(part.strip())
    return targets


def assert_local_postgres(url: str) -> None:
    """Refuse anything that is not a local/CI throwaway Postgres."""
    raw = _basic(url, "restore target")
    try:
        parsed = urlparse(raw)
    except ValueError as exc:
        raise GuardError("refusing restore target: unparseable database URL") from exc
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("postgres", "postgresql"):
        raise GuardError("refusing restore target: unsupported scheme")
    try:
        targets = _targets(parsed)
    except GuardError:
        raise
    except Exception as exc:
        raise GuardError("refusing restore target: unparseable database URL") from exc
    if not targets:
        # postgresql:///dbname uses a local unix socket.
        return
    for target in targets:
        if not _is_local_postgres_target(target):
            raise GuardError(
                f"refusing restore target: host {_label(target)} is not local"
            )


def assert_loopback_http(url: str) -> None:
    """Offline storage mocks must be an HTTP(S) server on a loopback host."""
    raw = _basic(url, "storage URL")
    try:
        parsed = urlparse(raw)
    except ValueError as exc:
        raise GuardError("refusing storage URL: unparseable URL") from exc
    if (parsed.scheme or "").lower() not in ("http", "https"):
        raise GuardError("refusing storage URL: unsupported scheme")
    host = _normalize_host(parsed.hostname or "")
    if host not in LOCAL_HOSTS:
        raise GuardError(f"refusing storage URL: host {_label(host or 'empty')} is not local")


def _expect_allow(fn, url: str) -> None:
    fn(url)


def _expect_deny(fn, url: str) -> None:
    try:
        fn(url)
    except GuardError as exc:
        text = str(exc)
        if url and url in text:
            raise AssertionError("guard error echoed the URL") from exc
        if "super-secret-pw" in text or "offline-guard-secret" in text:
            raise AssertionError("guard error echoed a password") from exc
        return
    raise AssertionError("guard allowed a URL that must be refused")


def self_test() -> int:
    failures = 0

    def check(name: str, fn) -> None:
        nonlocal failures
        try:
            fn()
            print(f"PASS: {name}")
        except Exception as exc:
            failures += 1
            print(f"FAIL: {name}: {exc}", file=sys.stderr)

    allow = [
        "postgresql://postgres:postgres@localhost:5432/oi_restore_test",
        "postgresql://postgres:postgres@127.0.0.1:5432/oi_restore_test",
        "postgresql://postgres:postgres@[::1]:5432/oi_restore_test",
        "postgres://127.0.0.1/db",
        "postgresql://localhost/db",
        "postgresql:///oi_restore_test",
        "postgresql://127.0.0.1/db?host=localhost",
        "postgresql://LOCALHOST:5432/db",
        "postgresql://user:pass@127.0.0.1/db?hostaddr=127.0.0.1",
        "postgresql://127.0.0.1/db?host=/var/run/postgresql",
        "postgresql://127.0.0.1/db?host=::1",
        "postgresql://[::1]/db?hostaddr=::1",
        "postgresql://127.0.0.1/db#@evil.example",
    ]
    deny = [
        "postgresql://postgres:postgres@db.bekaxmatcvxqpjixwsqn.supabase.co:5432/postgres",
        "postgresql://postgres:postgres@supabase.co/postgres",
        "postgresql://postgres:super-secret-pw@example.com:5432/db",
        "postgresql://postgres:postgres@localhost:5432/db?host=evil.com",
        "postgresql://postgres:postgres@localhost:5432/db?hostaddr=8.8.8.8",
        "postgresql://localhost:5432@evil.com/db",
        "postgresql://user:pass@127.0.0.1.evil.com/db",
        "postgresql://user:pass@localhost.supabase.co/db",
        "postgresql://127.0.0.1/db?host=127.0.0.1.evil.com",
        "postgresql://localhost,evil.com/db",
        "postgresql://127.0.0.1/db?host=localhost,evil.com",
        "postgresql://postgres:offline-guard-secret@example.com:5432/db",
        "postgresql://127.0.0.1/db?hostaddr=0.0.0.0",
        "postgresql://10.0.0.1/db",
        "postgresql://127.0.0.2/db",
        "http://127.0.0.1/db",
        "postgresql://127.0.0.1/db?host=/tmp/../etc/passwd",
        "",
        "postgresql://127.0.0.1/db?hostaddr=::ffff:127.0.0.1",
        "postgresql://user:pass@localhost/db?host=localhost&hostaddr=10.1.2.3",
        "postgresql://127.0.0.1/db?host=localhost.localdomain",
    ]
    # The password case above contains "supabase.co" and must be refused
    # even though the host is loopback. Confirm that explicitly.
    deny.append("postgresql://postgres:has-supabase.co-in-it@127.0.0.1:5432/db")

    def allow_all() -> None:
        for url in allow:
            _expect_allow(assert_local_postgres, url)

    def deny_all() -> None:
        for url in deny:
            _expect_deny(assert_local_postgres, url)

    check("local restore targets allowed", allow_all)
    check("non-local and supabase.co restore targets refused", deny_all)

    def http_cases() -> None:
        for url in (
            "http://127.0.0.1:8765",
            "https://localhost/storage",
            "http://[::1]:8765/storage",
        ):
            _expect_allow(assert_loopback_http, url)
        for url in (
            "https://bekaxmatcvxqpjixwsqn.supabase.co",
            "http://example.com",
            "http://127.0.0.1.evil.com",
            "postgresql://127.0.0.1/db",
        ):
            _expect_deny(assert_loopback_http, url)

    check("storage URL loopback guard", http_cases)
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write(
            "usage: guards.py restore-target|loopback-db|loopback-http|self-test\n"
        )
        return 2
    cmd = argv[1]
    if cmd == "self-test":
        try:
            return self_test()
        except Exception as exc:
            sys.stderr.write(f"ERROR: {exc}\n")
            return 1
    url = os.environ.get("SEC1_GUARD_URL", "")
    try:
        if cmd in ("restore-target", "loopback-db"):
            assert_local_postgres(url)
        elif cmd == "loopback-http":
            assert_loopback_http(url)
        else:
            sys.stderr.write("ERROR: unknown guard command\n")
            return 2
    except GuardError as exc:
        sys.stderr.write(f"ERROR: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
