#!/usr/bin/env python3
"""Keep 30 daily snapshots and 12 monthly snapshots. Fail if a delete fails.

Daily prefixes are snapshots/YYYY-MM-DD/. Monthly prefixes are
monthly/YYYY-MM-DD/ (written as YYYY-MM-01). Anything that is not a real
calendar date is left in place. After deleting, the listing is read again
and the run fails if a keeper is missing or an expired prefix remains.

Requires R2_ENDPOINT, R2_BUCKET, and AWS credentials in the environment.
"""

from __future__ import annotations

import datetime as dt
import os
import subprocess
import sys
import tempfile

KEEP_DAILY = 30
KEEP_MONTHLY = 12


def _fail(message: str) -> None:
    sys.stderr.write(f"ERROR: {message}\n")
    raise SystemExit(1)


def _ensure_path_style() -> None:
    if os.environ.get("AWS_CONFIG_FILE"):
        return
    fd, name = tempfile.mkstemp(prefix="sec1-aws-")
    os.write(fd, b"[default]\ns3 =\n    addressing_style = path\n")
    os.close(fd)
    os.chmod(name, 0o600)
    os.environ["AWS_CONFIG_FILE"] = name
    os.environ.setdefault("AWS_REQUEST_CHECKSUM_CALCULATION", "WHEN_REQUIRED")
    os.environ.setdefault("AWS_RESPONSE_CHECKSUM_VALIDATION", "WHEN_REQUIRED")


def _aws(args: list[str]) -> str:
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        _fail(f"aws command failed (exit {proc.returncode})")
    return proc.stdout


def _list_keys(endpoint: str, bucket: str) -> list[str]:
    out = _aws(
        [
            "aws",
            "s3",
            "ls",
            f"s3://{bucket}",
            "--recursive",
            "--endpoint-url",
            endpoint,
        ]
    )
    keys: list[str] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split(maxsplit=3)
        if len(parts) != 4:
            _fail("unexpected aws s3 ls output")
        keys.append(parts[3])
    return keys


def _dates_under(keys: list[str], root: str) -> list[str]:
    prefix = root.rstrip("/") + "/"
    found: set[str] = set()
    for key in keys:
        if not key.startswith(prefix):
            continue
        name = key[len(prefix) :].split("/", 1)[0]
        try:
            dt.date.fromisoformat(name)
        except ValueError:
            print(f"retention: ignoring non-date prefix {root}/{name}", file=sys.stderr)
            continue
        found.add(name)
    return sorted(found)


def _delete_prefix(endpoint: str, bucket: str, root: str, date: str) -> None:
    if not date or "/" in date or date in (".", ".."):
        _fail("refusing to delete an unsafe prefix")
    dt.date.fromisoformat(date)
    prefix = f"{root.strip('/')}/{date}/"
    print(f"retention: deleting s3://{bucket}/{prefix}", flush=True)
    _aws(
        [
            "aws",
            "s3",
            "rm",
            f"s3://{bucket}/{prefix}",
            "--recursive",
            "--endpoint-url",
            endpoint,
        ]
    )


def _prune(endpoint: str, bucket: str, root: str, keep: int, keys: list[str]) -> tuple[int, int]:
    dates = _dates_under(keys, root)
    before = len(dates)
    if before <= keep:
        print(f"retention {root}: {before} <= {keep}, nothing to prune", flush=True)
        return before, before
    keepers = dates[-keep:]
    doomed = dates[:-keep]
    for date in doomed:
        _delete_prefix(endpoint, bucket, root, date)
    after_keys = _list_keys(endpoint, bucket)
    remaining = _dates_under(after_keys, root)
    after = len(remaining)
    if after > keep:
        _fail(f"{root}: {after} prefixes remain after prune (limit {keep})")
    missing = [date for date in keepers if date not in remaining]
    if missing:
        _fail(f"{root}: prune removed a prefix that should have been kept")
    leftover = [date for date in doomed if date in remaining]
    if leftover:
        _fail(f"{root}: prune left an expired prefix")
    print(f"retention {root}: kept {after} deleted {before - after}", flush=True)
    return before, after


def main(argv: list[str]) -> int:
    if argv[1:]:
        sys.stderr.write("usage: retention.py\n")
        return 2
    endpoint = os.environ.get("R2_ENDPOINT", "")
    bucket = os.environ.get("R2_BUCKET", "")
    if not endpoint or not bucket:
        _fail("R2_ENDPOINT and R2_BUCKET are required")
    if not os.environ.get("AWS_ACCESS_KEY_ID") or not os.environ.get("AWS_SECRET_ACCESS_KEY"):
        _fail("AWS credentials are required")
    _ensure_path_style()
    keys = _list_keys(endpoint, bucket)
    daily_before, daily_after = _prune(endpoint, bucket, "snapshots", KEEP_DAILY, keys)
    # Re-list so a daily delete is visible before monthly accounting.
    keys = _list_keys(endpoint, bucket)
    monthly_before, monthly_after = _prune(endpoint, bucket, "monthly", KEEP_MONTHLY, keys)
    print(
        f"retention snapshots_before={daily_before} snapshots_after={daily_after} "
        f"monthly_before={monthly_before} monthly_after={monthly_after}",
        flush=True,
    )
    if daily_after > KEEP_DAILY or monthly_after > KEEP_MONTHLY:
        _fail("retention exceeded its keep limits")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except SystemExit:
        raise
    except Exception as exc:
        sys.stderr.write(f"ERROR: retention failed: {type(exc).__name__}\n")
        sys.exit(1)
