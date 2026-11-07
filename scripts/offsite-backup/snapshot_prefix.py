#!/usr/bin/env python3
"""Choose the newest snapshots/YYYY-MM-DD prefix from `aws s3 ls` text.

The listing is the `snapshots/` prefix written by the off-site backup.
Non-dates, invalid calendar days, and nested object keys are ignored.
No dated prefix is an error.
"""

from __future__ import annotations

import datetime
import sys


def select_prefix(listing: str) -> str:
    dates: list[str] = []
    for line in listing.splitlines():
        parts = line.split()
        if not parts:
            continue
        name = parts[-1].strip().rstrip("/")
        if not name or "/" in name:
            continue
        try:
            datetime.date.fromisoformat(name)
        except ValueError:
            continue
        dates.append(name)
    if not dates:
        raise SystemExit("ERROR: no dated snapshots found in the backup bucket")
    return "snapshots/" + sorted(dates)[-1]


def self_test() -> int:
    listing = "\n".join(
        [
            "                           PRE 2026-01-02/",
            "                           PRE 2024-12-31/",
            "                           PRE not-a-date/",
            "                           PRE 2026-02-31/",
            "2026-11-01 00:00:00          1 2026-11-01/manifest.sha256",
            "                           PRE 2026-11-07/",
            "                           PRE 2026-03-01",
            "",
        ]
    )
    chosen = select_prefix(listing)
    if chosen != "snapshots/2026-11-07":
        sys.stderr.write(f"FAIL: newest prefix was {chosen}\n")
        return 1
    for empty in ("", "\n", "                           PRE notes/\n"):
        try:
            select_prefix(empty)
        except SystemExit as exc:
            if "no dated snapshots" not in str(exc):
                sys.stderr.write(f"FAIL: unexpected empty-listing error: {exc}\n")
                return 1
        else:
            sys.stderr.write("FAIL: empty listing was accepted\n")
            return 1
    print("PASS: newest snapshot prefix")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "self-test":
        return self_test()
    if len(argv) != 1:
        sys.stderr.write("usage: snapshot_prefix.py [self-test] < listing\n")
        return 2
    try:
        print(select_prefix(sys.stdin.read()))
    except SystemExit as exc:
        sys.stderr.write(f"{exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
