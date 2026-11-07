#!/usr/bin/env python3
"""Redact passwords and credential material before anything is printed.

Usage:
  redact.py FILE            print FILE with secrets removed
  redact.py --check FILE    exit 1 if FILE contains a forbidden literal
                             or an unredacted PASSWORD clause

SEC1_SECRET_SCAN, when set for --check, is a newline-separated list of
extra literals that must not appear.
"""

from __future__ import annotations

import os
import re
import sys

PASSWORD_RE = re.compile(r"PASSWORD\s+'(?:[^']|'')*'", re.IGNORECASE)
SCRAM_RE = re.compile(r"SCRAM-SHA-256\$\S+")
USERINFO_RE = re.compile(r"(postgres(?:ql)?://)([^/\s@]+)@")
BEARER_RE = re.compile(r"Bearer\s+\S+", re.IGNORECASE)


def redact(text: str) -> str:
    text = PASSWORD_RE.sub("PASSWORD '[REDACTED]'", text)
    text = SCRAM_RE.sub("SCRAM-SHA-256$[REDACTED]", text)
    text = USERINFO_RE.sub(r"\1[REDACTED]@", text)
    text = BEARER_RE.sub("Bearer [REDACTED]", text)
    key = os.environ.get("BACKUP_ENCRYPTION_KEY", "")
    if key:
        text = text.replace(key, "[REDACTED]")
    return text


def main(argv: list[str]) -> int:
    check = False
    args = argv[1:]
    if args and args[0] == "--check":
        check = True
        args = args[1:]
    if len(args) != 1:
        sys.stderr.write("usage: redact.py [--check] FILE\n")
        return 2
    with open(args[0], "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
    if check:
        leaked = []
        if PASSWORD_RE.search(raw):
            leaked.append("PASSWORD clause")
        if SCRAM_RE.search(raw):
            leaked.append("SCRAM hash")
        extra = os.environ.get("SEC1_SECRET_SCAN", "")
        for item in extra.splitlines():
            if item and item in raw:
                leaked.append("configured literal")
        if leaked:
            sys.stderr.write("ERROR: output contains secret material\n")
            return 1
        return 0
    sys.stdout.write(redact(raw))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
