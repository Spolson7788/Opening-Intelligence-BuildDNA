#!/usr/bin/env python3
"""Write and verify a sha256sum manifest. Counts must match the files on disk.

manifest.py write ROOT
    Write ROOT/manifest.sha256 for every file except the manifest itself
    and run.json (run.json is written after the manifest).

manifest.py verify ROOT
    Fail unless the manifest lists exactly the files on disk (run.json may
    exist without being listed) and sha256sum -c succeeds.

manifest.py storage-count MANIFEST
    Print how many manifest entries live under storage/.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

SKIP_NAMES = frozenset({"manifest.sha256", "run.json"})


def _rel_files(root: Path) -> list[str]:
    found: list[str] = []
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if "\n" in rel or "\\" in rel or rel.startswith("../") or "/../" in rel:
                raise SystemExit(f"ERROR: unsafe manifest path {rel!r}")
            found.append(rel)
    return found


def _listed(manifest: Path) -> list[tuple[str, str]]:
    if not manifest.is_file():
        raise SystemExit("ERROR: manifest.sha256 is missing")
    rows: list[tuple[str, str]] = []
    text = manifest.read_text(encoding="utf-8")
    if text and not text.endswith("\n"):
        raise SystemExit("ERROR: manifest.sha256 is truncated")
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            raise SystemExit(f"ERROR: blank line in manifest.sha256:{line_no}")
        if "  " not in line:
            raise SystemExit(f"ERROR: malformed manifest.sha256:{line_no}")
        digest, rel = line.split("  ", 1)
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise SystemExit(f"ERROR: bad digest in manifest.sha256:{line_no}")
        if not rel or rel.startswith("/") or ".." in rel.split("/"):
            raise SystemExit(f"ERROR: bad path in manifest.sha256:{line_no}")
        rows.append((digest, rel))
    return rows


def write_manifest(root: Path) -> int:
    # run.json is metadata written after the manifest, so it is not listed.
    files = sorted(rel for rel in _rel_files(root) if Path(rel).name not in SKIP_NAMES)
    lines: list[str] = []
    for rel in files:
        proc = subprocess.run(
            ["sha256sum", "--", rel],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            sys.stderr.write(proc.stderr)
            raise SystemExit(f"ERROR: sha256sum failed for {rel} (exit {proc.returncode})")
        line = proc.stdout
        if not line.endswith("\n") or "  " not in line.rstrip("\n"):
            raise SystemExit(f"ERROR: unexpected sha256sum output for {rel}")
        lines.append(line)
    manifest = root / "manifest.sha256"
    manifest.write_text("".join(lines), encoding="utf-8")
    os.chmod(manifest, 0o600)
    if len(lines) != len(files):
        raise SystemExit("ERROR: manifest line count does not match file count")
    print(len(lines))
    return 0


def verify_manifest(root: Path) -> int:
    manifest = root / "manifest.sha256"
    rows = _listed(manifest)
    listed = [rel for _, rel in rows]
    if len(listed) != len(set(listed)):
        raise SystemExit("ERROR: manifest lists a path more than once")
    disk = set(_rel_files(root))
    disk.discard("manifest.sha256")
    extra = disk - set(listed)
    missing = set(listed) - disk
    allowed_extra = {"run.json"}
    unexpected = extra - allowed_extra
    if unexpected or missing:
        raise SystemExit(
            "ERROR: object count does not match manifest "
            f"(listed={len(listed)} on_disk={len(disk)} "
            f"missing={len(missing)} unexpected={len(unexpected)})"
        )
    proc = subprocess.run(
        ["sha256sum", "-c", "manifest.sha256"],
        cwd=root,
        check=False,
        text=True,
    )
    if proc.returncode != 0:
        raise SystemExit(f"ERROR: sha256sum -c failed (exit {proc.returncode})")
    storage = sum(1 for rel in listed if rel.startswith("storage/"))
    print(f"manifest_files={len(listed)} storage_files={storage}")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[1] == "write":
        return write_manifest(Path(argv[2]))
    if len(argv) == 3 and argv[1] == "verify":
        return verify_manifest(Path(argv[2]))
    if len(argv) == 3 and argv[1] == "storage-count":
        rows = _listed(Path(argv[2]))
        print(sum(1 for _, rel in rows if rel.startswith("storage/")))
        return 0
    sys.stderr.write("usage: manifest.py write|verify ROOT | storage-count MANIFEST\n")
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except SystemExit:
        raise
    except Exception as exc:
        sys.stderr.write(f"ERROR: {type(exc).__name__}: manifest operation failed\n")
        sys.exit(1)
