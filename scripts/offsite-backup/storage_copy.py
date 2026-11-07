#!/usr/bin/env python3
"""List and download a Supabase Storage bucket. Fail on any error.

Listing is one folder level at a time. This walks every subfolder and
every page (limit/offset) until a short page. Folder entries are those
with a null id, matching the Storage list API. Files are downloaded only
after the full listing succeeds. A short read, HTTP error, redirect, or
size mismatch aborts the process with a non-zero status.

Environment:
  OI_PROD_SUPABASE_URL
  OI_PROD_SUPABASE_SERVICE_ROLE_KEY
  MEDIA_BUCKET
  SEC1_STORAGE_PAGE_LIMIT   optional, 1..1000, default 1000

Usage: storage_copy.py DEST_DIR LIST_PATH
  LIST_PATH receives one relative object key per line.
  Stdout on success is "listed=N" and "downloaded=N".
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

MAX_OBJECTS = 1_000_000
MAX_PAGES_PER_PREFIX = 100_000


class RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError(f"refusing HTTP redirect {code}")


def _fail(message: str) -> None:
    sys.stderr.write(f"ERROR: {message}\n")
    raise SystemExit(1)


def _page_limit() -> int:
    raw = os.environ.get("SEC1_STORAGE_PAGE_LIMIT", "1000")
    try:
        limit = int(raw)
    except ValueError:
        _fail("SEC1_STORAGE_PAGE_LIMIT is not an integer")
    if limit < 1 or limit > 1000:
        _fail("SEC1_STORAGE_PAGE_LIMIT must be between 1 and 1000")
    return limit


def _safe_path(url: str) -> str:
    return urllib.parse.urlparse(url).path


def _request(opener, url: str, data: bytes | None, timeout: int) -> bytes:
    key = os.environ["OI_PROD_SUPABASE_SERVICE_ROLE_KEY"]
    headers = {
        "Authorization": "Bearer " + key,
        "apikey": key,
    }
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data is not None else "GET")
    try:
        with opener.open(req, timeout=timeout) as resp:
            status = getattr(resp, "status", 200)
            body = resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read(300).decode("utf-8", "replace").replace("\n", " ")
        secret = os.environ.get("OI_PROD_SUPABASE_SERVICE_ROLE_KEY", "")
        if secret:
            detail = detail.replace(secret, "[REDACTED]")
        _fail(f"storage HTTP {exc.code} for {_safe_path(url)}: {detail}")
    except Exception as exc:
        _fail(f"storage request failed for {_safe_path(url)}: {type(exc).__name__}")
    if status != 200:
        _fail(f"storage HTTP {status} for {_safe_path(url)}")
    return body


def _valid_segment(name: object) -> str:
    if not isinstance(name, str) or not name or name in (".", ".."):
        _fail("storage list entry has an invalid name")
    if "/" in name or "\\" in name or name != name.strip():
        _fail(f"storage list entry has an unsafe name {name!r}")
    return name


def _is_folder(item: dict) -> bool:
    if "id" not in item:
        _fail("storage list entry is missing id")
    return item["id"] is None


def _list_prefix(opener, list_url: str, prefix: str, limit: int, seen_prefixes: set[str]) -> list[tuple[str, dict]]:
    if prefix in seen_prefixes:
        _fail(f"storage folder cycle at {prefix!r}")
    seen_prefixes.add(prefix)
    files: list[tuple[str, dict]] = []
    seen_names: set[str] = set()
    offset = 0
    pages = 0
    while True:
        pages += 1
        if pages > MAX_PAGES_PER_PREFIX:
            _fail(f"too many listing pages under {prefix!r}")
        payload = json.dumps(
            {
                "prefix": prefix,
                "limit": limit,
                "offset": offset,
                "sortBy": {"column": "name", "order": "asc"},
            }
        ).encode("utf-8")
        raw = _request(opener, list_url, payload, timeout=120)
        try:
            page = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            _fail(f"storage list at {prefix!r} was not JSON")
        if not isinstance(page, list):
            _fail(f"storage list at {prefix!r} was not an array")
        for item in page:
            if not isinstance(item, dict):
                _fail("storage list entry was not an object")
            name = _valid_segment(item.get("name"))
            if name in seen_names:
                _fail(
                    f"duplicate name {name!r} under {prefix!r}; pagination is not advancing"
                )
            seen_names.add(name)
            if _is_folder(item):
                files.extend(
                    _list_prefix(opener, list_url, f"{prefix}{name}/", limit, seen_prefixes)
                )
            else:
                files.append((f"{prefix}{name}", item.get("metadata") or {}))
                if len(files) > MAX_OBJECTS:
                    _fail(f"refusing to list more than {MAX_OBJECTS} objects")
        if len(page) < limit:
            break
        offset += len(page)
    return files


def _download_one(opener, base: str, bucket: str, rel: str, meta: dict, dest_root: Path) -> None:
    quoted = urllib.parse.quote(rel, safe="/")
    url = f"{base}/storage/v1/object/{urllib.parse.quote(bucket, safe='')}/{quoted}"
    body = _request(opener, url, None, timeout=300)
    size = None
    if isinstance(meta, dict) and meta.get("size") is not None:
        try:
            size = int(meta["size"])
        except (TypeError, ValueError):
            _fail(f"listed size for {rel} is not an integer")
    if size is not None and size != len(body):
        _fail(f"download size mismatch for {rel}: listed {size} got {len(body)}")
    dest = dest_root.joinpath(*rel.split("/"))
    root_resolved = dest_root.resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.resolve().is_relative_to(root_resolved):
        _fail(f"refusing path escape for {rel}")
    tmp = dest.with_name(dest.name + ".partial")
    try:
        tmp.write_bytes(body)
        os.chmod(tmp, 0o600)
        os.replace(tmp, dest)
    except Exception:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        sys.stderr.write("usage: storage_copy.py DEST_DIR LIST_PATH\n")
        return 2
    for name in (
        "OI_PROD_SUPABASE_URL",
        "OI_PROD_SUPABASE_SERVICE_ROLE_KEY",
        "MEDIA_BUCKET",
    ):
        if not os.environ.get(name):
            _fail(f"missing required env {name}")
    dest_root = Path(argv[1])
    list_path = Path(argv[2])
    dest_root.mkdir(parents=True, exist_ok=True)
    base = os.environ["OI_PROD_SUPABASE_URL"].rstrip("/")
    bucket = os.environ["MEDIA_BUCKET"]
    limit = _page_limit()
    opener = urllib.request.build_opener(RefuseRedirect)
    list_url = f"{base}/storage/v1/object/list/{urllib.parse.quote(bucket, safe='')}"
    files = _list_prefix(opener, list_url, "", limit, set())
    # Download only after the full recursive listing is in hand.
    seen_rels: set[str] = set()
    for rel, _meta in files:
        if rel in seen_rels:
            _fail(f"duplicate object key {rel}")
        seen_rels.add(rel)
    for rel, meta in files:
        try:
            _download_one(opener, base, bucket, rel, meta if isinstance(meta, dict) else {}, dest_root)
        except SystemExit:
            raise
        except Exception as exc:
            _fail(f"download failed for {rel}: {type(exc).__name__}")
    on_disk = sorted(
        path.relative_to(dest_root).as_posix()
        for path in dest_root.rglob("*")
        if path.is_file()
    )
    listed = sorted(rel for rel, _meta in files)
    if on_disk != listed:
        _fail(f"downloaded object count {len(on_disk)} != listed {len(listed)}")
    list_path.write_text("".join(rel + "\n" for rel in listed), encoding="utf-8")
    os.chmod(list_path, 0o600)
    print(f"listed={len(listed)}")
    print(f"downloaded={len(on_disk)}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except SystemExit:
        raise
    except Exception as exc:
        sys.stderr.write(f"ERROR: download failed: {type(exc).__name__}\n")
        sys.exit(1)
