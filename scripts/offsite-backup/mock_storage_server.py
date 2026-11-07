#!/usr/bin/env python3
"""Local stand-in for the Supabase Storage list and download endpoints.

Lists one folder level per request and honors limit/offset, so a client
that is not recursive or not paginated cannot see the whole tree. A path
named in the fail file (one relative key per line, reread every request)
returns HTTP 500 on download.

Bind address is always 127.0.0.1.
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse


def _build_tree(root: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for path in root.rglob("*"):
        if path.is_file():
            files[path.relative_to(root).as_posix()] = path.read_bytes()
    return files


def _children(files: dict[str, bytes], prefix: str) -> list[dict]:
    names: dict[str, str] = {}
    for rel in files:
        if prefix and not rel.startswith(prefix):
            continue
        rest = rel[len(prefix) :] if prefix else rel
        if not rest:
            continue
        if "/" in rest:
            names[rest.split("/", 1)[0]] = "dir"
        else:
            names.setdefault(rest, "file")
    items = []
    for name in sorted(names):
        if names[name] == "dir":
            items.append({"name": name, "id": None, "metadata": None})
        else:
            data = files[prefix + name]
            items.append(
                {
                    "name": name,
                    "id": "id-" + prefix + name,
                    "metadata": {"size": len(data), "mimetype": "application/octet-stream"},
                }
            )
    return items


def _fail_set(path: Path | None) -> set[str]:
    if path is None or not path.is_file():
        return set()
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}


def make_handler(files: dict[str, bytes], bucket: str, log_path: Path, fail_path: Path | None, api_key: str):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args) -> None:
            return

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self) -> bool:
            auth = self.headers.get("Authorization", "")
            api = self.headers.get("apikey", "")
            return auth == f"Bearer {api_key}" and api == api_key

        def _record(self, event: dict) -> None:
            with log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, sort_keys=True) + "\n")

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/health":
                self._send(200, b"ok", "text/plain")
                return
            parts = [unquote(part) for part in parsed.path.split("/") if part]
            # storage / v1 / object / bucket / key...
            if len(parts) < 5 or parts[:3] != ["storage", "v1", "object"] or parts[3] == "list":
                self._send(404, b'{"error":"not found"}', "application/json")
                return
            if not self._authorized():
                self._send(401, b'{"error":"unauthorized"}', "application/json")
                return
            got_bucket = parts[3]
            rel = "/".join(parts[4:])
            self._record({"op": "get", "bucket": got_bucket, "path": rel})
            if got_bucket != bucket:
                self._send(404, b'{"error":"bucket"}', "application/json")
                return
            if rel in _fail_set(fail_path):
                self._send(500, b'{"error":"forced download failure"}', "application/json")
                return
            if rel not in files:
                self._send(404, b'{"error":"object"}', "application/json")
                return
            self._send(200, files[rel], "application/octet-stream")

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            parts = [unquote(part) for part in parsed.path.split("/") if part]
            # storage / v1 / object / list / bucket
            if parts[:4] != ["storage", "v1", "object", "list"] or len(parts) != 5:
                self._send(404, b'{"error":"not found"}', "application/json")
                return
            if not self._authorized():
                self._send(401, b'{"error":"unauthorized"}', "application/json")
                return
            got_bucket = parts[4]
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send(400, b'{"error":"length"}', "application/json")
                return
            if length < 0 or length > 1_000_000:
                self._send(413, b'{"error":"body too large"}', "application/json")
                return
            raw = self.rfile.read(length) if length else b""
            try:
                body = json.loads(raw.decode("utf-8")) if raw else {}
            except (UnicodeError, json.JSONDecodeError):
                self._send(400, b'{"error":"json"}', "application/json")
                return
            if got_bucket != bucket:
                self._send(404, b'{"error":"bucket"}', "application/json")
                return
            prefix = body.get("prefix") or ""
            if not isinstance(prefix, str) or ".." in prefix.split("/"):
                self._send(400, b'{"error":"prefix"}', "application/json")
                return
            try:
                limit = int(body.get("limit", 100))
                offset = int(body.get("offset", 0))
            except (TypeError, ValueError):
                self._send(400, b'{"error":"paging"}', "application/json")
                return
            if limit < 1 or offset < 0:
                self._send(400, b'{"error":"paging"}', "application/json")
                return
            items = _children(files, prefix)
            page = items[offset : offset + limit]
            self._record(
                {
                    "op": "list",
                    "prefix": prefix,
                    "limit": limit,
                    "offset": offset,
                    "returned": len(page),
                }
            )
            payload = json.dumps(page).encode("utf-8")
            self._send(200, payload, "application/json")

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--fail-file", type=Path, required=True)
    parser.add_argument("--api-key", required=True)
    args = parser.parse_args()
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        sys_err = "mock storage refuses to bind a non-local host"
        raise SystemExit(sys_err)
    files = _build_tree(args.root)
    args.log.write_text("", encoding="utf-8")
    handler = make_handler(files, args.bucket, args.log, args.fail_file, args.api_key)
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"mock storage listening on {args.host}:{args.port} objects={len(files)}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
