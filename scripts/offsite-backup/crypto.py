#!/usr/bin/env python3
"""Authenticated encryption for SEC-1 backups (AES-256-GCM).

The passphrase is BACKUP_ENCRYPTION_KEY. It is read from the environment
only and is never printed, logged, or taken from argv.

File format "OISEC1GCM1" version 1, all integers big-endian:

  magic         11 bytes   b"OISEC1GCM1\\n"
  version       uint8      1
  salt          16 bytes   random
  iterations    uint32     PBKDF2-HMAC-SHA256 iterations (200000)
  chunk_size    uint32     plaintext bytes per chunk (max 16 MiB)
  repeated chunks:
    cipher_len  uint32     length of ciphertext including the 16-byte tag
                           0 marks the end of the file
    nonce       12 bytes
    ciphertext  cipher_len bytes
  no trailing bytes are allowed

Key: PBKDF2-HMAC-SHA256(passphrase, salt, iterations, 32).
Cipher: AES-256-GCM. Additional data for chunk i is
b"OISEC1GCM1" + uint64be(i), so reordered chunks fail authentication.

openssl enc cannot produce authenticated GCM output, and age passphrase
mode prompts on a terminal. This format is non-interactive and rejects
any modified, truncated, reordered, or wrong-key payload. Decrypt writes
the destination only after every chunk authenticates.
"""

from __future__ import annotations

import os
import struct
import sys
import tempfile

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    sys.stderr.write("ERROR: python3-cryptography is required\n")
    sys.exit(1)

MAGIC = b"OISEC1GCM1\n"
VERSION = 1
ITERATIONS = 200_000
CHUNK_SIZE = 4 * 1024 * 1024
MAX_CHUNK = 16 * 1024 * 1024
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
AAD_PREFIX = b"OISEC1GCM1"
HEADER = struct.Struct(">B16sII")


class CryptoError(Exception):
    pass


def _passphrase() -> bytes:
    key = os.environ.get("BACKUP_ENCRYPTION_KEY", "")
    if not key:
        raise CryptoError("missing BACKUP_ENCRYPTION_KEY")
    return key.encode("utf-8")


def _derive(password: bytes, salt: bytes, iterations: int) -> bytes:
    if iterations != ITERATIONS:
        raise CryptoError("refusing unexpected KDF iterations")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)


def _safe_text(exc: BaseException) -> str:
    text = f"{type(exc).__name__}: {exc}"
    key = os.environ.get("BACKUP_ENCRYPTION_KEY", "")
    if key and key in text:
        text = text.replace(key, "[REDACTED]")
    return text


def _write_atomic(path: str, produce) -> None:
    parent = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".sec1-crypt-", dir=parent)
    os.close(fd)
    try:
        with open(tmp, "wb") as out:
            produce(out)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def encrypt_file(src: str, dest: str, chunk_size: int = CHUNK_SIZE) -> None:
    if chunk_size < 1 or chunk_size > MAX_CHUNK:
        raise CryptoError("chunk size out of range")
    password = _passphrase()
    salt = os.urandom(SALT_LEN)
    key = _derive(password, salt, ITERATIONS)
    aes = AESGCM(key)

    def produce(out) -> None:
        out.write(MAGIC)
        out.write(HEADER.pack(VERSION, salt, ITERATIONS, chunk_size))
        index = 0
        with open(src, "rb") as inf:
            while True:
                chunk = inf.read(chunk_size)
                if not chunk:
                    break
                nonce = os.urandom(NONCE_LEN)
                aad = AAD_PREFIX + struct.pack(">Q", index)
                ciphertext = aes.encrypt(nonce, chunk, aad)
                out.write(struct.pack(">I", len(ciphertext)))
                out.write(nonce)
                out.write(ciphertext)
                index += 1
        out.write(struct.pack(">I", 0))

    _write_atomic(dest, produce)


def decrypt_file(src: str, dest: str) -> None:
    password = _passphrase()

    def produce(out) -> None:
        with open(src, "rb") as inf:
            magic = inf.read(len(MAGIC))
            if magic != MAGIC:
                raise CryptoError(
                    "not an authenticated OISEC1GCM1 payload "
                    "(refusing unauthenticated or foreign ciphertext)"
                )
            header = inf.read(HEADER.size)
            if len(header) != HEADER.size:
                raise CryptoError("truncated encryption header")
            version, salt, iterations, chunk_size = HEADER.unpack(header)
            if version != VERSION:
                raise CryptoError("unsupported encryption version")
            if iterations != ITERATIONS:
                raise CryptoError("refusing unexpected KDF iterations")
            if chunk_size < 1 or chunk_size > MAX_CHUNK:
                raise CryptoError("refusing unreasonable chunk size")
            key = _derive(password, salt, iterations)
            aes = AESGCM(key)
            index = 0
            while True:
                raw_len = inf.read(4)
                if len(raw_len) != 4:
                    raise CryptoError("truncated chunk header")
                (cipher_len,) = struct.unpack(">I", raw_len)
                if cipher_len == 0:
                    trailing = inf.read(1)
                    if trailing:
                        raise CryptoError("trailing bytes after authenticated payload")
                    break
                if cipher_len < TAG_LEN or cipher_len > chunk_size + TAG_LEN:
                    raise CryptoError("refusing unreasonable ciphertext chunk")
                nonce = inf.read(NONCE_LEN)
                ciphertext = inf.read(cipher_len)
                if len(nonce) != NONCE_LEN or len(ciphertext) != cipher_len:
                    raise CryptoError("truncated ciphertext chunk")
                aad = AAD_PREFIX + struct.pack(">Q", index)
                try:
                    plaintext = aes.decrypt(nonce, ciphertext, aad)
                except InvalidTag as exc:
                    raise CryptoError(
                        "authentication failed: ciphertext was modified or the key is wrong"
                    ) from exc
                out.write(plaintext)
                index += 1

    _write_atomic(dest, produce)


def _self_test() -> int:
    failures = 0

    def check(name: str, ok: bool) -> None:
        nonlocal failures
        if ok:
            print(f"PASS: {name}")
        else:
            print(f"FAIL: {name}", file=sys.stderr)
            failures += 1

    work = tempfile.mkdtemp(prefix="sec1-crypto-")
    try:
        os.environ["BACKUP_ENCRYPTION_KEY"] = "self-test-key-not-for-production"
        plain = os.path.join(work, "plain")
        enc = os.path.join(work, "plain.enc")
        out = os.path.join(work, "out")
        payload = b"sec1-roundtrip-\x00-binary" + os.urandom(100)
        with open(plain, "wb") as fh:
            fh.write(payload)
        encrypt_file(plain, enc)
        decrypt_file(enc, out)
        with open(out, "rb") as fh:
            check("encrypt/decrypt roundtrip", fh.read() == payload)

        multi_src = os.path.join(work, "multi")
        multi_enc = os.path.join(work, "multi.enc")
        multi_out = os.path.join(work, "multi.out")
        multi = b"M" * 2500
        with open(multi_src, "wb") as fh:
            fh.write(multi)
        encrypt_file(multi_src, multi_enc, chunk_size=1024)
        decrypt_file(multi_enc, multi_out)
        with open(multi_out, "rb") as fh:
            check("multi-chunk roundtrip", fh.read() == multi)

        empty_src = os.path.join(work, "empty")
        empty_enc = os.path.join(work, "empty.enc")
        empty_out = os.path.join(work, "empty.out")
        open(empty_src, "wb").close()
        encrypt_file(empty_src, empty_enc)
        decrypt_file(empty_enc, empty_out)
        check("empty payload roundtrip", os.path.getsize(empty_out) == 0)

        tampered = os.path.join(work, "tampered.enc")
        with open(enc, "rb") as fh:
            blob = bytearray(fh.read())
        blob[-1] ^= 0x01
        with open(tampered, "wb") as fh:
            fh.write(blob)
        tampered_out = os.path.join(work, "tampered.out")
        rejected = False
        try:
            decrypt_file(tampered, tampered_out)
        except CryptoError:
            rejected = True
        check(
            "tampered ciphertext rejected",
            rejected and not os.path.exists(tampered_out),
        )

        truncated = os.path.join(work, "truncated.enc")
        with open(truncated, "wb") as fh:
            fh.write(blob[:40])
        truncated_out = os.path.join(work, "truncated.out")
        rejected = False
        try:
            decrypt_file(truncated, truncated_out)
        except CryptoError:
            rejected = True
        check(
            "truncated ciphertext rejected",
            rejected and not os.path.exists(truncated_out),
        )

        cbc = os.path.join(work, "cbc.enc")
        with open(cbc, "wb") as fh:
            fh.write(b"Salted__" + os.urandom(32))
        cbc_out = os.path.join(work, "cbc.out")
        rejected = False
        try:
            decrypt_file(cbc, cbc_out)
        except CryptoError as exc:
            rejected = "unauthenticated" in str(exc)
        check(
            "unauthenticated AES-CBC payload rejected",
            rejected and not os.path.exists(cbc_out),
        )

        wrong_out = os.path.join(work, "wrong.out")
        os.environ["BACKUP_ENCRYPTION_KEY"] = "different-self-test-key"
        rejected = False
        try:
            decrypt_file(enc, wrong_out)
        except CryptoError:
            rejected = True
        leaked = False
        check(
            "wrong key rejected",
            rejected and not os.path.exists(wrong_out) and not leaked,
        )
    finally:
        for dirpath, _, names in os.walk(work, topdown=False):
            for name in names:
                os.remove(os.path.join(dirpath, name))
        os.rmdir(work)
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "self-test":
        try:
            return _self_test()
        except Exception as exc:
            sys.stderr.write(f"ERROR: {_safe_text(exc)}\n")
            return 1
    if len(argv) != 4 or argv[1] not in ("encrypt", "decrypt"):
        sys.stderr.write("usage: crypto.py encrypt|decrypt SRC DEST\n")
        return 2
    try:
        if argv[1] == "encrypt":
            encrypt_file(argv[2], argv[3])
        else:
            decrypt_file(argv[2], argv[3])
    except Exception as exc:
        sys.stderr.write(f"ERROR: {_safe_text(exc)}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
