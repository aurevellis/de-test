"""Password-based encrypt/decrypt for interview stage blobs (stdlib only)."""

from __future__ import annotations

import hashlib
import hmac
import os
import tarfile
from io import BytesIO
from pathlib import Path

MAGIC = b"STG1"
SALT_LEN = 16
MAC_LEN = 32
PBKDF2_ITERS = 200_000
KEY_LEN = 64


class DecryptError(Exception):
    pass


class EmptySourceError(Exception):
    pass


def _keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    raw = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERS,
        dklen=KEY_LEN,
    )
    return raw[:32], raw[32:]


def _keystream(key: bytes, n: int) -> bytes:
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(key + i.to_bytes(8, "big")).digest()
        i += 1
    return bytes(out[:n])


def encrypt_bytes(plain: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_LEN)
    enc_key, mac_key = _keys(password, salt)
    cipher = bytes(a ^ b for a, b in zip(plain, _keystream(enc_key, len(plain))))
    mac = hmac.new(mac_key, MAGIC + salt + cipher, hashlib.sha256).digest()
    return MAGIC + salt + mac + cipher


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    prefix = MAGIC + bytes(SALT_LEN + MAC_LEN)
    if len(blob) < len(prefix) or not blob.startswith(MAGIC):
        raise DecryptError("not a stage blob")
    salt = blob[len(MAGIC) : len(MAGIC) + SALT_LEN]
    mac = blob[len(MAGIC) + SALT_LEN : len(prefix)]
    cipher = blob[len(prefix) :]
    enc_key, mac_key = _keys(password, salt)
    expected = hmac.new(mac_key, MAGIC + salt + cipher, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise DecryptError("wrong password or corrupt blob")
    return bytes(a ^ b for a, b in zip(cipher, _keystream(enc_key, len(cipher))))


def encrypt_dir(src: Path, password: str) -> bytes:
    files = [p for p in sorted(src.rglob("*")) if p.is_file()]
    if not files:
        raise EmptySourceError(f"no files under {src}")
    buf = BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path in files:
            tar.add(path, arcname=str(path.relative_to(src)))
    return encrypt_bytes(buf.getvalue(), password)


def _safe_members(tar: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members = []
    for m in tar.getmembers():
        name = Path(m.name)
        if m.issym() or m.islnk() or name.is_absolute() or ".." in name.parts:
            raise DecryptError(f"unsafe tar member: {m.name}")
        members.append(m)
    return members


def decrypt_dir(blob: bytes, password: str, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    raw = decrypt_bytes(blob, password)
    with tarfile.open(fileobj=BytesIO(raw), mode="r:gz") as tar:
        members = _safe_members(tar)
        try:
            tar.extractall(dest, members=members, filter="data")
        except TypeError:
            tar.extractall(dest, members=members)
