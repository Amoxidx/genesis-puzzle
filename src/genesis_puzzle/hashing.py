from __future__ import annotations

import hashlib


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256d(data: bytes) -> bytes:
    return sha256(sha256(data))


def _ripemd160(data: bytes) -> bytes:
    try:
        return hashlib.new("ripemd160", data).digest()
    except ValueError:
        return hashlib.new("ripemd160", data, usedforsecurity=False).digest()


def hash160(data: bytes) -> bytes:
    return _ripemd160(sha256(data))


def fingerprint_scalar(scalar: int) -> str:
    material = b"genesis-puzzle/fp/v1|" + scalar.to_bytes(32, "big")
    return sha256(material).hex()
