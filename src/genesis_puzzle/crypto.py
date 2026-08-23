from __future__ import annotations

from typing import Tuple

from coincurve import PrivateKey

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class InvalidScalar(ValueError):
    pass


def scalar_is_valid(scalar: int) -> bool:
    return 1 <= scalar < SECP256K1_N


def require_valid_scalar(scalar: int) -> None:
    if not scalar_is_valid(scalar):
        raise InvalidScalar("scalar is not in [1, n)")


def derive_pubkeys(scalar: int) -> Tuple[bytes, bytes]:
    """Return (uncompressed, compressed) public keys. Never logs the scalar."""
    require_valid_scalar(scalar)
    secret = scalar.to_bytes(32, "big")
    key = PrivateKey(secret)
    uncompressed = key.public_key.format(compressed=False)
    compressed = key.public_key.format(compressed=True)
    secret = b"\x00" * 32
    del secret
    del key
    return uncompressed, compressed
