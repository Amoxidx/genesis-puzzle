from __future__ import annotations

from genesis_puzzle.hashing import sha256d

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class Base58Error(ValueError):
    pass


def b58encode(data: bytes) -> str:
    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    number = int.from_bytes(data, "big")
    chars = []
    while number > 0:
        number, rem = divmod(number, 58)
        chars.append(ALPHABET[rem])
    return ("1" * pad) + "".join(reversed(chars))


def b58decode(text: str) -> bytes:
    pad = 0
    for char in text:
        if char == "1":
            pad += 1
        else:
            break
    number = 0
    for char in text:
        try:
            number = number * 58 + ALPHABET.index(char)
        except ValueError as exc:
            raise Base58Error("invalid base58 character") from exc
    if number == 0:
        body = b""
    else:
        length = (number.bit_length() + 7) // 8
        body = number.to_bytes(length, "big")
    return (b"\x00" * pad) + body


def base58check_encode(payload: bytes) -> str:
    return b58encode(payload + sha256d(payload)[:4])


def base58check_decode(text: str) -> bytes:
    raw = b58decode(text)
    if len(raw) < 4:
        raise Base58Error("truncated base58check")
    payload, checksum = raw[:-4], raw[-4:]
    if sha256d(payload)[:4] != checksum:
        raise Base58Error("bad base58check checksum")
    return payload
