from __future__ import annotations

from typing import Iterable, List, Sequence, Tuple

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


class Bech32Error(ValueError):
    pass


def _polymod(values: Iterable[int]) -> int:
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= GEN[i]
    return chk


def _hrp_expand(hrp: str) -> List[int]:
    return [ord(ch) >> 5 for ch in hrp] + [0] + [ord(ch) & 31 for ch in hrp]


def _create_checksum(hrp: str, data: Sequence[int]) -> List[int]:
    values = _hrp_expand(hrp) + list(data)
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def convertbits(data: Sequence[int], frombits: int, tobits: int, pad: bool = True) -> List[int]:
    acc = 0
    bits = 0
    ret: List[int] = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or value >> frombits:
            raise Bech32Error("invalid convertbits value")
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise Bech32Error("invalid convertbits padding")
    return ret


def bech32_encode(hrp: str, data: Sequence[int]) -> str:
    combined = list(data) + _create_checksum(hrp, data)
    return hrp + "1" + "".join(CHARSET[d] for d in combined)


def encode_segwit_address(hrp: str, witver: int, witprog: bytes) -> str:
    if witver != 0:
        raise Bech32Error("Milestone 1 encodes witness version 0 only")
    data = [witver] + convertbits(list(witprog), 8, 5, pad=True)
    return bech32_encode(hrp, data)


def decode_bech32(address: str) -> Tuple[str, List[int]]:
    if address.lower() != address and address.upper() != address:
        raise Bech32Error("mixed case")
    lowered = address.lower()
    pos = lowered.rfind("1")
    if pos < 1 or pos + 7 > len(lowered):
        raise Bech32Error("invalid separator")
    hrp, data_part = lowered[:pos], lowered[pos + 1 :]
    data = []
    for char in data_part:
        try:
            data.append(CHARSET.index(char))
        except ValueError as exc:
            raise Bech32Error("invalid bech32 character") from exc
    if _polymod(_hrp_expand(hrp) + data) != 1:
        raise Bech32Error("invalid bech32 checksum")
    return hrp, data[:-6]


def decode_segwit_address(address: str) -> Tuple[str, int, bytes]:
    hrp, data = decode_bech32(address)
    if not data:
        raise Bech32Error("empty data")
    witver = data[0]
    decoded = convertbits(data[1:], 5, 8, pad=False)
    program = bytes(decoded)
    if witver == 0 and len(program) not in (20, 32):
        raise Bech32Error("invalid v0 program length")
    return hrp, witver, program
