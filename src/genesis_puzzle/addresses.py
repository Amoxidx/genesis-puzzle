from __future__ import annotations

from dataclasses import dataclass

from genesis_puzzle.base58 import base58check_encode
from genesis_puzzle.bech32 import encode_segwit_address
from genesis_puzzle.hashing import hash160


@dataclass(frozen=True)
class DerivedAddresses:
    pubkey_uncompressed_hex: str
    pubkey_compressed_hex: str
    p2pkh_uncompressed: str
    p2pkh_compressed: str
    p2wpkh: str


def p2pkh_from_pubkey(pubkey: bytes) -> str:
    payload = b"\x00" + hash160(pubkey)
    return base58check_encode(payload)


def p2wpkh_from_compressed_pubkey(pubkey: bytes) -> str:
    if len(pubkey) != 33 or pubkey[0] not in (2, 3):
        raise ValueError("P2WPKH requires a compressed public key")
    return encode_segwit_address("bc", 0, hash160(pubkey))


def derive_standard_addresses(uncompressed: bytes, compressed: bytes) -> DerivedAddresses:
    return DerivedAddresses(
        pubkey_uncompressed_hex=uncompressed.hex(),
        pubkey_compressed_hex=compressed.hex(),
        p2pkh_uncompressed=p2pkh_from_pubkey(uncompressed),
        p2pkh_compressed=p2pkh_from_pubkey(compressed),
        p2wpkh=p2wpkh_from_compressed_pubkey(compressed),
    )
