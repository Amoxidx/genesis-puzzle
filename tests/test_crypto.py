from __future__ import annotations

import hashlib

import pytest

from genesis_puzzle.addresses import (
    derive_standard_addresses,
    p2pkh_from_pubkey,
    p2wpkh_from_compressed_pubkey,
)
from genesis_puzzle.base58 import base58check_decode, base58check_encode
from genesis_puzzle.bech32 import decode_segwit_address
from genesis_puzzle.crypto import InvalidScalar, derive_pubkeys, require_valid_scalar
from genesis_puzzle.hashing import hash160, sha256, sha256d

# Independent reference literals (NIST / BIP173 / well-known secp256k1 generator).
SHA256_EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
SHA256D_EMPTY = "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
UNCOMPRESSED_G = (
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)
COMPRESSED_G = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
HASH160_COMPRESSED_G = "751e76e8199196d454941c45d1b3a323f1433bd6"
HASH160_UNCOMPRESSED_G = "91b24bf9f5288532960ac687abb035127b1d28a5"
P2PKH_UNCOMPRESSED_K1 = "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"
P2PKH_COMPRESSED_K1 = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
P2WPKH_K1 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"


def test_sha256_reference_vectors():
    assert sha256(b"").hex() == SHA256_EMPTY
    assert sha256(b"abc").hex() == SHA256_ABC
    assert sha256d(b"").hex() == SHA256D_EMPTY
    assert hashlib.sha256(b"abc").hexdigest() == SHA256_ABC


def test_hash160_and_addresses_for_key_1():
    uncompressed, compressed = derive_pubkeys(1)
    assert uncompressed.hex() == UNCOMPRESSED_G
    assert compressed.hex() == COMPRESSED_G
    assert hash160(compressed).hex() == HASH160_COMPRESSED_G
    assert hash160(uncompressed).hex() == HASH160_UNCOMPRESSED_G
    assert p2pkh_from_pubkey(uncompressed) == P2PKH_UNCOMPRESSED_K1
    assert p2pkh_from_pubkey(compressed) == P2PKH_COMPRESSED_K1
    assert p2wpkh_from_compressed_pubkey(compressed) == P2WPKH_K1
    addrs = derive_standard_addresses(uncompressed, compressed)
    assert addrs.p2pkh_uncompressed == P2PKH_UNCOMPRESSED_K1
    assert addrs.p2pkh_compressed == P2PKH_COMPRESSED_K1
    assert addrs.p2wpkh == P2WPKH_K1


def test_base58check_roundtrip_and_checksum():
    payload = bytes.fromhex("00" + HASH160_COMPRESSED_G)
    encoded = base58check_encode(payload)
    assert encoded == P2PKH_COMPRESSED_K1
    assert base58check_decode(encoded) == payload


def test_bech32_p2wpkh_and_p2wsh_vector(targets):
    hrp, witver, prog = decode_segwit_address(P2WPKH_K1)
    assert hrp == "bc"
    assert witver == 0
    assert prog.hex() == HASH160_COMPRESSED_G
    target = targets[0]
    hrp2, witver2, prog2 = decode_segwit_address(target.address)
    assert hrp2 == "bc"
    assert witver2 == 0
    assert prog2.hex() == target.witness_program_hex
    assert len(prog2) == 32
    assert target.script_pubkey_hex == "0020" + target.witness_program_hex
    assert target.label == "suspected_puzzle_output"


def test_invalid_scalar_zero_never_reaches_curve():
    with pytest.raises(InvalidScalar):
        require_valid_scalar(0)
    with pytest.raises(InvalidScalar):
        derive_pubkeys(0)
