from __future__ import annotations

import pytest

from genesis_puzzle.hashing import sha256d
from genesis_puzzle.parser import (
    ParseError,
    ProofError,
    parse_genesis_block,
    parse_genesis_hex,
    verify_against_facts,
)


def test_parser_matches_canonical_constants(facts, genesis_block):
    header = genesis_block.header
    tx = genesis_block.coinbase
    assert header.version == 1
    assert header.timestamp == 1231006505
    assert header.bits == 0x1D00FFFF
    assert header.bits == 486604799
    assert facts.target_hex == ("00000000ffff0000000000000000000000000000000000000000000000000000")
    assert header.nonce == 2083236893
    assert header.prev_hash_wire == b"\x00" * 32
    assert genesis_block.block_hash_display_hex == (
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    )
    assert genesis_block.txid_display_hex == (
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    )
    assert tx.outputs[0].value_sats == 5000000000
    assert tx.headline == "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
    assert tx.pubkey.hex() == (
        "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
    )
    assert tx.raw.hex() == facts.raw_transaction_hex
    assert tx.inputs[0].script_sig.hex() == facts.script_sig_hex
    assert len(tx.inputs) == facts.input_count == 1
    assert len(tx.outputs) == facts.output_count == 1
    assert len(bytes.fromhex(facts.raw_block_hex)) == 285


def test_independent_hash_proofs(facts, genesis_block):
    header_hash = sha256d(genesis_block.header.raw)
    assert header_hash[::-1].hex() == facts.block_hash_display_hex
    txid = sha256d(genesis_block.coinbase.raw)
    assert txid[::-1].hex() == facts.txid_display_hex
    assert txid == genesis_block.header.merkle_root_wire
    assert genesis_block.txid_wire == genesis_block.header.merkle_root_wire


def test_truncated_block_is_rejected(facts):
    raw = bytes.fromhex(facts.raw_block_hex)
    with pytest.raises(ParseError, match="truncated"):
        parse_genesis_block(raw[:-1])


def test_trailing_bytes_are_rejected(facts):
    raw = bytes.fromhex(facts.raw_block_hex) + b"\x00"
    with pytest.raises(ParseError, match="trailing"):
        parse_genesis_block(raw)


def test_non_canonical_compact_size_rejected():
    # 80-byte zeros plus fd0100 (non-canonical compact size 1) is already invalid
    # as a full block; construct a compact-size-only failure via extra header.
    raw = bytes(80) + b"\xfd\x01\x00"
    with pytest.raises(ParseError):
        parse_genesis_block(raw)


def test_byte_mutation_breaks_verified_hash(facts, genesis_block):
    raw = bytearray(bytes.fromhex(facts.raw_block_hex))
    raw[4] ^= 0x01
    mutated = parse_genesis_block(bytes(raw))
    with pytest.raises(ProofError):
        verify_against_facts(mutated, facts)
    assert sha256d(mutated.header.raw)[::-1].hex() != facts.block_hash_display_hex


def test_invalid_hex_rejected():
    with pytest.raises(ParseError, match="invalid hex"):
        parse_genesis_hex("zz")
