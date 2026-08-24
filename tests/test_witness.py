from __future__ import annotations

import hashlib

import pytest

from genesis_puzzle.witness import (
    WITNESS_TEMPLATES,
    WitnessTemplate,
    build_p2wsh_candidates,
    compare_p2wsh_target,
    expected_witness_script,
    minimal_push,
)

# Independent secp256k1 generator / BIP173 P2WSH vector (k = 1).
UNCOMPRESSED_G = bytes.fromhex(
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)
COMPRESSED_G = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
HASH160_COMPRESSED_G = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
HASH160_UNCOMPRESSED_G = bytes.fromhex("91b24bf9f5288532960ac687abb035127b1d28a5")

BIP173_P2PK_COMPRESSED_SCRIPT = bytes.fromhex(
    "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac"
)
BIP173_P2PK_COMPRESSED_SHA256 = "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
BIP173_P2PK_COMPRESSED_ADDRESS = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"

EXPECTED_SCRIPTS = {
    "p2pk_compressed": BIP173_P2PK_COMPRESSED_SCRIPT,
    "p2pk_uncompressed": bytes.fromhex(
        "410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac"
    ),
    "multisig_1of1_compressed": bytes.fromhex(
        "51210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179851ae"
    ),
    "multisig_1of1_uncompressed": bytes.fromhex(
        "51410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b851ae"
    ),
    "p2pkh_compressed": bytes.fromhex("76a914") + HASH160_COMPRESSED_G + bytes.fromhex("88ac"),
    "p2pkh_uncompressed": bytes.fromhex("76a914") + HASH160_UNCOMPRESSED_G + bytes.fromhex("88ac"),
}

TEMPLATE_ORDER = (
    "p2pk_compressed",
    "p2pk_uncompressed",
    "multisig_1of1_compressed",
    "multisig_1of1_uncompressed",
    "p2pkh_compressed",
    "p2pkh_uncompressed",
)


def test_minimal_push_encodes_direct_length_prefix():
    assert minimal_push(COMPRESSED_G) == bytes([33]) + COMPRESSED_G
    assert minimal_push(UNCOMPRESSED_G) == bytes([65]) + UNCOMPRESSED_G
    assert minimal_push(HASH160_COMPRESSED_G) == bytes([20]) + HASH160_COMPRESSED_G
    with pytest.raises(ValueError):
        minimal_push(b"")
    with pytest.raises(ValueError):
        minimal_push(b"\x00" * 76)


def test_six_templates_exact_bytes_and_independent_sha256():
    candidates = build_p2wsh_candidates(UNCOMPRESSED_G, COMPRESSED_G)
    assert len(candidates) == 6
    by_name = {item.name: item for item in candidates}
    assert set(by_name) == set(EXPECTED_SCRIPTS)
    for name, expected_script in EXPECTED_SCRIPTS.items():
        item = by_name[name]
        assert item.witness_script == expected_script
        assert item.witness_script_hex == expected_script.hex()
        independent = hashlib.sha256(expected_script).digest()
        assert item.witness_program == independent
        assert item.witness_program_hex == independent.hex()
        assert item.address.startswith("bc1q")
        assert len(item.witness_program) == 32


def test_independent_k1_p2pk_compressed_bip173_vector():
    candidates = build_p2wsh_candidates(UNCOMPRESSED_G, COMPRESSED_G)
    p2pk = candidates[0]
    assert p2pk.name == "p2pk_compressed"
    assert p2pk.priority == 1
    assert p2pk.pubkey_mode == "compressed"
    assert p2pk.pubkey_hex == COMPRESSED_G.hex()
    assert p2pk.witness_script == BIP173_P2PK_COMPRESSED_SCRIPT
    assert p2pk.witness_script_hex == BIP173_P2PK_COMPRESSED_SCRIPT.hex()
    assert p2pk.witness_program_hex == BIP173_P2PK_COMPRESSED_SHA256
    assert p2pk.address == BIP173_P2PK_COMPRESSED_ADDRESS
    assert compare_p2wsh_target(
        p2pk, BIP173_P2PK_COMPRESSED_SHA256, BIP173_P2PK_COMPRESSED_ADDRESS
    )
    assert compare_p2wsh_target(
        p2pk, BIP173_P2PK_COMPRESSED_SHA256.upper(), BIP173_P2PK_COMPRESSED_ADDRESS
    )


def test_p2pkh_templates_use_hash160_of_the_matching_pubkey_mode():
    candidates = build_p2wsh_candidates(UNCOMPRESSED_G, COMPRESSED_G)
    by_name = {item.name: item for item in candidates}
    compressed = by_name["p2pkh_compressed"]
    uncompressed = by_name["p2pkh_uncompressed"]
    assert compressed.pubkey_hex == COMPRESSED_G.hex()
    assert uncompressed.pubkey_hex == UNCOMPRESSED_G.hex()
    assert HASH160_COMPRESSED_G.hex() in compressed.witness_script_hex
    assert HASH160_UNCOMPRESSED_G.hex() in uncompressed.witness_script_hex
    assert HASH160_UNCOMPRESSED_G.hex() not in compressed.witness_script_hex
    assert HASH160_COMPRESSED_G.hex() not in uncompressed.witness_script_hex


def test_deterministic_global_priority_order():
    first = build_p2wsh_candidates(UNCOMPRESSED_G, COMPRESSED_G)
    second = build_p2wsh_candidates(UNCOMPRESSED_G, COMPRESSED_G)
    assert [item.name for item in first] == list(TEMPLATE_ORDER)
    assert [item.priority for item in first] == [1, 2, 3, 4, 5, 6]
    assert [item.template_id for item in first] == list(TEMPLATE_ORDER)
    assert [item.pubkey_mode for item in first] == [
        "compressed",
        "uncompressed",
        "compressed",
        "uncompressed",
        "compressed",
        "uncompressed",
    ]
    assert [(item.template_id, item.witness_script_hex) for item in first] == [
        (item.template_id, item.witness_script_hex) for item in second
    ]
    assert [template.priority for template in WITNESS_TEMPLATES] == [1, 2, 3, 4, 5, 6]
    assert [template.name for template in WITNESS_TEMPLATES] == list(TEMPLATE_ORDER)


def test_exact_target_comparison_rejects_near_misses():
    candidates = build_p2wsh_candidates(UNCOMPRESSED_G, COMPRESSED_G)
    p2pk = candidates[0]
    other = candidates[1]
    assert compare_p2wsh_target(
        p2pk, BIP173_P2PK_COMPRESSED_SHA256, BIP173_P2PK_COMPRESSED_ADDRESS
    )
    assert not compare_p2wsh_target(
        other, BIP173_P2PK_COMPRESSED_SHA256, BIP173_P2PK_COMPRESSED_ADDRESS
    )
    assert not compare_p2wsh_target(
        p2pk, BIP173_P2PK_COMPRESSED_SHA256, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    )
    mutated_program = "19" + BIP173_P2PK_COMPRESSED_SHA256[2:]
    assert mutated_program != BIP173_P2PK_COMPRESSED_SHA256
    assert not compare_p2wsh_target(p2pk, mutated_program, BIP173_P2PK_COMPRESSED_ADDRESS)


def test_expected_witness_script_from_one_pubkey_matches_templates():
    for template in WITNESS_TEMPLATES:
        pubkey = COMPRESSED_G if template.pubkey_mode == "compressed" else UNCOMPRESSED_G
        assert expected_witness_script(template, pubkey) == EXPECTED_SCRIPTS[template.template_id]
    compressed = expected_witness_script(WITNESS_TEMPLATES[0], COMPRESSED_G)
    p2pkh_same_key = expected_witness_script(WITNESS_TEMPLATES[4], COMPRESSED_G)
    assert compressed != p2pkh_same_key
    with pytest.raises(ValueError, match="compressed pubkey"):
        expected_witness_script(WITNESS_TEMPLATES[0], UNCOMPRESSED_G)
    with pytest.raises(ValueError, match="uncompressed pubkey"):
        expected_witness_script(WITNESS_TEMPLATES[1], COMPRESSED_G)
    with pytest.raises(ValueError, match="compressed pubkey"):
        expected_witness_script(WITNESS_TEMPLATES[0], b"\x02" + b"\x00" * 31)
    fake = WitnessTemplate(
        template_id="not_a_template",
        name="not_a_template",
        priority=99,
        pubkey_mode="compressed",
        builder=WITNESS_TEMPLATES[0].builder,
    )
    with pytest.raises(ValueError, match="unknown witness template"):
        expected_witness_script(fake, COMPRESSED_G)


def test_wrong_serialization_lengths_and_prefixes_are_rejected():
    valid_uncompressed = UNCOMPRESSED_G
    valid_compressed = COMPRESSED_G
    with pytest.raises(ValueError, match="compressed pubkey"):
        build_p2wsh_candidates(valid_uncompressed, valid_uncompressed)
    with pytest.raises(ValueError, match="uncompressed pubkey"):
        build_p2wsh_candidates(valid_compressed, valid_compressed)
    with pytest.raises(ValueError, match="compressed pubkey"):
        build_p2wsh_candidates(valid_uncompressed, b"\x02" + b"\x00" * 31)
    with pytest.raises(ValueError, match="uncompressed pubkey"):
        build_p2wsh_candidates(b"\x04" + b"\x00" * 63, valid_compressed)
    with pytest.raises(ValueError, match="compressed pubkey"):
        build_p2wsh_candidates(valid_uncompressed, b"\x04" + valid_compressed[1:])
    with pytest.raises(ValueError, match="uncompressed pubkey"):
        build_p2wsh_candidates(b"\x06" + valid_uncompressed[1:], valid_compressed)
    with pytest.raises(ValueError, match="compressed pubkey"):
        build_p2wsh_candidates(valid_uncompressed, b"")
    with pytest.raises(ValueError, match="uncompressed pubkey"):
        build_p2wsh_candidates(b"", valid_compressed)
