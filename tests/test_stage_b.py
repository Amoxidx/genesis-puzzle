from __future__ import annotations

from genesis_puzzle.candidates import (
    compute_scalar,
    dedupe_valid_scalars,
    evaluate_recipe,
    preview_for_stage,
    preview_lines,
    recipes_for_stage,
    stage_a_recipes,
)
from genesis_puzzle.hashing import fingerprint_scalar, sha256
from genesis_puzzle.parser import compact_target
from genesis_puzzle.stage_b import stage_b_recipes

EXPECTED_STAGE_B_COUNT = 105
EXPECTED_UNIQUE_VALID_SCALARS_A_PLUS_B = 105
FORBIDDEN_TRANSFORM_FRAGMENTS = (
    "combin",
    "date",
    "pbkdf",
    "bip39",
    "neighborhood",
    "sha256d",
    "brute",
    "whitespace",
    "pair",
)


def _by_source(recipes, source: str):
    return [recipe for recipe in recipes if recipe.source == source]


def test_stage_b_count_ids_and_confidence_order(genesis_block):
    recipes = stage_b_recipes(genesis_block)
    assert len(recipes) == EXPECTED_STAGE_B_COUNT
    assert recipes[0].derivation_id == "B-001"
    assert recipes[-1].derivation_id == f"B-{EXPECTED_STAGE_B_COUNT:03d}"
    assert [recipe.derivation_id for recipe in recipes] == [
        f"B-{index:03d}" for index in range(1, EXPECTED_STAGE_B_COUNT + 1)
    ]
    assert [recipe.confidence for recipe in recipes] == sorted(
        (recipe.confidence for recipe in recipes), reverse=True
    )
    assert recipes[0].source == "genesis.header.nonce"
    assert recipes[0].representation == "ascii_decimal_newline"
    assert recipes[0].public_input_bytes == b"2083236893\n"
    assert recipes[-1].source == "text.genesis_block"
    assert recipes[-1].public_input_bytes == b"genesis block"
    for recipe in recipes:
        assert recipe.stage == "B"
        assert recipe.source
        assert recipe.original_public_source
        assert recipe.representation
        assert recipe.public_input_bytes is not None
        assert len(recipe.public_input_bytes) >= 1
        assert recipe.transformation
        assert recipe.formula
        assert recipe.recipe
        assert recipe.derivation_id.startswith("B-")


def test_stage_b_order_is_stable_across_repeated_calls(genesis_block):
    first = stage_b_recipes(genesis_block)
    second = stage_b_recipes(genesis_block)
    assert [
        (r.derivation_id, r.source, r.representation, r.transformation, r.public_input_bytes)
        for r in first
    ] == [
        (r.derivation_id, r.source, r.representation, r.transformation, r.public_input_bytes)
        for r in second
    ]
    assert recipes_for_stage(genesis_block, "B") == first
    assert recipes_for_stage(genesis_block, "A") == stage_a_recipes(genesis_block)


def test_stage_b_integer_matrix_forms_and_skips(genesis_block):
    recipes = stage_b_recipes(genesis_block)
    nonce = _by_source(recipes, "genesis.header.nonce")
    version = _by_source(recipes, "genesis.header.version")
    reward = _by_source(recipes, "genesis.tx.reward_sats")
    height = _by_source(recipes, "genesis.height")
    nonce_value = genesis_block.header.nonce
    nonce_le = nonce_value.to_bytes(4, "little")
    nonce_be = nonce_value.to_bytes(4, "big")

    assert any(
        r.public_input_bytes == b"2083236893\n" and r.transformation == "sha256" for r in nonce
    )
    assert any(r.public_input_bytes == b"7c2bac1d" for r in nonce)
    assert any(r.public_input_bytes == b"7C2BAC1D" for r in nonce)
    assert any(r.public_input_bytes == b"0x7c2bac1d" for r in nonce)
    assert any(r.public_input_bytes == b"0X7C2BAC1D" for r in nonce)
    assert any(r.public_input_bytes == nonce_le and r.transformation == "sha256" for r in nonce)
    assert any(
        r.public_input_bytes == nonce_le and r.transformation == "identity_bytes_be" for r in nonce
    )
    assert any(r.public_input_bytes == nonce_be and r.transformation == "sha256" for r in nonce)
    assert any(
        r.public_input_bytes == nonce_be and r.transformation == "identity_bytes_be" for r in nonce
    )
    assert not any(
        r.public_input_bytes == b"2083236893" and r.transformation == "sha256" for r in nonce
    )
    assert all(len(r.public_input_bytes) != 3 for r in nonce if r.transformation == "sha256")

    assert any(r.public_input_bytes == b"\x01" and r.transformation == "sha256" for r in version)
    assert any(r.representation == "uint_be_minimal" for r in version)
    assert not any(r.representation == "ascii_hex_upper" for r in version)

    reward_min_be = (5000000000).to_bytes(5, "big")
    reward_min_le = (5000000000).to_bytes(5, "little")
    assert any(
        r.public_input_bytes == reward_min_be and r.representation == "uint_be_minimal"
        for r in reward
    )
    assert any(
        r.public_input_bytes == reward_min_le and r.representation == "uint_le_minimal"
        for r in reward
    )
    assert reward_min_be != reward_min_le

    height_zero_be = b"\x00" * 4
    height_ids = [r for r in height if r.transformation == "identity_bytes_be"]
    assert len(height_ids) == 1
    assert height_ids[0].public_input_bytes == height_zero_be
    assert height_ids[0].skip_curve is False
    evaluated, scalar = evaluate_recipe(height_ids[0])
    assert evaluated.valid is False
    assert scalar is None
    assert evaluated.eliminated_reason == "scalar_out_of_range"
    assert any(r.public_input_bytes == b"\x00" and r.transformation == "sha256" for r in height)
    assert not any(r.representation == "uint_be_fixed" for r in height)
    assert sum(1 for r in height if r.public_input_bytes == height_zero_be) == 2


def test_stage_b_hash_serialized_headline_and_semantic_forms(genesis_block):
    recipes = stage_b_recipes(genesis_block)
    representations = {recipe.representation for recipe in recipes}
    for required in (
        "ascii_decimal_newline",
        "ascii_hex_lower",
        "ascii_hex_upper",
        "ascii_hex_0x_lower",
        "ascii_hex_0X_upper",
        "uint_le_fixed",
        "uint_be_fixed",
        "uint_be_minimal",
        "uint_le_minimal",
        "hash_wire",
        "hash_display",
        "hash_wire_ascii_hex_lower",
        "hash_wire_ascii_hex_upper",
        "hash_display_ascii_hex_lower",
        "hash_display_ascii_hex_upper",
        "hash_display_ascii_hex_lower_newline",
        "raw_bytes",
        "raw_header",
        "raw_tx",
        "raw_script_sig",
        "raw_script_pubkey",
        "raw_pubkey",
        "raw_block",
        "utf8_newline",
        "utf8_lower",
        "utf8_upper",
        "utf8",
    ):
        assert required in representations

    merkle = _by_source(recipes, "genesis.merkle_root")
    txid = _by_source(recipes, "genesis.txid")
    assert len(merkle) == 7
    assert len(txid) == 7
    merkle_by_repr = {(r.representation, r.transformation): r for r in merkle}
    txid_by_repr = {(r.representation, r.transformation): r for r in txid}
    assert set(merkle_by_repr) == set(txid_by_repr)
    for key, merkle_recipe in merkle_by_repr.items():
        assert merkle_recipe.public_input_bytes == txid_by_repr[key].public_input_bytes
        assert merkle_recipe.source != txid_by_repr[key].source

    target_bytes = compact_target(genesis_block.header.bits).to_bytes(32, "big")
    target = _by_source(recipes, "genesis.header.target")
    assert any(r.public_input_bytes == target_bytes for r in target)
    assert all(r.public_input_bytes != target_bytes[::-1] for r in target)
    assert all(r.public_input_bytes != target_bytes[::-1].hex().encode("ascii") for r in target)

    prev = _by_source(recipes, "genesis.header.previous_hash")
    assert any(r.public_input_bytes == genesis_block.header.prev_hash_wire for r in prev)
    assert not any(r.representation.startswith("hash_display") for r in prev)

    headline = genesis_block.coinbase.headline
    headline_recipes = _by_source(recipes, "genesis.coinbase.headline")
    assert {r.representation for r in headline_recipes} == {
        "utf8_newline",
        "utf8_lower",
        "utf8_upper",
    }
    assert not any(r.public_input_bytes == headline.encode("utf-8") for r in headline_recipes)

    semantic = {
        r.original_public_source: r.public_input_bytes
        for r in recipes
        if r.source.startswith("text.")
    }
    assert semantic == {
        "Satoshi Nakamoto": b"Satoshi Nakamoto",
        "Bitcoin": b"Bitcoin",
        "genesis": b"genesis",
        "genesis block": b"genesis block",
    }


def test_stage_b_no_within_source_byte_transform_duplicates(genesis_block):
    recipes = stage_b_recipes(genesis_block)
    seen_by_source = {}
    for recipe in recipes:
        key = (recipe.public_input_bytes, recipe.transformation)
        bucket = seen_by_source.setdefault(recipe.source, set())
        assert key not in bucket
        bucket.add(key)


def test_stage_b_excludes_combination_date_and_kdf_transforms(genesis_block):
    recipes = stage_b_recipes(genesis_block)
    allowed = {"sha256", "identity_bytes_be"}
    for recipe in recipes:
        assert recipe.transformation in allowed
        blob = " ".join(
            (
                recipe.transformation,
                recipe.representation,
                recipe.formula,
                recipe.recipe,
            )
        ).lower()
        for fragment in FORBIDDEN_TRANSFORM_FRAGMENTS:
            assert fragment not in blob
        assert recipe.transformation != "identity_integer"
        assert "sha256d" not in recipe.formula.lower()


def test_stage_b_newline_recipe_has_deterministic_fingerprint(genesis_block):
    recipes = stage_b_recipes(genesis_block)
    payload = b"2083236893\n"
    recipe = next(
        item
        for item in recipes
        if item.source == "genesis.header.nonce" and item.public_input_bytes == payload
    )
    assert recipe.transformation == "sha256"
    expected_fp = fingerprint_scalar(int.from_bytes(sha256(payload), "big"))
    evaluated, _scalar = evaluate_recipe(recipe)
    assert evaluated.valid is True
    assert evaluated.fingerprint == expected_fp
    endian_payload = genesis_block.header.nonce.to_bytes(4, "little")
    endian_recipe = next(
        item
        for item in recipes
        if item.source == "genesis.header.nonce"
        and item.public_input_bytes == endian_payload
        and item.transformation == "sha256"
    )
    endian_fp = fingerprint_scalar(int.from_bytes(sha256(endian_payload), "big"))
    endian_evaluated, _endian_scalar = evaluate_recipe(endian_recipe)
    assert endian_evaluated.fingerprint == endian_fp


def test_stage_b_preview_redacts_scalars_and_is_reusable(genesis_block):
    recipes = stage_b_recipes(genesis_block)
    text = "\n".join(preview_lines(recipes))
    digest = compute_scalar(recipes[0])
    assert f"{digest:064x}" not in text
    assert "private_scalar: REDACTED" in text
    assert "B-001" in text
    preview = preview_for_stage(genesis_block, "B")
    assert preview == preview_lines(recipes)
    assert preview[0].startswith("B-001")


def test_stage_a_plus_b_unique_valid_scalar_count(genesis_block):
    combined = stage_a_recipes(genesis_block) + stage_b_recipes(genesis_block)
    pairs = [evaluate_recipe(recipe) for recipe in combined]
    grouped = dedupe_valid_scalars(pairs)
    valid = [item for item, _scalar in pairs if item.valid]
    assert len(combined) == 23 + EXPECTED_STAGE_B_COUNT
    assert len(grouped) == EXPECTED_UNIQUE_VALID_SCALARS_A_PLUS_B
    assert len(valid) == 126
    assert len(valid) >= len(grouped)
