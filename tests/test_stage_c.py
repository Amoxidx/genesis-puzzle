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
from genesis_puzzle.stage_b import stage_b_recipes
from genesis_puzzle.stage_c import STAGE_C_SEPARATORS, stage_c_recipes

EXPECTED_STAGE_C_COUNT = 14
EXPECTED_NEW_UNIQUE_VALID = 14
EXPECTED_CUMULATIVE_UNIQUE_A_B_C = 119
FORBIDDEN_TRANSFORM_FRAGMENTS = (
    "date",
    "pbkdf",
    "bip39",
    "neighborhood",
    "sha256d",
    "brute",
    "kdf",
)
FORBIDDEN_FIELD_FRAGMENTS = (
    "bits",
    "version",
    "reward",
    "height",
    "merkle",
    "pubkey",
    "headline",
    "block_hash",
    "previous",
    "script",
    "target",
    "txid",
)
GENESIS_NONCE_ASCII = b"2083236893"
GENESIS_TIMESTAMP_ASCII = b"1231006505"
SEPARATOR_BYTES = (b"", b":", b"|", b"-", b"_", b" ", b"\n")


def _expected_payloads() -> list[bytes]:
    payloads: list[bytes] = []
    for separator in SEPARATOR_BYTES:
        payloads.append(GENESIS_NONCE_ASCII + separator + GENESIS_TIMESTAMP_ASCII)
        payloads.append(GENESIS_TIMESTAMP_ASCII + separator + GENESIS_NONCE_ASCII)
    return payloads


def test_stage_c_count_ids_and_separator_constant(genesis_block):
    recipes = stage_c_recipes(genesis_block)
    assert len(recipes) == EXPECTED_STAGE_C_COUNT
    assert [recipe.derivation_id for recipe in recipes] == [
        f"C-{index:03d}" for index in range(1, EXPECTED_STAGE_C_COUNT + 1)
    ]
    assert [separator.name for separator in STAGE_C_SEPARATORS] == [
        "empty string",
        "colon",
        "pipe",
        "hyphen",
        "underscore",
        "ASCII space",
        "ASCII newline",
    ]
    assert [separator.token for separator in STAGE_C_SEPARATORS] == [
        '""',
        '":"',
        '"|"',
        '"-"',
        '"_"',
        '" "',
        r'"\n"',
    ]
    assert [separator.value for separator in STAGE_C_SEPARATORS] == list(SEPARATOR_BYTES)
    assert [recipe.confidence for recipe in recipes] == sorted(
        (recipe.confidence for recipe in recipes), reverse=True
    )
    for recipe in recipes:
        assert recipe.stage == "C"
        assert recipe.source == "genesis.header.nonce_and_timestamp"
        assert recipe.original_public_source
        assert recipe.representation
        assert recipe.public_input_bytes is not None
        assert recipe.transformation == "sha256"
        assert recipe.formula
        assert recipe.recipe
        assert recipe.direct_integer is None
        assert recipe.skip_curve is False


def test_stage_c_byte_payload_order(genesis_block):
    recipes = stage_c_recipes(genesis_block)
    assert [recipe.public_input_bytes for recipe in recipes] == _expected_payloads()


def test_stage_c_first_and_newline_last_independent_sha256_fingerprint(genesis_block):
    recipes = stage_c_recipes(genesis_block)
    payloads = _expected_payloads()
    first_payload = payloads[0]
    newline_last_payload = payloads[-1]
    assert first_payload == GENESIS_NONCE_ASCII + GENESIS_TIMESTAMP_ASCII
    assert newline_last_payload == GENESIS_TIMESTAMP_ASCII + b"\n" + GENESIS_NONCE_ASCII
    assert recipes[0].derivation_id == "C-001"
    assert recipes[-1].derivation_id == "C-014"
    assert recipes[0].public_input_bytes == first_payload
    assert recipes[-1].public_input_bytes == newline_last_payload
    for recipe, payload in (
        (recipes[0], first_payload),
        (recipes[-1], newline_last_payload),
    ):
        expected_fp = fingerprint_scalar(int.from_bytes(sha256(payload), "big"))
        evaluated, _scalar = evaluate_recipe(recipe)
        assert evaluated.valid is True
        assert evaluated.fingerprint == expected_fp
        assert compute_scalar(recipe) == int.from_bytes(sha256(payload), "big")


def test_stage_c_order_is_stable_across_repeated_calls(genesis_block):
    first = stage_c_recipes(genesis_block)
    second = stage_c_recipes(genesis_block)
    assert [
        (r.derivation_id, r.source, r.representation, r.transformation, r.public_input_bytes)
        for r in first
    ] == [
        (r.derivation_id, r.source, r.representation, r.transformation, r.public_input_bytes)
        for r in second
    ]


def test_stage_c_only_sha256_and_excludes_forbidden_transforms_and_fields(genesis_block):
    recipes = stage_c_recipes(genesis_block)
    for recipe in recipes:
        assert recipe.transformation == "sha256"
        blob = " ".join(
            (
                recipe.transformation,
                recipe.representation,
                recipe.formula,
                recipe.recipe,
                recipe.source,
                recipe.original_public_source,
            )
        ).lower()
        for fragment in FORBIDDEN_TRANSFORM_FRAGMENTS:
            assert fragment not in blob
        for fragment in FORBIDDEN_FIELD_FRAGMENTS:
            assert fragment not in blob
        assert recipe.transformation != "identity_integer"
        assert recipe.transformation != "identity_bytes_be"
        assert "sha256d" not in recipe.formula.lower()


def test_stage_c_distinct_valid_scalars_no_overlap_with_a_plus_b(genesis_block):
    stage_c = stage_c_recipes(genesis_block)
    pairs_c = [evaluate_recipe(recipe) for recipe in stage_c]
    grouped_c = dedupe_valid_scalars(pairs_c)
    valid_c = [item for item, _scalar in pairs_c if item.valid]
    assert len(stage_c) == EXPECTED_STAGE_C_COUNT
    assert len(valid_c) == EXPECTED_STAGE_C_COUNT
    assert len(grouped_c) == EXPECTED_NEW_UNIQUE_VALID

    combined_ab = stage_a_recipes(genesis_block) + stage_b_recipes(genesis_block)
    pairs_ab = [evaluate_recipe(recipe) for recipe in combined_ab]
    grouped_ab = dedupe_valid_scalars(pairs_ab)
    fps_ab = {fp for fp, _scalar, _items in grouped_ab}
    fps_c = {fp for fp, _scalar, _items in grouped_c}
    assert fps_c.isdisjoint(fps_ab)

    combined_abc = combined_ab + stage_c
    grouped_abc = dedupe_valid_scalars([evaluate_recipe(recipe) for recipe in combined_abc])
    assert len(grouped_abc) == EXPECTED_CUMULATIVE_UNIQUE_A_B_C
    assert len(grouped_abc) == len(grouped_ab) + EXPECTED_NEW_UNIQUE_VALID


def test_stage_c_preview_redacts_scalars(genesis_block):
    recipes = stage_c_recipes(genesis_block)
    text = "\n".join(preview_lines(recipes))
    digest = compute_scalar(recipes[0])
    assert f"{digest:064x}" not in text
    assert "private_scalar: REDACTED" in text
    assert "C-001" in text
    assert recipes_for_stage(genesis_block, "C") == recipes
    preview = preview_for_stage(genesis_block, "C")
    assert preview == preview_lines(recipes)
    assert preview[0].startswith("C-001")
