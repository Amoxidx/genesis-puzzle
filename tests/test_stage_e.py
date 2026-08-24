from __future__ import annotations

import re
from pathlib import Path

from genesis_puzzle.candidates import (
    compute_scalar,
    dedupe_valid_scalars,
    evaluate_recipe,
    preview_for_stage,
    preview_lines,
    recipes_for_stage,
    stage_a_recipes,
)
from genesis_puzzle.crypto import scalar_is_valid
from genesis_puzzle.hashing import fingerprint_scalar, sha256
from genesis_puzzle.stage_b import stage_b_recipes
from genesis_puzzle.stage_c import stage_c_recipes
from genesis_puzzle.stage_d import stage_d_recipes

try:
    from genesis_puzzle.stage_e import STAGE_E_DATE_STRINGS, stage_e_recipes
except ImportError:

    def stage_e_recipes(_block):
        raise AssertionError("stage_e_recipes is not implemented on this tree")

    STAGE_E_DATE_STRINGS = (
        "2009-01-03T18:15:05Z",
        "2009-01-03 18:15:05 UTC",
        "2009-01-03",
        "03/Jan/2009",
        "03/01/2009",
        "01/03/2009",
        "03Jan2009",
        "20090103",
    )

EXPECTED_STAGE_E_COUNT = 8
EXPECTED_IDS = tuple(f"E-{index:03d}" for index in range(1, EXPECTED_STAGE_E_COUNT + 1))
FORBIDDEN_TRANSFORM_FRAGMENTS = (
    "sha256d",
    "identity_integer",
    "identity_bytes",
    "pbkdf",
    "bip39",
    "neighborhood",
    "brute",
    "gpu",
    "kdf",
    "concat",
    "window",
    "repeat",
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
    "nonce",
)


def _decimal_token_in_source(source_text: str, decimal: str) -> bool:
    return re.search(rf"(?<![0-9]){re.escape(decimal)}(?![0-9])", source_text) is not None


def _hex64_token_in_source(source_text: str, packed_hex: str) -> bool:
    return (
        re.search(
            rf"(?<![0-9a-fA-F]){re.escape(packed_hex)}(?![0-9a-fA-F])",
            source_text,
            flags=re.IGNORECASE,
        )
        is not None
    )


def _log_like(recipe) -> str:
    return (
        f"{recipe.derivation_id} stage={recipe.stage} source={recipe.source} "
        f"representation={recipe.representation} transform={recipe.transformation} "
        f"formula={recipe.formula} recipe={recipe.recipe} "
        f"public_source={recipe.original_public_source} "
        f"public_input_hex={recipe.public_input_bytes.hex()}"
    )


def _public_blob(recipe) -> str:
    return "\n".join(
        (
            recipe.derivation_id,
            recipe.stage,
            recipe.source,
            recipe.representation,
            recipe.transformation,
            recipe.formula,
            recipe.recipe,
            recipe.original_public_source,
            recipe.public_input_bytes.hex(),
            _log_like(recipe),
        )
    )


def _expected_payloads() -> tuple[bytes, ...]:
    return tuple(value.encode("utf-8") for value in STAGE_E_DATE_STRINGS)


def _formula_for(payload: bytes) -> str:
    text = payload.decode("utf-8")
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'k = SHA256(b"{escaped}")'


def test_stage_e_count_ids_order_utf8_inputs_and_sha256_once(genesis_block):
    recipes = stage_e_recipes(genesis_block)
    payloads = _expected_payloads()
    assert STAGE_E_DATE_STRINGS == (
        "2009-01-03T18:15:05Z",
        "2009-01-03 18:15:05 UTC",
        "2009-01-03",
        "03/Jan/2009",
        "03/01/2009",
        "01/03/2009",
        "03Jan2009",
        "20090103",
    )
    assert len(recipes) == EXPECTED_STAGE_E_COUNT
    assert [recipe.derivation_id for recipe in recipes] == list(EXPECTED_IDS)
    assert recipes[0].derivation_id == "E-001"
    assert recipes[-1].derivation_id == "E-008"
    assert [recipe.public_input_bytes for recipe in recipes] == list(payloads)
    for index, recipe in enumerate(recipes):
        payload = payloads[index]
        date = STAGE_E_DATE_STRINGS[index]
        assert recipe.stage == "E"
        assert recipe.transformation == "sha256"
        assert recipe.public_input_bytes == date.encode("utf-8")
        assert recipe.public_input_bytes == payload
        assert recipe.public_input_bytes.decode("utf-8") == date
        assert recipe.public_input_bytes.endswith(b"\n") is False
        assert recipe.skip_curve is False
        assert recipe.direct_integer is None
        assert recipe.formula == _formula_for(payload)
        assert recipe.original_public_source == date or date in recipe.original_public_source
        assert recipe.recipe
        assert date in recipe.recipe
        assert "SHA256" in recipe.formula
        assert compute_scalar(recipe) == int.from_bytes(sha256(payload), "big")
        assert compute_scalar(recipe) != int.from_bytes(sha256(sha256(payload)), "big")


def test_stage_e_no_newline_case_whitespace_timezone_or_other_date_variants(genesis_block):
    recipes = stage_e_recipes(genesis_block)
    payloads = [recipe.public_input_bytes for recipe in recipes]
    joined = b"\n".join(payloads)
    assert b"2009-01-03T18:15:05+00:00" not in joined
    assert b"03 January 2009" not in joined
    assert b"Jan 3, 2009" not in joined
    for payload in payloads:
        assert payload.startswith(b"\n") is False
        assert payload.endswith(b"\n") is False
        assert b"\n" not in payload
        assert b"\r" not in payload
        assert payload.endswith(b" ") is False
        assert payload.startswith(b" ") is False
    assert b"2009-01-03T18:15:05Z\n" not in payloads[0]
    assert payloads[0] == b"2009-01-03T18:15:05Z"
    assert all(payload == payload.decode("utf-8").encode("utf-8") for payload in payloads)
    lowered = [payload.lower() for payload in payloads]
    assert lowered != payloads or all(b"jan" not in payload for payload in payloads[3:4])
    assert recipes[3].public_input_bytes == b"03/Jan/2009"
    assert recipes[3].public_input_bytes != b"03/jan/2009"
    assert recipes[3].public_input_bytes != b"03/JAN/2009"
    assert recipes[1].public_input_bytes == b"2009-01-03 18:15:05 UTC"
    assert recipes[1].public_input_bytes != b"2009-01-03  18:15:05 UTC"
    assert recipes[1].public_input_bytes != b"2009-01-03 18:15:05UTC"
    texts = [payload.decode("utf-8") for payload in payloads]
    assert texts == list(STAGE_E_DATE_STRINGS)
    assert len(set(texts)) == EXPECTED_STAGE_E_COUNT


def test_stage_e_all_eight_valid_unique_and_disjoint_from_abcd(genesis_block):
    recipes = stage_e_recipes(genesis_block)
    pairs_e = [evaluate_recipe(recipe) for recipe in recipes]
    valid_e = [item for item, _scalar in pairs_e if item.valid]
    grouped_e = dedupe_valid_scalars(pairs_e)
    assert len(recipes) == EXPECTED_STAGE_E_COUNT
    assert len(valid_e) == EXPECTED_STAGE_E_COUNT
    assert len(grouped_e) == EXPECTED_STAGE_E_COUNT
    fingerprints = []
    for recipe, (evaluated, scalar) in zip(recipes, pairs_e):
        expected = int.from_bytes(sha256(recipe.public_input_bytes), "big")
        assert evaluated.valid is True
        assert scalar == expected
        assert scalar_is_valid(expected)
        assert evaluated.fingerprint == fingerprint_scalar(expected)
        fingerprints.append(evaluated.fingerprint)
    assert len(set(fingerprints)) == EXPECTED_STAGE_E_COUNT

    combined_abcd = (
        stage_a_recipes(genesis_block)
        + stage_b_recipes(genesis_block)
        + stage_c_recipes(genesis_block)
        + stage_d_recipes(genesis_block)
    )
    pairs_abcd = [evaluate_recipe(recipe) for recipe in combined_abcd]
    grouped_abcd = dedupe_valid_scalars(pairs_abcd)
    fps_abcd = {fp for fp, _scalar, _items in grouped_abcd}
    fps_e = {fp for fp, _scalar, _items in grouped_e}
    assert fps_e.isdisjoint(fps_abcd)
    unique_abcde = dedupe_valid_scalars(pairs_abcd + pairs_e)
    assert len(unique_abcde) == 167
    duplicate_count = sum(max(0, len(group) - 1) for _fp, _scalar, group in unique_abcde)
    assert duplicate_count == 21


def test_stage_e_order_is_deterministic_across_repeated_calls(genesis_block):
    first = stage_e_recipes(genesis_block)
    second = stage_e_recipes(genesis_block)
    assert [
        (
            r.derivation_id,
            r.source,
            r.representation,
            r.transformation,
            r.formula,
            r.original_public_source,
            r.public_input_bytes,
            r.stage,
        )
        for r in first
    ] == [
        (
            r.derivation_id,
            r.source,
            r.representation,
            r.transformation,
            r.formula,
            r.original_public_source,
            r.public_input_bytes,
            r.stage,
        )
        for r in second
    ]
    third = stage_e_recipes(genesis_block)
    assert [r.derivation_id for r in third] == list(EXPECTED_IDS)
    assert [r.public_input_bytes for r in third] == list(_expected_payloads())


def test_stage_e_public_surfaces_omit_computed_scalar(genesis_block):
    recipes = stage_e_recipes(genesis_block)
    preview = "\n".join(preview_lines(recipes))
    assert "private_scalar: REDACTED" in preview
    assert preview.startswith("E-001")
    for recipe in recipes:
        expected = compute_scalar(recipe)
        blob = _public_blob(recipe) + "\n" + preview
        packed_hex = f"{expected:064x}"
        decimal = str(expected)
        assert packed_hex not in blob
        assert packed_hex not in preview
        assert not _decimal_token_in_source(preview, decimal)
        assert not _hex64_token_in_source(preview, packed_hex)
        recipe_repr = repr(recipe)
        assert packed_hex not in recipe_repr
        assert "direct_integer" not in recipe_repr
        assert decimal not in recipe.formula
        assert decimal not in recipe.recipe


def test_stage_e_forbidden_transformations_and_fields_absent(genesis_block):
    recipes = stage_e_recipes(genesis_block)
    source_text = Path(stage_e_recipes.__code__.co_filename).read_text(encoding="utf-8")
    source_lower = source_text.lower()
    assert "sha256d" not in source_lower
    assert "pbkdf" not in source_lower
    assert "bip39" not in source_lower
    assert "gpu" not in source_lower
    assert "brute" not in source_lower
    assert "identity_integer" not in source_lower
    for recipe in recipes:
        assert recipe.transformation == "sha256"
        blob = " ".join(
            (
                recipe.transformation,
                recipe.representation,
                recipe.formula,
                recipe.recipe,
                recipe.source,
            )
        ).lower()
        for fragment in FORBIDDEN_TRANSFORM_FRAGMENTS:
            if fragment == "sha256":
                continue
            assert fragment not in blob
        for fragment in FORBIDDEN_FIELD_FRAGMENTS:
            assert fragment not in blob


def test_stage_e_computed_scalars_absent_from_stage_and_test_source(genesis_block):
    recipes = stage_e_recipes(genesis_block)
    source_paths = (
        Path(stage_e_recipes.__code__.co_filename),
        Path(__file__).resolve(),
    )
    texts = {path: path.read_text(encoding="utf-8") for path in source_paths}
    for recipe in recipes:
        value = compute_scalar(recipe)
        decimal = str(value)
        packed_hex = f"{value:064x}"
        for path, text in texts.items():
            assert not _decimal_token_in_source(text, decimal), (
                f"computed decimal found as token in {path}"
            )
            assert not _hex64_token_in_source(text, packed_hex), (
                f"computed 64-hex found as token in {path}"
            )


def test_recipes_for_stage_supports_e_and_preview_omits_scalars(genesis_block):
    expected = stage_e_recipes(genesis_block)
    recipes = recipes_for_stage(genesis_block, "E")
    assert recipes == expected
    assert len(recipes) == EXPECTED_STAGE_E_COUNT
    assert [recipe.derivation_id for recipe in recipes] == list(EXPECTED_IDS)
    preview = "\n".join(preview_for_stage(genesis_block, "E"))
    assert preview.startswith("E-001")
    assert "E-008" in preview
    assert "private_scalar: REDACTED" in preview
    for recipe in recipes:
        scalar = compute_scalar(recipe)
        assert str(scalar) not in preview
        assert f"{scalar:064x}" not in preview
    assert recipes_for_stage(genesis_block, "A") == stage_a_recipes(genesis_block)
    assert recipes_for_stage(genesis_block, "D") == stage_d_recipes(genesis_block)
