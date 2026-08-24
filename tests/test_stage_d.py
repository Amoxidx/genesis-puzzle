from __future__ import annotations

import re
from pathlib import Path

from genesis_puzzle.candidates import (
    compute_scalar,
    dedupe_valid_scalars,
    evaluate_recipe,
    preview_lines,
    stage_a_recipes,
)
from genesis_puzzle.crypto import scalar_is_valid
from genesis_puzzle.hashing import fingerprint_scalar
from genesis_puzzle.stage_b import stage_b_recipes
from genesis_puzzle.stage_c import stage_c_recipes
from genesis_puzzle.stage_d import stage_d_recipes

GENESIS_NONCE = 2083236893
GENESIS_TIMESTAMP = 1231006505
EXPECTED_STAGE_D_COUNT = 40
MIN_DISTANCE = 1
MAX_DISTANCE = 10
FORMULA_RE = re.compile(r"^k = uint\((nonce|timestamp)=(\d+)\) \+ \(([+-]\d+)\)$")
REPRESENTATION_RE = re.compile(r"^(nonce|timestamp)_signed_offset=([+-]\d+)$")
PUBLIC_SOURCE_RE = re.compile(r"^(nonce|timestamp)=(\d+) signed_offset=([+-]\d+)$")
FORBIDDEN_TRANSFORM_FRAGMENTS = (
    "sha256",
    "sha256d",
    "identity_bytes",
    "date",
    "pbkdf",
    "bip39",
    "neighborhood",
    "brute",
    "gpu",
    "kdf",
    "concat",
    "window",
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
EXPECTED_OFFSETS = (
    -1,
    1,
    -1,
    1,
    -2,
    2,
    -2,
    2,
    -3,
    3,
    -3,
    3,
    -4,
    4,
    -4,
    4,
    -5,
    5,
    -5,
    5,
    -6,
    6,
    -6,
    6,
    -7,
    7,
    -7,
    7,
    -8,
    8,
    -8,
    8,
    -9,
    9,
    -9,
    9,
    -10,
    10,
    -10,
    10,
)
EXPECTED_SOURCES = (
    "genesis.header.nonce",
    "genesis.header.nonce",
    "genesis.header.timestamp",
    "genesis.header.timestamp",
) * 10
EXPECTED_FIELDS = ("nonce", "nonce", "timestamp", "timestamp") * 10
EXPECTED_IDS = tuple(f"D-{index:03d}" for index in range(1, EXPECTED_STAGE_D_COUNT + 1))


def _spec_public(field: str) -> int:
    if field == "nonce":
        return GENESIS_NONCE
    if field == "timestamp":
        return GENESIS_TIMESTAMP
    raise AssertionError(f"unknown field {field!r}")


def _expected_directs() -> tuple[int, ...]:
    return tuple(
        _spec_public(field) + offset for field, offset in zip(EXPECTED_FIELDS, EXPECTED_OFFSETS)
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


def _signed(offset: int) -> str:
    return f"{offset:+d}"


def _spec_formula(field: str, offset: int) -> str:
    return f"k = uint({field}={_spec_public(field)}) + ({_signed(offset)})"


def _spec_representation(field: str, offset: int) -> str:
    return f"{field}_signed_offset={_signed(offset)}"


def _spec_public_source(field: str, offset: int) -> str:
    return f"{field}={_spec_public(field)} signed_offset={_signed(offset)}"


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


def test_stage_d_count_ids_order_source_offset_formula_and_directs(genesis_block):
    assert genesis_block.header.nonce == GENESIS_NONCE
    assert genesis_block.header.timestamp == GENESIS_TIMESTAMP
    recipes = stage_d_recipes(genesis_block)
    expected_directs = _expected_directs()
    assert len(recipes) == EXPECTED_STAGE_D_COUNT
    assert len(expected_directs) == EXPECTED_STAGE_D_COUNT
    assert len(EXPECTED_OFFSETS) == EXPECTED_STAGE_D_COUNT
    assert [recipe.derivation_id for recipe in recipes] == list(EXPECTED_IDS)
    assert recipes[0].derivation_id == "D-001"
    assert recipes[-1].derivation_id == "D-040"
    assert [recipe.source for recipe in recipes] == list(EXPECTED_SOURCES)
    assert [recipe.direct_integer for recipe in recipes] == list(expected_directs)
    assert recipes[0].direct_integer == GENESIS_NONCE - 1
    assert recipes[1].direct_integer == GENESIS_NONCE + 1
    assert recipes[2].direct_integer == GENESIS_TIMESTAMP - 1
    assert recipes[3].direct_integer == GENESIS_TIMESTAMP + 1
    assert recipes[-4].direct_integer == GENESIS_NONCE - 10
    assert recipes[-3].direct_integer == GENESIS_NONCE + 10
    assert recipes[-2].direct_integer == GENESIS_TIMESTAMP - 10
    assert recipes[-1].direct_integer == GENESIS_TIMESTAMP + 10
    for index, recipe in enumerate(recipes):
        field = EXPECTED_FIELDS[index]
        offset = EXPECTED_OFFSETS[index]
        public = _spec_public(field)
        assert recipe.stage == "D"
        assert recipe.transformation == "identity_integer"
        assert recipe.public_input_bytes == b""
        assert recipe.skip_curve is False
        assert recipe.direct_integer == public + offset
        assert recipe.formula == _spec_formula(field, offset)
        assert recipe.representation == _spec_representation(field, offset)
        assert recipe.original_public_source == _spec_public_source(field, offset)
        assert recipe.recipe
        assert field in recipe.recipe
        assert str(public) in recipe.recipe
        assert _signed(offset) in recipe.recipe
        assert str(recipe.direct_integer) not in recipe.recipe


def test_stage_d_zero_offset_absent_and_bounds_exactly_one_to_ten(genesis_block):
    recipes = stage_d_recipes(genesis_block)
    parsed_offsets = []
    for recipe in recipes:
        match = FORMULA_RE.fullmatch(recipe.formula)
        assert match is not None
        parsed_offsets.append(int(match.group(3)))
    assert 0 not in parsed_offsets
    assert parsed_offsets == list(EXPECTED_OFFSETS)
    magnitudes = sorted({abs(offset) for offset in parsed_offsets})
    assert magnitudes == list(range(MIN_DISTANCE, MAX_DISTANCE + 1))
    assert min(abs(offset) for offset in parsed_offsets) == 1
    assert max(abs(offset) for offset in parsed_offsets) == 10
    for recipe in recipes:
        assert "signed_offset=+0" not in recipe.original_public_source
        assert "signed_offset=-0" not in recipe.original_public_source
        assert "signed_offset=0" not in recipe.original_public_source
        assert recipe.direct_integer != GENESIS_NONCE
        assert recipe.direct_integer != GENESIS_TIMESTAMP


def test_stage_d_formula_is_sufficient_to_recompute(genesis_block):
    recipes = stage_d_recipes(genesis_block)
    for index, recipe in enumerate(recipes):
        match = FORMULA_RE.fullmatch(recipe.formula)
        assert match is not None
        field, public_text, offset_text = match.groups()
        public = int(public_text)
        offset = int(offset_text)
        assert field == EXPECTED_FIELDS[index]
        assert public == _spec_public(field)
        assert offset == EXPECTED_OFFSETS[index]
        recomputed = public + offset
        assert recomputed == _expected_directs()[index]
        assert recomputed == recipe.direct_integer
        assert compute_scalar(recipe) == recomputed
        representation = REPRESENTATION_RE.fullmatch(recipe.representation)
        public_source = PUBLIC_SOURCE_RE.fullmatch(recipe.original_public_source)
        assert representation is not None
        assert public_source is not None
        assert representation.group(1) == field
        assert int(representation.group(2)) == offset
        assert public_source.group(1) == field
        assert int(public_source.group(2)) == public
        assert int(public_source.group(3)) == offset


def test_stage_d_all_forty_valid_unique_and_disjoint_from_abc(genesis_block):
    recipes = stage_d_recipes(genesis_block)
    pairs_d = [evaluate_recipe(recipe) for recipe in recipes]
    valid_d = [item for item, scalar in pairs_d if item.valid]
    scalars_d = [scalar for _item, scalar in pairs_d]
    grouped_d = dedupe_valid_scalars(pairs_d)
    assert len(recipes) == EXPECTED_STAGE_D_COUNT
    assert len(valid_d) == EXPECTED_STAGE_D_COUNT
    assert len(grouped_d) == EXPECTED_STAGE_D_COUNT
    expected_directs = _expected_directs()
    assert None not in scalars_d
    assert scalars_d == list(expected_directs)
    assert all(scalar_is_valid(scalar) for scalar in scalars_d)
    fingerprints = []
    for _recipe, (evaluated, scalar), expected in zip(recipes, pairs_d, expected_directs):
        assert evaluated.valid is True
        assert scalar == expected
        assert evaluated.fingerprint == fingerprint_scalar(expected)
        fingerprints.append(evaluated.fingerprint)
    assert len(set(fingerprints)) == EXPECTED_STAGE_D_COUNT
    assert len(set(expected_directs)) == EXPECTED_STAGE_D_COUNT

    combined_abc = (
        stage_a_recipes(genesis_block)
        + stage_b_recipes(genesis_block)
        + stage_c_recipes(genesis_block)
    )
    pairs_abc = [evaluate_recipe(recipe) for recipe in combined_abc]
    grouped_abc = dedupe_valid_scalars(pairs_abc)
    fps_abc = {fp for fp, _scalar, _items in grouped_abc}
    fps_d = {fp for fp, _scalar, _items in grouped_d}
    assert fps_d.isdisjoint(fps_abc)
    assert GENESIS_NONCE not in scalars_d
    assert GENESIS_TIMESTAMP not in scalars_d


def test_stage_d_order_is_deterministic_across_repeated_calls(genesis_block):
    first = stage_d_recipes(genesis_block)
    second = stage_d_recipes(genesis_block)
    assert [
        (
            r.derivation_id,
            r.source,
            r.representation,
            r.transformation,
            r.formula,
            r.original_public_source,
            r.public_input_bytes,
            r.direct_integer,
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
            r.direct_integer,
            r.stage,
        )
        for r in second
    ]
    third = stage_d_recipes(genesis_block)
    assert [r.derivation_id for r in third] == list(EXPECTED_IDS)
    assert [r.direct_integer for r in third] == list(_expected_directs())


def test_stage_d_public_surfaces_omit_computed_scalar_and_empty_input(genesis_block):
    recipes = stage_d_recipes(genesis_block)
    preview = "\n".join(preview_lines(recipes))
    assert "private_scalar: REDACTED" in preview
    assert preview.startswith("D-001")
    for recipe, expected in zip(recipes, _expected_directs()):
        assert recipe.public_input_bytes == b""
        assert recipe.public_input_bytes.hex() == ""
        blob = _public_blob(recipe) + "\n" + preview
        assert str(expected) not in recipe.formula
        assert str(expected) not in recipe.recipe
        assert str(expected) not in recipe.representation
        assert str(expected) not in recipe.original_public_source
        assert str(expected) not in preview
        assert str(expected) not in _log_like(recipe)
        packed_hex = f"{expected:064x}"
        assert packed_hex not in blob
        assert packed_hex not in preview
        assert f"{expected:x}" not in recipe.representation
        assert f"{expected:x}" not in recipe.formula
        recipe_repr = repr(recipe)
        assert str(expected) not in recipe_repr
        assert packed_hex not in recipe_repr
        assert "direct_integer" not in recipe_repr


def test_stage_d_forbidden_transformations_and_fields_absent(genesis_block):
    recipes = stage_d_recipes(genesis_block)
    source_text = Path(stage_d_recipes.__code__.co_filename).read_text(encoding="utf-8")
    source_lower = source_text.lower()
    assert "sha256" not in source_lower
    assert "hashlib" not in source_lower
    assert "sha256d" not in source_lower
    assert "gpu" not in source_lower
    assert "brute" not in source_lower
    assert "pbkdf" not in source_lower
    assert "bip39" not in source_lower
    for recipe in recipes:
        assert recipe.transformation == "identity_integer"
        assert recipe.transformation != "sha256"
        assert recipe.transformation != "identity_bytes_be"
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
        assert "sha256" not in recipe.formula.lower()
        assert " + " in recipe.formula


def test_stage_d_computed_scalars_absent_from_stage_and_test_source():
    expected_directs = _expected_directs()
    allowed_public = {GENESIS_NONCE, GENESIS_TIMESTAMP}
    source_paths = (
        Path(stage_d_recipes.__code__.co_filename),
        Path(__file__).resolve(),
    )
    texts = {path: path.read_text(encoding="utf-8") for path in source_paths}
    assert len(expected_directs) == EXPECTED_STAGE_D_COUNT
    for value in expected_directs:
        assert value not in allowed_public
        decimal = str(value)
        packed_hex = f"{value:064x}"
        for path, text in texts.items():
            assert not _decimal_token_in_source(text, decimal), (
                f"computed decimal {decimal} found as token in {path}"
            )
            assert not _hex64_token_in_source(text, packed_hex), (
                f"computed 64-hex {packed_hex} found as token in {path}"
            )
