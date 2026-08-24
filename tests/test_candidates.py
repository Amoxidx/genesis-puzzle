from __future__ import annotations

from genesis_puzzle.candidates import (
    Recipe,
    compute_scalar,
    dedupe_valid_scalars,
    evaluate_recipe,
    stage_a_recipes,
)
from genesis_puzzle.crypto import scalar_is_valid


def test_first_eleven_order_and_formulas(genesis_block):
    recipes = stage_a_recipes(genesis_block)
    assert recipes[0].derivation_id == "A-01"
    first = [(r.source, r.transformation, r.formula) for r in recipes[:11]]
    assert first[0] == ("genesis.header.nonce", "identity_integer", "k = uint(nonce)")
    assert first[1][0] == "genesis.header.timestamp"
    assert first[2][0] == "genesis.header.bits"
    assert first[3] == ("genesis.header.nonce", "sha256", 'k = SHA256(b"2083236893")')
    assert first[4] == ("genesis.header.timestamp", "sha256", 'k = SHA256(b"1231006505")')
    assert first[5] == ("genesis.header.bits", "sha256", 'k = SHA256(b"1d00ffff")')
    assert recipes[6].source == "genesis.coinbase.headline"
    assert recipes[6].public_input_bytes == genesis_block.coinbase.headline.encode("utf-8")
    assert recipes[7].public_input_bytes == genesis_block.header.raw
    assert recipes[8].public_input_bytes == genesis_block.block_hash_wire
    assert recipes[9].public_input_bytes == genesis_block.header.merkle_root_wire
    assert recipes[10].public_input_bytes == genesis_block.coinbase.pubkey
    assert recipes[0].direct_integer == 2083236893
    assert recipes[1].direct_integer == 1231006505
    assert recipes[2].direct_integer == 0x1D00FFFF


def test_stage_a_includes_version_reward_height_and_hash_orders(genesis_block):
    recipes = stage_a_recipes(genesis_block)
    ids = [r.derivation_id for r in recipes]
    assert ids == [f"A-{i:02d}" for i in range(1, 24)]
    by_id = {r.derivation_id: r for r in recipes}
    assert by_id["A-12"].direct_integer == 1
    assert by_id["A-13"].direct_integer == 5000000000
    assert by_id["A-14"].direct_integer == 0
    assert by_id["A-14"].skip_curve is True
    assert by_id["A-15"].transformation == "identity_bytes_be"
    assert by_id["A-16"].public_input_bytes == genesis_block.block_hash_wire[::-1]
    assert by_id["A-17"].representation == "hash_wire"
    assert by_id["A-18"].representation == "hash_display"
    assert by_id["A-19"].formula == 'k = SHA256(b"1")'
    assert by_id["A-20"].formula == 'k = SHA256(b"5000000000")'
    assert by_id["A-21"].formula == 'k = SHA256(b"0")'
    assert by_id["A-22"].public_input_bytes == genesis_block.block_hash_wire[::-1]
    assert by_id["A-23"].public_input_bytes == genesis_block.header.merkle_root_wire[::-1]
    assert by_id["A-22"].transformation == "sha256"
    assert by_id["A-23"].transformation == "sha256"
    representations = {r.representation for r in recipes}
    assert "hash_wire" in representations
    assert "hash_display" in representations


def test_height_zero_is_invalid_and_not_a_valid_scalar(genesis_block):
    recipe = stage_a_recipes(genesis_block)[13]
    evaluated, scalar = evaluate_recipe(recipe)
    assert recipe.skip_curve
    assert evaluated.valid is False
    assert evaluated.fingerprint is None
    assert scalar is None
    assert evaluated.eliminated_reason == "height_zero_invalid_direct_scalar"
    assert not scalar_is_valid(0)


def test_deterministic_recipe_order(genesis_block):
    a = [r.derivation_id for r in stage_a_recipes(genesis_block)]
    b = [r.derivation_id for r in stage_a_recipes(genesis_block)]
    assert a == b


def test_deduplication_keeps_every_provenance_path():
    def make(derivation_id: str) -> Recipe:
        return Recipe(
            derivation_id=derivation_id,
            source="synthetic",
            original_public_source="1",
            representation="decimal_integer",
            public_input_bytes=b"1",
            transformation="identity_integer",
            formula="k = 1",
            confidence=0.1,
            stage="A",
            recipe="synthetic duplicate of scalar 1",
            direct_integer=1,
        )

    pairs = [evaluate_recipe(make("A-S1")), evaluate_recipe(make("A-S2"))]
    grouped = dedupe_valid_scalars(pairs)
    assert len(grouped) == 1
    _fp, scalar, items = grouped[0]
    assert scalar == 1
    assert [i.recipe.derivation_id for i in items] == ["A-S1", "A-S2"]


def test_preview_does_not_include_sha256_digest(genesis_block):
    from genesis_puzzle.candidates import preview_lines

    recipes = stage_a_recipes(genesis_block)
    text = "\n".join(preview_lines(recipes))
    digest = compute_scalar(recipes[3])
    assert f"{digest:064x}" not in text
    assert "private_scalar: REDACTED" in text


def test_recipes_for_stage_supports_a_b_and_c(genesis_block):
    from genesis_puzzle.candidates import recipes_for_stage, stage_a_recipes
    from genesis_puzzle.stage_b import stage_b_recipes
    from genesis_puzzle.stage_c import stage_c_recipes

    assert recipes_for_stage(genesis_block, "A") == stage_a_recipes(genesis_block)
    assert recipes_for_stage(genesis_block, "B") == stage_b_recipes(genesis_block)
    assert recipes_for_stage(genesis_block, "C") == stage_c_recipes(genesis_block)


def test_nonce_ascii_sha256_candidate_matches_expected_fingerprint(genesis_block):
    recipe = stage_a_recipes(genesis_block)[3]
    assert recipe.public_input_bytes == b"2083236893"
    evaluated, _scalar = evaluate_recipe(recipe)
    assert (
        evaluated.fingerprint == "d6cb232327bcefb8b740bc62aebe0b9bebb6717199ef2b4040841d4fff31fd77"
    )
