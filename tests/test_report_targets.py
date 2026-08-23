from __future__ import annotations

import io

from genesis_puzzle.addresses import DerivedAddresses, derive_standard_addresses
from genesis_puzzle.bech32 import encode_segwit_address
from genesis_puzzle.candidates import evaluate_recipe, stage_a_recipes
from genesis_puzzle.config import ModeConfig
from genesis_puzzle.crypto import derive_pubkeys
from genesis_puzzle.engine import compare_targets, run_stage_a
from genesis_puzzle.model import KnownTarget
from genesis_puzzle.report import render_report
from genesis_puzzle.storage import connect, counts, latest_run


def test_known_target_is_p2wsh_and_not_directly_comparable(targets):
    target = targets[0]
    assert target.label == "suspected_puzzle_output"
    assert target.script_type == "p2wsh"
    assert target.comparable_with_stage_a is False
    encoded = encode_segwit_address("bc", 0, bytes.fromhex(target.witness_program_hex))
    assert encoded == target.address


def test_compare_targets_does_not_claim_p2wsh_match(targets):
    addrs = DerivedAddresses(
        pubkey_uncompressed_hex="00",
        pubkey_compressed_hex="00",
        p2pkh_uncompressed="1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
        p2pkh_compressed="1BgGZ9tcN4rm9KBzDn7K2Qz4xEK4jP5WDq",
        p2wpkh="bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    )
    rows = compare_targets(addrs, targets)
    assert rows
    assert all(matched is False for *_, matched, _note in rows)
    assert all(comparable is False for *_rest, comparable, _matched, _note in rows)


def test_report_template_contains_required_sections(facts, targets):
    text = render_report(
        facts,
        targets,
        {
            "derivations": 0,
            "invalid": 0,
            "unique_keys": 0,
            "p2pkh_uncompressed": 0,
            "p2pkh_compressed": 0,
            "p2wpkh": 0,
            "target_matches": 0,
        },
        None,
        [],
        [],
        [],
    )
    assert "Puzzle statement" in text
    assert "Known public facts" in text
    assert "Verified Genesis data" in text
    assert "Hypotheses tested in Stage A" in text
    assert "known-target matches" in text
    assert "chain-history state: not checked" in text
    assert "Next highest-value Stage B experiment" in text
    assert "not executed" in text.lower()
    assert "P2WSH" in text
    assert "Addresses with blockchain history" in text


def test_stage_stops_after_comparable_known_target_match(tmp_path, genesis_block):
    first_recipe = stage_a_recipes(genesis_block)[0]
    _evaluated, scalar = evaluate_recipe(first_recipe)
    assert scalar is not None
    uncompressed, compressed = derive_pubkeys(scalar)
    target_address = derive_standard_addresses(uncompressed, compressed).p2pkh_uncompressed
    target = KnownTarget(
        id="synthetic-known-target",
        label="test-only",
        status="known",
        txid="00" * 32,
        block_height=0,
        block_time=0,
        value_sats=1,
        address=target_address,
        script_type="p2pkh",
        script_pubkey_hex="",
        witness_program_hex="",
        comparable_with_stage_a=True,
        notes="test-only comparable target",
    )
    store = connect(tmp_path / "state" / "research.sqlite")
    output = io.StringIO()
    result = run_stage_a(
        store,
        genesis_block,
        [target],
        ModeConfig("balanced", 1, 1.0, 0.0, "test"),
        out=output,
    )

    assert result["potential_match"] is True
    assert result["addresses"] == 3
    assert result["unique_valid_keys"] == 1
    assert counts(store.conn)["unique_keys"] == 1
    assert latest_run(store.conn)["unique_valid_keys"] == 1
    assert "POTENTIAL MATCH FOUND" in output.getvalue()
    assert f"{scalar:064x}" not in output.getvalue()
