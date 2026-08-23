from __future__ import annotations

import io
import re
from pathlib import Path

from genesis_puzzle.addresses import DerivedAddresses, derive_standard_addresses
from genesis_puzzle.bech32 import encode_segwit_address
from genesis_puzzle.candidates import evaluate_recipe, stage_a_recipes
from genesis_puzzle.cli import main
from genesis_puzzle.config import ModeConfig
from genesis_puzzle.crypto import derive_pubkeys
from genesis_puzzle.engine import compare_targets, run_stage_a
from genesis_puzzle.model import KnownTarget
from genesis_puzzle.report import STAGE_C_SEPARATORS, render_report
from genesis_puzzle.storage import connect, counts, latest_run

IMMEDIATE_DUP_ID = re.compile(r"`((?:A|B)-\d+)`, `\1`")
PREVIOUS_HASH_LINE = "- previous hash: 32 zero bytes"


def _assert_no_report_duplication(text: str) -> None:
    assert text.count(PREVIOUS_HASH_LINE) == 1
    assert IMMEDIATE_DUP_ID.search(text) is None


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
    assert "Hypotheses tested in Stage B" in text
    assert "known-target address matches" in text
    assert "chain-history state: not checked" in text
    assert "Next highest-value Stage B experiment (not executed)" in text
    assert "run --stage B" in text
    assert "Next highest-value Stage C experiment (not executed)" not in text
    assert "not executed" in text.lower()
    assert "P2WSH" in text
    assert "Addresses with blockchain history" in text
    assert "No Stage B run stored yet" in text or "No Stage B run is stored" in text
    assert "Stage B, brute force" not in text
    assert "Do not execute that experiment in Milestone 1" not in text
    assert "unexecuted" not in text.lower()
    assert "tested witness candidates: 630" not in text
    assert "132 Stage-A-only" not in text or "Once Stage B is executed" in text
    _assert_no_report_duplication(text)


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


def _cli(isolated: Path, repo_root: Path, argv: list[str]) -> str:
    buf = io.StringIO()
    code = main(
        [
            "--root",
            str(repo_root),
            "--config",
            str(repo_root / "config.toml"),
            "--state-dir",
            str(isolated / "state"),
            "--report-path",
            str(isolated / "research" / "report.md"),
            *argv,
        ],
        out=buf,
    )
    assert code == 0, buf.getvalue()
    return buf.getvalue()


def test_report_stage_a_only_before_b(isolated, repo_root):
    _cli(isolated, repo_root, ["init"])
    _cli(isolated, repo_root, ["run", "--stage", "A", "--mode", "balanced"])
    report = (isolated / "research" / "report.md").read_text(encoding="utf-8")
    assert "Stage A+B report" in report
    assert "Stage A derivations: 23" in report
    assert "Stage A invalid derivations: 1" in report
    assert "Stage A unique valid keys: 22" in report
    assert "cumulative unique valid keys after Stage A: 22" in report
    assert "cumulative duplicate provenance paths after Stage A: 0" in report
    assert "No Stage B run is stored" in report
    assert "tested witness candidates: 630" not in report
    assert "executed full run tested 630" not in report
    assert "P2WSH direct target matches: 0" not in report
    assert "Next highest-value Stage B experiment (not executed)" in report
    assert "run --stage B" in report
    assert "Next highest-value Stage C experiment (not executed)" not in report
    assert "Stage B, brute force" not in report
    assert "unexecuted" not in report.lower()
    assert "Do not execute that experiment in Milestone 1" not in report
    assert "chain-history state: not checked" in report
    assert "does not need a blockchain-history lookup" in report
    assert report.count("bc1q") < 20
    _assert_no_report_duplication(report)
    assert (
        "direct 32-byte integer interpretation"
        not in report.split("Hypotheses tested in Stage B", 1)[-1].split("Stage B results", 1)[0]
    )


def test_report_stage_a_and_b_after_b(isolated, repo_root):
    _cli(isolated, repo_root, ["init"])
    _cli(isolated, repo_root, ["run", "--stage", "A", "--mode", "balanced"])
    _cli(isolated, repo_root, ["run", "--stage", "B", "--mode", "balanced"])
    report = (isolated / "research" / "report.md").read_text(encoding="utf-8")
    assert "Stage A+B report" in report
    assert "Stage A derivations: 23" in report
    assert "Stage A invalid derivations: 1" in report
    assert "Stage A unique valid keys: 22" in report
    assert "Stage B derivations: 105" in report
    assert "Stage B invalid derivations: 1" in report
    assert "cumulative unique valid keys after A+B: 105" in report
    assert "cumulative duplicate provenance paths after A+B: 21" in report
    assert "tested witness candidates: 630" in report
    assert "P2WSH direct target matches: 0" in report
    assert "132 Stage-A-only" in report
    assert "not an extra 132 on top of 630" in report
    assert "The executed Stage B run tested 630 witness candidates." in report
    assert "does not disprove" in report
    assert "suspected_not_proven" in report
    assert "descriptor-compatible" in report
    assert "not standard descriptor-compatible" in report
    assert "does not dump those rows" in report
    assert "Next highest-value Stage C experiment (not executed)" in report
    assert "2083236893" in report
    assert "1231006505" in report
    assert "No Stage B run is stored" not in report
    assert "Next highest-value Stage B experiment" not in report
    assert "run --stage B" not in report
    assert "Stage B, brute force" not in report
    assert "unexecuted" not in report.lower()
    assert "Do not execute that experiment in Milestone 1" not in report
    assert "priority 1: `p2pk_compressed`" in report
    assert "priority 6: `p2pkh_uncompressed`" in report
    assert "tested 105" in report
    assert report.count("bc1q") < 30
    _assert_no_report_duplication(report)
    stage_b_hypotheses = report.split("Hypotheses tested in Stage B", 1)[-1].split(
        "Stage B results", 1
    )[0]
    assert "32-byte integer interpretation" not in stage_b_hypotheses
    assert "canonical fixed 4-byte or" in stage_b_hypotheses
    assert "8-byte endian byte sequence" in stage_b_hypotheses
    sep_block = report.split("exactly these seven separators:", 1)[1]
    positions = [
        sep_block.index(f"{index}. {name} `{token}`")
        for index, (name, token) in enumerate(STAGE_C_SEPARATORS, start=1)
    ]
    assert positions == sorted(positions)


def test_stage_c_separators_exact_names_tokens_and_report_order(facts, targets):
    assert [name for name, _token in STAGE_C_SEPARATORS] == [
        "empty string",
        "colon",
        "pipe",
        "hyphen",
        "underscore",
        "ASCII space",
        "ASCII newline",
    ]
    assert [token for _name, token in STAGE_C_SEPARATORS] == [
        '""',
        '":"',
        '"|"',
        '"-"',
        '"_"',
        '" "',
        r'"\n"',
    ]
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
            "witness_candidates": 0,
            "witness_matches": 0,
        },
        {"stage": "B", "status": "ok", "mode": "balanced", "notes": "checkpoint-not-needed"},
        [],
        [],
        [],
        [],
        stage_b_run={
            "status": "ok",
            "mode": "balanced",
            "notes": "checkpoint-not-needed",
            "derivation_count": 105,
            "invalid_count": 1,
            "unique_valid_keys": 105,
            "duplicate_count": 21,
            "tested_candidate_count": 630,
        },
    )
    assert "Next highest-value Stage C experiment (not executed)" in text
    assert "Next highest-value Stage B experiment (not executed)" not in text
    block = text.split("exactly these seven separators:", 1)[1]
    rendered = [
        f"{index}. {name} `{token}`"
        for index, (name, token) in enumerate(STAGE_C_SEPARATORS, start=1)
    ]
    positions = [block.index(line) for line in rendered]
    assert positions == sorted(positions)
    assert [token for _name, token in STAGE_C_SEPARATORS][2] == '"|"'
    assert '","' not in "".join(token for _name, token in STAGE_C_SEPARATORS)
    _assert_no_report_duplication(text)
