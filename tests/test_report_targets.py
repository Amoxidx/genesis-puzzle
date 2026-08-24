from __future__ import annotations

import io
import re
from pathlib import Path

from genesis_puzzle.addresses import DerivedAddresses, derive_standard_addresses
from genesis_puzzle.bech32 import encode_segwit_address
from genesis_puzzle.candidates import evaluate_recipe, stage_a_recipes
from genesis_puzzle.cli import _write_current_report, main
from genesis_puzzle.config import ModeConfig
from genesis_puzzle.crypto import derive_pubkeys
from genesis_puzzle.engine import compare_targets, run_stage_a
from genesis_puzzle.model import KnownTarget
from genesis_puzzle.report import STAGE_C_SEPARATORS, STAGE_E_DATE_STRINGS, render_report
from genesis_puzzle.stage_c import STAGE_C_SEPARATORS as STAGE_C_SEPARATORS_SOURCE
from genesis_puzzle.storage import (
    connect,
    counts,
    finish_run,
    insert_run,
    invalidate_stage_c_current_state,
    latest_run,
    upsert_derivation,
    upsert_key,
    upsert_witness_candidate,
)
from genesis_puzzle.witness import WITNESS_TEMPLATES

IMMEDIATE_DUP_ID = re.compile(r"`((?:A|B|C|D)-\d+)`, `\1`")
PREVIOUS_HASH_LINE = "- previous hash: 32 zero bytes"
EMPTY_COUNTS = {
    "derivations": 0,
    "invalid": 0,
    "unique_keys": 0,
    "p2pkh_uncompressed": 0,
    "p2pkh_compressed": 0,
    "p2wpkh": 0,
    "target_matches": 0,
    "witness_candidates": 0,
    "witness_matches": 0,
}
STAGE_B_RUN = {
    "status": "ok",
    "mode": "balanced",
    "notes": "checkpoint-not-needed",
    "derivation_count": 105,
    "invalid_count": 1,
    "unique_valid_keys": 105,
    "duplicate_count": 21,
    "tested_candidate_count": 630,
}
STAGE_C_RUN = {
    "status": "ok",
    "mode": "balanced",
    "notes": "checkpoint-not-needed",
    "derivation_count": 14,
    "invalid_count": 0,
    "unique_valid_keys": 119,
    "duplicate_count": 21,
    "tested_candidate_count": 84,
}
STAGE_D_RUN = {
    "status": "ok",
    "mode": "balanced",
    "notes": "checkpoint-not-needed",
    "derivation_count": 40,
    "invalid_count": 0,
    "unique_valid_keys": 159,
    "duplicate_count": 21,
    "tested_candidate_count": 240,
}


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
    assert "Stage A+B report" in text
    assert "Stage A+B+C report" not in text
    assert "Next highest-value Stage B experiment (not executed)" in text
    assert "run --stage B" in text
    assert "Next highest-value Stage C experiment (not executed)" not in text
    assert "Next highest-value Stage D experiment (not executed)" not in text
    assert "Next highest-value Stage E experiment (not executed)" not in text
    assert "Stage A+B+C+D report" not in text
    assert "Hypotheses tested in Stage D" not in text
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
    assert "Stage A+B+C report" not in report
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
    assert "Next highest-value Stage D experiment (not executed)" not in report
    assert "Next highest-value Stage E experiment (not executed)" not in report
    assert "Stage A+B+C+D report" not in report
    assert "Hypotheses tested in Stage D" not in report
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
    assert "Stage A+B+C report" not in report
    assert "Stage A derivations: 23" in report
    assert "Stage A invalid derivations: 1" in report
    assert "Stage A unique valid keys: 22" in report
    assert "Stage B derivations: 105" in report
    assert "Stage B invalid derivations: 1" in report
    assert "cumulative unique valid keys after A+B: 105" in report
    assert "cumulative duplicate provenance paths after A+B: 21" in report
    assert "tested witness candidates: 630" in report
    assert "P2WSH direct target matches: 0" in report
    assert "cumulative unique valid keys after A+B+C" not in report
    assert "Next highest-value Stage D experiment (not executed)" not in report
    assert "Next highest-value Stage E experiment (not executed)" not in report
    assert "Stage A+B+C+D report" not in report
    assert "Hypotheses tested in Stage D" not in report
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
        sep_block.index(f"{index}. {separator.name} `{separator.token}`")
        for index, separator in enumerate(STAGE_C_SEPARATORS, start=1)
    ]
    assert positions == sorted(positions)


def test_stage_c_separators_exact_names_tokens_and_report_order(facts, targets):
    assert STAGE_C_SEPARATORS is STAGE_C_SEPARATORS_SOURCE
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
    assert [separator.value for separator in STAGE_C_SEPARATORS] == [
        b"",
        b":",
        b"|",
        b"-",
        b"_",
        b" ",
        b"\n",
    ]
    text = render_report(
        facts,
        targets,
        EMPTY_COUNTS,
        {"stage": "B", "status": "ok", "mode": "balanced", "notes": "checkpoint-not-needed"},
        [],
        [],
        [],
        [],
        stage_b_run=STAGE_B_RUN,
    )
    assert "Next highest-value Stage C experiment (not executed)" in text
    assert "Next highest-value Stage B experiment (not executed)" not in text
    assert "Next highest-value Stage D experiment (not executed)" not in text
    assert "Next highest-value Stage E experiment (not executed)" not in text
    assert "Stage A+B+C report" not in text
    assert "Stage A+B+C+D report" not in text
    assert "Hypotheses tested in Stage D" not in text
    block = text.split("exactly these seven separators:", 1)[1]
    rendered = [
        f"{index}. {separator.name} `{separator.token}`"
        for index, separator in enumerate(STAGE_C_SEPARATORS, start=1)
    ]
    positions = [block.index(line) for line in rendered]
    assert positions == sorted(positions)
    assert STAGE_C_SEPARATORS[2].token == '"|"'
    assert '","' not in "".join(separator.token for separator in STAGE_C_SEPARATORS)
    _assert_no_report_duplication(text)


def _c_derivations(count: int = 14) -> list[dict]:
    return [
        {
            "derivation_id": f"C-{index:03d}",
            "stage": "C",
            "valid": 1,
            "recipe": f"SHA256 pairwise nonce/timestamp {index}",
            "source": "genesis.header.nonce_and_timestamp",
            "transformation": "sha256",
            "confidence": 0.18,
            "fingerprint": f"c-fp-{index:03d}",
        }
        for index in range(1, count + 1)
    ]


def _c_witness_rows(
    fingerprints: list[str],
    matched_fingerprint: str | None = None,
    templates: list[str] | None = None,
) -> list[dict]:
    names = templates or [template.name for template in WITNESS_TEMPLATES]
    rows = []
    for name in names:
        for fingerprint in fingerprints:
            rows.append(
                {
                    "fingerprint": fingerprint,
                    "template_id": name,
                    "template_name": name,
                    "matched": 1 if fingerprint == matched_fingerprint else 0,
                    "first_tested_stage": "C",
                }
            )
    return rows


def _d_derivations(count: int = 40) -> list[dict]:
    return [
        {
            "derivation_id": f"D-{index:03d}",
            "stage": "D",
            "valid": 1,
            "recipe": f"direct integer scalar offset {index}",
            "source": "genesis.header.nonce",
            "transformation": "identity_integer",
            "confidence": 0.25,
            "fingerprint": f"d-fp-{index:03d}",
        }
        for index in range(1, count + 1)
    ]


def _d_witness_rows(
    fingerprints: list[str],
    matched_fingerprint: str | None = None,
    templates: list[str] | None = None,
) -> list[dict]:
    names = templates or [template.name for template in WITNESS_TEMPLATES]
    rows = []
    for name in names:
        for fingerprint in fingerprints:
            rows.append(
                {
                    "fingerprint": fingerprint,
                    "template_id": name,
                    "template_name": name,
                    "matched": 1 if fingerprint == matched_fingerprint else 0,
                    "first_tested_stage": "D",
                }
            )
    return rows


def _expected_d_formula_lines(facts) -> list[str]:
    lines = []
    index = 0
    for distance in range(1, 11):
        for field, public in (("nonce", facts.nonce), ("timestamp", facts.timestamp)):
            for offset in (-distance, distance):
                index += 1
                lines.append(f"{index}. `k = uint({field}={public}) + ({offset:+d})`")
    return lines


def _complete_d_inputs(facts, targets):
    fingerprints_c = [f"c-fp-{index:03d}" for index in range(1, 15)]
    fingerprints_d = [f"d-fp-{index:03d}" for index in range(1, 41)]
    return (
        facts,
        targets,
        {
            **EMPTY_COUNTS,
            "unique_keys": 159,
            "witness_candidates": 954,
            "witness_matches": 0,
        },
        {"stage": "D", "status": "ok", "mode": "balanced", "notes": "checkpoint-not-needed"},
        _c_derivations() + _d_derivations(),
        [],
        [],
        _c_witness_rows(fingerprints_c) + _d_witness_rows(fingerprints_d),
    )


def _assert_complete_no_match_d(report: str) -> None:
    assert "Stage A+B+C+D report" in report
    assert "Stage A+B+C report" not in report
    assert "Stage A+B report" not in report
    assert "Deterministic Stages A, B, C, and D are implemented" in report
    assert "Stage E, brute force" in report
    assert "Stage D, brute force" not in report
    assert "Stage C, brute force" not in report
    assert "cumulative unique valid keys after A+B: 105" in report
    assert "tested witness candidates: 630" in report
    assert "Stage C derivations: 14" in report
    assert "Stage C new unique valid keys: 14" in report
    assert "cumulative unique valid keys after A+B+C: 119" in report
    assert "cumulative duplicate provenance paths after A+B+C: 21" in report
    assert "new Stage C witness candidates: 84" in report
    assert "cumulative B+C witness candidates: 714" in report
    assert "cumulative B+C witness candidates: 954" not in report
    assert "Stage D derivations: 40" in report
    assert "Stage D invalid derivations: 0" in report
    assert "Stage D new unique valid keys: 40" in report
    assert "cumulative unique valid keys after A+B+C+D: 159" in report
    assert "cumulative duplicate provenance paths after A+B+C+D: 21" in report
    assert "new Stage D witness candidates: 240" in report
    assert "cumulative B+C+D witness candidates: 954" in report
    assert "new Stage D witness candidates: 84" not in report
    assert "new Stage D witness candidates: 630" not in report
    assert "new Stage C witness candidates: 240" not in report
    assert "tested witness candidates: 954" not in report
    assert "six templates times" in report
    assert "40 keys" in report
    assert "P2WSH direct target matches: 0" in report
    assert "Next highest-value Stage E experiment (not executed)" in report
    assert "Next highest-value Stage D experiment (not executed)" not in report
    assert "Next highest-value Stage C experiment (not executed)" not in report
    assert "Do not execute Stage D here" not in report
    assert "Do not execute Stage D" not in report
    stage_e = report.split("Next highest-value Stage E experiment (not executed)", 1)[1]
    assert "SHA256 once over exactly these eight UTF-8" in stage_e
    assert "Eight candidate keys" in stage_e
    assert "at most 48 scripts" in stage_e
    assert "Do not execute Stage E here" in stage_e
    _assert_no_report_duplication(report)


def _assert_complete_no_match_c(report: str) -> None:
    assert "Stage A+B+C report" in report
    assert "Stage A+B report" not in report
    assert "Deterministic Stages A, B, C, and D are implemented" in report
    assert "Stage E, brute force" in report
    assert "Stage D, brute force" not in report
    assert "Stage C, brute force" not in report
    assert "cumulative unique valid keys after A+B: 105" in report
    assert "tested witness candidates: 630" in report
    assert "Stage C derivations: 14" in report
    assert "Stage C new unique valid keys: 14" in report
    assert "cumulative unique valid keys after A+B+C: 119" in report
    assert "cumulative duplicate provenance paths after A+B+C: 21" in report
    assert "new Stage C witness candidates: 84" in report
    assert "cumulative B+C witness candidates: 714" in report
    assert "six templates times" in report
    assert "14 keys" in report
    assert "P2WSH direct target matches: 0" in report
    assert "Next highest-value Stage D experiment (not executed)" in report
    assert "Next highest-value Stage C experiment (not executed)" not in report
    stage_d = report.split("Next highest-value Stage D experiment (not executed)", 1)[1]
    assert "direct-scalar" in stage_d or "direct scalar" in stage_d
    assert "-10..-1" in stage_d
    assert "+1..+10" in stage_d
    assert "excluding zero" in stage_d
    assert "40 keys" in stage_d
    assert "at most 240 scripts" in stage_d
    assert "Do not hash" in stage_d
    assert "combinations" in stage_d
    assert "dates" in stage_d
    assert "window" in stage_d
    assert "PBKDF2" in stage_d
    assert "BIP39" in stage_d
    assert "GPU" in stage_d
    assert "brute force" in stage_d
    assert "run --stage D" in stage_d
    assert "Do not execute Stage D here" not in report
    assert "Do not execute Stage D" not in report
    assert "Do not execute Stage E" in stage_d
    assert "Do not execute Stage E until" not in report
    assert "until that" not in stage_d
    assert "Stage E and later hypotheses remain out of scope" in stage_d
    assert "Stage A+B+C+D report" not in report
    assert "Next highest-value Stage E experiment (not executed)" not in report
    assert "Hypotheses tested in Stage D" not in report
    assert "SHA256 once over exactly these eight UTF-8" not in report
    _assert_no_report_duplication(report)


def test_report_complete_no_match_stage_c(facts, targets):
    fingerprints = [f"c-fp-{index:03d}" for index in range(1, 15)]
    text = render_report(
        facts,
        targets,
        {
            **EMPTY_COUNTS,
            "unique_keys": 119,
            "witness_candidates": 714,
            "witness_matches": 0,
        },
        {"stage": "C", "status": "ok", "mode": "balanced", "notes": "checkpoint-not-needed"},
        _c_derivations(),
        [],
        [],
        _c_witness_rows(fingerprints),
        stage_b_run=STAGE_B_RUN,
        stage_c_run=STAGE_C_RUN,
    )
    _assert_complete_no_match_c(text)
    for template in WITNESS_TEMPLATES:
        assert f"`{template.name}`" in text
        assert "tested 14" in text
    c_section = text.split("Hypotheses tested in Stage C", 1)[1]
    assert "tested 14" in c_section
    assert "first_tested_stage=B rows" in c_section
    assert "first_tested_stage=C" in c_section
    sep_block = c_section.split("exactly these seven separators:", 1)[1]
    positions = [
        sep_block.index(f"{index}. {separator.name} `{separator.token}`")
        for index, separator in enumerate(STAGE_C_SEPARATORS, start=1)
    ]
    assert positions == sorted(positions)


def test_report_stage_c_via_cli(isolated, repo_root):
    _cli(isolated, repo_root, ["init"])
    _cli(isolated, repo_root, ["run", "--stage", "A", "--mode", "balanced"])
    _cli(isolated, repo_root, ["run", "--stage", "B", "--mode", "balanced"])
    _cli(isolated, repo_root, ["run", "--stage", "C", "--mode", "balanced"])
    report = (isolated / "research" / "report.md").read_text(encoding="utf-8")
    _assert_complete_no_match_c(report)
    assert "priority 1: `p2pk_compressed`" in report
    assert "priority 6: `p2pkh_uncompressed`" in report
    assert "tested 105" in report
    assert "2083236893" in report
    assert "1231006505" in report
    assert report.count("bc1q") < 30


def test_report_partial_stage_c_match_does_not_recommend_d(facts, targets):
    fingerprint = "c-fp-001"
    text = render_report(
        facts,
        targets,
        {
            **EMPTY_COUNTS,
            "unique_keys": 106,
            "witness_candidates": 631,
            "witness_matches": 1,
        },
        {
            "stage": "C",
            "status": "potential_match",
            "mode": "balanced",
            "notes": "checkpoint-not-needed",
        },
        _c_derivations(1),
        [],
        [],
        _c_witness_rows(
            [fingerprint],
            matched_fingerprint=fingerprint,
            templates=["p2pk_compressed"],
        ),
        stage_b_run=STAGE_B_RUN,
        stage_c_run={
            **STAGE_C_RUN,
            "status": "potential_match",
            "derivation_count": 1,
            "unique_valid_keys": 106,
            "tested_candidate_count": 1,
        },
    )
    assert "Stage A+B+C report" in text
    assert "P2WSH direct target matches: 1" in text
    assert "1 direct P2WSH target-script match(es) were stored for Stage C keys" in text
    assert "Next highest-value Stage D experiment (not executed)" not in text
    assert "Next highest-value Stage E experiment (not executed)" not in text
    assert "Stage A+B+C+D report" not in text
    assert "Hypotheses tested in Stage D" not in text
    assert "run --stage D" not in text
    assert "Do not execute Stage D here" not in text
    assert "Do not execute Stage D" in text
    assert "Do not execute Stage E" in text
    assert "cumulative unique valid keys after A+B: 105" in text
    assert "tested witness candidates: 630" in text
    _assert_no_report_duplication(text)


def test_stale_stage_c_run_after_b_invalidation_stays_ab(facts, targets):
    text = render_report(
        facts,
        targets,
        {
            **EMPTY_COUNTS,
            "unique_keys": 105,
            "witness_candidates": 630,
            "witness_matches": 0,
        },
        {"stage": "B", "status": "ok", "mode": "balanced", "notes": "checkpoint-not-needed"},
        [],
        [],
        [],
        [{"template_name": "p2pk_compressed", "matched": 0}],
        stage_b_run=STAGE_B_RUN,
        stage_c_run=STAGE_C_RUN,
    )
    assert "Stage A+B report" in text
    assert "Stage A+B+C report" not in text
    assert "Next highest-value Stage C experiment (not executed)" in text
    assert "Next highest-value Stage D experiment (not executed)" not in text
    assert "Next highest-value Stage E experiment (not executed)" not in text
    assert "Stage A+B+C+D report" not in text
    assert "Hypotheses tested in Stage D" not in text
    assert "cumulative unique valid keys after A+B+C" not in text
    assert "Stage C derivations: 14" not in text
    assert "new Stage C witness candidates: 84" not in text
    _assert_no_report_duplication(text)


def test_stale_stage_c_after_cli_b_invalidation(isolated, repo_root):
    _cli(isolated, repo_root, ["init"])
    _cli(isolated, repo_root, ["run", "--stage", "A", "--mode", "balanced"])
    _cli(isolated, repo_root, ["run", "--stage", "B", "--mode", "balanced"])
    _cli(isolated, repo_root, ["run", "--stage", "C", "--mode", "balanced"])
    _cli(isolated, repo_root, ["run", "--stage", "B", "--mode", "balanced"])
    report = (isolated / "research" / "report.md").read_text(encoding="utf-8")
    assert "Stage A+B report" in report
    assert "Stage A+B+C report" not in report
    assert "Next highest-value Stage C experiment (not executed)" in report
    assert "Next highest-value Stage D experiment (not executed)" not in report
    assert "Next highest-value Stage E experiment (not executed)" not in report
    assert "Stage A+B+C+D report" not in report
    assert "cumulative unique valid keys after A+B: 105" in report
    assert "tested witness candidates: 630" in report
    assert "cumulative unique valid keys after A+B+C" not in report
    assert "Stage C, brute force" in report
    _assert_no_report_duplication(report)


def test_legacy_witness_without_first_tested_stage_counts_as_b(facts, targets):
    text = render_report(
        facts,
        targets,
        EMPTY_COUNTS,
        {"stage": "B", "status": "ok", "mode": "balanced", "notes": "checkpoint-not-needed"},
        [],
        [],
        [],
        [
            {"template_name": "p2pk_compressed", "matched": 0},
            {"template_name": "p2pkh_uncompressed", "matched": 0},
        ],
        stage_b_run=STAGE_B_RUN,
    )
    assert "Stage A+B report" in text
    assert "Stage A+B+C report" not in text
    assert "Next highest-value Stage C experiment (not executed)" in text
    assert "Next highest-value Stage D experiment (not executed)" not in text
    assert "Next highest-value Stage E experiment (not executed)" not in text
    assert "Stage A+B+C+D report" not in text
    _assert_no_report_duplication(text)


def _finish(
    conn,
    run_id: int,
    *,
    derivation_count: int,
    unique_valid_keys: int,
    duplicate_count: int = 0,
    tested_candidate_count: int = 0,
    elapsed_seconds: float = 1.0,
    status: str = "ok",
) -> None:
    finish_run(
        conn,
        run_id,
        "2026-01-01T00:00:01Z",
        status,
        derivation_count,
        0,
        unique_valid_keys,
        duplicate_count,
        0,
        elapsed_seconds,
        tested_candidate_count,
    )


def _seed_derivation(conn, derivation_id: str, fingerprint: str, run_id: int) -> None:
    upsert_derivation(
        conn,
        derivation_id=derivation_id,
        fingerprint=fingerprint,
        source="test",
        original_public_source="test",
        representation="test",
        public_input_hex="00",
        transformation="none",
        formula="k = 1",
        recipe="test recipe",
        confidence=0.1,
        stage=derivation_id[0],
        valid=True,
        eliminated_reason="",
        run_id=run_id,
    )


def _seed_witness(conn, fingerprint: str, run_id: int, first_tested_stage: str) -> None:
    upsert_witness_candidate(
        conn,
        fingerprint=fingerprint,
        target_id="t1",
        template_id="p2pk_compressed",
        template_name="p2pk_compressed",
        priority=1,
        pubkey_mode="compressed",
        pubkey_hex="02" + "ab" * 32,
        witness_script_hex="21" + "02" + "ab" * 32 + "ac",
        witness_program_hex="cd" * 32,
        address=f"bc1q{fingerprint}",
        derivation_ids=f"{first_tested_stage}-001",
        matched=False,
        run_id=run_id,
        first_tested_stage=first_tested_stage,
    )


def _capture_render(monkeypatch) -> dict:
    captured: dict = {}

    def fake_render(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return "captured-report"

    monkeypatch.setattr("genesis_puzzle.cli.render_report", fake_render)
    return captured


def test_cli_report_passes_exact_c_run_when_latest_run_is_another_stage(
    isolated, repo_root, monkeypatch
):
    store = connect(isolated / "state" / "research.sqlite")
    conn = store.conn
    run_c = insert_run(conn, "2026-01-01T00:00:00Z", "C", "eco", "ok")
    _finish(
        conn,
        run_c,
        derivation_count=14,
        unique_valid_keys=119,
        duplicate_count=21,
        tested_candidate_count=84,
        elapsed_seconds=9.87,
    )
    run_a = insert_run(conn, "2026-01-01T00:01:00Z", "A", "max", "ok")
    _finish(
        conn,
        run_a,
        derivation_count=23,
        unique_valid_keys=22,
        elapsed_seconds=0.11,
    )
    upsert_key(conn, "fp-c", run_c)
    _seed_derivation(conn, "C-001", "fp-c", run_c)
    _seed_witness(conn, "fp-c", run_c, "C")
    conn.commit()

    captured = _capture_render(monkeypatch)
    _write_current_report(store, repo_root, isolated / "research" / "report.md")
    stage_c_run = captured["kwargs"]["stage_c_run"]
    latest = captured["args"][3]
    assert latest is not None
    assert latest["id"] == run_a
    assert latest["stage"] == "A"
    assert stage_c_run is not None
    assert stage_c_run["id"] == run_c
    assert stage_c_run["stage"] == "C"
    assert stage_c_run["mode"] == "eco"
    assert stage_c_run["unique_valid_keys"] == 119
    assert stage_c_run["derivation_count"] == 14
    assert stage_c_run["tested_candidate_count"] == 84
    assert stage_c_run["elapsed_seconds"] == 9.87
    assert captured["kwargs"]["stage_a_run"]["id"] == run_a


def test_cli_report_ignores_stale_historical_c_after_b_invalidation(
    isolated, repo_root, monkeypatch
):
    store = connect(isolated / "state" / "research.sqlite")
    conn = store.conn
    run_c = insert_run(conn, "2026-01-01T00:00:00Z", "C", "eco", "ok")
    _finish(
        conn,
        run_c,
        derivation_count=14,
        unique_valid_keys=119,
        duplicate_count=21,
        tested_candidate_count=84,
        elapsed_seconds=9.87,
    )
    upsert_key(conn, "fp-b", run_c)
    upsert_key(conn, "fp-c", run_c)
    _seed_derivation(conn, "B-001", "fp-b", run_c)
    _seed_derivation(conn, "C-001", "fp-c", run_c)
    _seed_witness(conn, "fp-b", run_c, "B")
    _seed_witness(conn, "fp-c", run_c, "C")
    invalidate_stage_c_current_state(conn)
    run_b = insert_run(conn, "2026-01-01T00:02:00Z", "B", "balanced", "ok")
    _finish(
        conn,
        run_b,
        derivation_count=105,
        unique_valid_keys=105,
        duplicate_count=21,
        tested_candidate_count=630,
        elapsed_seconds=2.0,
    )
    conn.commit()

    captured = _capture_render(monkeypatch)
    _write_current_report(store, repo_root, isolated / "research" / "report.md")
    latest = captured["args"][3]
    assert latest is not None
    assert latest["id"] == run_b
    assert latest["stage"] == "B"
    assert captured["kwargs"]["stage_c_run"] is None
    assert captured["kwargs"]["stage_b_run"]["id"] == run_b
    remaining_stages = {row["stage"] for row in captured["args"][4]}
    assert "C" not in remaining_stages
    witness_stages = {row.get("first_tested_stage") for row in captured["args"][7]}
    assert "C" not in witness_stages


def test_report_complete_no_match_stage_d(facts, targets):
    args = _complete_d_inputs(facts, targets)
    text = render_report(
        *args,
        stage_b_run=STAGE_B_RUN,
        stage_c_run=STAGE_C_RUN,
        stage_d_run=STAGE_D_RUN,
    )
    _assert_complete_no_match_d(text)
    d_section = text.split("Hypotheses tested in Stage D", 1)[1]
    assert "tested 40" in d_section
    assert "first_tested_stage=D" in d_section
    assert "first_tested_stage=B rows" in d_section
    assert "first_tested_stage=C" in d_section
    c_section = text.split("Hypotheses tested in Stage C", 1)[1].split(
        "Hypotheses tested in Stage D", 1
    )[0]
    assert "tested 14" in c_section
    assert "first_tested_stage=B rows" in c_section
    assert "first_tested_stage=C" in c_section
    for template in WITNESS_TEMPLATES:
        assert f"`{template.name}`" in d_section
    assert "distance-first" in d_section
    assert "No hashing" in d_section
    assert "zero is excluded" in d_section or "offset\nzero is excluded" in d_section
    assert (
        "public_input bytes stay\nempty" in d_section
        or "public_input bytes stay empty" in d_section
    )
    assert "raw scalar is not stored or logged" in d_section
    assert "formula" in d_section.lower()
    assert "fingerprint" in d_section
    assert "Stage A, Stage B, Stage C, and Stage D are sequential." in text


def test_report_stage_d_from_latest_run_without_explicit_kwarg(facts, targets):
    facts_arg, targets_arg, counts, _latest, derivations, comparisons, history, witness = (
        _complete_d_inputs(facts, targets)
    )
    text = render_report(
        facts_arg,
        targets_arg,
        counts,
        {**STAGE_D_RUN, "stage": "D"},
        derivations,
        comparisons,
        history,
        witness,
        stage_b_run=STAGE_B_RUN,
        stage_c_run=STAGE_C_RUN,
    )
    _assert_complete_no_match_d(text)


def test_report_stage_d_formulas_exact_order_and_no_secret_wording(facts, targets):
    text = render_report(
        *_complete_d_inputs(facts, targets),
        stage_b_run=STAGE_B_RUN,
        stage_c_run=STAGE_C_RUN,
        stage_d_run=STAGE_D_RUN,
    )
    block = text.split("Hypotheses tested in Stage D", 1)[1].split("Stage D results", 1)[0]
    expected = _expected_d_formula_lines(facts)
    assert len(expected) == 40
    positions = [block.index(line) for line in expected]
    assert positions == sorted(positions)
    assert expected[0] == f"1. `k = uint(nonce={facts.nonce}) + (-1)`"
    assert expected[1] == f"2. `k = uint(nonce={facts.nonce}) + (+1)`"
    assert expected[2] == f"3. `k = uint(timestamp={facts.timestamp}) + (-1)`"
    assert expected[3] == f"4. `k = uint(timestamp={facts.timestamp}) + (+1)`"
    assert expected[-4] == f"37. `k = uint(nonce={facts.nonce}) + (-10)`"
    assert expected[-1] == f"40. `k = uint(timestamp={facts.timestamp}) + (+10)`"
    assert "+0)" not in block
    assert "nonce-d, nonce+d, timestamp-d, timestamp+d" in block
    assert f"k = {facts.nonce - 1}" not in text
    assert f"k = {facts.nonce + 1}" not in text
    assert f"k = {facts.timestamp - 1}" not in text
    assert "private_scalar" not in text.lower()
    assert "identity_integer" in block or "identity integer" in block


def test_report_stage_e_strings_order_count_and_prohibitions(facts, targets):
    text = render_report(
        *_complete_d_inputs(facts, targets),
        stage_b_run=STAGE_B_RUN,
        stage_c_run=STAGE_C_RUN,
        stage_d_run=STAGE_D_RUN,
    )
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
    assert len(STAGE_E_DATE_STRINGS) == 8
    stage_e = text.split("Next highest-value Stage E experiment (not executed)", 1)[1]
    rendered = [f"{index}. `{value}`" for index, value in enumerate(STAGE_E_DATE_STRINGS, start=1)]
    positions = [stage_e.index(line) for line in rendered]
    assert positions == sorted(positions)
    assert "European/day-first ambiguous" in stage_e
    assert "American/month-first ambiguous" in stage_e
    assert "Eight candidate keys" in stage_e
    assert "at most 48 scripts" in stage_e
    assert "newline" in stage_e
    assert "case" in stage_e
    assert "whitespace" in stage_e
    assert "time zones" in stage_e
    assert "other dates" in stage_e
    assert "PBKDF2" in stage_e
    assert "BIP39" in stage_e
    assert "repeated hashing" in stage_e
    assert "GPU" in stage_e
    assert "neighborhoods" in stage_e
    assert "larger\ncombinations" in stage_e or "larger combinations" in stage_e
    assert "brute force" in stage_e
    assert "Do not execute Stage E here" in stage_e
    assert "2009-01-03T18:15:05+00:00" not in stage_e
    assert "03 January 2009" not in stage_e
    assert "PBKDF2/BIP39" not in stage_e.split("Do not use", 1)[-1] or "PBKDF2" in stage_e
    rest = text.split("## Resource and safety notes", 1)[0]
    assert rest.count("Next highest-value Stage E experiment (not executed)") == 1
    assert "Next highest-value Stage D experiment (not executed)" not in rest


def test_report_partial_stage_d_match_does_not_recommend_e(facts, targets):
    fingerprint = "d-fp-001"
    c_fingerprints = [f"c-fp-{index:03d}" for index in range(1, 15)]
    text = render_report(
        facts,
        targets,
        {
            **EMPTY_COUNTS,
            "unique_keys": 120,
            "witness_candidates": 715,
            "witness_matches": 1,
        },
        {
            "stage": "D",
            "status": "potential_match",
            "mode": "balanced",
            "notes": "checkpoint-not-needed",
        },
        _c_derivations() + _d_derivations(1),
        [],
        [],
        _c_witness_rows(c_fingerprints)
        + _d_witness_rows(
            [fingerprint],
            matched_fingerprint=fingerprint,
            templates=["p2pk_compressed"],
        ),
        stage_b_run=STAGE_B_RUN,
        stage_c_run=STAGE_C_RUN,
        stage_d_run={
            **STAGE_D_RUN,
            "status": "potential_match",
            "derivation_count": 1,
            "unique_valid_keys": 120,
            "tested_candidate_count": 1,
        },
    )
    assert "Stage A+B+C+D report" in text
    assert "Stage D derivations: 1" in text
    assert "Stage D new unique valid keys: 1" in text
    assert "new Stage D witness candidates: 1" in text
    assert "P2WSH direct target matches: 1" in text
    assert "1 direct P2WSH target-script match(es) were stored for Stage D keys" in text
    assert "tested witness candidates: 630" in text
    assert "new Stage C witness candidates: 84" in text
    assert "cumulative B+C witness candidates: 714" in text
    assert "Next highest-value Stage E experiment (not executed)" not in text
    assert "Next highest-value Stage D experiment (not executed)" not in text
    assert "Do not execute Stage E" in text
    assert "SHA256 once over exactly these eight UTF-8" not in text
    _assert_no_report_duplication(text)


def test_stale_stage_d_run_after_rows_removed_stays_abc(facts, targets):
    fingerprints = [f"c-fp-{index:03d}" for index in range(1, 15)]
    text = render_report(
        facts,
        targets,
        {
            **EMPTY_COUNTS,
            "unique_keys": 119,
            "witness_candidates": 714,
            "witness_matches": 0,
        },
        {"stage": "D", "status": "ok", "mode": "balanced", "notes": "checkpoint-not-needed"},
        _c_derivations(),
        [],
        [],
        _c_witness_rows(fingerprints),
        stage_b_run=STAGE_B_RUN,
        stage_c_run=STAGE_C_RUN,
        stage_d_run=STAGE_D_RUN,
    )
    _assert_complete_no_match_c(text)
    assert "Stage A+B+C+D report" not in text
    assert "Stage D derivations: 40" not in text
    assert "new Stage D witness candidates: 240" not in text
    assert "cumulative unique valid keys after A+B+C+D" not in text
    assert "Hypotheses tested in Stage D" not in text
    assert "Next highest-value Stage E experiment (not executed)" not in text


def test_unknown_witness_stage_is_not_counted_as_b(facts, targets):
    text = render_report(
        facts,
        targets,
        EMPTY_COUNTS,
        {"stage": "B", "status": "ok", "mode": "balanced", "notes": "checkpoint-not-needed"},
        [],
        [],
        [],
        [
            {"template_name": "p2pk_compressed", "matched": 0, "first_tested_stage": "B"},
            {"template_name": "p2pk_compressed", "matched": 0, "first_tested_stage": "B"},
            {"template_name": "p2pk_compressed", "matched": 0, "first_tested_stage": "X"},
        ],
        stage_b_run=STAGE_B_RUN,
    )
    assert "Stage A+B report" in text
    assert "Stage A+B+C report" not in text
    assert "Stage A+B+C+D report" not in text
    assert "- tested witness candidates: 2\n" in text
    assert "- tested witness candidates: 3\n" not in text
    assert "; tested 2" in text
    assert "; tested 3" not in text
    assert "Next highest-value Stage C experiment (not executed)" in text
    assert "Hypotheses tested in Stage D" not in text
    _assert_no_report_duplication(text)


def test_legacy_empty_witness_stage_counts_as_b_not_d(facts, targets):
    text = render_report(
        facts,
        targets,
        EMPTY_COUNTS,
        {"stage": "B", "status": "ok", "mode": "balanced", "notes": "checkpoint-not-needed"},
        _d_derivations(1),
        [],
        [],
        [
            {"template_name": "p2pk_compressed", "matched": 0, "first_tested_stage": ""},
            {"template_name": "p2pk_compressed", "matched": 0, "first_tested_stage": None},
            {
                "template_name": "p2pk_compressed",
                "matched": 0,
                "first_tested_stage": "D",
                "fingerprint": "d-fp-001",
            },
        ],
        stage_b_run=STAGE_B_RUN,
        stage_d_run={
            **STAGE_D_RUN,
            "derivation_count": 1,
            "unique_valid_keys": 106,
            "tested_candidate_count": 1,
        },
    )
    assert "Stage A+B+C+D report" in text
    assert "- tested witness candidates: 2\n" in text
    assert "new Stage D witness candidates: 1" in text
    assert "cumulative B+C+D witness candidates: 3" in text
    _assert_no_report_duplication(text)


def test_report_does_not_conflate_b_c_d_witness_counts(facts, targets):
    text = render_report(
        facts,
        targets,
        {
            **EMPTY_COUNTS,
            "unique_keys": 8,
            "witness_candidates": 9,
            "witness_matches": 0,
        },
        {"stage": "D", "status": "ok", "mode": "balanced", "notes": "checkpoint-not-needed"},
        _c_derivations(3) + _d_derivations(4),
        [],
        [],
        [
            {
                "template_name": "p2pk_compressed",
                "matched": 0,
                "first_tested_stage": "B",
                "fingerprint": "b-fp-1",
            },
            {
                "template_name": "p2pk_compressed",
                "matched": 0,
                "first_tested_stage": "B",
                "fingerprint": "b-fp-2",
            },
            {
                "template_name": "p2pk_compressed",
                "matched": 0,
                "first_tested_stage": "C",
                "fingerprint": "c-fp-001",
            },
            {
                "template_name": "p2pk_compressed",
                "matched": 0,
                "first_tested_stage": "C",
                "fingerprint": "c-fp-002",
            },
            {
                "template_name": "p2pk_compressed",
                "matched": 0,
                "first_tested_stage": "C",
                "fingerprint": "c-fp-003",
            },
            {
                "template_name": "p2pk_compressed",
                "matched": 0,
                "first_tested_stage": "D",
                "fingerprint": "d-fp-001",
            },
            {
                "template_name": "p2pk_compressed",
                "matched": 0,
                "first_tested_stage": "D",
                "fingerprint": "d-fp-002",
            },
            {
                "template_name": "p2pk_compressed",
                "matched": 0,
                "first_tested_stage": "D",
                "fingerprint": "d-fp-003",
            },
            {
                "template_name": "p2pk_compressed",
                "matched": 0,
                "first_tested_stage": "D",
                "fingerprint": "d-fp-004",
            },
        ],
        stage_b_run=STAGE_B_RUN,
        stage_c_run={
            **STAGE_C_RUN,
            "derivation_count": 3,
            "unique_valid_keys": 4,
            "tested_candidate_count": 3,
        },
        stage_d_run={
            **STAGE_D_RUN,
            "derivation_count": 4,
            "unique_valid_keys": 8,
            "tested_candidate_count": 4,
        },
    )
    assert "Stage A+B+C+D report" in text
    assert "- tested witness candidates: 2\n" in text
    assert "new Stage C witness candidates: 3" in text
    assert "cumulative B+C witness candidates: 5" in text
    assert "new Stage D witness candidates: 4" in text
    assert "cumulative B+C+D witness candidates: 9" in text
    assert "tested witness candidates: 630" not in text
    assert "new Stage C witness candidates: 84" not in text
    assert "cumulative B+C witness candidates: 714" not in text
    assert "cumulative B+C witness candidates: 9" not in text
    assert "new Stage D witness candidates: 240" not in text
    assert "Next highest-value Stage E experiment (not executed)" not in text
    _assert_no_report_duplication(text)
