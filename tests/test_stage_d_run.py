from __future__ import annotations

import io
from dataclasses import replace
from pathlib import Path

import pytest

import genesis_puzzle.engine as engine_mod
import genesis_puzzle.storage as storage_mod
from genesis_puzzle.candidates import (
    compute_scalar,
    dedupe_valid_scalars,
    evaluate_recipe,
    stage_a_recipes,
)
from genesis_puzzle.cli import _build_parser, _write_current_report, main
from genesis_puzzle.config import ModeConfig
from genesis_puzzle.crypto import derive_pubkeys
from genesis_puzzle.engine import (
    StageDPrerequisiteError,
    TargetConsistencyError,
    run_stage_a,
    run_stage_b,
    run_stage_c,
    run_stage_d,
)
from genesis_puzzle.model import KnownTarget
from genesis_puzzle.parser import ParsedBlock
from genesis_puzzle.stage_b import stage_b_recipes
from genesis_puzzle.stage_c import stage_c_recipes
from genesis_puzzle.stage_d import stage_d_recipes
from genesis_puzzle.storage import (
    Store,
    connect,
    counts,
    dump_text,
    finish_run,
    insert_run,
    invalidate_stage_d_current_state,
    latest_run,
    list_witness_candidates,
    upsert_derivation,
    upsert_key,
    upsert_witness_candidate,
)
from genesis_puzzle.witness import (
    WITNESS_TEMPLATES,
    build_p2wsh_candidate,
    expected_witness_script,
    p2wsh_program_and_address,
)

TEMPLATE_ORDER = (
    "p2pk_compressed",
    "p2pk_uncompressed",
    "multisig_1of1_compressed",
    "multisig_1of1_uncompressed",
    "p2pkh_compressed",
    "p2pkh_uncompressed",
)
MODE = ModeConfig("balanced", 1, 1.0, 0.0, "test")
FORBIDDEN_COLUMN_FRAGMENTS = ("scalar", "private", "secret", "seed")


def _count_engine_derive_pubkeys(monkeypatch: pytest.MonkeyPatch) -> dict:
    calls = {"n": 0}
    real = engine_mod.derive_pubkeys

    def wrapped(scalar):
        calls["n"] += 1
        return real(scalar)

    monkeypatch.setattr(engine_mod, "derive_pubkeys", wrapped)
    return calls


def _boom_stage_d_recipes(monkeypatch: pytest.MonkeyPatch, message: str) -> None:
    def boom_recipes(_block):
        raise AssertionError(message)

    monkeypatch.setattr(engine_mod, "stage_d_recipes", boom_recipes)


def _store(path: Path) -> Store:
    return connect(path / "state" / "research.sqlite")


def _prepare_ab(path: Path, genesis_block: ParsedBlock, targets: list[KnownTarget]) -> Store:
    store = _store(path)
    run_stage_a(store, genesis_block, targets, MODE)
    run_stage_b(store, genesis_block, targets, MODE)
    return store


def _prepare_abc(path: Path, genesis_block: ParsedBlock, targets: list[KnownTarget]) -> Store:
    store = _prepare_ab(path, genesis_block, targets)
    run_stage_c(store, genesis_block, targets, MODE)
    return store


def _sha256_scalar_hexes(genesis_block: ParsedBlock) -> list[str]:
    hexes = []
    recipes = (
        stage_a_recipes(genesis_block)
        + stage_b_recipes(genesis_block)
        + stage_c_recipes(genesis_block)
    )
    for recipe in recipes:
        if recipe.transformation != "sha256":
            continue
        hexes.append(f"{compute_scalar(recipe):064x}")
    return hexes


def _stage_d_secret_tokens(genesis_block: ParsedBlock) -> list[str]:
    tokens = []
    for recipe in stage_d_recipes(genesis_block):
        scalar = compute_scalar(recipe)
        tokens.append(str(scalar))
        tokens.append(f"{scalar:064x}")
    return tokens


def _assert_no_secrets(text: str, genesis_block: ParsedBlock) -> None:
    for secret in _sha256_scalar_hexes(genesis_block):
        assert secret not in text
    for secret in _stage_d_secret_tokens(genesis_block):
        assert secret not in text
    assert f"{2083236893:064x}" not in text.lower()


def _witness_public_snapshot(row) -> tuple:
    return (
        int(row["id"]),
        row["fingerprint"],
        row["target_id"],
        row["template_id"],
        row["template_name"],
        int(row["priority"]),
        row["pubkey_mode"],
        row["pubkey_hex"],
        row["witness_script_hex"],
        row["witness_program_hex"],
        row["derivation_ids"],
        row["address"],
        int(row["matched"]),
        int(row["run_id"]),
        row["first_tested_stage"],
    )


def _state_snapshot(store: Store) -> tuple:
    derivations = [
        (
            str(row["derivation_id"]),
            None if row["fingerprint"] is None else str(row["fingerprint"]),
            int(row["valid"]),
            str(row["stage"]),
            str(row["public_input_hex"]),
        )
        for row in store.conn.execute(
            "SELECT derivation_id, fingerprint, valid, stage, public_input_hex "
            "FROM derivations ORDER BY derivation_id"
        )
    ]
    keys = [
        str(row[0])
        for row in store.conn.execute("SELECT fingerprint FROM keys ORDER BY fingerprint")
    ]
    witness = [_witness_public_snapshot(row) for row in list_witness_candidates(store.conn)]
    runs = [
        (int(row["id"]), str(row["stage"]), str(row["status"]), row["tested_candidate_count"])
        for row in store.conn.execute("SELECT id, stage, status, tested_candidate_count FROM runs")
    ]
    running = int(
        store.conn.execute("SELECT COUNT(*) FROM runs WHERE status = 'running'").fetchone()[0]
    )
    return (derivations, keys, witness, runs, running)


def _assert_public_schema(store: Store) -> None:
    for table in ("witness_candidates", "derivations", "keys", "runs", "addresses", "history"):
        names = [str(row[1]) for row in store.conn.execute(f"PRAGMA table_info({table})")]
        for name in names:
            lowered = name.lower()
            for fragment in FORBIDDEN_COLUMN_FRAGMENTS:
                assert fragment not in lowered


def _assert_no_stage_d(store: Store, before: tuple) -> None:
    assert _state_snapshot(store) == before
    assert store.conn.execute("SELECT COUNT(*) FROM runs WHERE stage = 'D'").fetchone()[0] == 0
    assert (
        store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'D'").fetchone()[0] == 0
    )
    assert list_witness_candidates(store.conn, "D") == []


def test_run_d_before_a_is_controlled_error_without_curve_or_run(
    isolated, genesis_block, targets, monkeypatch
):
    store = _store(isolated)
    before = _state_snapshot(store)
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    _boom_stage_d_recipes(monkeypatch, "Stage D recipes must not run before Stage A")
    with pytest.raises(StageDPrerequisiteError, match="run Stage A first"):
        run_stage_d(store, genesis_block, targets, MODE)
    assert derive_calls["n"] == 0
    _assert_no_stage_d(store, before)


def test_run_d_before_b_is_controlled_error_without_curve_or_run(
    isolated, genesis_block, targets, monkeypatch
):
    store = _store(isolated)
    run_stage_a(store, genesis_block, targets, MODE)
    before = _state_snapshot(store)
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    derive_calls["n"] = 0
    _boom_stage_d_recipes(monkeypatch, "Stage D recipes must not run before Stage B")
    with pytest.raises(StageDPrerequisiteError, match="run Stage B first"):
        run_stage_d(store, genesis_block, targets, MODE)
    assert derive_calls["n"] == 0
    _assert_no_stage_d(store, before)


def test_run_d_before_c_is_controlled_error_without_curve_or_run(
    isolated, genesis_block, targets, monkeypatch
):
    store = _prepare_ab(isolated, genesis_block, targets)
    before = _state_snapshot(store)
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    derive_calls["n"] = 0
    _boom_stage_d_recipes(monkeypatch, "Stage D recipes must not run before Stage C")
    with pytest.raises(StageDPrerequisiteError, match="run Stage C first"):
        run_stage_d(store, genesis_block, targets, MODE)
    assert derive_calls["n"] == 0
    _assert_no_stage_d(store, before)


def test_stage_d_real_target_counts_ordering_preservation_and_idempotent_rerun(
    isolated, genesis_block, targets, monkeypatch
):
    store = _prepare_abc(isolated, genesis_block, targets)
    b_snapshot = [
        _witness_public_snapshot(row) for row in list_witness_candidates(store.conn, "B")
    ]
    c_snapshot = [
        _witness_public_snapshot(row) for row in list_witness_candidates(store.conn, "C")
    ]
    assert len(b_snapshot) == 630
    assert len(c_snapshot) == 84
    address_rows = store.conn.execute("SELECT COUNT(*) FROM addresses").fetchone()[0]
    history_rows_n = store.conn.execute("SELECT COUNT(*) FROM history").fetchone()[0]

    expected_d_fps = []
    for recipe in stage_d_recipes(genesis_block):
        evaluated, _scalar = evaluate_recipe(recipe)
        assert evaluated.fingerprint is not None
        expected_d_fps.append(evaluated.fingerprint)
    assert len(expected_d_fps) == 40
    assert len(set(expected_d_fps)) == 40

    output = io.StringIO()
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    result = run_stage_d(store, genesis_block, targets, MODE, out=output)
    assert derive_calls["n"] == 40
    text = output.getvalue()
    run = latest_run(store.conn)
    after = counts(store.conn)
    d_rows = list_witness_candidates(store.conn, "D")
    all_rows = list_witness_candidates(store.conn)
    assert result["derivations"] == 40
    assert result["invalid"] == 0
    assert result["unique_valid_keys"] == 159
    assert result["new_unique_keys"] == 40
    assert result["duplicates"] == 21
    assert result["witness_candidates_tested"] == 240
    assert result["cumulative_witness_candidates"] == 954
    assert result["potential_match"] is False
    assert isinstance(result["elapsed_seconds"], float)
    assert after["unique_keys"] == 159
    assert after["witness_candidates"] == 954
    assert after["witness_matches"] == 0
    assert after["addresses"] == address_rows
    assert store.conn.execute("SELECT COUNT(*) FROM history").fetchone()[0] == history_rows_n
    assert (
        store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'D'").fetchone()[0]
        == 40
    )
    assert (
        store.conn.execute(
            "SELECT COUNT(*) FROM derivations WHERE stage = 'D' AND valid = 0"
        ).fetchone()[0]
        == 0
    )
    empty_inputs = store.conn.execute(
        "SELECT COUNT(*) FROM derivations WHERE stage = 'D' AND public_input_hex = ''"
    ).fetchone()[0]
    assert empty_inputs == 40
    assert run["stage"] == "D"
    assert run["status"] == "ok"
    assert run["derivation_count"] == 40
    assert run["invalid_count"] == 0
    assert run["unique_valid_keys"] == 159
    assert run["duplicate_count"] == 21
    assert run["address_count"] == 0
    assert run["tested_candidate_count"] == 240
    assert len(d_rows) == 240
    assert len(all_rows) == 954
    assert [_witness_public_snapshot(row) for row in list_witness_candidates(store.conn, "B")] == (
        b_snapshot
    )
    assert [_witness_public_snapshot(row) for row in list_witness_candidates(store.conn, "C")] == (
        c_snapshot
    )
    assert all(row["first_tested_stage"] == "B" for row in all_rows[:630])
    assert all(row["first_tested_stage"] == "C" for row in all_rows[630:714])
    assert all(row["first_tested_stage"] == "D" for row in all_rows[714:])
    assert all(row["template_id"] == "p2pk_compressed" for row in d_rows[:40])
    assert all(row["template_id"] == "p2pkh_uncompressed" for row in d_rows[-40:])
    assert [row["template_id"] for row in d_rows[::40]] == list(TEMPLATE_ORDER)
    assert [row["fingerprint"] for row in d_rows[:40]] == expected_d_fps
    assert d_rows[0]["priority"] == 1
    assert d_rows[-1]["priority"] == 6
    assert d_rows[0]["pubkey_mode"] == "compressed"
    assert d_rows[-1]["pubkey_mode"] == "uncompressed"
    assert all(int(row["matched"]) == 0 for row in d_rows)
    assert "POTENTIAL MATCH FOUND" not in text
    assert "private_scalar=REDACTED" in text

    store.conn.execute(
        "UPDATE witness_candidates SET derivation_ids = 'STALE-D' WHERE id = ?",
        (d_rows[0]["id"],),
    )
    store.conn.commit()
    assert (
        store.conn.execute(
            "SELECT derivation_ids FROM witness_candidates WHERE id = ?",
            (d_rows[0]["id"],),
        ).fetchone()[0]
        == "STALE-D"
    )

    derive_calls["n"] = 0
    output2 = io.StringIO()
    result2 = run_stage_d(store, genesis_block, targets, MODE, out=output2)
    assert derive_calls["n"] == 40
    assert result2["new_unique_keys"] == 40
    assert result2["witness_candidates_tested"] == 240
    assert result2["cumulative_witness_candidates"] == 954
    d_rows2 = list_witness_candidates(store.conn, "D")
    assert [_witness_public_snapshot(row) for row in list_witness_candidates(store.conn, "B")] == (
        b_snapshot
    )
    assert [_witness_public_snapshot(row) for row in list_witness_candidates(store.conn, "C")] == (
        c_snapshot
    )
    assert len(d_rows2) == 240
    assert d_rows2[0]["derivation_ids"] != "STALE-D"
    assert [row["fingerprint"] for row in d_rows2[:40]] == expected_d_fps
    dumped = dump_text(store.conn)
    combined = text + output2.getvalue() + dumped
    _assert_no_secrets(combined, genesis_block)
    _assert_public_schema(store)


def test_stage_d_prerequisite_corruptions_do_not_mutate_or_call_curve(
    isolated, genesis_block, targets, monkeypatch
):
    cases = (
        "missing_row",
        "wrong_derivation_fingerprint",
        "wrong_template_metadata",
        "wrong_script",
        "wrong_program",
        "wrong_address",
        "matched_row",
        "potential_baseline",
        "wrong_c_metrics",
    )
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    for name in cases:
        fresh = _prepare_abc(isolated / name, genesis_block, targets)
        before = _state_snapshot(fresh)
        c_row = list_witness_candidates(fresh.conn, "C")[0]
        a01_fp = fresh.conn.execute(
            "SELECT fingerprint FROM derivations WHERE derivation_id = 'A-01'"
        ).fetchone()[0]
        c001_id = fresh.conn.execute(
            "SELECT derivation_id FROM derivations WHERE stage = 'C' AND valid = 1 LIMIT 1"
        ).fetchone()[0]
        if name == "missing_row":
            fresh.conn.execute("DELETE FROM witness_candidates WHERE id = ?", (c_row["id"],))
        elif name == "wrong_derivation_fingerprint":
            fresh.conn.execute(
                "UPDATE derivations SET fingerprint = ? WHERE derivation_id = ?",
                (a01_fp, c001_id),
            )
        elif name == "wrong_template_metadata":
            fresh.conn.execute(
                """
                UPDATE witness_candidates
                SET template_name = 'not-canonical', priority = 99
                WHERE id = ?
                """,
                (c_row["id"],),
            )
        elif name == "wrong_script":
            fresh.conn.execute(
                "UPDATE witness_candidates SET witness_script_hex = ? WHERE id = ?",
                ("00" * 10, c_row["id"]),
            )
        elif name == "wrong_program":
            fresh.conn.execute(
                "UPDATE witness_candidates SET witness_program_hex = ? WHERE id = ?",
                ("11" * 32, c_row["id"]),
            )
        elif name == "wrong_address":
            fresh.conn.execute(
                "UPDATE witness_candidates SET address = ? WHERE id = ?",
                ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", c_row["id"]),
            )
        elif name == "matched_row":
            fresh.conn.execute(
                "UPDATE witness_candidates SET matched = 1 WHERE id = ?",
                (c_row["id"],),
            )
        elif name == "potential_baseline":
            fresh.conn.execute("UPDATE runs SET status = 'potential_match' WHERE stage = 'C'")
        else:
            fresh.conn.execute(
                """
                UPDATE runs
                SET unique_valid_keys = 1, tested_candidate_count = 0
                WHERE stage = 'C'
                """
            )
        fresh.conn.commit()
        mutated = _state_snapshot(fresh)
        derive_calls["n"] = 0
        _boom_stage_d_recipes(
            monkeypatch, f"Stage D recipes must not run on corrupted C baseline {name}"
        )
        with pytest.raises(StageDPrerequisiteError):
            run_stage_d(fresh, genesis_block, targets, MODE)
        assert derive_calls["n"] == 0
        _assert_no_stage_d(fresh, mutated)
        assert _state_snapshot(fresh) != before


def test_first_synthetic_d_candidate_match_stops_after_one(isolated, genesis_block, monkeypatch):
    pairs = [evaluate_recipe(recipe) for recipe in stage_d_recipes(genesis_block)]
    unique = dedupe_valid_scalars(pairs)
    fingerprint, scalar, group = unique[0]
    uncompressed, compressed = derive_pubkeys(scalar)
    candidate = build_p2wsh_candidate(WITNESS_TEMPLATES[0], uncompressed, compressed)
    program = candidate.witness_program
    target = KnownTarget(
        id="synthetic-first-d-p2wsh",
        label="test-only",
        status="known",
        txid="00" * 32,
        block_height=0,
        block_time=0,
        value_sats=1,
        address=candidate.address,
        script_type="p2wsh",
        script_pubkey_hex=(bytes([0x00, 0x20]) + program).hex(),
        witness_program_hex=program.hex(),
        comparable_with_stage_a=False,
        notes="synthetic first global Stage D candidate",
    )
    store = _store(isolated)
    run_stage_a(store, genesis_block, [target], MODE)
    b_result = run_stage_b(store, genesis_block, [target], MODE)
    assert b_result["potential_match"] is False
    c_result = run_stage_c(store, genesis_block, [target], MODE)
    assert c_result["potential_match"] is False
    abc_rows = list_witness_candidates(store.conn)
    assert len(list_witness_candidates(store.conn, "B")) == 630
    assert len(list_witness_candidates(store.conn, "C")) == 84
    assert len(abc_rows) == 714
    assert all(int(row["matched"]) == 0 for row in abc_rows)
    assert all(row["target_id"] == target.id for row in abc_rows)
    b_snapshot = [
        _witness_public_snapshot(row) for row in list_witness_candidates(store.conn, "B")
    ]
    c_snapshot = [
        _witness_public_snapshot(row) for row in list_witness_candidates(store.conn, "C")
    ]
    output = io.StringIO()
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    result = run_stage_d(store, genesis_block, [target], MODE, out=output)
    assert derive_calls["n"] == 1
    text = output.getvalue()
    d_rows = list_witness_candidates(store.conn, "D")
    run = latest_run(store.conn)
    assert result["potential_match"] is True
    assert result["witness_candidates_tested"] == 1
    assert result["cumulative_witness_candidates"] == 715
    assert run["status"] == "potential_match"
    assert run["tested_candidate_count"] == 1
    assert len(d_rows) == 1
    assert int(d_rows[0]["matched"]) == 1
    assert d_rows[0]["template_id"] == "p2pk_compressed"
    assert d_rows[0]["fingerprint"] == fingerprint
    assert d_rows[0]["first_tested_stage"] == "D"
    assert [_witness_public_snapshot(row) for row in list_witness_candidates(store.conn, "B")] == (
        b_snapshot
    )
    assert [_witness_public_snapshot(row) for row in list_witness_candidates(store.conn, "C")] == (
        c_snapshot
    )
    assert counts(store.conn)["witness_candidates"] == 715
    assert "POTENTIAL MATCH FOUND" in text
    assert fingerprint in text
    assert candidate.name in text
    assert candidate.pubkey_hex in text
    assert candidate.address in text
    assert candidate.witness_script_hex in text
    provenance = ",".join(item.recipe.derivation_id for item in group)
    assert provenance in text
    assert f"{scalar:064x}" not in text
    assert str(scalar) not in text
    assert "private_scalar=REDACTED" in text
    _assert_public_schema(store)


def test_stage_d_replacement_rolls_back_without_partial_state(
    isolated, genesis_block, targets, monkeypatch
):
    store = _prepare_abc(isolated, genesis_block, targets)
    before = _state_snapshot(store)
    real_upsert = storage_mod.upsert_witness_candidate
    inserted = {"count": 0}

    def flaky(conn, **kwargs):
        inserted["count"] += 1
        result = real_upsert(conn, **kwargs)
        if inserted["count"] >= 1:
            raise RuntimeError("injected stage D replacement failure")
        return result

    monkeypatch.setattr(storage_mod, "upsert_witness_candidate", flaky)
    with pytest.raises(RuntimeError, match="injected stage D replacement failure"):
        run_stage_d(store, genesis_block, targets, MODE)
    assert inserted["count"] >= 1
    assert _state_snapshot(store) == before
    assert store.conn.execute("SELECT COUNT(*) FROM runs WHERE stage = 'D'").fetchone()[0] == 0
    assert list_witness_candidates(store.conn, "D") == []
    assert counts(store.conn)["unique_keys"] == 119
    assert counts(store.conn)["witness_candidates"] == 714


def test_stage_b_rerun_invalidates_stage_c_and_d_down_to_b_state(
    isolated, genesis_block, targets, monkeypatch
):
    store = _prepare_abc(isolated, genesis_block, targets)
    run_stage_d(store, genesis_block, targets, MODE)
    assert counts(store.conn)["unique_keys"] == 159
    assert counts(store.conn)["witness_candidates"] == 954
    assert list_witness_candidates(store.conn, "C")
    assert list_witness_candidates(store.conn, "D")
    d_runs = store.conn.execute("SELECT COUNT(*) FROM runs WHERE stage = 'D'").fetchone()[0]
    c_runs = store.conn.execute("SELECT COUNT(*) FROM runs WHERE stage = 'C'").fetchone()[0]
    assert d_runs == 1
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    result = run_stage_b(store, genesis_block, targets, MODE)
    assert derive_calls["n"] == 105
    assert result["witness_candidates"] == 630
    after = counts(store.conn)
    rows = list_witness_candidates(store.conn)
    assert after["unique_keys"] == 105
    assert after["witness_candidates"] == 630
    assert after["witness_matches"] == 0
    assert len(rows) == 630
    assert all(row["first_tested_stage"] == "B" for row in rows)
    assert list_witness_candidates(store.conn, "C") == []
    assert list_witness_candidates(store.conn, "D") == []
    assert (
        store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'C'").fetchone()[0] == 0
    )
    assert (
        store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'D'").fetchone()[0] == 0
    )
    assert (
        store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'B'").fetchone()[0]
        == 105
    )
    assert store.conn.execute("SELECT COUNT(*) FROM runs WHERE stage = 'C'").fetchone()[0] == (
        c_runs
    )
    assert store.conn.execute("SELECT COUNT(*) FROM runs WHERE stage = 'D'").fetchone()[0] == (
        d_runs
    )
    b_fps = {
        str(row[0])
        for row in store.conn.execute(
            "SELECT DISTINCT fingerprint FROM derivations WHERE stage IN ('A', 'B') "
            "AND fingerprint IS NOT NULL"
        )
    }
    key_fps = {
        str(row[0]) for row in store.conn.execute("SELECT fingerprint FROM keys").fetchall()
    }
    assert key_fps == b_fps
    assert len(key_fps) == 105
    _assert_public_schema(store)


def test_stage_d_rejects_target_id_mismatch_without_curve_or_mutation(
    isolated, genesis_block, targets, monkeypatch
):
    store = _prepare_abc(isolated, genesis_block, targets)
    before = _state_snapshot(store)
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    _boom_stage_d_recipes(monkeypatch, "Stage D recipes must not run on a target-ID mismatch")
    other = replace(targets[0], id="synthetic-other-p2wsh")
    with pytest.raises(StageDPrerequisiteError, match="current validated P2WSH target ID"):
        run_stage_d(store, genesis_block, [other], MODE)
    assert derive_calls["n"] == 0
    _assert_no_stage_d(store, before)


def test_stage_d_rejects_self_consistent_wrong_c_script_without_curve_or_mutation(
    isolated, genesis_block, targets, monkeypatch
):
    store = _prepare_abc(isolated, genesis_block, targets)
    c_row = list_witness_candidates(store.conn, "C")[0]
    template = next(item for item in WITNESS_TEMPLATES if item.template_id == c_row["template_id"])
    other = next(
        item
        for item in WITNESS_TEMPLATES
        if item.pubkey_mode == template.pubkey_mode and item.template_id != template.template_id
    )
    pubkey = bytes.fromhex(str(c_row["pubkey_hex"]))
    alt_script = expected_witness_script(other, pubkey)
    original_script = bytes.fromhex(str(c_row["witness_script_hex"]))
    assert alt_script != original_script
    program, address = p2wsh_program_and_address(alt_script)
    store.conn.execute(
        """
        UPDATE witness_candidates
        SET witness_script_hex = ?, witness_program_hex = ?, address = ?
        WHERE id = ?
        """,
        (alt_script.hex(), program.hex(), address, c_row["id"]),
    )
    store.conn.commit()
    stored = store.conn.execute(
        "SELECT template_id, pubkey_hex, witness_script_hex, witness_program_hex, address "
        "FROM witness_candidates WHERE id = ?",
        (c_row["id"],),
    ).fetchone()
    assert stored["template_id"] == c_row["template_id"]
    assert stored["pubkey_hex"] == c_row["pubkey_hex"]
    assert stored["witness_script_hex"] == alt_script.hex()
    mutated = _state_snapshot(store)
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    _boom_stage_d_recipes(monkeypatch, "Stage D recipes must not run on a corrupted C script")
    with pytest.raises(StageDPrerequisiteError, match="exact template script"):
        run_stage_d(store, genesis_block, targets, MODE)
    assert derive_calls["n"] == 0
    _assert_no_stage_d(store, mutated)


def test_inconsistent_p2wsh_target_rejected_before_stage_d_curve(
    isolated, genesis_block, targets, monkeypatch
):
    store = _prepare_abc(isolated, genesis_block, targets)
    before = _state_snapshot(store)
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    _boom_stage_d_recipes(monkeypatch, "Stage D recipes must not run on an inconsistent target")
    target = targets[0]
    bad_targets = [
        replace(target, witness_program_hex="aa" * 31),
        replace(target, script_pubkey_hex="00" * 34),
        replace(target, address="bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
    ]
    for bad in bad_targets:
        derive_calls["n"] = 0
        with pytest.raises(TargetConsistencyError):
            run_stage_d(store, genesis_block, [bad], MODE)
        assert derive_calls["n"] == 0
        _assert_no_stage_d(store, before)


def _argv(isolated: Path, repo_root: Path, argv: list[str]) -> list[str]:
    return [
        "--root",
        str(repo_root),
        "--config",
        str(repo_root / "config.toml"),
        "--state-dir",
        str(isolated / "state"),
        "--report-path",
        str(isolated / "research" / "report.md"),
        *argv,
    ]


def _cli(isolated: Path, repo_root: Path, argv: list[str]) -> str:
    buf = io.StringIO()
    code = main(_argv(isolated, repo_root, argv), out=buf)
    assert code == 0, buf.getvalue()
    return buf.getvalue()


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


def _capture_render(monkeypatch: pytest.MonkeyPatch) -> dict:
    captured: dict = {}

    def fake_render(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return "captured-report"

    monkeypatch.setattr("genesis_puzzle.cli.render_report", fake_render)
    return captured


def test_cli_parser_exposes_stage_d_choices_and_help():
    parser = _build_parser()
    help_text = parser.format_help()
    assert "Stage A" in help_text
    assert "Stage B" in help_text
    assert "Stage C" in help_text
    assert "Stage D" in help_text
    assert "sequential/offline" in help_text
    assert "direct bounded" in help_text
    candidates = parser.parse_args(["candidates", "--stage", "D"])
    assert candidates.stage == "D"
    run = parser.parse_args(["run", "--stage", "D", "--mode", "balanced"])
    assert run.stage == "D"
    with pytest.raises(SystemExit):
        parser.parse_args(["run", "--stage", "E"])
    with pytest.raises(SystemExit):
        parser.parse_args(["candidates", "--stage", "E"])


def test_cli_stage_d_preview_lists_recipes_and_templates(isolated, repo_root, genesis_block):
    preview = _cli(isolated, repo_root, ["candidates", "--stage", "D"])
    assert "stage D recipes: 40" in preview
    assert "D-001" in preview
    assert "D-040" in preview
    assert "private_scalar: REDACTED" in preview
    assert "scalars not derived" in preview
    assert "up to six scripts per unique key" in preview
    assert "Preview does not derive a scalar or public key" in preview
    positions = [preview.index(name) for name in TEMPLATE_ORDER]
    assert positions == sorted(positions)
    for name in TEMPLATE_ORDER:
        assert name in preview
    for recipe in stage_d_recipes(genesis_block):
        scalar = compute_scalar(recipe)
        assert str(scalar) not in preview
        assert f"{scalar:064x}" not in preview
    _assert_no_secrets(preview, genesis_block)


def test_run_d_before_a_is_controlled_cli_error_without_running_row(isolated, repo_root):
    _cli(isolated, repo_root, ["init"])
    buf = io.StringIO()
    code = main(_argv(isolated, repo_root, ["run", "--stage", "D"]), out=buf)
    assert code != 0
    text = buf.getvalue()
    assert "error:" in text
    assert "Stage D requires a complete stored Stage A result" in text
    store = connect(isolated / "state" / "research.sqlite")
    assert store.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0
    running = store.conn.execute("SELECT COUNT(*) FROM runs WHERE status = 'running'").fetchone()[
        0
    ]
    assert running == 0


def test_run_d_before_b_is_controlled_cli_error_without_d_row(isolated, repo_root):
    _cli(isolated, repo_root, ["init"])
    _cli(isolated, repo_root, ["run", "--stage", "A"])
    buf = io.StringIO()
    code = main(_argv(isolated, repo_root, ["run", "--stage", "D"]), out=buf)
    assert code != 0
    text = buf.getvalue()
    assert "error:" in text
    assert "Stage D requires a complete stored Stage B result" in text
    store = connect(isolated / "state" / "research.sqlite")
    assert store.conn.execute("SELECT COUNT(*) FROM runs WHERE stage = 'D'").fetchone()[0] == 0
    running = store.conn.execute("SELECT COUNT(*) FROM runs WHERE status = 'running'").fetchone()[
        0
    ]
    assert running == 0
    assert (
        store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'D'").fetchone()[0] == 0
    )


def test_run_d_before_c_is_controlled_cli_error_without_d_row(isolated, repo_root):
    _cli(isolated, repo_root, ["init"])
    _cli(isolated, repo_root, ["run", "--stage", "A"])
    _cli(isolated, repo_root, ["run", "--stage", "B"])
    buf = io.StringIO()
    code = main(_argv(isolated, repo_root, ["run", "--stage", "D"]), out=buf)
    assert code != 0
    text = buf.getvalue()
    assert "error:" in text
    assert "Stage D requires a complete stored Stage C result" in text
    store = connect(isolated / "state" / "research.sqlite")
    assert store.conn.execute("SELECT COUNT(*) FROM runs WHERE stage = 'D'").fetchone()[0] == 0
    running = store.conn.execute("SELECT COUNT(*) FROM runs WHERE status = 'running'").fetchone()[
        0
    ]
    assert running == 0
    assert (
        store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'D'").fetchone()[0] == 0
    )


def test_cli_stage_a_b_c_d_run_summary_status_report_and_redaction(
    isolated, repo_root, genesis_block
):
    _cli(isolated, repo_root, ["init"])
    _cli(isolated, repo_root, ["run", "--stage", "A", "--mode", "balanced"])
    _cli(isolated, repo_root, ["run", "--stage", "B", "--mode", "balanced"])
    _cli(isolated, repo_root, ["run", "--stage", "C", "--mode", "balanced"])
    out_d = _cli(isolated, repo_root, ["run", "--stage", "D", "--mode", "balanced"])
    assert "run complete" in out_d
    assert "derivations=40" in out_d
    assert "invalid=0" in out_d
    assert "unique_keys=159" in out_d
    assert "duplicates=21" in out_d
    assert "new_unique_keys=40" in out_d
    assert "witness_candidates_tested=240" in out_d
    assert "cumulative_witness_candidates=954" in out_d
    assert "elapsed_s=" in out_d
    assert "checkpoint=not-needed" in out_d
    assert "private_scalar=REDACTED" in out_d
    assert "POTENTIAL MATCH FOUND" not in out_d
    status = _cli(isolated, repo_root, ["status"])
    assert "status=ok" in status
    assert "stage=D" in status
    assert "unique_keys=159" in status
    assert "checkpoint=not-needed" in status
    assert "mode=balanced" in status
    report = (isolated / "research" / "report.md").read_text(encoding="utf-8")
    assert "Stage A+B+C+D report" in report
    assert "Stage A+B+C report" not in report
    assert "Hypotheses tested in Stage D" in report
    assert "Stage D derivations: 40" in report
    assert "cumulative unique valid keys after A+B+C+D: 159" in report
    assert "new Stage D witness candidates: 240" in report
    assert "cumulative B+C+D witness candidates: 954" in report
    assert "Next highest-value Stage E experiment (not executed)" in report
    assert "Do not execute Stage E here" in report
    assert "Next highest-value Stage D experiment (not executed)" not in report
    dumped = dump_text(connect(isolated / "state" / "research.sqlite").conn)
    combined = out_d + status + report + dumped
    _assert_no_secrets(combined, genesis_block)
    _assert_public_schema(connect(isolated / "state" / "research.sqlite"))


def test_cli_report_passes_exact_d_run_when_latest_run_is_another_stage(
    isolated, repo_root, monkeypatch
):
    store = connect(isolated / "state" / "research.sqlite")
    conn = store.conn
    run_d = insert_run(conn, "2026-01-01T00:00:00Z", "D", "eco", "ok")
    _finish(
        conn,
        run_d,
        derivation_count=40,
        unique_valid_keys=159,
        duplicate_count=21,
        tested_candidate_count=240,
        elapsed_seconds=11.11,
    )
    run_a = insert_run(conn, "2026-01-01T00:01:00Z", "A", "max", "ok")
    _finish(
        conn,
        run_a,
        derivation_count=23,
        unique_valid_keys=22,
        elapsed_seconds=0.11,
    )
    upsert_key(conn, "fp-d", run_d)
    _seed_derivation(conn, "D-001", "fp-d", run_d)
    _seed_witness(conn, "fp-d", run_d, "D")
    conn.commit()

    captured = _capture_render(monkeypatch)
    _write_current_report(store, repo_root, isolated / "research" / "report.md")
    stage_d_run = captured["kwargs"]["stage_d_run"]
    latest = captured["args"][3]
    assert latest is not None
    assert latest["id"] == run_a
    assert latest["stage"] == "A"
    assert stage_d_run is not None
    assert stage_d_run["id"] == run_d
    assert stage_d_run["stage"] == "D"
    assert stage_d_run["mode"] == "eco"
    assert stage_d_run["unique_valid_keys"] == 159
    assert stage_d_run["derivation_count"] == 40
    assert stage_d_run["tested_candidate_count"] == 240
    assert stage_d_run["elapsed_seconds"] == 11.11
    assert captured["kwargs"]["stage_a_run"]["id"] == run_a


def test_cli_report_ignores_stale_historical_d_after_c_invalidation(
    isolated, repo_root, monkeypatch
):
    store = connect(isolated / "state" / "research.sqlite")
    conn = store.conn
    run_d = insert_run(conn, "2026-01-01T00:00:00Z", "D", "eco", "ok")
    _finish(
        conn,
        run_d,
        derivation_count=40,
        unique_valid_keys=159,
        duplicate_count=21,
        tested_candidate_count=240,
        elapsed_seconds=11.11,
    )
    upsert_key(conn, "fp-c", run_d)
    upsert_key(conn, "fp-d", run_d)
    _seed_derivation(conn, "C-001", "fp-c", run_d)
    _seed_derivation(conn, "D-001", "fp-d", run_d)
    _seed_witness(conn, "fp-c", run_d, "C")
    _seed_witness(conn, "fp-d", run_d, "D")
    invalidate_stage_d_current_state(conn)
    run_c = insert_run(conn, "2026-01-01T00:02:00Z", "C", "balanced", "ok")
    _finish(
        conn,
        run_c,
        derivation_count=14,
        unique_valid_keys=119,
        duplicate_count=21,
        tested_candidate_count=84,
        elapsed_seconds=2.0,
    )
    conn.commit()

    captured = _capture_render(monkeypatch)
    _write_current_report(store, repo_root, isolated / "research" / "report.md")
    latest = captured["args"][3]
    assert latest is not None
    assert latest["id"] == run_c
    assert latest["stage"] == "C"
    assert captured["kwargs"]["stage_d_run"] is None
    assert captured["kwargs"]["stage_c_run"]["id"] == run_c
    remaining_stages = {row["stage"] for row in captured["args"][4]}
    assert "D" not in remaining_stages
    witness_stages = {row.get("first_tested_stage") for row in captured["args"][7]}
    assert "D" not in witness_stages
    assert store.conn.execute("SELECT COUNT(*) FROM runs WHERE stage = 'D'").fetchone()[0] == 1
