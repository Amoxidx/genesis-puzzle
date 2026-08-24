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

try:
    from genesis_puzzle.stage_e import stage_e_recipes
except ImportError:

    def stage_e_recipes(_block):
        raise AssertionError("stage_e_recipes is not implemented on this tree")


StageEPrerequisiteError = getattr(engine_mod, "StageEPrerequisiteError", None)
if StageEPrerequisiteError is None:

    class StageEPrerequisiteError(ValueError):
        """Collection-safe stub used only on pre-Stage-E trees."""


def run_stage_e(*args, **kwargs):
    fn = getattr(engine_mod, "run_stage_e", None)
    assert fn is not None, "run_stage_e is not implemented on this tree"
    return fn(*args, **kwargs)


def invalidate_stage_e_current_state(*args, **kwargs):
    fn = getattr(storage_mod, "invalidate_stage_e_current_state", None)
    assert fn is not None, "invalidate_stage_e_current_state is not implemented on this tree"
    return fn(*args, **kwargs)


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


def _boom_stage_e_recipes(monkeypatch: pytest.MonkeyPatch, message: str) -> None:
    def boom_recipes(_block):
        raise AssertionError(message)

    monkeypatch.setattr(engine_mod, "stage_e_recipes", boom_recipes)


def _store(path: Path) -> Store:
    return connect(path / "state" / "research.sqlite")


def _prepare_abcd(path: Path, genesis_block: ParsedBlock, targets: list[KnownTarget]) -> Store:
    store = _store(path)
    run_stage_a(store, genesis_block, targets, MODE)
    run_stage_b(store, genesis_block, targets, MODE)
    run_stage_c(store, genesis_block, targets, MODE)
    run_stage_d(store, genesis_block, targets, MODE)
    return store


def _sha256_scalar_hexes(genesis_block: ParsedBlock) -> list[str]:
    hexes = []
    recipes = (
        stage_a_recipes(genesis_block)
        + stage_b_recipes(genesis_block)
        + stage_c_recipes(genesis_block)
        + stage_e_recipes(genesis_block)
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


def _stage_e_secret_tokens(genesis_block: ParsedBlock) -> list[str]:
    tokens = []
    for recipe in stage_e_recipes(genesis_block):
        scalar = compute_scalar(recipe)
        tokens.append(str(scalar))
        tokens.append(f"{scalar:064x}")
    return tokens


def _assert_no_secrets(text: str, genesis_block: ParsedBlock) -> None:
    for secret in _sha256_scalar_hexes(genesis_block):
        assert secret not in text
    for secret in _stage_d_secret_tokens(genesis_block):
        assert secret not in text
    for secret in _stage_e_secret_tokens(genesis_block):
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


def _assert_no_stage_e(store: Store, before: tuple) -> None:
    assert _state_snapshot(store) == before
    assert store.conn.execute("SELECT COUNT(*) FROM runs WHERE stage = 'E'").fetchone()[0] == 0
    assert (
        store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'E'").fetchone()[0] == 0
    )
    assert list_witness_candidates(store.conn, "E") == []


def test_run_e_before_a_is_controlled_error_without_curve_or_run(
    isolated, genesis_block, targets, monkeypatch
):
    store = _store(isolated)
    before = _state_snapshot(store)
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    _boom_stage_e_recipes(monkeypatch, "Stage E recipes must not run before Stage A")
    with pytest.raises(StageEPrerequisiteError, match="run Stage A first"):
        run_stage_e(store, genesis_block, targets, MODE)
    assert derive_calls["n"] == 0
    _assert_no_stage_e(store, before)


def test_run_e_before_b_c_d_is_controlled_error_without_curve_or_run(
    isolated, genesis_block, targets, monkeypatch
):
    store = _store(isolated)
    run_stage_a(store, genesis_block, targets, MODE)
    before_b = _state_snapshot(store)
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    derive_calls["n"] = 0
    _boom_stage_e_recipes(monkeypatch, "Stage E recipes must not run before Stage B")
    with pytest.raises(StageEPrerequisiteError, match="run Stage B first"):
        run_stage_e(store, genesis_block, targets, MODE)
    assert derive_calls["n"] == 0
    _assert_no_stage_e(store, before_b)

    run_stage_b(store, genesis_block, targets, MODE)
    before_c = _state_snapshot(store)
    derive_calls["n"] = 0
    _boom_stage_e_recipes(monkeypatch, "Stage E recipes must not run before Stage C")
    with pytest.raises(StageEPrerequisiteError, match="run Stage C first"):
        run_stage_e(store, genesis_block, targets, MODE)
    assert derive_calls["n"] == 0
    _assert_no_stage_e(store, before_c)

    run_stage_c(store, genesis_block, targets, MODE)
    before_d = _state_snapshot(store)
    derive_calls["n"] = 0
    _boom_stage_e_recipes(monkeypatch, "Stage E recipes must not run before Stage D")
    with pytest.raises(StageEPrerequisiteError, match="run Stage D first"):
        run_stage_e(store, genesis_block, targets, MODE)
    assert derive_calls["n"] == 0
    _assert_no_stage_e(store, before_d)


def test_stage_e_real_target_counts_ordering_preservation_and_idempotent_rerun(
    isolated, genesis_block, targets, monkeypatch
):
    store = _prepare_abcd(isolated, genesis_block, targets)
    b_snapshot = [
        _witness_public_snapshot(row) for row in list_witness_candidates(store.conn, "B")
    ]
    c_snapshot = [
        _witness_public_snapshot(row) for row in list_witness_candidates(store.conn, "C")
    ]
    d_snapshot = [
        _witness_public_snapshot(row) for row in list_witness_candidates(store.conn, "D")
    ]
    assert len(b_snapshot) == 630
    assert len(c_snapshot) == 84
    assert len(d_snapshot) == 240
    address_rows = store.conn.execute("SELECT COUNT(*) FROM addresses").fetchone()[0]
    history_rows_n = store.conn.execute("SELECT COUNT(*) FROM history").fetchone()[0]

    expected_e_fps = []
    for recipe in stage_e_recipes(genesis_block):
        evaluated, _scalar = evaluate_recipe(recipe)
        assert evaluated.fingerprint is not None
        expected_e_fps.append(evaluated.fingerprint)
    assert len(expected_e_fps) == 8
    assert len(set(expected_e_fps)) == 8

    output = io.StringIO()
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    result = run_stage_e(store, genesis_block, targets, MODE, out=output)
    assert derive_calls["n"] == 167
    text = output.getvalue()
    run = latest_run(store.conn)
    after = counts(store.conn)
    e_rows = list_witness_candidates(store.conn, "E")
    all_rows = list_witness_candidates(store.conn)
    assert result["derivations"] == 8
    assert result["invalid"] == 0
    assert result["unique_valid_keys"] == 167
    assert result["new_unique_keys"] == 8
    assert result["duplicates"] == 21
    assert result["witness_candidates_tested"] == 48
    assert result["cumulative_witness_candidates"] == 1002
    assert result["potential_match"] is False
    assert after["unique_keys"] == 167
    assert after["witness_candidates"] == 1002
    assert after["witness_matches"] == 0
    assert after["addresses"] == address_rows
    assert store.conn.execute("SELECT COUNT(*) FROM history").fetchone()[0] == history_rows_n
    assert (
        store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'E'").fetchone()[0] == 8
    )
    assert run["stage"] == "E"
    assert run["status"] == "ok"
    assert run["derivation_count"] == 8
    assert run["invalid_count"] == 0
    assert run["unique_valid_keys"] == 167
    assert run["duplicate_count"] == 21
    assert run["address_count"] == 0
    assert run["tested_candidate_count"] == 48
    assert len(e_rows) == 48
    assert len(all_rows) == 1002
    assert [_witness_public_snapshot(row) for row in list_witness_candidates(store.conn, "B")] == (
        b_snapshot
    )
    assert [_witness_public_snapshot(row) for row in list_witness_candidates(store.conn, "C")] == (
        c_snapshot
    )
    assert [_witness_public_snapshot(row) for row in list_witness_candidates(store.conn, "D")] == (
        d_snapshot
    )
    assert all(row["first_tested_stage"] == "B" for row in all_rows[:630])
    assert all(row["first_tested_stage"] == "C" for row in all_rows[630:714])
    assert all(row["first_tested_stage"] == "D" for row in all_rows[714:954])
    assert all(row["first_tested_stage"] == "E" for row in all_rows[954:])
    assert all(row["template_id"] == "p2pk_compressed" for row in e_rows[:8])
    assert all(row["template_id"] == "p2pkh_uncompressed" for row in e_rows[-8:])
    assert [row["template_id"] for row in e_rows[::8]] == list(TEMPLATE_ORDER)
    assert [row["fingerprint"] for row in e_rows[:8]] == expected_e_fps
    assert all(int(row["matched"]) == 0 for row in e_rows)
    assert "POTENTIAL MATCH FOUND" not in text
    assert "private_scalar=REDACTED" in text

    store.conn.execute(
        "UPDATE witness_candidates SET derivation_ids = 'STALE-E' WHERE id = ?",
        (e_rows[0]["id"],),
    )
    store.conn.commit()
    derive_calls["n"] = 0
    output2 = io.StringIO()
    result2 = run_stage_e(store, genesis_block, targets, MODE, out=output2)
    assert derive_calls["n"] == 167
    assert result2["new_unique_keys"] == 8
    assert result2["cumulative_witness_candidates"] == 1002
    e_rows2 = list_witness_candidates(store.conn, "E")
    assert [_witness_public_snapshot(row) for row in list_witness_candidates(store.conn, "B")] == (
        b_snapshot
    )
    assert [_witness_public_snapshot(row) for row in list_witness_candidates(store.conn, "D")] == (
        d_snapshot
    )
    assert len(e_rows2) == 48
    assert e_rows2[0]["derivation_ids"] != "STALE-E"
    dumped = dump_text(store.conn)
    combined = text + output2.getvalue() + dumped
    _assert_no_secrets(combined, genesis_block)
    _assert_public_schema(store)


def test_stage_e_prerequisite_corruptions_do_not_mutate_or_call_curve(
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
        "wrong_d_metrics",
    )
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    for name in cases:
        fresh = _prepare_abcd(isolated / name, genesis_block, targets)
        before = _state_snapshot(fresh)
        d_row = list_witness_candidates(fresh.conn, "D")[0]
        a01_fp = fresh.conn.execute(
            "SELECT fingerprint FROM derivations WHERE derivation_id = 'A-01'"
        ).fetchone()[0]
        d001_id = fresh.conn.execute(
            "SELECT derivation_id FROM derivations WHERE stage = 'D' AND valid = 1 LIMIT 1"
        ).fetchone()[0]
        if name == "missing_row":
            fresh.conn.execute("DELETE FROM witness_candidates WHERE id = ?", (d_row["id"],))
        elif name == "wrong_derivation_fingerprint":
            fresh.conn.execute(
                "UPDATE derivations SET fingerprint = ? WHERE derivation_id = ?",
                (a01_fp, d001_id),
            )
        elif name == "wrong_template_metadata":
            fresh.conn.execute(
                """
                UPDATE witness_candidates
                SET template_name = 'not-canonical', priority = 99
                WHERE id = ?
                """,
                (d_row["id"],),
            )
        elif name == "wrong_script":
            fresh.conn.execute(
                "UPDATE witness_candidates SET witness_script_hex = ? WHERE id = ?",
                ("00" * 10, d_row["id"]),
            )
        elif name == "wrong_program":
            fresh.conn.execute(
                "UPDATE witness_candidates SET witness_program_hex = ? WHERE id = ?",
                ("11" * 32, d_row["id"]),
            )
        elif name == "wrong_address":
            fresh.conn.execute(
                "UPDATE witness_candidates SET address = ? WHERE id = ?",
                ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", d_row["id"]),
            )
        elif name == "matched_row":
            fresh.conn.execute(
                "UPDATE witness_candidates SET matched = 1 WHERE id = ?",
                (d_row["id"],),
            )
        elif name == "potential_baseline":
            fresh.conn.execute("UPDATE runs SET status = 'potential_match' WHERE stage = 'D'")
        else:
            fresh.conn.execute(
                """
                UPDATE runs
                SET unique_valid_keys = 1, tested_candidate_count = 0
                WHERE stage = 'D'
                """
            )
        fresh.conn.commit()
        mutated = _state_snapshot(fresh)
        derive_calls["n"] = 0
        _boom_stage_e_recipes(
            monkeypatch, f"Stage E recipes must not run on corrupted D baseline {name}"
        )
        with pytest.raises(StageEPrerequisiteError):
            run_stage_e(fresh, genesis_block, targets, MODE)
        assert derive_calls["n"] == 0
        _assert_no_stage_e(fresh, mutated)
        assert _state_snapshot(fresh) != before


def test_first_synthetic_e_candidate_match_stops_after_one(isolated, genesis_block, monkeypatch):
    pairs = [evaluate_recipe(recipe) for recipe in stage_e_recipes(genesis_block)]
    unique = dedupe_valid_scalars(pairs)
    fingerprint, scalar, group = unique[0]
    uncompressed, compressed = derive_pubkeys(scalar)
    candidate = build_p2wsh_candidate(WITNESS_TEMPLATES[0], uncompressed, compressed)
    program = candidate.witness_program
    target = KnownTarget(
        id="synthetic-first-e-p2wsh",
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
        notes="synthetic first global Stage E candidate",
    )
    store = _store(isolated)
    run_stage_a(store, genesis_block, [target], MODE)
    assert run_stage_b(store, genesis_block, [target], MODE)["potential_match"] is False
    assert run_stage_c(store, genesis_block, [target], MODE)["potential_match"] is False
    assert run_stage_d(store, genesis_block, [target], MODE)["potential_match"] is False
    abcd_rows = list_witness_candidates(store.conn)
    assert len(list_witness_candidates(store.conn, "B")) == 630
    assert len(list_witness_candidates(store.conn, "C")) == 84
    assert len(list_witness_candidates(store.conn, "D")) == 240
    assert len(abcd_rows) == 954
    assert all(int(row["matched"]) == 0 for row in abcd_rows)
    b_snapshot = [
        _witness_public_snapshot(row) for row in list_witness_candidates(store.conn, "B")
    ]
    d_snapshot = [
        _witness_public_snapshot(row) for row in list_witness_candidates(store.conn, "D")
    ]
    output = io.StringIO()
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    result = run_stage_e(store, genesis_block, [target], MODE, out=output)
    assert derive_calls["n"] == 160
    text = output.getvalue()
    e_rows = list_witness_candidates(store.conn, "E")
    run = latest_run(store.conn)
    assert result["potential_match"] is True
    assert result["witness_candidates_tested"] == 1
    assert result["cumulative_witness_candidates"] == 955
    assert run["status"] == "potential_match"
    assert run["tested_candidate_count"] == 1
    assert len(e_rows) == 1
    assert int(e_rows[0]["matched"]) == 1
    assert e_rows[0]["template_id"] == "p2pk_compressed"
    assert e_rows[0]["fingerprint"] == fingerprint
    assert e_rows[0]["first_tested_stage"] == "E"
    assert [_witness_public_snapshot(row) for row in list_witness_candidates(store.conn, "B")] == (
        b_snapshot
    )
    assert [_witness_public_snapshot(row) for row in list_witness_candidates(store.conn, "D")] == (
        d_snapshot
    )
    assert "POTENTIAL MATCH FOUND" in text
    assert fingerprint in text
    assert f"{scalar:064x}" not in text
    assert str(scalar) not in text
    assert "private_scalar=REDACTED" in text
    _assert_public_schema(store)


def test_stage_e_replacement_rolls_back_without_partial_state(
    isolated, genesis_block, targets, monkeypatch
):
    store = _prepare_abcd(isolated, genesis_block, targets)
    before = _state_snapshot(store)
    real_upsert = storage_mod.upsert_witness_candidate
    inserted = {"count": 0}

    def flaky(conn, **kwargs):
        inserted["count"] += 1
        result = real_upsert(conn, **kwargs)
        if inserted["count"] >= 1:
            raise RuntimeError("injected stage E replacement failure")
        return result

    monkeypatch.setattr(storage_mod, "upsert_witness_candidate", flaky)
    with pytest.raises(RuntimeError, match="injected stage E replacement failure"):
        run_stage_e(store, genesis_block, targets, MODE)
    assert inserted["count"] >= 1
    assert _state_snapshot(store) == before
    assert store.conn.execute("SELECT COUNT(*) FROM runs WHERE stage = 'E'").fetchone()[0] == 0
    assert list_witness_candidates(store.conn, "E") == []
    assert counts(store.conn)["unique_keys"] == 159
    assert counts(store.conn)["witness_candidates"] == 954


def test_stage_b_c_d_reruns_invalidate_downstream_e(isolated, genesis_block, targets, monkeypatch):
    store = _prepare_abcd(isolated, genesis_block, targets)
    run_stage_e(store, genesis_block, targets, MODE)
    assert counts(store.conn)["unique_keys"] == 167
    assert counts(store.conn)["witness_candidates"] == 1002
    e_runs = store.conn.execute("SELECT COUNT(*) FROM runs WHERE stage = 'E'").fetchone()[0]
    d_runs = store.conn.execute("SELECT COUNT(*) FROM runs WHERE stage = 'D'").fetchone()[0]
    assert e_runs == 1
    result_d = run_stage_d(store, genesis_block, targets, MODE)
    assert result_d["cumulative_witness_candidates"] == 954
    assert list_witness_candidates(store.conn, "E") == []
    assert (
        store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'E'").fetchone()[0] == 0
    )
    assert counts(store.conn)["unique_keys"] == 159
    assert store.conn.execute("SELECT COUNT(*) FROM runs WHERE stage = 'E'").fetchone()[0] == (
        e_runs
    )
    assert store.conn.execute("SELECT COUNT(*) FROM runs WHERE stage = 'D'").fetchone()[0] == (
        d_runs + 1
    )

    run_stage_e(store, genesis_block, targets, MODE)
    result_c = run_stage_c(store, genesis_block, targets, MODE)
    assert result_c["cumulative_witness_candidates"] == 714
    assert list_witness_candidates(store.conn, "D") == []
    assert list_witness_candidates(store.conn, "E") == []
    assert counts(store.conn)["unique_keys"] == 119

    run_stage_d(store, genesis_block, targets, MODE)
    run_stage_e(store, genesis_block, targets, MODE)
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    result_b = run_stage_b(store, genesis_block, targets, MODE)
    assert derive_calls["n"] == 105
    assert result_b["witness_candidates"] == 630
    assert counts(store.conn)["unique_keys"] == 105
    assert list_witness_candidates(store.conn, "C") == []
    assert list_witness_candidates(store.conn, "D") == []
    assert list_witness_candidates(store.conn, "E") == []
    _assert_public_schema(store)


def test_stage_e_rejects_target_id_mismatch_without_curve_or_mutation(
    isolated, genesis_block, targets, monkeypatch
):
    store = _prepare_abcd(isolated, genesis_block, targets)
    before = _state_snapshot(store)
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    _boom_stage_e_recipes(monkeypatch, "Stage E recipes must not run on a target-ID mismatch")
    other = replace(targets[0], id="synthetic-other-p2wsh")
    with pytest.raises(StageEPrerequisiteError, match="current validated P2WSH target ID"):
        run_stage_e(store, genesis_block, [other], MODE)
    assert derive_calls["n"] == 0
    _assert_no_stage_e(store, before)


def _swap_stored_pubkey_with_self_consistent_script(store: Store, stage: str) -> None:
    rows = [
        row
        for row in list_witness_candidates(store.conn, stage)
        if str(row["template_id"]) == "p2pk_compressed"
    ]
    donor = rows[0]
    victim = next(
        row
        for row in rows
        if str(row["fingerprint"]) != str(donor["fingerprint"])
        and str(row["pubkey_hex"]) != str(donor["pubkey_hex"])
    )
    template = next(
        item for item in WITNESS_TEMPLATES if item.template_id == victim["template_id"]
    )
    swapped_pubkey = bytes.fromhex(str(donor["pubkey_hex"]))
    script = expected_witness_script(template, swapped_pubkey)
    program, address = p2wsh_program_and_address(script)
    store.conn.execute(
        """
        UPDATE witness_candidates
        SET pubkey_hex = ?, witness_script_hex = ?, witness_program_hex = ?, address = ?
        WHERE id = ?
        """,
        (swapped_pubkey.hex(), script.hex(), program.hex(), address, victim["id"]),
    )
    store.conn.commit()


def _current_target_equal_to_stored_row(target: KnownTarget, row) -> KnownTarget:
    program = bytes.fromhex(str(row["witness_program_hex"]))
    address = str(row["address"])
    return replace(
        target,
        witness_program_hex=program.hex(),
        address=address,
        script_pubkey_hex=(bytes([0x00, 0x20]) + program).hex(),
    )


def test_stage_e_rejects_swapped_d_pubkey_with_self_consistent_script(
    isolated, genesis_block, targets, monkeypatch
):
    store = _prepare_abcd(isolated, genesis_block, targets)
    _swap_stored_pubkey_with_self_consistent_script(store, "D")
    mutated = _state_snapshot(store)
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    _boom_stage_e_recipes(monkeypatch, "Stage E recipes must not run on a swapped D pubkey")
    with pytest.raises(StageEPrerequisiteError, match="recomputed scalar"):
        run_stage_e(store, genesis_block, targets, MODE)
    assert derive_calls["n"] >= 1
    _assert_no_stage_e(store, mutated)


def test_stage_e_rejects_lying_unmatched_d_row_that_equals_current_target(
    isolated, genesis_block, targets, monkeypatch
):
    store = _prepare_abcd(isolated, genesis_block, targets)
    d_row = list_witness_candidates(store.conn, "D")[0]
    assert int(d_row["matched"]) == 0
    lying_target = _current_target_equal_to_stored_row(targets[0], d_row)
    before = _state_snapshot(store)
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    _boom_stage_e_recipes(monkeypatch, "Stage E recipes must not run on a lying unmatched D match")
    with pytest.raises(StageEPrerequisiteError, match="equal the current target"):
        run_stage_e(store, genesis_block, [lying_target], MODE)
    assert derive_calls["n"] == 0
    _assert_no_stage_e(store, before)


def test_inconsistent_p2wsh_target_rejected_before_stage_e_curve(
    isolated, genesis_block, targets, monkeypatch
):
    store = _prepare_abcd(isolated, genesis_block, targets)
    before = _state_snapshot(store)
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    _boom_stage_e_recipes(monkeypatch, "Stage E recipes must not run on an inconsistent target")
    target = targets[0]
    bad_targets = [
        replace(target, witness_program_hex="aa" * 31),
        replace(target, script_pubkey_hex="00" * 34),
        replace(target, address="bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
    ]
    for bad in bad_targets:
        derive_calls["n"] = 0
        with pytest.raises(TargetConsistencyError):
            run_stage_e(store, genesis_block, [bad], MODE)
        assert derive_calls["n"] == 0
        _assert_no_stage_e(store, before)


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


def test_cli_parser_exposes_stage_e_choices_and_help():
    parser = _build_parser()
    help_text = parser.format_help()
    assert "Stage A" in help_text
    assert "Stage E" in help_text
    assert "sequential/offline" in help_text
    candidates = parser.parse_args(["candidates", "--stage", "E"])
    assert candidates.stage == "E"
    run = parser.parse_args(["run", "--stage", "E", "--mode", "balanced"])
    assert run.stage == "E"
    with pytest.raises(SystemExit):
        parser.parse_args(["run", "--stage", "F"])
    with pytest.raises(SystemExit):
        parser.parse_args(["candidates", "--stage", "F"])


def test_cli_stage_e_preview_lists_recipes_and_templates(isolated, repo_root, genesis_block):
    preview = _cli(isolated, repo_root, ["candidates", "--stage", "E"])
    assert "stage E recipes: 8" in preview
    assert "E-001" in preview
    assert "E-008" in preview
    assert "private_scalar: REDACTED" in preview
    assert "scalars not derived" in preview
    assert "up to six scripts per unique key" in preview
    positions = [preview.index(name) for name in TEMPLATE_ORDER]
    assert positions == sorted(positions)
    for recipe in stage_e_recipes(genesis_block):
        scalar = compute_scalar(recipe)
        assert str(scalar) not in preview
        assert f"{scalar:064x}" not in preview


def test_run_e_before_a_is_controlled_cli_error_without_running_row(isolated, repo_root):
    _cli(isolated, repo_root, ["init"])
    buf = io.StringIO()
    code = main(_argv(isolated, repo_root, ["run", "--stage", "E"]), out=buf)
    assert code != 0
    text = buf.getvalue()
    assert "error:" in text
    assert "Stage E requires a complete stored Stage A result" in text
    store = connect(isolated / "state" / "research.sqlite")
    assert store.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0


def test_cli_stage_a_through_e_run_summary_status_report_and_redaction(
    isolated, repo_root, genesis_block
):
    _cli(isolated, repo_root, ["init"])
    _cli(isolated, repo_root, ["run", "--stage", "A", "--mode", "balanced"])
    _cli(isolated, repo_root, ["run", "--stage", "B", "--mode", "balanced"])
    _cli(isolated, repo_root, ["run", "--stage", "C", "--mode", "balanced"])
    _cli(isolated, repo_root, ["run", "--stage", "D", "--mode", "balanced"])
    out_e = _cli(isolated, repo_root, ["run", "--stage", "E", "--mode", "balanced"])
    assert "run complete" in out_e
    assert "derivations=8" in out_e
    assert "invalid=0" in out_e
    assert "unique_keys=167" in out_e
    assert "duplicates=21" in out_e
    assert "new_unique_keys=8" in out_e
    assert "witness_candidates_tested=48" in out_e
    assert "cumulative_witness_candidates=1002" in out_e
    assert "checkpoint=not-needed" in out_e
    assert "private_scalar=REDACTED" in out_e
    assert "POTENTIAL MATCH FOUND" not in out_e
    status = _cli(isolated, repo_root, ["status"])
    assert "status=ok" in status
    assert "stage=E" in status
    assert "unique_keys=167" in status
    assert "checkpoint=not-needed" in status
    report = (isolated / "research" / "report.md").read_text(encoding="utf-8")
    assert "Stage A+B+C+D+E report" in report
    assert "Stage A+B+C+D report" not in report
    assert "Hypotheses tested in Stage E" in report
    assert "Stage E derivations: 8" in report
    assert "cumulative unique valid keys after A+B+C+D+E: 167" in report
    assert "new Stage E witness candidates: 48" in report
    assert "cumulative B+C+D+E witness candidates: 1002" in report
    assert "Next highest-value Stage F experiment (not executed)" in report
    assert "Do not execute Stage F here" in report
    assert "1..2^20" in report or "1..2^{20}" in report or "2^20" in report
    assert "explicit-opt-in" in report or "explicit opt-in" in report
    dumped = dump_text(connect(isolated / "state" / "research.sqlite").conn)
    combined = out_e + status + report + dumped
    _assert_no_secrets(combined, genesis_block)
    _assert_public_schema(connect(isolated / "state" / "research.sqlite"))


def test_cli_report_passes_exact_e_run_when_latest_run_is_another_stage(
    isolated, repo_root, monkeypatch
):
    store = connect(isolated / "state" / "research.sqlite")
    conn = store.conn
    run_e = insert_run(conn, "2026-01-01T00:00:00Z", "E", "eco", "ok")
    _finish(
        conn,
        run_e,
        derivation_count=8,
        unique_valid_keys=167,
        duplicate_count=21,
        tested_candidate_count=48,
        elapsed_seconds=3.3,
    )
    run_a = insert_run(conn, "2026-01-01T00:01:00Z", "A", "max", "ok")
    _finish(
        conn,
        run_a,
        derivation_count=23,
        unique_valid_keys=22,
        elapsed_seconds=0.11,
    )
    upsert_key(conn, "fp-e", run_e)
    _seed_derivation(conn, "E-001", "fp-e", run_e)
    _seed_witness(conn, "fp-e", run_e, "E")
    conn.commit()

    captured = _capture_render(monkeypatch)
    _write_current_report(store, repo_root, isolated / "research" / "report.md")
    stage_e_run = captured["kwargs"]["stage_e_run"]
    latest = captured["args"][3]
    assert latest is not None
    assert latest["id"] == run_a
    assert latest["stage"] == "A"
    assert stage_e_run is not None
    assert stage_e_run["id"] == run_e
    assert stage_e_run["stage"] == "E"
    assert stage_e_run["unique_valid_keys"] == 167
    assert stage_e_run["tested_candidate_count"] == 48


def test_cli_report_ignores_stale_historical_e_after_d_invalidation(
    isolated, repo_root, monkeypatch
):
    store = connect(isolated / "state" / "research.sqlite")
    conn = store.conn
    run_e = insert_run(conn, "2026-01-01T00:00:00Z", "E", "eco", "ok")
    _finish(
        conn,
        run_e,
        derivation_count=8,
        unique_valid_keys=167,
        duplicate_count=21,
        tested_candidate_count=48,
        elapsed_seconds=3.3,
    )
    upsert_key(conn, "fp-d", run_e)
    upsert_key(conn, "fp-e", run_e)
    _seed_derivation(conn, "D-001", "fp-d", run_e)
    _seed_derivation(conn, "E-001", "fp-e", run_e)
    _seed_witness(conn, "fp-d", run_e, "D")
    _seed_witness(conn, "fp-e", run_e, "E")
    invalidate_stage_e_current_state(conn)
    run_d = insert_run(conn, "2026-01-01T00:02:00Z", "D", "balanced", "ok")
    _finish(
        conn,
        run_d,
        derivation_count=40,
        unique_valid_keys=159,
        duplicate_count=21,
        tested_candidate_count=240,
        elapsed_seconds=2.0,
    )
    conn.commit()

    captured = _capture_render(monkeypatch)
    _write_current_report(store, repo_root, isolated / "research" / "report.md")
    latest = captured["args"][3]
    assert latest is not None
    assert latest["id"] == run_d
    assert captured["kwargs"]["stage_e_run"] is None
    remaining_stages = {row["stage"] for row in captured["args"][4]}
    assert "E" not in remaining_stages
    witness_stages = {row.get("first_tested_stage") for row in captured["args"][7]}
    assert "E" not in witness_stages
    assert store.conn.execute("SELECT COUNT(*) FROM runs WHERE stage = 'E'").fetchone()[0] == 1
