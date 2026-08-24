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
from genesis_puzzle.cli import _build_parser, main
from genesis_puzzle.config import ModeConfig
from genesis_puzzle.crypto import derive_pubkeys
from genesis_puzzle.engine import (
    StageCPrerequisiteError,
    TargetConsistencyError,
    run_stage_a,
    run_stage_b,
    run_stage_c,
)
from genesis_puzzle.model import KnownTarget
from genesis_puzzle.parser import ParsedBlock
from genesis_puzzle.stage_b import stage_b_recipes
from genesis_puzzle.stage_c import stage_c_recipes
from genesis_puzzle.storage import (
    Store,
    connect,
    counts,
    dump_text,
    latest_run,
    list_witness_candidates,
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


def _store(path: Path) -> Store:
    return connect(path / "state" / "research.sqlite")


def _prepare_ab(path: Path, genesis_block: ParsedBlock, targets: list[KnownTarget]) -> Store:
    store = _store(path)
    run_stage_a(store, genesis_block, targets, MODE)
    run_stage_b(store, genesis_block, targets, MODE)
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


def _witness_public_snapshot(row) -> tuple:
    return (
        int(row["id"]),
        row["fingerprint"],
        row["template_id"],
        row["witness_script_hex"],
        row["witness_program_hex"],
        row["derivation_ids"],
        row["address"],
        int(row["matched"]),
        row["first_tested_stage"],
    )


def _state_snapshot(store: Store) -> tuple:
    derivations = [
        (
            str(row["derivation_id"]),
            None if row["fingerprint"] is None else str(row["fingerprint"]),
            int(row["valid"]),
            str(row["stage"]),
        )
        for row in store.conn.execute(
            "SELECT derivation_id, fingerprint, valid, stage FROM derivations "
            "ORDER BY derivation_id"
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
    names = [str(row[1]) for row in store.conn.execute("PRAGMA table_info(witness_candidates)")]
    for name in names:
        lowered = name.lower()
        for fragment in FORBIDDEN_COLUMN_FRAGMENTS:
            assert fragment not in lowered


def _assert_no_stage_c(store: Store, before: tuple) -> None:
    assert _state_snapshot(store) == before
    assert store.conn.execute("SELECT COUNT(*) FROM runs WHERE stage = 'C'").fetchone()[0] == 0
    assert (
        store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'C'").fetchone()[0] == 0
    )
    assert list_witness_candidates(store.conn, "C") == []


def test_run_c_before_a_is_controlled_error_without_curve_or_run(
    isolated, genesis_block, targets, monkeypatch
):
    store = _store(isolated)
    before = _state_snapshot(store)
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)

    def boom_recipes(_block):
        raise AssertionError("Stage C recipes must not run before Stage A")

    monkeypatch.setattr(engine_mod, "stage_c_recipes", boom_recipes)
    with pytest.raises(StageCPrerequisiteError, match="run Stage A first"):
        run_stage_c(store, genesis_block, targets, MODE)
    assert derive_calls["n"] == 0
    _assert_no_stage_c(store, before)


def test_run_c_before_b_is_controlled_error_without_curve_or_run(
    isolated, genesis_block, targets, monkeypatch
):
    store = _store(isolated)
    run_stage_a(store, genesis_block, targets, MODE)
    before = _state_snapshot(store)
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    derive_calls["n"] = 0

    def boom_recipes(_block):
        raise AssertionError("Stage C recipes must not run before Stage B")

    monkeypatch.setattr(engine_mod, "stage_c_recipes", boom_recipes)
    with pytest.raises(StageCPrerequisiteError, match="run Stage B first"):
        run_stage_c(store, genesis_block, targets, MODE)
    assert derive_calls["n"] == 0
    _assert_no_stage_c(store, before)


def test_stage_c_real_target_counts_ordering_and_idempotent_rerun(
    isolated, genesis_block, targets, monkeypatch
):
    store = _prepare_ab(isolated, genesis_block, targets)
    b_rows = list_witness_candidates(store.conn, "B")
    b_snapshot = [_witness_public_snapshot(row) for row in b_rows]
    assert len(b_snapshot) == 630
    address_rows = store.conn.execute("SELECT COUNT(*) FROM addresses").fetchone()[0]
    history_rows_n = store.conn.execute("SELECT COUNT(*) FROM history").fetchone()[0]

    expected_c_fps = []
    for recipe in stage_c_recipes(genesis_block):
        evaluated, _scalar = evaluate_recipe(recipe)
        assert evaluated.fingerprint is not None
        expected_c_fps.append(evaluated.fingerprint)
    assert len(expected_c_fps) == 14

    output = io.StringIO()
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    result = run_stage_c(store, genesis_block, targets, MODE, out=output)
    assert derive_calls["n"] == 14
    text = output.getvalue()
    run = latest_run(store.conn)
    after = counts(store.conn)
    c_rows = list_witness_candidates(store.conn, "C")
    all_rows = list_witness_candidates(store.conn)
    assert result["new_unique_keys"] == 14
    assert result["witness_candidates_tested"] == 84
    assert result["cumulative_witness_candidates"] == 714
    assert result["potential_match"] is False
    assert isinstance(result["elapsed"], float)
    assert after["unique_keys"] == 119
    assert after["witness_candidates"] == 714
    assert after["witness_matches"] == 0
    assert after["addresses"] == address_rows
    assert store.conn.execute("SELECT COUNT(*) FROM history").fetchone()[0] == history_rows_n
    assert (
        store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'C'").fetchone()[0]
        == 14
    )
    assert (
        store.conn.execute(
            "SELECT COUNT(*) FROM derivations WHERE stage = 'C' AND valid = 0"
        ).fetchone()[0]
        == 0
    )
    assert run["stage"] == "C"
    assert run["status"] == "ok"
    assert run["derivation_count"] == 14
    assert run["invalid_count"] == 0
    assert run["unique_valid_keys"] == 119
    assert run["duplicate_count"] == 21
    assert run["address_count"] == 0
    assert run["tested_candidate_count"] == 84
    assert len(c_rows) == 84
    assert len(all_rows) == 714
    assert [_witness_public_snapshot(row) for row in list_witness_candidates(store.conn, "B")] == (
        b_snapshot
    )
    assert all(row["first_tested_stage"] == "B" for row in all_rows[:630])
    assert all(row["first_tested_stage"] == "C" for row in all_rows[630:])
    assert all(row["template_id"] == "p2pk_compressed" for row in c_rows[:14])
    assert all(row["template_id"] == "p2pkh_uncompressed" for row in c_rows[-14:])
    assert [row["template_id"] for row in c_rows[::14]] == list(TEMPLATE_ORDER)
    assert [row["fingerprint"] for row in c_rows[:14]] == expected_c_fps
    assert c_rows[0]["priority"] == 1
    assert c_rows[-1]["priority"] == 6
    assert c_rows[0]["pubkey_mode"] == "compressed"
    assert c_rows[-1]["pubkey_mode"] == "uncompressed"
    assert all(int(row["matched"]) == 0 for row in c_rows)
    assert "POTENTIAL MATCH FOUND" not in text
    assert "private_scalar=REDACTED" in text

    store.conn.execute(
        "UPDATE witness_candidates SET derivation_ids = 'STALE-C' WHERE id = ?",
        (c_rows[0]["id"],),
    )
    store.conn.commit()
    assert (
        store.conn.execute(
            "SELECT derivation_ids FROM witness_candidates WHERE id = ?",
            (c_rows[0]["id"],),
        ).fetchone()[0]
        == "STALE-C"
    )

    derive_calls["n"] = 0
    output2 = io.StringIO()
    result2 = run_stage_c(store, genesis_block, targets, MODE, out=output2)
    assert derive_calls["n"] == 14
    assert result2["new_unique_keys"] == 14
    assert result2["witness_candidates_tested"] == 84
    assert result2["cumulative_witness_candidates"] == 714
    c_rows2 = list_witness_candidates(store.conn, "C")
    b_rows2 = list_witness_candidates(store.conn, "B")
    assert [_witness_public_snapshot(row) for row in b_rows2] == b_snapshot
    assert len(c_rows2) == 84
    assert c_rows2[0]["derivation_ids"] != "STALE-C"
    assert [row["fingerprint"] for row in c_rows2[:14]] == expected_c_fps
    dumped = dump_text(store.conn)
    combined = text + output2.getvalue() + dumped
    for secret in _sha256_scalar_hexes(genesis_block):
        assert secret not in combined
    assert f"{2083236893:064x}" not in combined.lower()
    _assert_public_schema(store)


def test_stage_c_prerequisite_corruptions_do_not_mutate_or_call_curve(
    isolated, genesis_block, targets, monkeypatch
):
    cases = (
        "missing_row",
        "wrong_derivation_fingerprint",
        "wrong_script",
        "wrong_program",
        "wrong_address",
        "matched_row",
        "potential_baseline",
    )
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    for name in cases:
        fresh = _prepare_ab(isolated / name, genesis_block, targets)
        before = _state_snapshot(fresh)
        b_row = list_witness_candidates(fresh.conn, "B")[0]
        a01_fp = fresh.conn.execute(
            "SELECT fingerprint FROM derivations WHERE derivation_id = 'A-01'"
        ).fetchone()[0]
        b001_id = fresh.conn.execute(
            "SELECT derivation_id FROM derivations WHERE stage = 'B' AND valid = 1 LIMIT 1"
        ).fetchone()[0]
        if name == "missing_row":
            fresh.conn.execute("DELETE FROM witness_candidates WHERE id = ?", (b_row["id"],))
        elif name == "wrong_derivation_fingerprint":
            fresh.conn.execute(
                "UPDATE derivations SET fingerprint = ? WHERE derivation_id = ?",
                (a01_fp, b001_id),
            )
        elif name == "wrong_script":
            fresh.conn.execute(
                "UPDATE witness_candidates SET witness_script_hex = ? WHERE id = ?",
                ("00" * 10, b_row["id"]),
            )
        elif name == "wrong_program":
            fresh.conn.execute(
                "UPDATE witness_candidates SET witness_program_hex = ? WHERE id = ?",
                ("11" * 32, b_row["id"]),
            )
        elif name == "wrong_address":
            fresh.conn.execute(
                "UPDATE witness_candidates SET address = ? WHERE id = ?",
                ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", b_row["id"]),
            )
        elif name == "matched_row":
            fresh.conn.execute(
                "UPDATE witness_candidates SET matched = 1 WHERE id = ?",
                (b_row["id"],),
            )
        else:
            fresh.conn.execute("UPDATE runs SET status = 'potential_match' WHERE stage = 'B'")
        fresh.conn.commit()
        mutated = _state_snapshot(fresh)
        derive_calls["n"] = 0
        with pytest.raises(StageCPrerequisiteError):
            run_stage_c(fresh, genesis_block, targets, MODE)
        assert derive_calls["n"] == 0
        _assert_no_stage_c(fresh, mutated)
        assert _state_snapshot(fresh) != before


def test_first_synthetic_c_candidate_match_stops_after_one(isolated, genesis_block, monkeypatch):
    pairs = [evaluate_recipe(recipe) for recipe in stage_c_recipes(genesis_block)]
    unique = dedupe_valid_scalars(pairs)
    fingerprint, scalar, group = unique[0]
    uncompressed, compressed = derive_pubkeys(scalar)
    candidate = build_p2wsh_candidate(WITNESS_TEMPLATES[0], uncompressed, compressed)
    program = candidate.witness_program
    target = KnownTarget(
        id="synthetic-first-c-p2wsh",
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
        notes="synthetic first global Stage C candidate",
    )
    store = _store(isolated)
    run_stage_a(store, genesis_block, [target], MODE)
    b_result = run_stage_b(store, genesis_block, [target], MODE)
    assert b_result["potential_match"] is False
    b_rows = list_witness_candidates(store.conn, "B")
    assert len(b_rows) == 630
    assert all(int(row["matched"]) == 0 for row in b_rows)
    assert all(row["target_id"] == target.id for row in b_rows)
    b_snapshot = [_witness_public_snapshot(row) for row in b_rows]
    output = io.StringIO()
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    result = run_stage_c(store, genesis_block, [target], MODE, out=output)
    assert derive_calls["n"] == 1
    text = output.getvalue()
    c_rows = list_witness_candidates(store.conn, "C")
    run = latest_run(store.conn)
    assert result["potential_match"] is True
    assert result["witness_candidates_tested"] == 1
    assert result["cumulative_witness_candidates"] == 631
    assert run["status"] == "potential_match"
    assert run["tested_candidate_count"] == 1
    assert len(c_rows) == 1
    assert int(c_rows[0]["matched"]) == 1
    assert c_rows[0]["template_id"] == "p2pk_compressed"
    assert c_rows[0]["fingerprint"] == fingerprint
    assert c_rows[0]["first_tested_stage"] == "C"
    assert [_witness_public_snapshot(row) for row in list_witness_candidates(store.conn, "B")] == (
        b_snapshot
    )
    assert "POTENTIAL MATCH FOUND" in text
    assert fingerprint in text
    assert candidate.name in text
    assert candidate.pubkey_hex in text
    assert candidate.address in text
    assert candidate.witness_script_hex in text
    provenance = ",".join(item.recipe.derivation_id for item in group)
    assert provenance in text
    assert f"{scalar:064x}" not in text
    assert "private_scalar=REDACTED" in text
    _assert_public_schema(store)


def test_stage_c_replacement_rolls_back_without_partial_state(
    isolated, genesis_block, targets, monkeypatch
):
    store = _prepare_ab(isolated, genesis_block, targets)
    before = _state_snapshot(store)
    real_upsert = storage_mod.upsert_witness_candidate
    inserted = {"count": 0}

    def flaky(conn, **kwargs):
        inserted["count"] += 1
        result = real_upsert(conn, **kwargs)
        if inserted["count"] >= 1:
            raise RuntimeError("injected stage C replacement failure")
        return result

    monkeypatch.setattr(storage_mod, "upsert_witness_candidate", flaky)
    with pytest.raises(RuntimeError, match="injected stage C replacement failure"):
        run_stage_c(store, genesis_block, targets, MODE)
    assert inserted["count"] >= 1
    assert _state_snapshot(store) == before
    assert store.conn.execute("SELECT COUNT(*) FROM runs WHERE stage = 'C'").fetchone()[0] == 0
    assert list_witness_candidates(store.conn, "C") == []
    assert counts(store.conn)["unique_keys"] == 105
    assert counts(store.conn)["witness_candidates"] == 630


def test_stage_b_rerun_invalidates_stage_c_down_to_b_state(
    isolated, genesis_block, targets, monkeypatch
):
    store = _prepare_ab(isolated, genesis_block, targets)
    run_stage_c(store, genesis_block, targets, MODE)
    assert counts(store.conn)["unique_keys"] == 119
    assert counts(store.conn)["witness_candidates"] == 714
    assert list_witness_candidates(store.conn, "C")
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
    assert (
        store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'C'").fetchone()[0] == 0
    )
    assert (
        store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'B'").fetchone()[0]
        == 105
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


def test_cli_parser_exposes_stage_c_choices_and_help():
    parser = _build_parser()
    help_text = parser.format_help()
    assert "Stage A" in help_text
    assert "Stage B" in help_text
    assert "Stage C" in help_text
    assert "sequential/offline" in help_text
    candidates = parser.parse_args(["candidates", "--stage", "C"])
    assert candidates.stage == "C"
    run = parser.parse_args(["run", "--stage", "C", "--mode", "balanced"])
    assert run.stage == "C"
    with pytest.raises(SystemExit):
        parser.parse_args(["run", "--stage", "D"])


def test_cli_stage_c_preview_lists_recipes_and_templates(isolated, repo_root, genesis_block):
    preview = _cli(isolated, repo_root, ["candidates", "--stage", "C"])
    assert "stage C recipes: 14" in preview
    assert "C-001" in preview
    assert "C-014" in preview
    assert "private_scalar: REDACTED" in preview
    assert "scalars not derived" in preview
    assert "up to six scripts per unique key" in preview
    assert "Preview does not derive a scalar or public key" in preview
    positions = [preview.index(name) for name in TEMPLATE_ORDER]
    assert positions == sorted(positions)
    for name in TEMPLATE_ORDER:
        assert name in preview
    for secret in _sha256_scalar_hexes(genesis_block):
        assert secret not in preview
    assert f"{2083236893:064x}" not in preview


def test_run_c_before_a_is_controlled_cli_error_without_running_row(isolated, repo_root):
    _cli(isolated, repo_root, ["init"])
    buf = io.StringIO()
    code = main(_argv(isolated, repo_root, ["run", "--stage", "C"]), out=buf)
    assert code != 0
    text = buf.getvalue()
    assert "error:" in text
    assert "Stage C requires a complete stored Stage A result" in text
    store = connect(isolated / "state" / "research.sqlite")
    assert store.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0
    running = store.conn.execute("SELECT COUNT(*) FROM runs WHERE status = 'running'").fetchone()[
        0
    ]
    assert running == 0


def test_run_c_before_b_is_controlled_cli_error_without_c_row(isolated, repo_root):
    _cli(isolated, repo_root, ["init"])
    _cli(isolated, repo_root, ["run", "--stage", "A"])
    buf = io.StringIO()
    code = main(_argv(isolated, repo_root, ["run", "--stage", "C"]), out=buf)
    assert code != 0
    text = buf.getvalue()
    assert "error:" in text
    assert "Stage C requires a complete stored Stage B result" in text
    store = connect(isolated / "state" / "research.sqlite")
    assert store.conn.execute("SELECT COUNT(*) FROM runs WHERE stage = 'C'").fetchone()[0] == 0
    running = store.conn.execute("SELECT COUNT(*) FROM runs WHERE status = 'running'").fetchone()[
        0
    ]
    assert running == 0
    assert (
        store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'C'").fetchone()[0] == 0
    )


def test_cli_stage_a_b_c_run_summary_status_and_redaction(isolated, repo_root, genesis_block):
    _cli(isolated, repo_root, ["init"])
    out_a = _cli(isolated, repo_root, ["run", "--stage", "A", "--mode", "balanced"])
    assert "run complete" in out_a
    assert "addresses=" in out_a
    assert "checkpoint=not-needed" in out_a
    out_b = _cli(isolated, repo_root, ["run", "--stage", "B", "--mode", "balanced"])
    assert "witness_candidates=630" in out_b
    assert "unique_keys=105" in out_b
    assert "checkpoint=not-needed" in out_b
    out_c = _cli(isolated, repo_root, ["run", "--stage", "C", "--mode", "balanced"])
    assert "run complete" in out_c
    assert "derivations=14" in out_c
    assert "invalid=0" in out_c
    assert "unique_keys=119" in out_c
    assert "new_unique_keys=14" in out_c
    assert "witness_candidates_tested=84" in out_c
    assert "cumulative_witness_candidates=714" in out_c
    assert "elapsed_s=" in out_c
    assert "checkpoint=not-needed" in out_c
    assert "private_scalar=REDACTED" in out_c
    assert "POTENTIAL MATCH FOUND" not in out_c
    status = _cli(isolated, repo_root, ["status"])
    assert "status=ok" in status
    assert "stage=C" in status
    assert "unique_keys=119" in status
    assert "checkpoint=not-needed" in status
    assert "mode=balanced" in status
    for secret in _sha256_scalar_hexes(genesis_block):
        assert secret not in out_c
        assert secret not in status
    assert f"{2083236893:064x}" not in out_c
    assert f"{2083236893:064x}" not in status


def test_stage_c_rejects_target_id_mismatch_without_curve_or_mutation(
    isolated, genesis_block, targets, monkeypatch
):
    store = _prepare_ab(isolated, genesis_block, targets)
    before = _state_snapshot(store)
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)

    def boom_recipes(_block):
        raise AssertionError("Stage C recipes must not run on a target-ID mismatch")

    monkeypatch.setattr(engine_mod, "stage_c_recipes", boom_recipes)
    other = replace(targets[0], id="synthetic-other-p2wsh")
    with pytest.raises(StageCPrerequisiteError, match="current validated P2WSH target ID"):
        run_stage_c(store, genesis_block, [other], MODE)
    assert derive_calls["n"] == 0
    _assert_no_stage_c(store, before)


def test_stage_c_rejects_self_consistent_wrong_b_script_without_curve_or_mutation(
    isolated, genesis_block, targets, monkeypatch
):
    store = _prepare_ab(isolated, genesis_block, targets)
    b_row = list_witness_candidates(store.conn, "B")[0]
    template = next(item for item in WITNESS_TEMPLATES if item.template_id == b_row["template_id"])
    other = next(
        item
        for item in WITNESS_TEMPLATES
        if item.pubkey_mode == template.pubkey_mode and item.template_id != template.template_id
    )
    pubkey = bytes.fromhex(str(b_row["pubkey_hex"]))
    alt_script = expected_witness_script(other, pubkey)
    original_script = bytes.fromhex(str(b_row["witness_script_hex"]))
    assert alt_script != original_script
    program, address = p2wsh_program_and_address(alt_script)
    store.conn.execute(
        """
        UPDATE witness_candidates
        SET witness_script_hex = ?, witness_program_hex = ?, address = ?
        WHERE id = ?
        """,
        (alt_script.hex(), program.hex(), address, b_row["id"]),
    )
    store.conn.commit()
    stored = store.conn.execute(
        "SELECT template_id, pubkey_hex, witness_script_hex, witness_program_hex, address "
        "FROM witness_candidates WHERE id = ?",
        (b_row["id"],),
    ).fetchone()
    assert stored["template_id"] == b_row["template_id"]
    assert stored["pubkey_hex"] == b_row["pubkey_hex"]
    assert stored["witness_script_hex"] == alt_script.hex()
    mutated = _state_snapshot(store)
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)

    def boom_recipes(_block):
        raise AssertionError("Stage C recipes must not run on a corrupted B script")

    monkeypatch.setattr(engine_mod, "stage_c_recipes", boom_recipes)
    with pytest.raises(StageCPrerequisiteError, match="exact template script"):
        run_stage_c(store, genesis_block, targets, MODE)
    assert derive_calls["n"] == 0
    _assert_no_stage_c(store, mutated)


def test_inconsistent_p2wsh_target_rejected_before_stage_c_curve(
    isolated, genesis_block, targets, monkeypatch
):
    store = _prepare_ab(isolated, genesis_block, targets)
    before = _state_snapshot(store)
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    target = targets[0]
    bad_targets = [
        replace(target, witness_program_hex="aa" * 31),
        replace(target, script_pubkey_hex="00" * 34),
        replace(target, address="bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
    ]
    for bad in bad_targets:
        derive_calls["n"] = 0
        with pytest.raises(TargetConsistencyError):
            run_stage_c(store, genesis_block, [bad], MODE)
        assert derive_calls["n"] == 0
        _assert_no_stage_c(store, before)
