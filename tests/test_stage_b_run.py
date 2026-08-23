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
from genesis_puzzle.cli import main
from genesis_puzzle.config import ModeConfig
from genesis_puzzle.crypto import derive_pubkeys
from genesis_puzzle.engine import StageBPrerequisiteError, TargetConsistencyError, run_stage_b
from genesis_puzzle.model import KnownTarget, load_known_targets
from genesis_puzzle.stage_b import stage_b_recipes
from genesis_puzzle.storage import (
    connect,
    counts,
    dump_text,
    latest_run,
    list_witness_candidates,
    replace_witness_candidates,
    transaction,
)
from genesis_puzzle.witness import WITNESS_TEMPLATES, build_p2wsh_candidate

TEMPLATE_ORDER = (
    "p2pk_compressed",
    "p2pk_uncompressed",
    "multisig_1of1_compressed",
    "multisig_1of1_uncompressed",
    "p2pkh_compressed",
    "p2pkh_uncompressed",
)
MODE = ModeConfig("balanced", 1, 1.0, 0.0, "test")


def _count_engine_derive_pubkeys(monkeypatch: pytest.MonkeyPatch) -> dict:
    calls = {"n": 0}
    real = engine_mod.derive_pubkeys

    def wrapped(scalar):
        calls["n"] += 1
        return real(scalar)

    monkeypatch.setattr(engine_mod, "derive_pubkeys", wrapped)
    return calls


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


def _assert_no_stage_b(store, runs_before: int) -> None:
    assert store.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == runs_before
    assert store.conn.execute("SELECT COUNT(*) FROM runs WHERE stage = 'B'").fetchone()[0] == 0
    assert list_witness_candidates(store.conn) == []
    assert (
        store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'B'").fetchone()[0] == 0
    )


def _witness_public_snapshot(row) -> tuple:
    return (
        row["fingerprint"],
        row["template_id"],
        row["witness_script_hex"],
        row["derivation_ids"],
        row["address"],
    )


def _witness_upsert_payload(row) -> dict:
    return {
        "fingerprint": row["fingerprint"],
        "target_id": row["target_id"],
        "template_id": row["template_id"],
        "template_name": row["template_name"],
        "priority": int(row["priority"]),
        "pubkey_mode": row["pubkey_mode"],
        "pubkey_hex": row["pubkey_hex"],
        "witness_script_hex": row["witness_script_hex"],
        "witness_program_hex": row["witness_program_hex"],
        "address": row["address"],
        "derivation_ids": row["derivation_ids"],
        "matched": bool(int(row["matched"])),
        "run_id": int(row["run_id"]),
    }


def _sha256_scalar_hexes(genesis_block) -> list[str]:
    hexes = []
    for recipe in stage_a_recipes(genesis_block) + stage_b_recipes(genesis_block):
        if recipe.transformation != "sha256":
            continue
        hexes.append(f"{compute_scalar(recipe):064x}")
    return hexes


def test_cli_stage_b_preview_lists_recipes_and_templates(isolated, repo_root, genesis_block):
    preview = _cli(isolated, repo_root, ["candidates", "--stage", "B"])
    assert "stage B recipes: 105" in preview
    assert "B-001" in preview
    assert "B-105" in preview
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
    nonce_padded = f"{2083236893:064x}"
    assert nonce_padded not in preview


def test_run_b_before_a_is_controlled_error_without_running_row(isolated, repo_root):
    _cli(isolated, repo_root, ["init"])
    buf = io.StringIO()
    code = main(_argv(isolated, repo_root, ["run", "--stage", "B"]), out=buf)
    assert code != 0
    text = buf.getvalue()
    assert "error:" in text
    assert "Stage B requires a complete stored Stage A result" in text
    store = connect(isolated / "state" / "research.sqlite")
    assert store.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0
    running = store.conn.execute("SELECT COUNT(*) FROM runs WHERE status = 'running'").fetchone()[
        0
    ]
    assert running == 0


def test_stage_a_then_b_real_target_counts_idempotent_and_redacted(
    isolated, repo_root, genesis_block, monkeypatch
):
    _cli(isolated, repo_root, ["init"])
    out_a = _cli(isolated, repo_root, ["run", "--stage", "A", "--mode", "balanced"])
    store = connect(isolated / "state" / "research.sqlite")
    after_a = counts(store.conn)
    assert after_a["derivations"] == 23
    assert after_a["unique_keys"] == 22
    assert after_a["addresses"] == 66
    address_rows = store.conn.execute("SELECT COUNT(*) FROM addresses").fetchone()[0]
    history_rows_n = store.conn.execute("SELECT COUNT(*) FROM history").fetchone()[0]

    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    out_b = _cli(isolated, repo_root, ["run", "--stage", "B", "--mode", "balanced"])
    assert derive_calls["n"] == 105
    store = connect(isolated / "state" / "research.sqlite")
    b_n = store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'B'").fetchone()[0]
    b_invalid = store.conn.execute(
        "SELECT COUNT(*) FROM derivations WHERE stage = 'B' AND valid = 0"
    ).fetchone()[0]
    after_b = counts(store.conn)
    rows = list_witness_candidates(store.conn)
    run = latest_run(store.conn)
    assert b_n == 105
    assert b_invalid == 1
    assert after_b["unique_keys"] == 105
    assert after_b["witness_candidates"] == 630
    assert after_b["witness_matches"] == 0
    assert after_b["addresses"] == 66
    assert store.conn.execute("SELECT COUNT(*) FROM addresses").fetchone()[0] == address_rows
    assert store.conn.execute("SELECT COUNT(*) FROM history").fetchone()[0] == history_rows_n
    assert len(rows) == 630
    assert run["stage"] == "B"
    assert run["status"] == "ok"
    assert run["derivation_count"] == 105
    assert run["invalid_count"] == 1
    assert run["unique_valid_keys"] == 105
    assert run["tested_candidate_count"] == 630
    assert rows[0]["template_id"] == "p2pk_compressed"
    assert rows[0]["priority"] == 1
    assert rows[-1]["template_id"] == "p2pkh_uncompressed"
    assert rows[-1]["priority"] == 6
    assert all(row["template_id"] == "p2pk_compressed" for row in rows[:105])
    assert all(row["template_id"] == "p2pkh_uncompressed" for row in rows[-105:])
    first_snapshot = (
        rows[0]["fingerprint"],
        rows[0]["template_id"],
        rows[0]["witness_script_hex"],
        rows[0]["derivation_ids"],
        rows[0]["address"],
    )
    last_snapshot = (
        rows[-1]["fingerprint"],
        rows[-1]["template_id"],
        rows[-1]["witness_script_hex"],
        rows[-1]["derivation_ids"],
        rows[-1]["address"],
    )
    assert "POTENTIAL MATCH FOUND" not in out_b
    assert "witness_candidates=630" in out_b
    assert "private_scalar=REDACTED" in out_b

    store.conn.execute(
        "UPDATE witness_candidates SET derivation_ids = 'STALE' WHERE id = ?",
        (rows[0]["id"],),
    )
    store.conn.commit()
    stale = store.conn.execute(
        "SELECT derivation_ids FROM witness_candidates WHERE id = ?",
        (rows[0]["id"],),
    ).fetchone()[0]
    assert stale == "STALE"

    derive_calls["n"] = 0
    out_b2 = _cli(isolated, repo_root, ["run", "--stage", "B", "--mode", "balanced"])
    assert derive_calls["n"] == 105
    store = connect(isolated / "state" / "research.sqlite")
    rows2 = list_witness_candidates(store.conn)
    after_rerun = counts(store.conn)
    assert len(rows2) == 630
    assert after_rerun["witness_candidates"] == 630
    assert after_rerun["unique_keys"] == 105
    assert (
        rows2[0]["fingerprint"],
        rows2[0]["template_id"],
        rows2[0]["witness_script_hex"],
        rows2[0]["derivation_ids"],
        rows2[0]["address"],
    ) == first_snapshot
    assert (
        rows2[-1]["fingerprint"],
        rows2[-1]["template_id"],
        rows2[-1]["witness_script_hex"],
        rows2[-1]["derivation_ids"],
        rows2[-1]["address"],
    ) == last_snapshot
    assert rows2[0]["derivation_ids"] != "STALE"
    dumped = dump_text(store.conn)
    combined = out_a + out_b + out_b2 + dumped
    for secret in _sha256_scalar_hexes(genesis_block):
        assert secret not in combined
    assert f"{2083236893:064x}" not in combined.lower()
    witness_cols = [
        str(row[1]) for row in store.conn.execute("PRAGMA table_info(witness_candidates)")
    ]
    assert not any("scalar" in name.lower() for name in witness_cols)


def test_first_global_candidate_match_stops_after_one(
    isolated, repo_root, genesis_block, monkeypatch
):
    _cli(isolated, repo_root, ["init"])
    _cli(isolated, repo_root, ["run", "--stage", "A"])
    pairs = [evaluate_recipe(recipe) for recipe in stage_a_recipes(genesis_block)]
    pairs.extend(evaluate_recipe(recipe) for recipe in stage_b_recipes(genesis_block))
    unique = dedupe_valid_scalars(pairs)
    fingerprint, scalar, group = unique[0]
    uncompressed, compressed = derive_pubkeys(scalar)
    candidate = build_p2wsh_candidate(WITNESS_TEMPLATES[0], uncompressed, compressed)
    program = candidate.witness_program
    target = KnownTarget(
        id="synthetic-first-p2wsh",
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
        notes="synthetic first global candidate",
    )
    store = connect(isolated / "state" / "research.sqlite")
    output = io.StringIO()
    derive_calls = _count_engine_derive_pubkeys(monkeypatch)
    result = run_stage_b(store, genesis_block, [target], MODE, out=output)
    assert derive_calls["n"] == 1
    text = output.getvalue()
    rows = list_witness_candidates(store.conn)
    run = latest_run(store.conn)
    assert result["potential_match"] is True
    assert result["witness_candidates"] == 1
    assert run["status"] == "potential_match"
    assert run["tested_candidate_count"] == 1
    assert len(rows) == 1
    assert int(rows[0]["matched"]) == 1
    assert rows[0]["template_id"] == "p2pk_compressed"
    assert rows[0]["fingerprint"] == fingerprint
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


def test_inconsistent_p2wsh_target_rejected_before_stage_b_run(isolated, repo_root, genesis_block):
    _cli(isolated, repo_root, ["init"])
    _cli(isolated, repo_root, ["run", "--stage", "A"])
    store = connect(isolated / "state" / "research.sqlite")
    runs_before = store.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
    target = load_known_targets(repo_root)[0]
    bad_targets = [
        replace(target, witness_program_hex="aa" * 31),
        replace(target, script_pubkey_hex="00" * 34),
        replace(
            target,
            address="bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        ),
    ]
    for bad in bad_targets:
        with pytest.raises(TargetConsistencyError):
            run_stage_b(store, genesis_block, [bad], MODE)
        assert store.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == runs_before
        running = store.conn.execute(
            "SELECT COUNT(*) FROM runs WHERE status = 'running'"
        ).fetchone()[0]
        assert running == 0
        assert store.conn.execute("SELECT COUNT(*) FROM runs WHERE stage = 'B'").fetchone()[0] == 0
        assert list_witness_candidates(store.conn) == []


def test_witness_candidates_run_id_references_runs(isolated, repo_root):
    _cli(isolated, repo_root, ["init"])
    store = connect(isolated / "state" / "research.sqlite")
    columns = {
        str(row[1]): row
        for row in store.conn.execute("PRAGMA table_info(witness_candidates)").fetchall()
    }
    run_id_col = columns["run_id"]
    assert str(run_id_col[2]).upper() == "INTEGER"
    assert int(run_id_col[3]) == 1
    fks = store.conn.execute("PRAGMA foreign_key_list(witness_candidates)").fetchall()
    run_id_fks = [row for row in fks if str(row[3]) == "run_id"]
    assert len(run_id_fks) == 1
    assert str(run_id_fks[0][2]) == "runs"
    assert str(run_id_fks[0][4]) == "id"


def test_empty_p2wsh_target_set_rejected_before_stage_b_run(
    isolated, repo_root, genesis_block, monkeypatch
):
    _cli(isolated, repo_root, ["init"])
    _cli(isolated, repo_root, ["run", "--stage", "A"])
    store = connect(isolated / "state" / "research.sqlite")
    runs_before = store.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
    p2pkh = KnownTarget(
        id="not-p2wsh",
        label="test-only",
        status="known",
        txid="00" * 32,
        block_height=0,
        block_time=0,
        value_sats=1,
        address="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
        script_type="p2pkh",
        script_pubkey_hex="76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
        witness_program_hex="",
        comparable_with_stage_a=True,
        notes="non-p2wsh",
    )

    def boom(*_args, **_kwargs):
        raise AssertionError("Stage B recipes must not be evaluated for an empty P2WSH set")

    monkeypatch.setattr("genesis_puzzle.engine.stage_b_recipes", boom)
    for targets in ([], [p2pkh]):
        with pytest.raises(TargetConsistencyError, match="non-empty P2WSH target set"):
            run_stage_b(store, genesis_block, targets, MODE)
        _assert_no_stage_b(store, runs_before)


def test_tampered_a14_valid_fingerprint_rejected_before_stage_b_run(
    isolated, repo_root, genesis_block
):
    _cli(isolated, repo_root, ["init"])
    _cli(isolated, repo_root, ["run", "--stage", "A"])
    store = connect(isolated / "state" / "research.sqlite")
    a01_fp = store.conn.execute(
        "SELECT fingerprint FROM derivations WHERE derivation_id = 'A-01'"
    ).fetchone()[0]
    store.conn.execute(
        "UPDATE derivations SET valid = 1, fingerprint = ? WHERE derivation_id = 'A-14'",
        (a01_fp,),
    )
    store.conn.commit()
    runs_before = store.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
    with pytest.raises(StageBPrerequisiteError):
        run_stage_b(store, genesis_block, load_known_targets(repo_root), MODE)
    _assert_no_stage_b(store, runs_before)


def test_missing_stage_a_key_row_rejected_before_stage_b_run(isolated, repo_root, genesis_block):
    _cli(isolated, repo_root, ["init"])
    _cli(isolated, repo_root, ["run", "--stage", "A"])
    store = connect(isolated / "state" / "research.sqlite")
    fingerprint = store.conn.execute(
        "SELECT fingerprint FROM derivations WHERE derivation_id = 'A-01'"
    ).fetchone()[0]
    addresses = [
        str(row[0])
        for row in store.conn.execute(
            "SELECT address FROM addresses WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchall()
    ]
    for address in addresses:
        store.conn.execute("DELETE FROM history WHERE address = ?", (address,))
        store.conn.execute("DELETE FROM target_comparisons WHERE address = ?", (address,))
    store.conn.execute("DELETE FROM addresses WHERE fingerprint = ?", (fingerprint,))
    store.conn.execute("DELETE FROM keys WHERE fingerprint = ?", (fingerprint,))
    store.conn.commit()
    assert (
        store.conn.execute(
            "SELECT COUNT(*) FROM keys WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()[0]
        == 0
    )
    runs_before = store.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
    with pytest.raises(StageBPrerequisiteError):
        run_stage_b(store, genesis_block, load_known_targets(repo_root), MODE)
    _assert_no_stage_b(store, runs_before)


def test_tampered_incomplete_latest_stage_a_run_rejected_before_stage_b_run(
    isolated, repo_root, genesis_block
):
    _cli(isolated, repo_root, ["init"])
    _cli(isolated, repo_root, ["run", "--stage", "A"])
    store = connect(isolated / "state" / "research.sqlite")
    store.conn.execute(
        """
        UPDATE runs
        SET status = 'running', derivation_count = 1, invalid_count = 0,
            unique_valid_keys = 1, address_count = 3, finished_at = NULL
        WHERE stage = 'A'
        """
    )
    store.conn.commit()
    runs_before = store.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
    with pytest.raises(StageBPrerequisiteError, match="completed latest Stage A run"):
        run_stage_b(store, genesis_block, load_known_targets(repo_root), MODE)
    _assert_no_stage_b(store, runs_before)


def test_replace_witness_candidates_rolls_back_atomically(isolated, repo_root, monkeypatch):
    _cli(isolated, repo_root, ["init"])
    _cli(isolated, repo_root, ["run", "--stage", "A"])
    _cli(isolated, repo_root, ["run", "--stage", "B"])
    store = connect(isolated / "state" / "research.sqlite")
    rows = list_witness_candidates(store.conn)
    assert len(rows) == 630
    first_snapshot = _witness_public_snapshot(rows[0])
    last_snapshot = _witness_public_snapshot(rows[-1])
    original_ids = [int(row["id"]) for row in rows]
    original_run_ids = [int(row["run_id"]) for row in rows]
    target_ids = sorted({str(row["target_id"]) for row in rows})
    replacements = [_witness_upsert_payload(row) for row in rows]
    real_upsert = storage_mod.upsert_witness_candidate
    inserted = {"count": 0}

    def flaky(conn, **kwargs):
        inserted["count"] += 1
        result = real_upsert(conn, **kwargs)
        if inserted["count"] >= 1:
            raise RuntimeError("injected replacement failure")
        return result

    monkeypatch.setattr(storage_mod, "upsert_witness_candidate", flaky)
    with pytest.raises(RuntimeError, match="injected replacement failure"):
        with transaction(store) as conn:
            replace_witness_candidates(conn, target_ids, replacements)
    assert inserted["count"] >= 1
    after = list_witness_candidates(store.conn)
    assert len(after) == 630
    assert [int(row["id"]) for row in after] == original_ids
    assert [int(row["run_id"]) for row in after] == original_run_ids
    assert _witness_public_snapshot(after[0]) == first_snapshot
    assert _witness_public_snapshot(after[-1]) == last_snapshot
