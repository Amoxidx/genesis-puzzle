from __future__ import annotations

import hashlib
import io
import os
import stat
from pathlib import Path

from genesis_puzzle.candidates import compute_scalar, stage_a_recipes
from genesis_puzzle.cli import main
from genesis_puzzle.storage import connect, counts, dump_text


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


def test_cli_smoke_init_candidates_run_status_report_benchmark(isolated, repo_root, genesis_block):
    out_init = _cli(isolated, repo_root, ["init"])
    assert "proofs=verified" in out_init
    db = isolated / "state" / "research.sqlite"
    assert db.is_file()
    mode = stat.S_IMODE(os.stat(db).st_mode)
    assert mode == 0o600

    preview = _cli(isolated, repo_root, ["candidates", "--stage", "A"])
    assert "A-01" in preview
    assert "scalars not derived" in preview
    digest = hashlib.sha256(b"2083236893").hexdigest()
    assert digest not in preview

    run_out = _cli(isolated, repo_root, ["run", "--stage", "A", "--mode", "balanced"])
    assert "run complete" in run_out
    assert "checkpoint=not-needed" in run_out
    assert "private_scalar=REDACTED" in run_out
    assert digest not in run_out

    status = _cli(isolated, repo_root, ["status"])
    assert "status=ok" in status
    assert "checkpoint=not-needed" in status
    assert "mode=balanced" in status

    report_out = _cli(isolated, repo_root, ["report"])
    assert "wrote" in report_out
    report = (isolated / "research" / "report.md").read_text(encoding="utf-8")
    assert "Puzzle statement" in report
    assert "suspected_puzzle_output" in report
    assert "P2WSH" in report
    assert "<compressed pubkey> OP_CHECKSIG" in report
    assert "chain-history state: not checked" in report
    assert digest not in report

    bench = _cli(isolated, repo_root, ["benchmark"])
    assert "local throughput" in bench
    assert "/s" in bench


def test_idempotent_sqlite_and_redaction(isolated, repo_root, genesis_block):
    _cli(isolated, repo_root, ["init"])
    _cli(isolated, repo_root, ["run", "--stage", "A"])
    store = connect(isolated / "state" / "research.sqlite")
    first = counts(store.conn)
    assert first["derivations"] == 23
    assert first["invalid"] == 1
    assert first["unique_keys"] == first["derivations"] - first["invalid"]
    assert first["addresses"] == first["unique_keys"] * 3
    assert first["p2pkh_uncompressed"] == first["unique_keys"]
    assert first["p2pkh_compressed"] == first["unique_keys"]
    assert first["p2wpkh"] == first["unique_keys"]
    assert first["target_matches"] == 0

    store.conn.execute("UPDATE derivations SET recipe = 'STALE' WHERE derivation_id = 'A-01'")
    store.conn.commit()

    _cli(isolated, repo_root, ["run", "--stage", "A"])
    store = connect(isolated / "state" / "research.sqlite")
    second = counts(store.conn)
    assert second["derivations"] == first["derivations"]
    assert second["unique_keys"] == first["unique_keys"]
    assert second["addresses"] == first["addresses"]
    refreshed_recipe = store.conn.execute(
        "SELECT recipe FROM derivations WHERE derivation_id = 'A-01'"
    ).fetchone()[0]
    assert refreshed_recipe == "Interpret the public Genesis header nonce as a secp256k1 scalar."
    runs = store.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
    assert runs == 2

    dumped = dump_text(store.conn).lower()
    report = (isolated / "research" / "report.md").read_text(encoding="utf-8").lower()
    recipes = stage_a_recipes(genesis_block)
    public_hex = {
        genesis_block.block_hash_wire.hex(),
        genesis_block.block_hash_wire[::-1].hex(),
        genesis_block.header.merkle_root_wire.hex(),
        genesis_block.header.merkle_root_wire[::-1].hex(),
        genesis_block.header.raw.hex(),
        genesis_block.coinbase.pubkey.hex(),
    }
    for recipe in recipes:
        if recipe.transformation != "sha256":
            continue
        secret_hex = f"{compute_scalar(recipe):064x}"
        assert secret_hex not in dumped
        assert secret_hex not in report
        assert secret_hex not in public_hex
    nonce_padded = f"{2083236893:064x}"
    assert nonce_padded not in dumped
    assert nonce_padded not in report


def test_history_check_requires_flag(isolated, repo_root):
    buf = io.StringIO()
    code = main(
        [
            "--root",
            str(repo_root),
            "--state-dir",
            str(isolated / "state"),
            "history-check",
        ],
        out=buf,
    )
    assert code == 2
    assert "refusing" in buf.getvalue()
