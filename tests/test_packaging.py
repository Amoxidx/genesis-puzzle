from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path

import pytest

import genesis_puzzle
from genesis_puzzle.cli import _build_parser

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


def test_package_version_matches_dunder_version(repo_root: Path):
    payload = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))
    assert payload["project"]["version"] == genesis_puzzle.__version__
    assert genesis_puzzle.__version__ == "0.3.0"
    description = payload["project"]["description"]
    assert "Stage A" in description
    assert "Stage B" in description
    assert "Stage C" in description
    assert "sequential/offline" in description
    assert "Milestone 1" not in description
    assert genesis_puzzle.__doc__ is not None
    assert "A+B+C" in genesis_puzzle.__doc__
    assert "sequential/offline" in genesis_puzzle.__doc__
    assert "Milestone 1" not in genesis_puzzle.__doc__
    package_dir = Path(inspect.getfile(genesis_puzzle)).resolve().parent
    assert (package_dir / "stage_c.py").is_file()
    assert (package_dir / "stage_b.py").is_file()
    assert (package_dir / "cli.py").is_file()


def test_packaged_public_data_matches_source_data(repo_root: Path):
    packaged = repo_root / "src" / "genesis_puzzle" / "data"
    for name in ("genesis.json", "known_targets.json"):
        root_payload = json.loads((repo_root / "data" / name).read_text(encoding="utf-8"))
        packaged_payload = json.loads((packaged / name).read_text(encoding="utf-8"))
        assert packaged_payload == root_payload


def test_packaged_default_config_matches_source_config(repo_root: Path):
    root_payload = tomllib.loads((repo_root / "config.toml").read_text(encoding="utf-8"))
    packaged_payload = tomllib.loads(
        (repo_root / "src" / "genesis_puzzle" / "data" / "config.toml").read_text(encoding="utf-8")
    )
    assert packaged_payload == root_payload
    for payload in (root_payload, packaged_payload):
        for name in ("eco", "balanced", "max"):
            description = payload["modes"][name]["description"]
            assert "A+B+C" in description
            assert "sequential" in description
            assert "offline" in description


def test_cli_help_and_stage_choices_include_c_not_d():
    parser = _build_parser()
    help_text = parser.format_help()
    assert "genesis-puzzle" in help_text
    assert "Stage A" in help_text
    assert "Stage B" in help_text
    assert "Stage C" in help_text
    assert "sequential/offline" in help_text
    assert parser.parse_args(["candidates", "--stage", "A"]).stage == "A"
    assert parser.parse_args(["candidates", "--stage", "B"]).stage == "B"
    assert parser.parse_args(["candidates", "--stage", "C"]).stage == "C"
    assert parser.parse_args(["run", "--stage", "C", "--mode", "balanced"]).stage == "C"
    with pytest.raises(SystemExit):
        parser.parse_args(["run", "--stage", "D"])
    with pytest.raises(SystemExit):
        parser.parse_args(["candidates", "--stage", "D"])


def test_readme_stage_c_release_contract(repo_root: Path):
    text = (repo_root / "README.md").read_text(encoding="utf-8")
    lowered = text.lower()
    assert "Stages A, B, and C" in text
    assert "sequential" in lowered
    assert "offline" in lowered
    assert "ASCII decimal" in text
    assert "both orders" in lowered or "nonce || separator || timestamp" in text
    for separator in (
        "empty string",
        "colon",
        "pipe",
        "hyphen",
        "underscore",
        "space",
        "newline",
    ):
        assert separator in lowered
    assert "SHA256" in text
    assert "14 Stage C recipes" in text or "14 recipes" in lowered
    assert "14" in text
    assert "119" in text
    assert "84" in text
    assert "714" in text
    assert "run --stage C" in text
    assert "candidates --stage C" in text
    assert "never printed" in lowered or "never" in lowered
    assert "stored in sqlite" in lowered
    assert "Stage D is not executed" in text or "Do not execute Stage D" in text
    assert "-10..-1" in text
    assert "+1..+10" in text
    assert "excluding zero" in lowered
    assert "40 keys" in text
    assert "240 scripts" in text
    assert "direct-scalar" in lowered or "direct scalar" in lowered
    assert "solved the puzzle" not in lowered
    assert "live chain" in lowered or "does not look up live chain" in lowered
    assert "history-check --yes-network" in text


def test_quality_gate_stage_c_smoke_contract(repo_root: Path):
    text = (repo_root / "scripts" / "quality-gate.sh").read_text(encoding="utf-8")
    preview_c = text.index("candidates --stage C")
    run_a = text.index("run --stage A")
    run_b = text.index("run --stage B")
    run_c = text.index("run --stage C")
    assert preview_c < run_a < run_b < run_c
    assert "candidates --stage B" in text
    assert "stage B recipes: 105" in text
    assert "Stage B derivations: 105" in text
    assert "cumulative unique valid keys after A+B: 105" in text
    assert "132 Stage-A-only" in text
    assert "630" in text
    assert "stage C recipes: 14" in text
    assert "derivations=14" in text
    assert "new_unique_keys=14" in text
    assert "unique_keys=119" in text
    assert "witness_candidates_tested=84" in text
    assert "cumulative_witness_candidates=714" in text
    assert "Stage C derivations: 14" in text
    assert "Stage C new unique valid keys: 14" in text
    assert "cumulative unique valid keys after A+B+C: 119" in text
    assert "new Stage C witness candidates: 84" in text
    assert "cumulative B+C witness candidates: 714" in text
    assert "P2WSH direct target matches: 0" in text
    assert "Next highest-value Stage D experiment (not executed)" in text
    assert '"Next highest-value Stage C experiment (not executed)" not in text' in text
    assert '"Stage-C-not-executed" not in text' in text
    assert '"Do not execute Stage C here" not in text' in text
    assert "history-check" not in text
