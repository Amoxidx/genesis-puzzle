from __future__ import annotations

from pathlib import Path

import pytest

from genesis_puzzle.model import load_genesis_facts, load_known_targets
from genesis_puzzle.parser import parse_and_verify
from genesis_puzzle.paths import project_root

REPO_ROOT = project_root()


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture
def facts():
    return load_genesis_facts(REPO_ROOT)


@pytest.fixture
def genesis_block(facts):
    return parse_and_verify(facts)


@pytest.fixture
def targets():
    return load_known_targets(REPO_ROOT)


@pytest.fixture
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GENESIS_PUZZLE_ROOT", str(REPO_ROOT))
    monkeypatch.setenv("GENESIS_PUZZLE_DATA", str(REPO_ROOT / "data"))
    return tmp_path
