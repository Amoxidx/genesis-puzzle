from __future__ import annotations

import json
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


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
