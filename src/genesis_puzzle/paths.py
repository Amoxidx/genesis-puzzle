from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


def project_root(explicit: Optional[Path] = None) -> Path:
    if explicit is not None:
        return explicit.resolve()
    env = os.environ.get("GENESIS_PUZZLE_ROOT")
    if env:
        return Path(env).resolve()
    here = Path.cwd().resolve()
    for candidate in [here, *here.parents]:
        if (candidate / "pyproject.toml").is_file() and (
            candidate / "data" / "genesis.json"
        ).is_file():
            return candidate
    pkg = Path(__file__).resolve().parent
    repo_from_src = pkg.parents[1]
    if (repo_from_src / "data" / "genesis.json").is_file():
        return repo_from_src
    return here


def data_dir(root: Optional[Path] = None) -> Path:
    env = os.environ.get("GENESIS_PUZZLE_DATA")
    if env:
        return Path(env).resolve()
    pkg_data = Path(__file__).resolve().parent / "data"
    root_data = project_root(root) / "data"
    if root_data.is_dir():
        return root_data
    if pkg_data.is_dir():
        return pkg_data
    raise FileNotFoundError("data directory not found")


def default_config_path(root: Optional[Path] = None) -> Path:
    env = os.environ.get("GENESIS_PUZZLE_CONFIG")
    if env:
        return Path(env).resolve()
    root_config = project_root(root) / "config.toml"
    if root_config.is_file():
        return root_config
    packaged_config = Path(__file__).resolve().parent / "data" / "config.toml"
    if packaged_config.is_file():
        return packaged_config
    return root_config


def default_state_dir(root: Optional[Path] = None) -> Path:
    env = os.environ.get("GENESIS_PUZZLE_STATE")
    if env:
        return Path(env).resolve()
    return project_root(root) / "state"


def default_report_path(root: Optional[Path] = None) -> Path:
    env = os.environ.get("GENESIS_PUZZLE_REPORT")
    if env:
        return Path(env).resolve()
    return project_root(root) / "research" / "report.md"
