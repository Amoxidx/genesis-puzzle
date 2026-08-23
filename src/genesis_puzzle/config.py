from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


@dataclass(frozen=True)
class ModeConfig:
    name: str
    workers: int
    duty_cycle: float
    max_candidates_per_second: float
    description: str


@dataclass(frozen=True)
class HistoryConfig:
    batch_size: int
    provider: str
    base_url: str
    timeout_seconds: float


@dataclass(frozen=True)
class AppConfig:
    default_mode: str
    gpu: bool
    modes: Mapping[str, ModeConfig]
    history: HistoryConfig
    state_dir: str
    database_name: str

    def mode(self, name: Optional[str] = None) -> ModeConfig:
        chosen = name or self.default_mode
        if chosen not in self.modes:
            raise ValueError(f"unknown mode {chosen!r}")
        return self.modes[chosen]


def _require_mapping(payload: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = payload[key]
    if not isinstance(value, dict):
        raise ValueError(f"{key} must be a table")
    return value


def load_config(path: Path) -> AppConfig:
    raw = path.read_bytes()
    payload = tomllib.loads(raw.decode("utf-8"))
    default_mode = str(payload.get("default_mode", "balanced"))
    gpu = bool(payload.get("gpu", False))
    modes_raw = _require_mapping(payload, "modes")
    modes = {}
    for name, body in modes_raw.items():
        if not isinstance(body, dict):
            raise ValueError(f"mode {name} must be a table")
        modes[name] = ModeConfig(
            name=name,
            workers=int(body.get("workers", 1)),
            duty_cycle=float(body.get("duty_cycle", 1.0)),
            max_candidates_per_second=float(body.get("max_candidates_per_second", 0)),
            description=str(body.get("description", "")),
        )
        if modes[name].workers != 1:
            raise ValueError("Stage A is sequential; workers must stay 1")
    history_raw = payload.get("history", {})
    history = HistoryConfig(
        batch_size=int(history_raw.get("batch_size", 10)),
        provider=str(history_raw.get("provider", "blockchain.info-multiaddr")),
        base_url=str(history_raw.get("base_url", "https://blockchain.info")),
        timeout_seconds=float(history_raw.get("timeout_seconds", 20)),
    )
    storage = payload.get("storage", {})
    if default_mode not in modes:
        raise ValueError("default_mode is not defined")
    if gpu:
        raise ValueError("GPU is disabled in Milestone 1")
    return AppConfig(
        default_mode=default_mode,
        gpu=False,
        modes=modes,
        history=history,
        state_dir=str(storage.get("state_dir", "state")),
        database_name=str(storage.get("database_name", "research.sqlite")),
    )
