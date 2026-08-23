# genesis-puzzle

Local, auditable researcher for a **narrowly scoped** Bitcoin Genesis puzzle.
Milestone 1 implements **Stage A only**.

This is not a general-purpose address or private-key cracking framework. Stage
B, brute force, PBKDF2/BIP39, Metal, transaction creation, wallet import,
spending, and broadcasting are out of scope.

Private candidate scalars are never printed, logged, stored in SQLite, written
into reports, sent to APIs, copied to the clipboard, or interpolated into a
shell command. There is no reveal or export command.

Offline is the default. Remote history checks are explicit (`history-check
--yes-network`), use blockchain.info's multi-address endpoint, and send only
derived public addresses. One HTTP request is made per configured batch, never
one request per address.

## Layout

- `data/genesis.json` — canonical public Genesis facts
- `data/known_targets.json` — public announcement target, labelled `suspected_puzzle_output`
- `src/genesis_puzzle/` — parser, Stage A generator, secp256k1/address primitives, SQLite, CLI
- `tests/` — reference vectors and CLI smoke
- `research/report.md` — regenerated from stored facts/results
- `config.toml` — eco / balanced / max resource caps (balanced default, GPU false)
- `state/research.sqlite` — local research database (owner `0600`)

## Dependencies

Pinned in `pyproject.toml`. Each runtime and dev dependency is here for a
stated reason:

| Pin | Why |
| --- | --- |
| `coincurve==21.0.0` | Mature libsecp256k1 bindings. Deterministic 32-byte secret to compressed and uncompressed public keys on macOS arm64. |
| `tomli==2.2.1` | TOML parser for `config.toml` on Python 3.9 and 3.10 (`tomllib` exists from 3.11). |
| `pytest==8.3.5` | Test runner for the repository test gate. |
| `ruff==0.11.2` | Format check and lint gate. |
| `mypy==1.15.0` | Typing gate. |
| `build==1.2.2.post1` | Package build gate. |
| `setuptools==75.8.2`, `wheel==0.45.1` | Build backend. |

Everything else (argparse, hashlib, sqlite3, urllib, json, pathlib) is the
standard library. Base58Check, HASH160, Bech32, and scripts are implemented
locally and checked against independent reference vectors.

## Install

Python 3.9+.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
```

Console command: `genesis-puzzle`.

## Commands

```sh
genesis-puzzle init
genesis-puzzle candidates --stage A
genesis-puzzle run --stage A --mode balanced
genesis-puzzle benchmark
genesis-puzzle status
genesis-puzzle report
genesis-puzzle history-check --yes-network
```

`run --mode` is `eco`, `balanced`, or `max`. Balanced is the default from
`config.toml`. Stage A is tiny and sequential in every mode; extra workers are
rejected. Pause, resume, and checkpointing are **future bounded-search
features** and are not implemented because Stage A does not need them.
`status` always reports `checkpoint=not-needed`.

`config.toml` also records the requested CPU/GPU duty-cycle, batch-pause,
thermal-limit, and checkpoint defaults for future bounded searches. Milestone 1
does not consume those values and does not claim access to macOS temperature
sensors.

`candidates --stage A` prints ordered recipes and provenance without deriving a
private scalar.

`history-check` is optional, explicit, and offline unless `--yes-network` is
passed. It may send only derived public addresses.

## Quality gate

The complete local repository gate is `scripts/quality-gate.sh`. It runs these
literal commands:

```sh
python -m ruff format --check src tests
python -m ruff check src tests
python -m mypy src
python -m pytest
python -m build
python -m pip install --force-reinstall --no-deps dist/genesis_puzzle-*.whl
```

Tests stay laptop-safe and do not start a worker pool.

## Stage A

Deterministic, ordered, deduplicated by exact private scalar (fingerprint
stored, scalar discarded). Each unique valid key yields exactly three
addresses: uncompressed P2PKH, compressed P2PKH, compressed P2WPKH.

The suspected announcement output is P2WSH. Standard P2PKH/P2WPKH derivations
cannot test its unknown witness script. That limitation is recorded, not
papered over.

## Safety

Do not paste candidate scalars into a wallet. This tool will not import keys,
build transactions, or broadcast.
