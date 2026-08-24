# genesis-puzzle

Local, auditable researcher for a **narrowly scoped** Bitcoin Genesis puzzle.
This release implements deterministic **Stages A, B, C, and D** as an offline
sequential pipeline: A then B then C then D.

This is not a general-purpose address or private-key cracking framework.
Stage E is proposed, not executed. Brute force, PBKDF2/BIP39, Metal,
transaction creation, wallet import, spending, and broadcasting remain out of
scope.

Private candidate scalars are never printed, logged, stored in SQLite, written
into reports, sent to APIs, copied to the clipboard, or interpolated into a
shell command. There is no reveal or export command.

Offline is the default. Stage B, Stage C, and Stage D are offline. Stage B
requires a completed Stage A run. Stage C requires completed Stage A and Stage
B runs in the same database. Stage D requires completed Stage A, Stage B, and
Stage C runs in the same database. Remote history checks are explicit
(`history-check --yes-network`), use blockchain.info's multi-address endpoint,
and send only derived public addresses. One HTTP request is made per configured
batch, never one request per address. Stage C and Stage D themselves do not
look up live chain history.

## Layout

- `data/genesis.json` — canonical public Genesis facts
- `data/known_targets.json` — public announcement target, labelled `suspected_puzzle_output`
- `src/genesis_puzzle/` — parser, Stage A/B/C/D generators, P2WSH templates, secp256k1/address primitives, SQLite, CLI
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
genesis-puzzle run --stage A --mode balanced
genesis-puzzle candidates --stage B
genesis-puzzle run --stage B --mode balanced
genesis-puzzle candidates --stage C
genesis-puzzle run --stage C --mode balanced
genesis-puzzle candidates --stage D
genesis-puzzle run --stage D --mode balanced
genesis-puzzle report
```

Related commands:

```sh
genesis-puzzle candidates --stage A
genesis-puzzle benchmark
genesis-puzzle status
genesis-puzzle history-check --yes-network
```

`run --mode` is `eco`, `balanced`, or `max`. Balanced is the default from
`config.toml`. Stages A, B, C, and D are tiny and sequential in every mode;
extra workers are rejected. Pause, resume, and checkpointing are **future
bounded-search features** and are not implemented because these deterministic
stages do not need them. `status` always reports `checkpoint=not-needed`.

`config.toml` also records the requested CPU/GPU duty-cycle, batch-pause,
thermal-limit, and checkpoint defaults for future bounded searches. This
release does not consume those values and does not claim access to macOS
temperature sensors.

`candidates --stage A`, `--stage B`, `--stage C`, or `--stage D` prints ordered
recipes and provenance without deriving a private scalar. Stage B, Stage C,
and Stage D previews also list the six witness templates.

Stage B is offline. It needs a completed Stage A result in the same database.
Stage C is offline. It needs completed Stage A and Stage B results in the same
database. Stage D is offline. It needs completed Stage A, Stage B, and Stage C
results in the same database. None of those stages queries chain history.
Direct P2WSH comparison is `SHA256(witnessScript)` plus the native address.

`history-check` is optional, explicit, and offline unless `--yes-network` is
passed. It may send only derived public addresses.

There is no `run --stage E` command. Do not execute Stage E.

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

Tests stay laptop-safe and do not start a worker pool. The installed-wheel
smoke previews Stage D and then executes Stage A, Stage B, Stage C, and Stage D
sequentially outside the checkout.

## Stages A, B, C, and D

Stage A is deterministic, ordered, and deduplicated by exact private scalar
(fingerprint stored, scalar discarded). Each unique valid key yields exactly
three addresses: uncompressed P2PKH, compressed P2PKH, compressed P2WPKH.

Stage B adds a bounded representation matrix (105 recipes) and six generic
single-key P2WSH templates. Combined unique keys are tested against those
templates in template-priority order. After the checked no-match run that is
the current result: 105 Stage B recipes, 105 cumulative unique keys, 630
scripts, 0 direct P2WSH matches. That does not solve the puzzle and does not
disprove it. The announcement target remains `suspected_not_proven`.

The 132 Stage-A-only scripts are the 22 unique Stage A keys times six
templates. They are a subset of the 630 combined A+B scripts, not an extra
count.

Stage C is a bounded pairwise combination of the actual Genesis nonce and
timestamp as ASCII decimal values, in both orders (`nonce || separator ||
timestamp` and `timestamp || separator || nonce`), with exactly these seven
separators: empty string, colon, pipe, hyphen, underscore, ASCII space, and
ASCII newline. Each of those 14 public strings is SHA256'd, then the same six
P2WSH templates are applied. Canonical expected counts: 14 Stage C recipes, 14
new unique keys, 119 cumulative unique keys after A+B+C, 84 new Stage C
scripts, 714 combined B+C scripts. Direct comparison remains
`SHA256(witnessScript)` plus the native address. A no-match on this bounded
set does not solve the puzzle, does not disprove it, and is not a live chain
lookup.

Compressed templates are modern canonical / descriptor-compatible.
Uncompressed P2WSH pubkeys were tested only as lower-priority
historical/manual possibilities.

Stage D is the implemented bounded direct-scalar neighborhood of the actual
Genesis nonce and timestamp. Canonical direct nonce and timestamp values were
already Stage A, so offset zero is excluded. Offsets are exactly ±1..±10
(`-10..-1` and `+1..+10`). Priority is distance-first: for each distance d
from 1 to 10, nonce-d, nonce+d, timestamp-d, timestamp+d. Do not hash. Do not
form combinations. Do not enlarge that window.

Each of those 40 recipes is the identity integer
`k = uint(field=public_value) + (signed_offset)`. public_input bytes stay
empty. The raw scalar is never printed or stored. The formula, signed offset,
and fingerprint are sufficient to recompute the same public key.

Canonical expected and current contract: 40 Stage D recipes, 0 invalid,
40 new unique keys (40 keys), 159 cumulative unique keys after A+B+C+D,
21 cumulative duplicate provenance paths, 240 new Stage D scripts,
954 combined B+C+D scripts, 0 direct P2WSH target matches. A no-match on
this bounded set does not solve the puzzle, does not disprove it, and is
not a live chain lookup.

Stage E is not executed. The next proposed Stage E experiment is SHA256 once
over exactly these eight UTF-8 date/time strings, in this order:

1. `2009-01-03T18:15:05Z`
2. `2009-01-03 18:15:05 UTC`
3. `2009-01-03`
4. `03/Jan/2009`
5. `03/01/2009` (European/day-first ambiguous)
6. `01/03/2009` (American/month-first ambiguous)
7. `03Jan2009`
8. `20090103`

Eight candidate keys, at most 48 scripts. Do not add newline, case, or
whitespace variants. Do not add alternate time zones or other dates. Do not
use PBKDF2, BIP39, repeated hashing, GPU, neighborhoods, larger combinations,
or brute force. Do not execute Stage E.

## Safety

Do not paste candidate scalars into a wallet. This tool will not import keys,
build transactions, or broadcast.
