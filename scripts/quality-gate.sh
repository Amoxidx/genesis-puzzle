#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

if [ -z "${VIRTUAL_ENV:-}" ]; then
  echo "quality-gate: run inside the project virtualenv" >&2
  exit 1
fi

echo "== format check =="
python -m ruff format --check src tests

echo "== lint =="
python -m ruff check src tests

echo "== typing =="
python -m mypy src

echo "== tests =="
python -m pytest

echo "== package build =="
QA_DIR="$(mktemp -d)"
trap 'rm -rf "$QA_DIR"' EXIT INT TERM
python -m build --outdir "$QA_DIR/dist"
set -- "$QA_DIR"/dist/genesis_puzzle-*.whl
test "$#" -eq 1
WHEEL="$1"
set -- "$QA_DIR"/dist/genesis_puzzle-*.tar.gz
test "$#" -eq 1
SDIST="$1"
tar -tzf "$SDIST" | grep -q '/tests/conftest.py$'
python -c '
import sys, zipfile
wheel = sys.argv[1]
with zipfile.ZipFile(wheel) as zf:
    names = zf.namelist()
assert any(name.endswith("genesis_puzzle/witness.py") for name in names), names
assert any(name.endswith("genesis_puzzle/stage_b.py") for name in names), names
assert any(name.endswith("genesis_puzzle/stage_c.py") for name in names), names
assert any(name.endswith("genesis_puzzle/stage_d.py") for name in names), names
print("wheel contains witness.py, stage_b.py, stage_c.py, and stage_d.py")
' "$WHEEL"

echo "== package install (wheel) =="
python -m pip install --force-reinstall --no-deps "$WHEEL"
python -c "import genesis_puzzle, inspect, pathlib; root = pathlib.Path(inspect.getfile(genesis_puzzle)).resolve().parent; assert (root / 'witness.py').is_file(); assert (root / 'stage_b.py').is_file(); assert (root / 'stage_c.py').is_file(); assert (root / 'stage_d.py').is_file(); print('installed', genesis_puzzle.__version__, inspect.getfile(genesis_puzzle))"

echo "== CLI smoke after install, outside source checkout =="
SMOKE_DIR="$QA_DIR/smoke"
mkdir -p "$SMOKE_DIR"
cd "$SMOKE_DIR"
genesis-puzzle --help >/dev/null
genesis-puzzle --state-dir "$SMOKE_DIR/state" --report-path "$SMOKE_DIR/report.md" init
genesis-puzzle candidates --stage A >"$SMOKE_DIR/candidates_a.txt"
genesis-puzzle candidates --stage B >"$SMOKE_DIR/candidates_b.txt"
genesis-puzzle candidates --stage C >"$SMOKE_DIR/candidates_c.txt"
genesis-puzzle candidates --stage D >"$SMOKE_DIR/candidates_d.txt"
grep -q 'stage B recipes: 105' "$SMOKE_DIR/candidates_b.txt"
grep -q 'p2pk_compressed' "$SMOKE_DIR/candidates_b.txt"
grep -q 'stage C recipes: 14' "$SMOKE_DIR/candidates_c.txt"
grep -q 'p2pk_compressed' "$SMOKE_DIR/candidates_c.txt"
grep -q 'stage D recipes: 40' "$SMOKE_DIR/candidates_d.txt"
grep -q 'p2pk_compressed' "$SMOKE_DIR/candidates_d.txt"
genesis-puzzle --state-dir "$SMOKE_DIR/state" --report-path "$SMOKE_DIR/report.md" run --stage A --mode balanced
genesis-puzzle --state-dir "$SMOKE_DIR/state" --report-path "$SMOKE_DIR/report.md" run --stage B --mode balanced
genesis-puzzle --state-dir "$SMOKE_DIR/state" --report-path "$SMOKE_DIR/report.md" run --stage C --mode balanced | tee "$SMOKE_DIR/run_c.txt"
grep -q 'derivations=14' "$SMOKE_DIR/run_c.txt"
grep -q 'invalid=0' "$SMOKE_DIR/run_c.txt"
grep -q 'unique_keys=119' "$SMOKE_DIR/run_c.txt"
grep -q 'new_unique_keys=14' "$SMOKE_DIR/run_c.txt"
grep -q 'witness_candidates_tested=84' "$SMOKE_DIR/run_c.txt"
grep -q 'cumulative_witness_candidates=714' "$SMOKE_DIR/run_c.txt"
grep -q 'elapsed_s=' "$SMOKE_DIR/run_c.txt"
grep -q 'checkpoint=not-needed' "$SMOKE_DIR/run_c.txt"
genesis-puzzle --state-dir "$SMOKE_DIR/state" status | tee "$SMOKE_DIR/status_c.txt"
grep -q 'stage=C' "$SMOKE_DIR/status_c.txt"
grep -q 'status=ok' "$SMOKE_DIR/status_c.txt"
grep -q 'count=14' "$SMOKE_DIR/status_c.txt"
grep -q 'unique_keys=119' "$SMOKE_DIR/status_c.txt"
genesis-puzzle --state-dir "$SMOKE_DIR/state" --report-path "$SMOKE_DIR/report.md" run --stage D --mode balanced | tee "$SMOKE_DIR/run_d.txt"
grep -q 'derivations=40' "$SMOKE_DIR/run_d.txt"
grep -q 'invalid=0' "$SMOKE_DIR/run_d.txt"
grep -q 'unique_keys=159' "$SMOKE_DIR/run_d.txt"
grep -q 'new_unique_keys=40' "$SMOKE_DIR/run_d.txt"
grep -q 'duplicates=21' "$SMOKE_DIR/run_d.txt"
grep -q 'witness_candidates_tested=240' "$SMOKE_DIR/run_d.txt"
grep -q 'cumulative_witness_candidates=954' "$SMOKE_DIR/run_d.txt"
grep -q 'elapsed_s=' "$SMOKE_DIR/run_d.txt"
grep -q 'checkpoint=not-needed' "$SMOKE_DIR/run_d.txt"
genesis-puzzle --state-dir "$SMOKE_DIR/state" status | tee "$SMOKE_DIR/status.txt"
grep -q 'stage=D' "$SMOKE_DIR/status.txt"
grep -q 'status=ok' "$SMOKE_DIR/status.txt"
grep -q 'count=40' "$SMOKE_DIR/status.txt"
grep -q 'unique_keys=159' "$SMOKE_DIR/status.txt"
genesis-puzzle --state-dir "$SMOKE_DIR/state" --report-path "$SMOKE_DIR/report.md" report
genesis-puzzle benchmark
test -s "$SMOKE_DIR/report.md"
python -c 'import os, stat, sys; assert stat.S_IMODE(os.stat(sys.argv[1]).st_mode) == 0o600' "$SMOKE_DIR/state/research.sqlite"
python -c '
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text(encoding="utf-8")
assert "Stage A+B+C+D report" in text
assert "Stage A+B+C report" not in text
assert "Stage A+B report" not in text
assert "Stage B derivations: 105" in text
assert "cumulative unique valid keys after A+B: 105" in text
assert "P2WSH direct target matches: 0" in text
assert "132 Stage-A-only" in text
assert "630" in text
assert "Stage C derivations: 14" in text
assert "Stage C new unique valid keys: 14" in text
assert "cumulative unique valid keys after A+B+C: 119" in text
assert "new Stage C witness candidates: 84" in text
assert "cumulative B+C witness candidates: 714" in text
assert "Stage D derivations: 40" in text
assert "Stage D invalid derivations: 0" in text
assert "Stage D new unique valid keys: 40" in text
assert "cumulative unique valid keys after A+B+C+D: 159" in text
assert "cumulative duplicate provenance paths after A+B+C+D: 21" in text
assert "new Stage D witness candidates: 240" in text
assert "cumulative B+C+D witness candidates: 954" in text
assert "suspected_not_proven" in text
assert "does not disprove" in text
assert "Next highest-value Stage E experiment (not executed)" in text
assert "SHA256 once over exactly these eight UTF-8" in text
assert "Eight candidate keys" in text
assert "at most 48 scripts" in text
assert "Do not execute Stage E here" in text
assert "2009-01-03T18:15:05Z" in text
assert "2009-01-03 18:15:05 UTC" in text
assert "2009-01-03" in text
assert "03/Jan/2009" in text
assert "03/01/2009" in text
assert "01/03/2009" in text
assert "03Jan2009" in text
assert "20090103" in text
assert "European/day-first ambiguous" in text
assert "American/month-first ambiguous" in text
dates = [
    "1. `2009-01-03T18:15:05Z`",
    "2. `2009-01-03 18:15:05 UTC`",
    "3. `2009-01-03`",
    "4. `03/Jan/2009`",
    "5. `03/01/2009`",
    "6. `01/03/2009`",
    "7. `03Jan2009`",
    "8. `20090103`",
]
stage_e = text.split("Next highest-value Stage E experiment (not executed)", 1)[1]
positions = [stage_e.index(item) for item in dates]
assert positions == sorted(positions)
assert "unexecuted" not in text.lower()
assert "Do not execute that experiment in Milestone 1" not in text
assert "Stage B, brute force" not in text
assert "Stage C, brute force" not in text
assert "Stage D, brute force" not in text
assert "Next highest-value Stage D experiment (not executed)" not in text
assert "Next highest-value Stage C experiment (not executed)" not in text
assert "Do not execute Stage D here" not in text
assert "Do not execute Stage D" not in text
assert "Do not execute Stage C here" not in text
assert "Stage-D-not-executed" not in text
assert "Stage-C-not-executed" not in text
print("smoke report asserts ok")
' "$SMOKE_DIR/report.md"
python -c '
import inspect
import json
import re
import sys
from pathlib import Path

import genesis_puzzle
from genesis_puzzle.storage import connect, dump_text

pkg = Path(inspect.getfile(genesis_puzzle)).resolve().parent
header = json.loads((pkg / "data" / "genesis.json").read_text(encoding="utf-8"))["header"]
nonce = int(header["nonce"])
timestamp = int(header["timestamp"])
computed = []
for distance in range(1, 11):
    for public in (nonce, timestamp):
        for offset in (-distance, distance):
            value = public + offset
            assert value not in (nonce, timestamp)
            computed.append(value)
assert len(computed) == 40
assert len(set(computed)) == 40
blob_parts = [Path(path).read_text(encoding="utf-8") for path in sys.argv[1:5]]
store = connect(Path(sys.argv[5]))
try:
    blob_parts.append(dump_text(store.conn))
finally:
    store.conn.close()
blob = "\n".join(blob_parts)
for value in computed:
    decimal = str(value)
    packed = f"{value:064x}"
    if re.search(rf"(?<![0-9]){re.escape(decimal)}(?![0-9])", blob):
        raise AssertionError("computed Stage D decimal scalar leaked into smoke outputs")
    if re.search(rf"(?<![0-9a-fA-F]){re.escape(packed)}(?![0-9a-fA-F])", blob, flags=re.IGNORECASE):
        raise AssertionError("computed Stage D 64-hex scalar leaked into smoke outputs")
print("smoke Stage D scalar redaction asserts ok")
' "$SMOKE_DIR/candidates_d.txt" "$SMOKE_DIR/run_d.txt" "$SMOKE_DIR/status.txt" "$SMOKE_DIR/report.md" "$SMOKE_DIR/state/research.sqlite"

echo "quality-gate: ok"
