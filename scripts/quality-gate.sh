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
print("wheel contains witness.py, stage_b.py, and stage_c.py")
' "$WHEEL"

echo "== package install (wheel) =="
python -m pip install --force-reinstall --no-deps "$WHEEL"
python -c "import genesis_puzzle, inspect, pathlib; root = pathlib.Path(inspect.getfile(genesis_puzzle)).resolve().parent; assert (root / 'witness.py').is_file(); assert (root / 'stage_b.py').is_file(); assert (root / 'stage_c.py').is_file(); print('installed', genesis_puzzle.__version__, inspect.getfile(genesis_puzzle))"

echo "== CLI smoke after install, outside source checkout =="
SMOKE_DIR="$QA_DIR/smoke"
mkdir -p "$SMOKE_DIR"
cd "$SMOKE_DIR"
genesis-puzzle --help >/dev/null
genesis-puzzle --state-dir "$SMOKE_DIR/state" --report-path "$SMOKE_DIR/report.md" init
genesis-puzzle candidates --stage A >"$SMOKE_DIR/candidates_a.txt"
genesis-puzzle candidates --stage B >"$SMOKE_DIR/candidates_b.txt"
genesis-puzzle candidates --stage C >"$SMOKE_DIR/candidates_c.txt"
grep -q 'stage B recipes: 105' "$SMOKE_DIR/candidates_b.txt"
grep -q 'p2pk_compressed' "$SMOKE_DIR/candidates_b.txt"
grep -q 'stage C recipes: 14' "$SMOKE_DIR/candidates_c.txt"
grep -q 'p2pk_compressed' "$SMOKE_DIR/candidates_c.txt"
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
genesis-puzzle --state-dir "$SMOKE_DIR/state" status | tee "$SMOKE_DIR/status.txt"
grep -q 'stage=C' "$SMOKE_DIR/status.txt"
grep -q 'status=ok' "$SMOKE_DIR/status.txt"
grep -q 'count=14' "$SMOKE_DIR/status.txt"
grep -q 'unique_keys=119' "$SMOKE_DIR/status.txt"
genesis-puzzle --state-dir "$SMOKE_DIR/state" --report-path "$SMOKE_DIR/report.md" report
genesis-puzzle benchmark
test -s "$SMOKE_DIR/report.md"
python -c 'import os, stat, sys; assert stat.S_IMODE(os.stat(sys.argv[1]).st_mode) == 0o600' "$SMOKE_DIR/state/research.sqlite"
python -c '
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text(encoding="utf-8")
assert "Stage A+B+C report" in text
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
assert "suspected_not_proven" in text
assert "does not disprove" in text
assert "Next highest-value Stage D experiment (not executed)" in text
assert "-10..-1" in text
assert "+1..+10" in text
assert "excluding zero" in text
assert "40 keys" in text
assert "240 scripts" in text
assert "Do not execute Stage D here" in text or "Do not\nexecute Stage D here" in text
assert "unexecuted" not in text.lower()
assert "Do not execute that experiment in Milestone 1" not in text
assert "Stage B, brute force" not in text
assert "Stage C, brute force" not in text
assert "Next highest-value Stage C experiment (not executed)" not in text
assert "Do not execute Stage C here" not in text
assert "Stage-C-not-executed" not in text
print("smoke report asserts ok")
' "$SMOKE_DIR/report.md"

echo "quality-gate: ok"
