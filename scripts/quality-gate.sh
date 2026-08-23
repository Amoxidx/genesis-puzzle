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
print("wheel contains witness.py and stage_b.py")
' "$WHEEL"

echo "== package install (wheel) =="
python -m pip install --force-reinstall --no-deps "$WHEEL"
python -c "import genesis_puzzle, inspect, pathlib; root = pathlib.Path(inspect.getfile(genesis_puzzle)).resolve().parent; assert (root / 'witness.py').is_file(); assert (root / 'stage_b.py').is_file(); print('installed', genesis_puzzle.__version__, inspect.getfile(genesis_puzzle))"

echo "== CLI smoke after install, outside source checkout =="
SMOKE_DIR="$QA_DIR/smoke"
mkdir -p "$SMOKE_DIR"
cd "$SMOKE_DIR"
genesis-puzzle --help >/dev/null
genesis-puzzle --state-dir "$SMOKE_DIR/state" --report-path "$SMOKE_DIR/report.md" init
genesis-puzzle candidates --stage A >"$SMOKE_DIR/candidates_a.txt"
genesis-puzzle candidates --stage B >"$SMOKE_DIR/candidates_b.txt"
grep -q 'stage B recipes: 105' "$SMOKE_DIR/candidates_b.txt"
grep -q 'p2pk_compressed' "$SMOKE_DIR/candidates_b.txt"
genesis-puzzle --state-dir "$SMOKE_DIR/state" --report-path "$SMOKE_DIR/report.md" run --stage A --mode balanced
genesis-puzzle --state-dir "$SMOKE_DIR/state" --report-path "$SMOKE_DIR/report.md" run --stage B --mode balanced
genesis-puzzle --state-dir "$SMOKE_DIR/state" status | tee "$SMOKE_DIR/status.txt"
grep -q 'stage=B' "$SMOKE_DIR/status.txt"
grep -q 'status=ok' "$SMOKE_DIR/status.txt"
grep -q 'unique_keys=105' "$SMOKE_DIR/status.txt"
genesis-puzzle --state-dir "$SMOKE_DIR/state" --report-path "$SMOKE_DIR/report.md" report
genesis-puzzle benchmark
test -s "$SMOKE_DIR/report.md"
python -c 'import os, stat, sys; assert stat.S_IMODE(os.stat(sys.argv[1]).st_mode) == 0o600' "$SMOKE_DIR/state/research.sqlite"
python -c '
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text(encoding="utf-8")
assert "Stage A+B report" in text
assert "Stage B derivations: 105" in text
assert "cumulative unique valid keys after A+B: 105" in text
assert "tested witness candidates: 630" in text
assert "P2WSH direct target matches: 0" in text
assert "132 Stage-A-only" in text
assert "630" in text
assert "suspected_not_proven" in text
assert "does not disprove" in text
assert "Next highest-value Stage C experiment (not executed)" in text
assert "unexecuted" not in text.lower()
assert "Do not execute that experiment in Milestone 1" not in text
assert "Stage B, brute force" not in text
print("smoke report asserts ok")
' "$SMOKE_DIR/report.md"

echo "quality-gate: ok"
