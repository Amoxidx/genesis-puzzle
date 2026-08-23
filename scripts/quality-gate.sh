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

echo "== package install (wheel) =="
python -m pip install --force-reinstall --no-deps "$WHEEL"
python -c "import genesis_puzzle, inspect; print('installed', genesis_puzzle.__version__, inspect.getfile(genesis_puzzle))"

echo "== CLI smoke after install, outside source checkout =="
SMOKE_DIR="$QA_DIR/smoke"
mkdir -p "$SMOKE_DIR"
cd "$SMOKE_DIR"
genesis-puzzle --help >/dev/null
genesis-puzzle --state-dir "$SMOKE_DIR/state" --report-path "$SMOKE_DIR/report.md" init
genesis-puzzle candidates --stage A >"$SMOKE_DIR/candidates.txt"
genesis-puzzle --state-dir "$SMOKE_DIR/state" --report-path "$SMOKE_DIR/report.md" run --stage A --mode balanced
genesis-puzzle --state-dir "$SMOKE_DIR/state" status
genesis-puzzle --state-dir "$SMOKE_DIR/state" --report-path "$SMOKE_DIR/report.md" report
genesis-puzzle benchmark
test -s "$SMOKE_DIR/report.md"
python -c 'import os, stat, sys; assert stat.S_IMODE(os.stat(sys.argv[1]).st_mode) == 0o600' "$SMOKE_DIR/state/research.sqlite"

echo "quality-gate: ok"
