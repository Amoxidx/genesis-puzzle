from __future__ import annotations

import ast
import inspect
import json
import re
import sys
from pathlib import Path

import pytest

import genesis_puzzle
from genesis_puzzle.cli import _build_parser

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

STAGE_E_DATE_STRINGS = (
    "2009-01-03T18:15:05Z",
    "2009-01-03 18:15:05 UTC",
    "2009-01-03",
    "03/Jan/2009",
    "03/01/2009",
    "01/03/2009",
    "03Jan2009",
    "20090103",
)


def _decimal_token_in_source(source_text: str, decimal: str) -> bool:
    return re.search(rf"(?<![0-9]){re.escape(decimal)}(?![0-9])", source_text) is not None


def _hex64_token_in_source(source_text: str, packed_hex: str) -> bool:
    return (
        re.search(
            rf"(?<![0-9a-fA-F]){re.escape(packed_hex)}(?![0-9a-fA-F])",
            source_text,
            flags=re.IGNORECASE,
        )
        is not None
    )


def _genesis_nonce_timestamp(repo_root: Path) -> tuple[int, int]:
    header = json.loads((repo_root / "data" / "genesis.json").read_text(encoding="utf-8"))[
        "header"
    ]
    return int(header["nonce"]), int(header["timestamp"])


def _stage_d_computed_scalars(nonce: int, timestamp: int) -> tuple[int, ...]:
    values = []
    for distance in range(1, 11):
        for public in (nonce, timestamp):
            for offset in (-distance, distance):
                value = public + offset
                assert value not in (nonce, timestamp)
                values.append(value)
    return tuple(values)


def _posix_single_quoted_body(source: str, opening_quote: int) -> str:
    if opening_quote >= len(source) or source[opening_quote] != "'":
        raise AssertionError("expected POSIX single-quoted string")
    closing = source.find("'", opening_quote + 1)
    if closing < 0:
        raise AssertionError("unterminated POSIX single-quoted string")
    return source[opening_quote + 1 : closing]


def _quoted_heredoc_body(source: str, command: str) -> str | None:
    match = re.search(
        rf"^{re.escape(command)} <<'([^'\n]+)'\n(.*?)\n\1(?:\n|$)",
        source,
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None:
        return None
    return match.group(2)


def _quality_gate_report_assertion_python(script: str) -> str:
    heredoc = _quoted_heredoc_body(script, 'python - "$SMOKE_DIR/report.md"')
    if heredoc is not None:
        return heredoc
    search_from = 0
    while True:
        idx = script.find("python -c", search_from)
        if idx < 0:
            break
        cursor = idx + len("python -c")
        while cursor < len(script) and script[cursor] in " \t":
            cursor += 1
        if cursor < len(script) and script[cursor] == "'":
            body = _posix_single_quoted_body(script, cursor)
            if "Stage A+B+C+D+E report" in body:
                return body
        search_from = idx + 1
    raise AssertionError("quality-gate report assertion python block not found")


def test_package_version_matches_dunder_version(repo_root: Path):
    payload = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))
    assert payload["project"]["version"] == genesis_puzzle.__version__
    assert genesis_puzzle.__version__ == "0.5.0"
    description = payload["project"]["description"]
    assert "Stage A" in description
    assert "Stage B" in description
    assert "Stage C" in description
    assert "Stage D" in description
    assert "sequential/offline" in description
    assert "Milestone 1" not in description
    assert genesis_puzzle.__doc__ is not None
    assert "A+B+C+D+E" in genesis_puzzle.__doc__
    assert "sequential/offline" in genesis_puzzle.__doc__
    assert "Milestone 1" not in genesis_puzzle.__doc__
    package_dir = Path(inspect.getfile(genesis_puzzle)).resolve().parent
    assert (package_dir / "stage_e.py").is_file()
    assert (package_dir / "stage_d.py").is_file()
    assert (package_dir / "stage_c.py").is_file()
    assert (package_dir / "stage_b.py").is_file()
    assert (package_dir / "cli.py").is_file()


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
    for payload in (root_payload, packaged_payload):
        for name in ("eco", "balanced", "max"):
            description = payload["modes"][name]["description"]
            assert "A+B+C+D+E" in description
            assert "sequential" in description
            assert "offline" in description


def test_cli_help_and_stage_choices_include_e_not_f():
    parser = _build_parser()
    help_text = parser.format_help()
    assert "genesis-puzzle" in help_text
    assert "Stage A" in help_text
    assert "Stage B" in help_text
    assert "Stage C" in help_text
    assert "Stage D" in help_text
    assert "Stage E" in help_text
    assert "sequential/offline" in help_text
    assert "direct bounded" in help_text
    assert parser.parse_args(["candidates", "--stage", "A"]).stage == "A"
    assert parser.parse_args(["candidates", "--stage", "B"]).stage == "B"
    assert parser.parse_args(["candidates", "--stage", "C"]).stage == "C"
    assert parser.parse_args(["candidates", "--stage", "D"]).stage == "D"
    assert parser.parse_args(["candidates", "--stage", "E"]).stage == "E"
    assert parser.parse_args(["run", "--stage", "E", "--mode", "balanced"]).stage == "E"
    with pytest.raises(SystemExit):
        parser.parse_args(["run", "--stage", "F"])
    with pytest.raises(SystemExit):
        parser.parse_args(["candidates", "--stage", "F"])


def test_readme_stage_d_release_contract(repo_root: Path):
    text = (repo_root / "README.md").read_text(encoding="utf-8")
    lowered = text.lower()
    assert "Stages A, B, C, D, and E" in text
    assert "A then B then C then D then E" in text
    assert "sequential" in lowered
    assert "offline" in lowered
    assert "ASCII decimal" in text
    assert "both orders" in lowered or "nonce || separator || timestamp" in text
    for separator in (
        "empty string",
        "colon",
        "pipe",
        "hyphen",
        "underscore",
        "space",
        "newline",
    ):
        assert separator in lowered
    assert "SHA256" in text
    assert "14 Stage C recipes" in text or "14 recipes" in lowered
    assert "14" in text
    assert "119" in text
    assert "84" in text
    assert "714" in text
    assert "run --stage C" in text
    assert "candidates --stage C" in text
    assert "run --stage D" in text
    assert "candidates --stage D" in text
    assert "run --stage E" in text
    assert "candidates --stage E" in text
    assert "never printed" in lowered or "never" in lowered
    assert "stored in sqlite" in lowered
    assert "Stage D is not executed" not in text
    assert "Do not execute Stage D" not in text
    assert "There is no `run --stage D`" not in text
    assert "There is no `run --stage E` command" not in text
    assert "There is no `run --stage F` command" in text
    assert "Do not execute Stage F" in text
    assert "-10..-1" in text
    assert "+1..+10" in text
    assert "excluding zero" in lowered or "offset zero is excluded" in lowered
    assert "distance-first" in lowered
    assert "do not hash" in lowered
    assert "public_input" in lowered
    assert "formula" in lowered
    assert "fingerprint" in lowered
    assert "40 Stage D recipes" in text or "40 recipes" in lowered
    assert "0 invalid" in text
    assert "159" in text
    assert "21" in text
    assert "40 keys" in text or "40 new unique keys" in lowered
    assert "240" in text
    assert "954" in text
    assert "8 Stage E recipes" in text or "8 recipes" in lowered
    assert "167" in text
    assert "48" in text
    assert "1002" in text
    assert "direct-scalar" in lowered or "direct scalar" in lowered
    assert "solved the puzzle" not in lowered
    assert "live chain" in lowered or "does not look up live chain" in lowered
    assert "history-check --yes-network" in text
    assert "SHA256 once" in text
    assert "Eight candidate keys" in text
    assert "at most 48 scripts" in text
    assert "European/day-first ambiguous" in text
    assert "American/month-first ambiguous" in text
    rendered = [f"{index}. `{value}`" for index, value in enumerate(STAGE_E_DATE_STRINGS, start=1)]
    positions = [text.index(line) for line in rendered]
    assert positions == sorted(positions)
    assert "newline" in lowered
    assert "time zones" in lowered
    assert "PBKDF2" in text
    assert "BIP39" in text
    assert "repeated hashing" in lowered
    assert "neighborhoods" in lowered
    assert "brute force" in lowered


def test_quality_gate_stage_d_smoke_contract(repo_root: Path):
    text = (repo_root / "scripts" / "quality-gate.sh").read_text(encoding="utf-8")
    preview_c = text.index("candidates --stage C")
    preview_d = text.index("candidates --stage D")
    preview_e = text.index("candidates --stage E")
    run_a = text.index("run --stage A")
    run_b = text.index("run --stage B")
    run_c = text.index("run --stage C")
    run_d = text.index("run --stage D")
    run_e = text.index("run --stage E")
    assert preview_c < preview_d < preview_e < run_a < run_b < run_c < run_d < run_e
    assert "candidates --stage B" in text
    assert "stage B recipes: 105" in text
    assert "Stage B derivations: 105" in text
    assert "cumulative unique valid keys after A+B: 105" in text
    assert "132 Stage-A-only" in text
    assert "630" in text
    assert "stage C recipes: 14" in text
    assert "derivations=14" in text
    assert "new_unique_keys=14" in text
    assert "unique_keys=119" in text
    assert "witness_candidates_tested=84" in text
    assert "cumulative_witness_candidates=714" in text
    assert "Stage C derivations: 14" in text
    assert "Stage C new unique valid keys: 14" in text
    assert "cumulative unique valid keys after A+B+C: 119" in text
    assert "new Stage C witness candidates: 84" in text
    assert "cumulative B+C witness candidates: 714" in text
    assert "stage_d.py" in text
    assert "stage_e.py" in text
    assert "stage D recipes: 40" in text
    assert "derivations=40" in text
    assert "unique_keys=159" in text
    assert "new_unique_keys=40" in text
    assert "duplicates=21" in text
    assert "witness_candidates_tested=240" in text
    assert "cumulative_witness_candidates=954" in text
    assert "stage=D" in text
    assert "count=40" in text
    assert "Stage A+B+C+D+E report" in text
    assert "Stage A+B+C+D report" in text
    assert "Stage D derivations: 40" in text
    assert "Stage D invalid derivations: 0" in text
    assert "Stage D new unique valid keys: 40" in text
    assert "cumulative unique valid keys after A+B+C+D: 159" in text
    assert "cumulative duplicate provenance paths after A+B+C+D: 21" in text
    assert "new Stage D witness candidates: 240" in text
    assert "cumulative B+C+D witness candidates: 954" in text
    assert "P2WSH direct target matches: 0" in text
    assert "Next highest-value Stage F experiment (not executed)" in text
    assert "Do not execute Stage F here" in text
    assert "stage E recipes: 8" in text
    assert "derivations=8" in text
    assert "unique_keys=167" in text
    assert "new_unique_keys=8" in text
    assert "witness_candidates_tested=48" in text
    assert "cumulative_witness_candidates=1002" in text
    assert "Stage E derivations: 8" in text
    assert "cumulative unique valid keys after A+B+C+D+E: 167" in text
    assert "new Stage E witness candidates: 48" in text
    assert "cumulative B+C+D+E witness candidates: 1002" in text
    assert "genesis-puzzle benchmark" in text
    assert "run --stage E" in text
    assert "candidates --stage E" in text
    assert "computed Stage E decimal scalar leaked" in text
    assert "computed Stage E 64-hex scalar leaked" in text
    assert '"Next highest-value Stage D experiment (not executed)" not in text' in text
    assert '"Next highest-value Stage C experiment (not executed)" not in text' in text
    assert '"Do not execute Stage D here" not in text' in text
    assert '"Do not execute Stage D" not in text' in text
    assert '"Stage-D-not-executed" not in text' in text
    assert '"Stage-C-not-executed" not in text' in text
    assert '"Do not execute Stage C here" not in text' in text
    assert "history-check" not in text
    assert "dump_text" in text
    assert "computed Stage D decimal scalar leaked" in text
    assert "computed Stage D 64-hex scalar leaked" in text


def test_quality_gate_report_assertion_python_is_syntactically_valid(repo_root: Path):
    script = (repo_root / "scripts" / "quality-gate.sh").read_text(encoding="utf-8")
    source = _quality_gate_report_assertion_python(script)
    try:
        ast.parse(source)
    except SyntaxError as exc:
        pytest.fail(
            f"quality-gate report assertion python is not valid ({exc.msg} at line {exc.lineno})"
        )
    assert "SHA256'd" in source
    assert "Stage A+B+C+D+E report" in source
    assert re.search(
        r"^python - \"\$SMOKE_DIR/report\.md\" <<'[^'\n]+'$",
        script,
        flags=re.MULTILINE,
    ), "report assertions must use a quoted heredoc with the report path as argv"


def test_report_module_abc_current_state_recommends_implemented_stage_d(repo_root: Path):
    text = (repo_root / "src" / "genesis_puzzle" / "report.py").read_text(encoding="utf-8")
    assert "run --stage D" in text
    assert "run --stage E" in text
    assert "Do not execute Stage D here" not in text
    assert "Deterministic Stages A, B, C, D, and E are implemented" in text
    assert "Stage F, brute force" in text
    assert "Stage E, brute force" not in text
    assert "Stage D, brute force" not in text
    assert "Do not execute Stage F" in text
    assert "Do not execute Stage E until" not in text
    assert "Stage F and later hypotheses remain out of scope" in text


def test_computed_stage_d_scalars_absent_from_release_contract_sources(repo_root: Path):
    nonce, timestamp = _genesis_nonce_timestamp(repo_root)
    computed = _stage_d_computed_scalars(nonce, timestamp)
    assert len(computed) == 40
    paths = (
        repo_root / "README.md",
        repo_root / "scripts" / "quality-gate.sh",
        Path(__file__).resolve(),
    )
    texts = {path: path.read_text(encoding="utf-8") for path in paths}
    for value in computed:
        decimal = str(value)
        packed_hex = f"{value:064x}"
        for path, text in texts.items():
            assert not _decimal_token_in_source(text, decimal), path.name
            assert not _hex64_token_in_source(text, packed_hex), path.name
