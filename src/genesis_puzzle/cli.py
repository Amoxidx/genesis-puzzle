from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Sequence, TextIO

from genesis_puzzle.benchmark import run_benchmark
from genesis_puzzle.candidates import preview_for_stage, recipes_for_stage
from genesis_puzzle.config import AppConfig, load_config
from genesis_puzzle.engine import (
    StageBPrerequisiteError,
    TargetConsistencyError,
    run_stage_a,
    run_stage_b,
)
from genesis_puzzle.history import BlockchainInfoMultiaddrProvider, HistoryResult, chunked
from genesis_puzzle.model import load_genesis_facts, load_known_targets
from genesis_puzzle.parser import parse_and_verify
from genesis_puzzle.paths import (
    default_config_path,
    default_report_path,
    default_state_dir,
    project_root,
)
from genesis_puzzle.report import render_report, write_report
from genesis_puzzle.storage import (
    Store,
    connect,
    history_rows,
    latest_run,
    latest_run_for_stage,
    list_addresses,
    list_witness_candidates,
    transaction,
    update_history,
)
from genesis_puzzle.storage import (
    counts as store_counts,
)
from genesis_puzzle.witness import WITNESS_TEMPLATES


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="genesis-puzzle",
        description=(
            "Local auditable Bitcoin Genesis Puzzle researcher. "
            "Implements Stage A and Stage B deterministic stages. "
            "Pause/resume/checkpointing are future bounded-search features and "
            "are not used here."
        ),
    )
    parser.add_argument("--root", default=None, help="Project root (data/, config.toml)")
    parser.add_argument("--config", default=None, help="Path to config.toml")
    parser.add_argument("--state-dir", default=None, help="Directory for the SQLite state file")
    parser.add_argument("--report-path", default=None, help="Markdown report path")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Create state/database and validate Genesis proofs")

    cand = sub.add_parser(
        "candidates",
        help="Preview ordered Stage A or Stage B recipes without deriving a private scalar",
    )
    cand.add_argument("--stage", required=True, choices=["A", "B"])

    run = sub.add_parser(
        "run",
        help="Derive Stage A or Stage B keys and store public results",
    )
    run.add_argument("--stage", required=True, choices=["A", "B"])
    run.add_argument("--mode", choices=["eco", "balanced", "max"], default=None)

    sub.add_parser(
        "benchmark",
        help="Measure local SHA256, scalar-to-pubkey, P2PKH, P2WPKH, and pipeline throughput",
    )
    sub.add_parser(
        "status",
        help=(
            "Latest run status/count/rate/mode/elapsed; checkpoint is not needed "
            "for Stage A+B deterministic stages"
        ),
    )
    sub.add_parser("report", help="Regenerate research/report.md from stored facts/results")

    hist = sub.add_parser(
        "history-check",
        help="Explicit batched address-history lookup (sends derived public addresses only)",
    )
    hist.add_argument(
        "--yes-network",
        action="store_true",
        help="Required acknowledgement that public addresses will be sent to the history provider",
    )
    return parser


def _load_app(
    args: argparse.Namespace,
) -> tuple[Path, AppConfig, Path, Path, Path]:
    root = project_root(Path(args.root) if args.root else None)
    cfg_path = Path(args.config) if args.config else default_config_path(root)
    config = load_config(cfg_path)
    if args.state_dir:
        state_dir = Path(args.state_dir)
    else:
        state_dir = default_state_dir(root)
    db_path = state_dir / config.database_name
    report_path = Path(args.report_path) if args.report_path else default_report_path(root)
    return root, config, state_dir, db_path, report_path


def _open_store(db_path: Path) -> Store:
    return connect(db_path)


def _write_current_report(store: Store, root: Path, report_path: Path) -> None:
    facts = load_genesis_facts(root)
    targets = load_known_targets(root)
    conn = store.conn
    c = store_counts(conn)
    run = latest_run(conn)
    run_map = dict(run) if run is not None else None
    stage_a = latest_run_for_stage(conn, "A")
    stage_b = latest_run_for_stage(conn, "B")
    derivations = [
        dict(row)
        for row in conn.execute("SELECT * FROM derivations ORDER BY derivation_id").fetchall()
    ]
    comparisons = [
        dict(row) for row in conn.execute("SELECT * FROM target_comparisons").fetchall()
    ]
    checked_history = [dict(row) for row in history_rows(conn)]
    witness_rows = [dict(row) for row in list_witness_candidates(conn)]
    content = render_report(
        facts,
        targets,
        c,
        run_map,
        derivations,
        comparisons,
        checked_history,
        witness_rows,
        stage_a_run=dict(stage_a) if stage_a is not None else None,
        stage_b_run=dict(stage_b) if stage_b is not None else None,
    )
    write_report(report_path, content)


def cmd_init(args: argparse.Namespace, out: TextIO) -> int:
    root, _config, state_dir, db_path, report_path = _load_app(args)
    facts = load_genesis_facts(root)
    block = parse_and_verify(facts)
    store = _open_store(db_path)
    _write_current_report(store, root, report_path)
    out.write(f"init ok  db={db_path}  proofs=verified  header_bytes={len(block.header.raw)}\n")
    out.write(
        "checkpointing is a future bounded-search feature; Stage A+B deterministic "
        "stages do not need it\n"
    )
    return 0


def cmd_candidates(args: argparse.Namespace, out: TextIO) -> int:
    root, _config, _state_dir, _db_path, _report_path = _load_app(args)
    facts = load_genesis_facts(root)
    block = parse_and_verify(facts)
    recipes = recipes_for_stage(block, args.stage)
    out.write(f"stage {args.stage} recipes: {len(recipes)} (preview only, scalars not derived)\n")
    for line in preview_for_stage(block, args.stage):
        out.write(line + "\n")
    if args.stage == "B":
        out.write("witness templates (global priority order, up to six scripts per unique key):\n")
        for template in WITNESS_TEMPLATES:
            out.write(f"    {template.priority}. {template.name}\n")
        out.write(
            "Each unique valid key is tested against these six generic single-key "
            "witness scripts. Preview does not derive a scalar or public key.\n"
        )
    return 0


def cmd_run(args: argparse.Namespace, out: TextIO) -> int:
    root, config, _state_dir, db_path, report_path = _load_app(args)
    facts = load_genesis_facts(root)
    block = parse_and_verify(facts)
    targets = load_known_targets(root)
    mode = config.mode(args.mode)
    store = _open_store(db_path)
    try:
        if args.stage == "A":
            summary = run_stage_a(store, block, targets, mode, out=out)
            extra = f"addresses={summary['addresses']}"
        else:
            summary = run_stage_b(store, block, targets, mode, out=out)
            extra = f"witness_candidates={summary['witness_candidates']}"
    except (StageBPrerequisiteError, TargetConsistencyError) as exc:
        out.write(f"error: {exc}\n")
        return 1
    _write_current_report(store, root, report_path)
    out.write(
        "run complete  "
        f"derivations={summary['derivations']}  invalid={summary['invalid']}  "
        f"unique_keys={summary['unique_valid_keys']}  duplicates={summary['duplicates']}  "
        f"{extra}  elapsed_s={summary['elapsed_seconds']:.4f}  "
        f"checkpoint=not-needed  report={report_path}\n"
    )
    return 0


def cmd_benchmark(args: argparse.Namespace, out: TextIO) -> int:
    root, _config, _state_dir, _db_path, _report_path = _load_app(args)
    facts = load_genesis_facts(root)
    block = parse_and_verify(facts)
    for line in run_benchmark(block):
        out.write(line + "\n")
    return 0


def cmd_status(args: argparse.Namespace, out: TextIO) -> int:
    _root, _config, _state_dir, db_path, _report_path = _load_app(args)
    if not db_path.is_file():
        out.write("status: no database; run init first\n")
        return 1
    store = _open_store(db_path)
    run = latest_run(store.conn)
    if run is None:
        out.write("status: no runs stored\n")
        out.write(
            "checkpoint: not needed (Stage A+B deterministic stages are tiny and sequential)\n"
        )
        return 0
    out.write(
        f"status={run['status']}  stage={run['stage']}  mode={run['mode']}  "
        f"count={run['derivation_count']}  unique_keys={run['unique_valid_keys']}  "
        f"rate={run['rate_per_second']}  elapsed={run['elapsed_seconds']}  "
        f"checkpoint=not-needed\n"
    )
    return 0


def cmd_report(args: argparse.Namespace, out: TextIO) -> int:
    root, _config, _state_dir, db_path, report_path = _load_app(args)
    store = _open_store(db_path)
    _write_current_report(store, root, report_path)
    out.write(f"wrote {report_path}\n")
    return 0


def cmd_history_check(args: argparse.Namespace, out: TextIO) -> int:
    if not args.yes_network:
        out.write("refusing: history-check requires --yes-network (sends public addresses only)\n")
        return 2
    root, config, _state_dir, db_path, report_path = _load_app(args)
    store = _open_store(db_path)
    rows = list_addresses(store.conn)
    if not rows:
        out.write("no addresses stored; run --stage A first\n")
        return 1
    addresses = [row["address"] for row in rows]
    if config.history.provider != "blockchain.info-multiaddr":
        raise ValueError(f"unsupported history provider {config.history.provider!r}")
    provider = BlockchainInfoMultiaddrProvider(config.history)
    all_results: dict[str, HistoryResult] = {}
    batches = chunked(addresses, config.history.batch_size)
    for batch in batches:
        all_results.update(provider.fetch_batch(batch))
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with transaction(store) as conn:
        for address, result in all_results.items():
            update_history(
                conn,
                address,
                result.seen_on_chain,
                result.balance_sats,
                result.total_received_sats,
                result.total_sent_sats,
                result.transaction_count,
                result.status,
                result.first_seen,
                now,
            )
            out.write(
                f"history  address={address}  status={result.status}  "
                f"balance_sats={result.balance_sats}  tx_count={result.transaction_count}  "
                f"checked={now}\n"
            )
            if result.seen_on_chain:
                out.write("POTENTIAL MATCH FOUND\n")
                out.write(
                    f"    public_address={address} status={result.status} "
                    f"verification=batched_chain_history\n"
                )
    _write_current_report(store, root, report_path)
    out.write(
        f"history-check complete  addresses={len(all_results)}  "
        f"http_batches={len(batches)}  report={report_path}\n"
    )
    return 0


def main(argv: Optional[Sequence[str]] = None, out: Optional[TextIO] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    stream = out if out is not None else sys.stdout
    handlers = {
        "init": cmd_init,
        "candidates": cmd_candidates,
        "run": cmd_run,
        "benchmark": cmd_benchmark,
        "status": cmd_status,
        "report": cmd_report,
        "history-check": cmd_history_check,
    }
    return handlers[args.command](args, stream)


def dispatch(argv: List[str]) -> int:
    return main(argv)
