from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import List, Optional, Sequence, TextIO

from genesis_puzzle.addresses import DerivedAddresses, derive_standard_addresses
from genesis_puzzle.candidates import (
    EvaluatedDerivation,
    Recipe,
    dedupe_valid_scalars,
    evaluate_recipe,
    stage_a_recipes,
)
from genesis_puzzle.config import ModeConfig
from genesis_puzzle.crypto import derive_pubkeys
from genesis_puzzle.model import KnownTarget
from genesis_puzzle.parser import ParsedBlock
from genesis_puzzle.storage import (
    Store,
    finish_run,
    insert_run,
    transaction,
    upsert_address,
    upsert_comparison,
    upsert_derivation,
    upsert_key,
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log(out: Optional[TextIO], message: str) -> None:
    if out is not None:
        out.write(message + "\n")


def _throttle(mode: ModeConfig, started: float, done: int) -> None:
    if mode.duty_cycle < 1.0:
        time.sleep(max(0.0, (1.0 - mode.duty_cycle) * 0.01))
    cap = mode.max_candidates_per_second
    if cap > 0 and done > 0:
        expected = done / cap
        elapsed = time.perf_counter() - started
        if expected > elapsed:
            time.sleep(expected - elapsed)


def compare_targets(
    addrs: DerivedAddresses,
    targets: Sequence[KnownTarget],
) -> List[tuple]:
    produced = [
        ("p2pkh_uncompressed", addrs.p2pkh_uncompressed),
        ("p2pkh_compressed", addrs.p2pkh_compressed),
        ("p2wpkh", addrs.p2wpkh),
    ]
    rows = []
    for target in targets:
        for address_type, address in produced:
            comparable = target.script_type in ("p2pkh", "p2wpkh") and target.script_type == (
                "p2wpkh" if address_type == "p2wpkh" else "p2pkh"
            )
            if target.script_type == "p2wsh":
                comparable = False
                note = (
                    "suspected target is P2WSH; standard P2PKH/P2WPKH cannot test the "
                    "unknown witness script"
                )
                matched = False
            else:
                matched = comparable and address == target.address
                note = "address equal" if matched else "no address match"
            rows.append((address, address_type, target.id, comparable, matched, note))
    return rows


def run_stage_a(
    store: Store,
    block: ParsedBlock,
    targets: Sequence[KnownTarget],
    mode: ModeConfig,
    out: Optional[TextIO] = None,
) -> dict:
    recipes: List[Recipe] = stage_a_recipes(block)
    started_mono = time.perf_counter()
    started_at = _now()
    evaluated_pairs = []
    with transaction(store) as conn:
        run_id = insert_run(conn, started_at, "A", mode.name, "running")

    _log(
        out, f"run start stage=A mode={mode.name} derivations={len(recipes)} checkpoint=not-needed"
    )
    _log(out, "private scalars are redacted; fingerprints and addresses are public")

    for index, recipe in enumerate(recipes, start=1):
        evaluated, scalar = evaluate_recipe(recipe)
        evaluated_pairs.append((evaluated, scalar))
        _log(
            out,
            f"{recipe.derivation_id}  source={recipe.source}  "
            f"representation={recipe.representation}  transform={recipe.transformation}  "
            f"valid={evaluated.valid}  fingerprint={evaluated.fingerprint or 'n/a'}  "
            f"public_input_hex={recipe.public_input_bytes.hex()}  private_scalar=REDACTED",
        )
        if not evaluated.valid:
            _log(out, f"    eliminated: {evaluated.eliminated_reason}")
        _throttle(mode, started_mono, index)

    unique = dedupe_valid_scalars(evaluated_pairs)
    duplicate_count = sum(max(0, len(group) - 1) for _, _, group in unique)

    derived = 0
    potential_match = False
    with transaction(store) as conn:
        for evaluated, _scalar in evaluated_pairs:
            recipe = evaluated.recipe
            upsert_derivation(
                conn,
                derivation_id=recipe.derivation_id,
                fingerprint=evaluated.fingerprint,
                source=recipe.source,
                original_public_source=recipe.original_public_source,
                representation=recipe.representation,
                public_input_hex=recipe.public_input_bytes.hex(),
                transformation=recipe.transformation,
                formula=recipe.formula,
                recipe=recipe.recipe,
                confidence=recipe.confidence,
                stage=recipe.stage,
                valid=evaluated.valid,
                eliminated_reason=evaluated.eliminated_reason,
                run_id=run_id,
            )
        for fingerprint, scalar, group in unique:
            upsert_key(conn, fingerprint, run_id)
            uncompressed, compressed = derive_pubkeys(scalar)
            addrs = derive_standard_addresses(uncompressed, compressed)
            derived += 1
            upsert_address(
                conn,
                fingerprint,
                addrs.p2pkh_uncompressed,
                "p2pkh_uncompressed",
                addrs.pubkey_uncompressed_hex,
                "uncompressed",
            )
            upsert_address(
                conn,
                fingerprint,
                addrs.p2pkh_compressed,
                "p2pkh_compressed",
                addrs.pubkey_compressed_hex,
                "compressed",
            )
            upsert_address(
                conn,
                fingerprint,
                addrs.p2wpkh,
                "p2wpkh",
                addrs.pubkey_compressed_hex,
                "compressed",
            )
            ids = ",".join(item.recipe.derivation_id for item in group)
            _log(
                out,
                f"key fp={fingerprint}  provenance={ids}  "
                f"uncompressed_pubkey={addrs.pubkey_uncompressed_hex}  "
                f"compressed_pubkey={addrs.pubkey_compressed_hex}  "
                f"uncompressed_p2pkh={addrs.p2pkh_uncompressed}  "
                f"compressed_p2pkh={addrs.p2pkh_compressed}  "
                f"p2wpkh={addrs.p2wpkh}  chain=not_checked  result=derived",
            )
            for address, address_type, target_id, comparable, matched, note in compare_targets(
                addrs, targets
            ):
                upsert_comparison(
                    conn,
                    fingerprint,
                    address,
                    address_type,
                    target_id,
                    comparable,
                    matched,
                    note,
                )
                if matched:
                    potential_match = True
                    _log(out, "POTENTIAL MATCH FOUND")
                    _log(
                        out,
                        f"    candidate_fingerprint={fingerprint} provenance={ids} "
                        f"target={target_id} address={address} address_type={address_type}",
                    )
            if potential_match:
                break
        invalid_count = sum(1 for evaluated, _ in evaluated_pairs if not evaluated.valid)
        elapsed = time.perf_counter() - started_mono
        finish_run(
            conn,
            run_id,
            _now(),
            "potential_match" if potential_match else "ok",
            derivation_count=len(recipes),
            invalid_count=invalid_count,
            unique_valid_keys=derived,
            duplicate_count=duplicate_count,
            address_count=derived * 3,
            elapsed_seconds=elapsed,
        )

    return {
        "run_id": run_id,
        "derivations": len(recipes),
        "invalid": sum(1 for evaluated, _ in evaluated_pairs if not evaluated.valid),
        "unique_valid_keys": derived,
        "duplicates": duplicate_count,
        "addresses": derived * 3,
        "potential_match": potential_match,
        "elapsed_seconds": time.perf_counter() - started_mono,
    }


def evaluated_without_curve(recipes: Sequence[Recipe]) -> List[EvaluatedDerivation]:
    out = []
    for recipe in recipes:
        evaluated, _scalar = evaluate_recipe(recipe)
        out.append(evaluated)
        _scalar = None
    return out
