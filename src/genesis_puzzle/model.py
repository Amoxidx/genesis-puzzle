from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from genesis_puzzle.paths import data_dir


@dataclass(frozen=True)
class KnownTarget:
    id: str
    label: str
    status: str
    txid: str
    block_height: int
    block_time: int
    value_sats: int
    address: str
    script_type: str
    script_pubkey_hex: str
    witness_program_hex: str
    comparable_with_stage_a: bool
    notes: str


@dataclass(frozen=True)
class GenesisFacts:
    raw_block_hex: str
    raw_block_length_bytes: int
    version: int
    timestamp: int
    bits: int
    bits_hex: str
    target_hex: str
    nonce: int
    previous_hash_wire_hex: str
    previous_hash_display_hex: str
    merkle_root_wire_hex: str
    merkle_root_display_hex: str
    block_hash_wire_hex: str
    block_hash_display_hex: str
    txid_wire_hex: str
    txid_display_hex: str
    tx_version: int
    raw_transaction_hex: str
    input_count: int
    output_count: int
    locktime: int
    reward_sats: int
    headline: str
    pubkey_uncompressed_hex: str
    script_pubkey_hex: str
    height: int
    coinbase_prevout_index: int
    script_sig_hex: str
    sequence: int


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_genesis_facts(base: Optional[Path] = None) -> GenesisFacts:
    payload = _load_json(data_dir(base) / "genesis.json")
    header = payload["header"]
    tx = payload["transaction"]
    return GenesisFacts(
        raw_block_hex=payload["raw_block_hex"],
        raw_block_length_bytes=int(payload["raw_block_length_bytes"]),
        version=int(header["version"]),
        timestamp=int(header["timestamp"]),
        bits=int(header["bits"]),
        bits_hex=str(header["bits_hex"]),
        target_hex=str(header["target_hex"]),
        nonce=int(header["nonce"]),
        previous_hash_wire_hex=str(header["previous_hash_wire_hex"]),
        previous_hash_display_hex=str(header["previous_hash_display_hex"]),
        merkle_root_wire_hex=str(header["merkle_root_wire_hex"]),
        merkle_root_display_hex=str(header["merkle_root_display_hex"]),
        block_hash_wire_hex=str(payload["block_hash_wire_hex"]),
        block_hash_display_hex=str(payload["block_hash_display_hex"]),
        txid_wire_hex=str(payload["txid_wire_hex"]),
        txid_display_hex=str(payload["txid_display_hex"]),
        tx_version=int(tx["version"]),
        raw_transaction_hex=str(tx["raw_transaction_hex"]),
        input_count=int(tx["input_count"]),
        output_count=int(tx["output_count"]),
        locktime=int(tx["locktime"]),
        reward_sats=int(tx["reward_sats"]),
        headline=str(tx["headline"]),
        pubkey_uncompressed_hex=str(tx["pubkey_uncompressed_hex"]),
        script_pubkey_hex=str(tx["script_pubkey_hex"]),
        height=int(payload["height"]),
        coinbase_prevout_index=int(tx["coinbase_prevout_index"]),
        script_sig_hex=str(tx["script_sig_hex"]),
        sequence=int(tx["sequence"]),
    )


def load_known_targets(base: Optional[Path] = None) -> List[KnownTarget]:
    payload = _load_json(data_dir(base) / "known_targets.json")
    out: List[KnownTarget] = []
    for item in payload["targets"]:
        out.append(
            KnownTarget(
                id=str(item["id"]),
                label=str(item["label"]),
                status=str(item["status"]),
                txid=str(item["txid"]),
                block_height=int(item["block_height"]),
                block_time=int(item["block_time"]),
                value_sats=int(item["value_sats"]),
                address=str(item["address"]),
                script_type=str(item["script_type"]),
                script_pubkey_hex=str(item["script_pubkey_hex"]),
                witness_program_hex=str(item["witness_program_hex"]),
                comparable_with_stage_a=bool(item["comparable_with_stage_a"]),
                notes=str(item["notes"]),
            )
        )
    return out


def facts_as_public_dict(facts: GenesisFacts) -> Dict[str, Any]:
    return {
        "version": facts.version,
        "timestamp": facts.timestamp,
        "bits": facts.bits,
        "bits_hex": facts.bits_hex,
        "target_hex": facts.target_hex,
        "nonce": facts.nonce,
        "block_hash_display_hex": facts.block_hash_display_hex,
        "block_hash_wire_hex": facts.block_hash_wire_hex,
        "merkle_root_display_hex": facts.merkle_root_display_hex,
        "merkle_root_wire_hex": facts.merkle_root_wire_hex,
        "txid_display_hex": facts.txid_display_hex,
        "reward_sats": facts.reward_sats,
        "headline": facts.headline,
        "pubkey_uncompressed_hex": facts.pubkey_uncompressed_hex,
        "height": facts.height,
    }


def targets_as_public_dicts(targets: List[KnownTarget]) -> List[Mapping[str, Any]]:
    return [
        {
            "id": t.id,
            "label": t.label,
            "status": t.status,
            "txid": t.txid,
            "block_height": t.block_height,
            "block_time": t.block_time,
            "value_sats": t.value_sats,
            "address": t.address,
            "script_type": t.script_type,
            "comparable_with_stage_a": t.comparable_with_stage_a,
            "notes": t.notes,
        }
        for t in targets
    ]
