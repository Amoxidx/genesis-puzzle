from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple

from genesis_puzzle.crypto import scalar_is_valid
from genesis_puzzle.hashing import fingerprint_scalar, sha256
from genesis_puzzle.parser import ParsedBlock


@dataclass(frozen=True)
class Recipe:
    derivation_id: str
    source: str
    original_public_source: str
    representation: str
    public_input_bytes: bytes
    transformation: str
    formula: str
    confidence: float
    stage: str
    recipe: str
    direct_integer: Optional[int] = None
    skip_curve: bool = False


@dataclass
class EvaluatedDerivation:
    recipe: Recipe
    valid: bool
    eliminated_reason: str
    fingerprint: Optional[str]

    def __repr__(self) -> str:
        return (
            f"EvaluatedDerivation(id={self.recipe.derivation_id!r}, "
            f"valid={self.valid}, fingerprint={self.fingerprint!r})"
        )


def _rid(index: int) -> str:
    return f"A-{index:02d}"


def stage_a_recipes(block: ParsedBlock) -> List[Recipe]:
    header = block.header
    headline = block.coinbase.headline.encode("utf-8")
    pubkey = block.coinbase.pubkey
    nonce_ascii = str(header.nonce).encode("ascii")
    timestamp_ascii = str(header.timestamp).encode("ascii")
    bits_hex = header.bits_hex.encode("ascii")
    version_ascii = str(header.version).encode("ascii")
    reward_ascii = str(block.coinbase.outputs[0].value_sats).encode("ascii")
    height_ascii = b"0"
    block_hash_wire = block.block_hash_wire
    block_hash_display = block_hash_wire[::-1]
    merkle_wire = header.merkle_root_wire
    merkle_display = merkle_wire[::-1]

    recipes: List[Recipe] = [
        Recipe(
            derivation_id=_rid(1),
            source="genesis.header.nonce",
            original_public_source=str(header.nonce),
            representation="decimal_integer",
            public_input_bytes=nonce_ascii,
            transformation="identity_integer",
            formula="k = uint(nonce)",
            confidence=0.55,
            stage="A",
            recipe="Interpret the public Genesis header nonce as a secp256k1 scalar.",
            direct_integer=header.nonce,
        ),
        Recipe(
            derivation_id=_rid(2),
            source="genesis.header.timestamp",
            original_public_source=str(header.timestamp),
            representation="decimal_integer",
            public_input_bytes=timestamp_ascii,
            transformation="identity_integer",
            formula="k = uint(timestamp)",
            confidence=0.50,
            stage="A",
            recipe="Interpret the public Genesis header timestamp as a secp256k1 scalar.",
            direct_integer=header.timestamp,
        ),
        Recipe(
            derivation_id=_rid(3),
            source="genesis.header.bits",
            original_public_source=header.bits_hex,
            representation="compact_bits_hex",
            public_input_bytes=bits_hex,
            transformation="identity_integer",
            formula="k = uint(0x1d00ffff)",
            confidence=0.45,
            stage="A",
            recipe="Interpret nBits 0x1d00ffff as a secp256k1 scalar.",
            direct_integer=header.bits,
        ),
        Recipe(
            derivation_id=_rid(4),
            source="genesis.header.nonce",
            original_public_source=str(header.nonce),
            representation="ascii_decimal",
            public_input_bytes=nonce_ascii,
            transformation="sha256",
            formula='k = SHA256(b"2083236893")',
            confidence=0.40,
            stage="A",
            recipe="SHA256 of the ASCII decimal nonce.",
        ),
        Recipe(
            derivation_id=_rid(5),
            source="genesis.header.timestamp",
            original_public_source=str(header.timestamp),
            representation="ascii_decimal",
            public_input_bytes=timestamp_ascii,
            transformation="sha256",
            formula='k = SHA256(b"1231006505")',
            confidence=0.40,
            stage="A",
            recipe="SHA256 of the ASCII decimal timestamp.",
        ),
        Recipe(
            derivation_id=_rid(6),
            source="genesis.header.bits",
            original_public_source=header.bits_hex,
            representation="ascii_hex",
            public_input_bytes=bits_hex,
            transformation="sha256",
            formula='k = SHA256(b"1d00ffff")',
            confidence=0.40,
            stage="A",
            recipe="SHA256 of the canonical lowercase nBits hex without 0x.",
        ),
        Recipe(
            derivation_id=_rid(7),
            source="genesis.coinbase.headline",
            original_public_source=block.coinbase.headline,
            representation="utf8",
            public_input_bytes=headline,
            transformation="sha256",
            formula="k = SHA256(headline_utf8)",
            confidence=0.50,
            stage="A",
            recipe="SHA256 of the exact coinbase headline UTF-8 bytes.",
        ),
        Recipe(
            derivation_id=_rid(8),
            source="genesis.header.raw",
            original_public_source="80-byte Genesis header",
            representation="raw_header",
            public_input_bytes=header.raw,
            transformation="sha256",
            formula="k = SHA256(header_80)",
            confidence=0.35,
            stage="A",
            recipe="SHA256 of the raw 80-byte Genesis header (single SHA256, not SHA256d).",
        ),
        Recipe(
            derivation_id=_rid(9),
            source="genesis.block_hash.wire",
            original_public_source="block hash wire/internal bytes",
            representation="hash_wire",
            public_input_bytes=block_hash_wire,
            transformation="sha256",
            formula="k = SHA256(block_hash_wire)",
            confidence=0.30,
            stage="A",
            recipe="SHA256 of the block-hash raw/wire bytes.",
        ),
        Recipe(
            derivation_id=_rid(10),
            source="genesis.merkle_root.wire",
            original_public_source="Merkle root wire/internal bytes",
            representation="hash_wire",
            public_input_bytes=merkle_wire,
            transformation="sha256",
            formula="k = SHA256(merkle_root_wire)",
            confidence=0.30,
            stage="A",
            recipe="SHA256 of the Merkle-root raw/wire bytes.",
        ),
        Recipe(
            derivation_id=_rid(11),
            source="genesis.coinbase.pubkey",
            original_public_source="uncompressed Genesis P2PK public key",
            representation="raw_pubkey",
            public_input_bytes=pubkey,
            transformation="sha256",
            formula="k = SHA256(genesis_pubkey)",
            confidence=0.30,
            stage="A",
            recipe="SHA256 of the raw 65-byte Genesis public key.",
        ),
        Recipe(
            derivation_id=_rid(12),
            source="genesis.header.version",
            original_public_source=str(header.version),
            representation="decimal_integer",
            public_input_bytes=version_ascii,
            transformation="identity_integer",
            formula="k = uint(version)",
            confidence=0.25,
            stage="A",
            recipe="Interpret the public Genesis block version as a secp256k1 scalar.",
            direct_integer=header.version,
        ),
        Recipe(
            derivation_id=_rid(13),
            source="genesis.tx.reward_sats",
            original_public_source=str(block.coinbase.outputs[0].value_sats),
            representation="decimal_integer",
            public_input_bytes=reward_ascii,
            transformation="identity_integer",
            formula="k = uint(reward_sats)",
            confidence=0.25,
            stage="A",
            recipe="Interpret the 50 BTC coinbase value in sats as a secp256k1 scalar.",
            direct_integer=block.coinbase.outputs[0].value_sats,
        ),
        Recipe(
            derivation_id=_rid(14),
            source="genesis.height",
            original_public_source="0",
            representation="decimal_integer",
            public_input_bytes=height_ascii,
            transformation="identity_integer",
            formula="k = uint(height)",
            confidence=0.05,
            stage="A",
            recipe=(
                "Record height 0 as an invalid/eliminated direct scalar. "
                "It is never passed to coincurve."
            ),
            direct_integer=0,
            skip_curve=True,
        ),
        Recipe(
            derivation_id=_rid(15),
            source="genesis.block_hash.wire",
            original_public_source="block hash wire/internal bytes",
            representation="hash_wire",
            public_input_bytes=block_hash_wire,
            transformation="identity_bytes_be",
            formula="k = int.from_bytes(block_hash_wire, 'big')",
            confidence=0.20,
            stage="A",
            recipe=(
                "Direct scalar interpretation of the 32-byte block hash in wire/internal order."
            ),
        ),
        Recipe(
            derivation_id=_rid(16),
            source="genesis.block_hash.display",
            original_public_source="block hash display-order bytes",
            representation="hash_display",
            public_input_bytes=block_hash_display,
            transformation="identity_bytes_be",
            formula="k = int.from_bytes(block_hash_display, 'big')",
            confidence=0.20,
            stage="A",
            recipe="Direct scalar interpretation of the 32-byte block hash in display order.",
        ),
        Recipe(
            derivation_id=_rid(17),
            source="genesis.merkle_root.wire",
            original_public_source="Merkle root wire/internal bytes",
            representation="hash_wire",
            public_input_bytes=merkle_wire,
            transformation="identity_bytes_be",
            formula="k = int.from_bytes(merkle_root_wire, 'big')",
            confidence=0.20,
            stage="A",
            recipe=(
                "Direct scalar interpretation of the 32-byte Merkle root in wire/internal order."
            ),
        ),
        Recipe(
            derivation_id=_rid(18),
            source="genesis.merkle_root.display",
            original_public_source="Merkle root display-order bytes",
            representation="hash_display",
            public_input_bytes=merkle_display,
            transformation="identity_bytes_be",
            formula="k = int.from_bytes(merkle_root_display, 'big')",
            confidence=0.20,
            stage="A",
            recipe="Direct scalar interpretation of the 32-byte Merkle root in display order.",
        ),
        Recipe(
            derivation_id=_rid(19),
            source="genesis.header.version",
            original_public_source=str(header.version),
            representation="ascii_decimal",
            public_input_bytes=version_ascii,
            transformation="sha256",
            formula='k = SHA256(b"1")',
            confidence=0.25,
            stage="A",
            recipe="SHA256 of the canonical ASCII decimal version.",
        ),
        Recipe(
            derivation_id=_rid(20),
            source="genesis.tx.reward_sats",
            original_public_source=str(block.coinbase.outputs[0].value_sats),
            representation="ascii_decimal",
            public_input_bytes=reward_ascii,
            transformation="sha256",
            formula='k = SHA256(b"5000000000")',
            confidence=0.25,
            stage="A",
            recipe="SHA256 of the canonical ASCII decimal reward in sats.",
        ),
        Recipe(
            derivation_id=_rid(21),
            source="genesis.height",
            original_public_source="0",
            representation="ascii_decimal",
            public_input_bytes=height_ascii,
            transformation="sha256",
            formula='k = SHA256(b"0")',
            confidence=0.20,
            stage="A",
            recipe="SHA256 of the canonical ASCII decimal height.",
        ),
        Recipe(
            derivation_id=_rid(22),
            source="genesis.block_hash.display",
            original_public_source="block hash display-order bytes",
            representation="hash_display",
            public_input_bytes=block_hash_display,
            transformation="sha256",
            formula="k = SHA256(block_hash_display)",
            confidence=0.19,
            stage="A",
            recipe="SHA256 of the block-hash display-order bytes.",
        ),
        Recipe(
            derivation_id=_rid(23),
            source="genesis.merkle_root.display",
            original_public_source="Merkle root display-order bytes",
            representation="hash_display",
            public_input_bytes=merkle_display,
            transformation="sha256",
            formula="k = SHA256(merkle_root_display)",
            confidence=0.19,
            stage="A",
            recipe="SHA256 of the Merkle-root display-order bytes.",
        ),
    ]
    return recipes


def compute_scalar(recipe: Recipe) -> int:
    if recipe.transformation == "identity_integer":
        if recipe.direct_integer is None:
            raise ValueError("direct integer recipe missing value")
        return recipe.direct_integer
    if recipe.transformation == "identity_bytes_be":
        return int.from_bytes(recipe.public_input_bytes, "big")
    if recipe.transformation == "sha256":
        return int.from_bytes(sha256(recipe.public_input_bytes), "big")
    raise ValueError(f"unknown transformation {recipe.transformation}")


def evaluate_recipe(recipe: Recipe) -> Tuple[EvaluatedDerivation, Optional[int]]:
    scalar = compute_scalar(recipe)
    if recipe.skip_curve or not scalar_is_valid(scalar):
        reason = "scalar_out_of_range"
        if recipe.skip_curve:
            reason = "height_zero_invalid_direct_scalar"
        evaluated = EvaluatedDerivation(
            recipe=recipe,
            valid=False,
            eliminated_reason=reason,
            fingerprint=None,
        )
        return evaluated, None
    evaluated = EvaluatedDerivation(
        recipe=recipe,
        valid=True,
        eliminated_reason="",
        fingerprint=fingerprint_scalar(scalar),
    )
    return evaluated, scalar


def dedupe_valid_scalars(
    pairs: Sequence[Tuple[EvaluatedDerivation, Optional[int]]],
) -> List[Tuple[str, int, List[EvaluatedDerivation]]]:
    grouped: dict[str, tuple[int, list[EvaluatedDerivation]]] = {}
    order: List[str] = []
    for evaluated, scalar in pairs:
        if not evaluated.valid or scalar is None or evaluated.fingerprint is None:
            continue
        fp = evaluated.fingerprint
        if fp not in grouped:
            grouped[fp] = (scalar, [])
            order.append(fp)
        grouped[fp][1].append(evaluated)
    return [(fp, grouped[fp][0], grouped[fp][1]) for fp in order]


def preview_lines(recipes: Iterable[Recipe]) -> List[str]:
    lines = []
    for recipe in recipes:
        lines.append(
            f"{recipe.derivation_id}  stage={recipe.stage}  source={recipe.source}  "
            f"representation={recipe.representation}  transform={recipe.transformation}  "
            f"confidence={recipe.confidence:.2f}"
        )
        lines.append(f"    recipe: {recipe.recipe}")
        lines.append(f"    formula: {recipe.formula}")
        lines.append(f"    public_source: {recipe.original_public_source}")
        lines.append(f"    public_input_hex: {recipe.public_input_bytes.hex()}")
        lines.append("    private_scalar: REDACTED (not derived in preview)")
    return lines


def recipes_for_stage(block: ParsedBlock, stage: str) -> List[Recipe]:
    if stage == "A":
        return stage_a_recipes(block)
    if stage == "B":
        from genesis_puzzle.stage_b import stage_b_recipes

        return stage_b_recipes(block)
    if stage == "C":
        from genesis_puzzle.stage_c import stage_c_recipes

        return stage_c_recipes(block)
    raise ValueError(f"unsupported stage {stage!r}")


def preview_for_stage(block: ParsedBlock, stage: str) -> List[str]:
    return preview_lines(recipes_for_stage(block, stage))
