from __future__ import annotations

from typing import List, Tuple

from genesis_puzzle.candidates import Recipe
from genesis_puzzle.parser import ParsedBlock

_FIELDS: Tuple[Tuple[str, str], ...] = (
    ("nonce", "genesis.header.nonce"),
    ("timestamp", "genesis.header.timestamp"),
)


def _rid(index: int) -> str:
    return f"D-{index:03d}"


def _signed(offset: int) -> str:
    return f"{offset:+d}"


def stage_d_recipes(block: ParsedBlock) -> List[Recipe]:
    values = {
        "nonce": block.header.nonce,
        "timestamp": block.header.timestamp,
    }
    recipes: List[Recipe] = []
    index = 0
    for distance in range(1, 11):
        for field, source in _FIELDS:
            public_value = values[field]
            for offset in (-distance, distance):
                index += 1
                signed = _signed(offset)
                recipes.append(
                    Recipe(
                        derivation_id=_rid(index),
                        source=source,
                        original_public_source=(f"{field}={public_value} signed_offset={signed}"),
                        representation=f"{field}_signed_offset={signed}",
                        public_input_bytes=b"",
                        transformation="identity_integer",
                        formula=f"k = uint({field}={public_value}) + ({signed})",
                        confidence=round(0.25 - 0.002 * (index - 1), 3),
                        stage="D",
                        recipe=(
                            f"Interpret the public Genesis header {field} "
                            f"{public_value} plus signed offset {signed} as a "
                            "secp256k1 scalar."
                        ),
                        direct_integer=public_value + offset,
                    )
                )
    return recipes
