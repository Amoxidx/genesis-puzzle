from __future__ import annotations

from typing import List, NamedTuple, Tuple

from genesis_puzzle.candidates import Recipe
from genesis_puzzle.parser import ParsedBlock


class StageCSeparator(NamedTuple):
    name: str
    token: str
    value: bytes


STAGE_C_SEPARATORS: Tuple[StageCSeparator, ...] = (
    StageCSeparator("empty string", '""', b""),
    StageCSeparator("colon", '":"', b":"),
    StageCSeparator("pipe", '"|"', b"|"),
    StageCSeparator("hyphen", '"-"', b"-"),
    StageCSeparator("underscore", '"_"', b"_"),
    StageCSeparator("ASCII space", '" "', b" "),
    StageCSeparator("ASCII newline", r'"\n"', b"\n"),
)


def _rid(index: int) -> str:
    return f"C-{index:03d}"


def _slug(separator: StageCSeparator) -> str:
    return separator.name.replace("ASCII ", "").replace(" string", "")


def _formula(data: bytes) -> str:
    text = data.decode("ascii")
    escaped = text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'k = SHA256(b"{escaped}")'


def stage_c_recipes(block: ParsedBlock) -> List[Recipe]:
    nonce_text = str(block.header.nonce)
    timestamp_text = str(block.header.timestamp)
    nonce_ascii = nonce_text.encode("ascii")
    timestamp_ascii = timestamp_text.encode("ascii")
    recipes: List[Recipe] = []
    index = 0
    for separator in STAGE_C_SEPARATORS:
        slug = _slug(separator)
        for reversed_order in (False, True):
            index += 1
            if reversed_order:
                left_label = "timestamp"
                right_label = "nonce"
                left_ascii = timestamp_ascii
                right_ascii = nonce_ascii
                left_text = timestamp_text
                right_text = nonce_text
                representation = f"ascii_decimal_timestamp_nonce_{slug}"
            else:
                left_label = "nonce"
                right_label = "timestamp"
                left_ascii = nonce_ascii
                right_ascii = timestamp_ascii
                left_text = nonce_text
                right_text = timestamp_text
                representation = f"ascii_decimal_nonce_timestamp_{slug}"
            payload = left_ascii + separator.value + right_ascii
            recipes.append(
                Recipe(
                    derivation_id=_rid(index),
                    source="genesis.header.nonce_and_timestamp",
                    original_public_source=(
                        f"{left_label}={left_text} separator={separator.token} "
                        f"{right_label}={right_text}"
                    ),
                    representation=representation,
                    public_input_bytes=payload,
                    transformation="sha256",
                    formula=_formula(payload),
                    confidence=round(0.18 - 0.005 * (index - 1), 3),
                    stage="C",
                    recipe=(
                        f"SHA256 of the ASCII decimal {left_label} followed by "
                        f"{separator.name} {separator.token} followed by the ASCII "
                        f"decimal {right_label}."
                    ),
                )
            )
    return recipes
