from __future__ import annotations

from typing import List, Tuple

from genesis_puzzle.candidates import Recipe
from genesis_puzzle.parser import ParsedBlock

STAGE_E_DATE_STRINGS: Tuple[str, ...] = (
    "2009-01-03T18:15:05Z",
    "2009-01-03 18:15:05 UTC",
    "2009-01-03",
    "03/Jan/2009",
    "03/01/2009",
    "01/03/2009",
    "03Jan2009",
    "20090103",
)
STAGE_E_DATE_NOTES: Tuple[str, ...] = (
    "",
    "",
    "",
    "",
    " (European/day-first ambiguous)",
    " (American/month-first ambiguous)",
    "",
    "",
)


def _rid(index: int) -> str:
    return f"E-{index:03d}"


def _formula(data: bytes) -> str:
    text = data.decode("utf-8")
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'k = SHA256(b"{escaped}")'


def stage_e_recipes(_block: ParsedBlock) -> List[Recipe]:
    if len(STAGE_E_DATE_STRINGS) != 8 or len(STAGE_E_DATE_NOTES) != 8:
        raise ValueError("Stage E requires exactly eight date/time strings")
    recipes: List[Recipe] = []
    for index, (date, note) in enumerate(zip(STAGE_E_DATE_STRINGS, STAGE_E_DATE_NOTES), start=1):
        payload = date.encode("utf-8")
        recipes.append(
            Recipe(
                derivation_id=_rid(index),
                source="genesis.header.timestamp.utf8_date",
                original_public_source=f"{date}{note}" if note else date,
                representation="utf8",
                public_input_bytes=payload,
                transformation="sha256",
                formula=_formula(payload),
                confidence=round(0.16 - 0.002 * (index - 1), 3),
                stage="E",
                recipe=f"SHA256 of the exact UTF-8 date/time string {date}{note}.",
            )
        )
    return recipes
