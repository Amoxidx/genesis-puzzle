from __future__ import annotations

from dataclasses import dataclass, replace
from typing import List, Literal, Set, Tuple

from genesis_puzzle.candidates import Recipe
from genesis_puzzle.parser import ParsedBlock, compact_target

_SEEN = Set[Tuple[bytes, str]]


@dataclass(frozen=True)
class _IntegerField:
    source: str
    original_public_source: str
    value: int
    width: int
    confidence: float
    label: str


@dataclass(frozen=True)
class _HashField:
    source: str
    original_public_source: str
    wire: bytes
    display: bytes
    confidence: float
    label: str


@dataclass(frozen=True)
class _RawField:
    source: str
    original_public_source: str
    raw: bytes
    confidence: float
    label: str
    raw_representation: str


def _minimal_unsigned(value: int, endian: Literal["little", "big"]) -> bytes:
    if value == 0:
        return b"\x00"
    length = (value.bit_length() + 7) // 8
    return value.to_bytes(length, endian)


def _sha256_formula(data: bytes, name: str) -> str:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return f"k = SHA256({name})"
    if any(ch != "\n" and not ch.isprintable() for ch in text) or len(text) > 40:
        return f"k = SHA256({name})"
    escaped = text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'k = SHA256(b"{escaped}")'


def _append(
    recipes: List[Recipe],
    seen: _SEEN,
    *,
    source: str,
    original_public_source: str,
    representation: str,
    public_input_bytes: bytes,
    transformation: str,
    formula: str,
    confidence: float,
    recipe: str,
) -> None:
    key = (public_input_bytes, transformation)
    if key in seen:
        return
    seen.add(key)
    recipes.append(
        Recipe(
            derivation_id="",
            source=source,
            original_public_source=original_public_source,
            representation=representation,
            public_input_bytes=public_input_bytes,
            transformation=transformation,
            formula=formula,
            confidence=confidence,
            stage="B",
            recipe=recipe,
        )
    )


def _add_integer_field(recipes: List[Recipe], field: _IntegerField) -> None:
    seen: _SEEN = set()
    value = field.value
    width = field.width
    bits = width * 8
    source = field.source
    original = field.original_public_source
    conf = field.confidence
    label = field.label

    decimal_newline = f"{value}\n".encode("ascii")
    _append(
        recipes,
        seen,
        source=source,
        original_public_source=original,
        representation="ascii_decimal_newline",
        public_input_bytes=decimal_newline,
        transformation="sha256",
        formula=_sha256_formula(decimal_newline, f"{label}_ascii_decimal_newline"),
        confidence=conf,
        recipe=f"SHA256 of the ASCII decimal {label} followed by a newline.",
    )

    hex_lower = format(value, "x").encode("ascii")
    _append(
        recipes,
        seen,
        source=source,
        original_public_source=original,
        representation="ascii_hex_lower",
        public_input_bytes=hex_lower,
        transformation="sha256",
        formula=_sha256_formula(hex_lower, f"{label}_hex_lower"),
        confidence=conf,
        recipe=f"SHA256 of the lowercase hex {label} without prefix.",
    )
    hex_upper = format(value, "X").encode("ascii")
    _append(
        recipes,
        seen,
        source=source,
        original_public_source=original,
        representation="ascii_hex_upper",
        public_input_bytes=hex_upper,
        transformation="sha256",
        formula=_sha256_formula(hex_upper, f"{label}_hex_upper"),
        confidence=conf,
        recipe=f"SHA256 of the uppercase hex {label} without prefix.",
    )
    prefixed_lower = f"0x{value:x}".encode("ascii")
    _append(
        recipes,
        seen,
        source=source,
        original_public_source=original,
        representation="ascii_hex_0x_lower",
        public_input_bytes=prefixed_lower,
        transformation="sha256",
        formula=_sha256_formula(prefixed_lower, f"{label}_hex_0x_lower"),
        confidence=conf,
        recipe=f"SHA256 of the 0x-prefixed lowercase hex {label}.",
    )
    prefixed_upper = f"0X{value:X}".encode("ascii")
    _append(
        recipes,
        seen,
        source=source,
        original_public_source=original,
        representation="ascii_hex_0X_upper",
        public_input_bytes=prefixed_upper,
        transformation="sha256",
        formula=_sha256_formula(prefixed_upper, f"{label}_hex_0X_upper"),
        confidence=conf,
        recipe=f"SHA256 of the 0X-prefixed uppercase hex {label}.",
    )

    fixed_le = value.to_bytes(width, "little")
    fixed_be = value.to_bytes(width, "big")
    le_name = f"{label}_uint{bits}_le"
    be_name = f"{label}_uint{bits}_be"
    _append(
        recipes,
        seen,
        source=source,
        original_public_source=original,
        representation="uint_le_fixed",
        public_input_bytes=fixed_le,
        transformation="sha256",
        formula=_sha256_formula(fixed_le, le_name),
        confidence=conf,
        recipe=f"SHA256 of the {width}-byte little-endian {label}.",
    )
    _append(
        recipes,
        seen,
        source=source,
        original_public_source=original,
        representation="uint_le_fixed",
        public_input_bytes=fixed_le,
        transformation="identity_bytes_be",
        formula=f"k = int.from_bytes({le_name}, 'big')",
        confidence=conf,
        recipe=f"Direct big-endian integer of the {width}-byte little-endian {label}.",
    )
    _append(
        recipes,
        seen,
        source=source,
        original_public_source=original,
        representation="uint_be_fixed",
        public_input_bytes=fixed_be,
        transformation="sha256",
        formula=_sha256_formula(fixed_be, be_name),
        confidence=conf,
        recipe=f"SHA256 of the {width}-byte big-endian {label}.",
    )
    _append(
        recipes,
        seen,
        source=source,
        original_public_source=original,
        representation="uint_be_fixed",
        public_input_bytes=fixed_be,
        transformation="identity_bytes_be",
        formula=f"k = int.from_bytes({be_name}, 'big')",
        confidence=conf,
        recipe=f"Direct big-endian integer of the {width}-byte big-endian {label}.",
    )

    min_be = _minimal_unsigned(value, "big")
    min_le = _minimal_unsigned(value, "little")
    _append(
        recipes,
        seen,
        source=source,
        original_public_source=original,
        representation="uint_be_minimal",
        public_input_bytes=min_be,
        transformation="sha256",
        formula=_sha256_formula(min_be, f"{label}_uint_minimal_be"),
        confidence=conf,
        recipe=f"SHA256 of the minimal unsigned big-endian {label}.",
    )
    _append(
        recipes,
        seen,
        source=source,
        original_public_source=original,
        representation="uint_le_minimal",
        public_input_bytes=min_le,
        transformation="sha256",
        formula=_sha256_formula(min_le, f"{label}_uint_minimal_le"),
        confidence=conf,
        recipe=f"SHA256 of the minimal unsigned little-endian {label}.",
    )


def _add_hash_field(recipes: List[Recipe], field: _HashField) -> None:
    seen: _SEEN = set()
    source = field.source
    original = field.original_public_source
    conf = field.confidence
    label = field.label
    wire_hex = field.wire.hex()
    display_hex = field.display.hex()
    forms = (
        (
            field.wire,
            "hash_wire",
            f"{label}_wire",
            f"SHA256 of the {label} raw/wire bytes.",
        ),
        (
            field.display,
            "hash_display",
            f"{label}_display",
            f"SHA256 of the {label} display-order bytes.",
        ),
        (
            wire_hex.encode("ascii"),
            "hash_wire_ascii_hex_lower",
            f"{label}_wire_hex_lower",
            f"SHA256 of the lowercase ASCII hex {label} in wire order.",
        ),
        (
            wire_hex.upper().encode("ascii"),
            "hash_wire_ascii_hex_upper",
            f"{label}_wire_hex_upper",
            f"SHA256 of the uppercase ASCII hex {label} in wire order.",
        ),
        (
            display_hex.encode("ascii"),
            "hash_display_ascii_hex_lower",
            f"{label}_display_hex_lower",
            f"SHA256 of the lowercase ASCII hex {label} in display order.",
        ),
        (
            display_hex.upper().encode("ascii"),
            "hash_display_ascii_hex_upper",
            f"{label}_display_hex_upper",
            f"SHA256 of the uppercase ASCII hex {label} in display order.",
        ),
        (
            (display_hex + "\n").encode("ascii"),
            "hash_display_ascii_hex_lower_newline",
            f"{label}_display_hex_lower_newline",
            f"SHA256 of the lowercase display ASCII hex {label} followed by a newline.",
        ),
    )
    for data, representation, name, recipe in forms:
        _append(
            recipes,
            seen,
            source=source,
            original_public_source=original,
            representation=representation,
            public_input_bytes=data,
            transformation="sha256",
            formula=_sha256_formula(data, name),
            confidence=conf,
            recipe=recipe,
        )


def _add_raw_hex_sha256(recipes: List[Recipe], field: _RawField) -> None:
    seen: _SEEN = set()
    hex_lower = field.raw.hex().encode("ascii")
    hex_upper = field.raw.hex().upper().encode("ascii")
    forms = (
        (
            field.raw,
            field.raw_representation,
            field.label,
            f"SHA256 of the {field.label}.",
        ),
        (
            hex_lower,
            "ascii_hex_lower",
            f"{field.label}_hex_lower",
            f"SHA256 of the lowercase ASCII hex {field.label}.",
        ),
        (
            hex_upper,
            "ascii_hex_upper",
            f"{field.label}_hex_upper",
            f"SHA256 of the uppercase ASCII hex {field.label}.",
        ),
    )
    for data, representation, name, recipe in forms:
        _append(
            recipes,
            seen,
            source=field.source,
            original_public_source=field.original_public_source,
            representation=representation,
            public_input_bytes=data,
            transformation="sha256",
            formula=_sha256_formula(data, name),
            confidence=field.confidence,
            recipe=recipe,
        )


def _finalize(recipes: List[Recipe]) -> List[Recipe]:
    ordered = sorted(enumerate(recipes), key=lambda item: (-item[1].confidence, item[0]))
    finalized: List[Recipe] = []
    for index, (_, recipe) in enumerate(ordered, start=1):
        finalized.append(replace(recipe, derivation_id=f"B-{index:03d}"))
    return finalized


def stage_b_recipes(block: ParsedBlock) -> List[Recipe]:
    header = block.header
    coinbase = block.coinbase
    reward_sats = coinbase.outputs[0].value_sats
    target_bytes = compact_target(header.bits).to_bytes(32, "big")
    recipes: List[Recipe] = []

    for integer_field in (
        _IntegerField(
            source="genesis.header.nonce",
            original_public_source=str(header.nonce),
            value=header.nonce,
            width=4,
            confidence=0.34,
            label="nonce",
        ),
        _IntegerField(
            source="genesis.header.timestamp",
            original_public_source=str(header.timestamp),
            value=header.timestamp,
            width=4,
            confidence=0.33,
            label="timestamp",
        ),
        _IntegerField(
            source="genesis.header.bits",
            original_public_source=header.bits_hex,
            value=header.bits,
            width=4,
            confidence=0.32,
            label="bits",
        ),
        _IntegerField(
            source="genesis.header.version",
            original_public_source=str(header.version),
            value=header.version,
            width=4,
            confidence=0.31,
            label="version",
        ),
        _IntegerField(
            source="genesis.tx.reward_sats",
            original_public_source=str(reward_sats),
            value=reward_sats,
            width=8,
            confidence=0.30,
            label="reward_sats",
        ),
        _IntegerField(
            source="genesis.height",
            original_public_source="0",
            value=0,
            width=4,
            confidence=0.22,
            label="height",
        ),
    ):
        _add_integer_field(recipes, integer_field)

    block_hash_wire = block.block_hash_wire
    merkle_wire = header.merkle_root_wire
    txid_wire = block.txid_wire
    for hash_field in (
        _HashField(
            source="genesis.block_hash",
            original_public_source=block.block_hash_display_hex,
            wire=block_hash_wire,
            display=block_hash_wire[::-1],
            confidence=0.21,
            label="block hash",
        ),
        _HashField(
            source="genesis.merkle_root",
            original_public_source=header.merkle_root_display_hex,
            wire=merkle_wire,
            display=merkle_wire[::-1],
            confidence=0.20,
            label="Merkle root",
        ),
        _HashField(
            source="genesis.txid",
            original_public_source=block.txid_display_hex,
            wire=txid_wire,
            display=txid_wire[::-1],
            confidence=0.19,
            label="coinbase txid",
        ),
    ):
        _add_hash_field(recipes, hash_field)

    _add_raw_hex_sha256(
        recipes,
        _RawField(
            source="genesis.header.previous_hash",
            original_public_source=header.prev_hash_display_hex,
            raw=header.prev_hash_wire,
            confidence=0.17,
            label="previous block hash",
            raw_representation="raw_bytes",
        ),
    )
    _add_raw_hex_sha256(
        recipes,
        _RawField(
            source="genesis.header.target",
            original_public_source=target_bytes.hex(),
            raw=target_bytes,
            confidence=0.16,
            label="expanded target",
            raw_representation="raw_bytes",
        ),
    )

    for raw_field in (
        _RawField(
            source="genesis.header.raw",
            original_public_source="80-byte Genesis header",
            raw=header.raw,
            confidence=0.14,
            label="raw 80-byte header",
            raw_representation="raw_header",
        ),
        _RawField(
            source="genesis.tx.raw",
            original_public_source="raw Genesis coinbase transaction",
            raw=coinbase.raw,
            confidence=0.13,
            label="raw coinbase transaction",
            raw_representation="raw_tx",
        ),
        _RawField(
            source="genesis.coinbase.script_sig",
            original_public_source="Genesis coinbase scriptSig",
            raw=coinbase.inputs[0].script_sig,
            confidence=0.12,
            label="coinbase scriptSig",
            raw_representation="raw_script_sig",
        ),
        _RawField(
            source="genesis.coinbase.script_pubkey",
            original_public_source="Genesis coinbase scriptPubKey",
            raw=coinbase.outputs[0].script_pubkey,
            confidence=0.11,
            label="coinbase scriptPubKey",
            raw_representation="raw_script_pubkey",
        ),
        _RawField(
            source="genesis.coinbase.pubkey",
            original_public_source="uncompressed Genesis P2PK public key",
            raw=coinbase.pubkey,
            confidence=0.10,
            label="Genesis public key",
            raw_representation="raw_pubkey",
        ),
        _RawField(
            source="genesis.block.raw",
            original_public_source="complete raw Genesis block",
            raw=block.raw,
            confidence=0.09,
            label="complete raw Genesis block",
            raw_representation="raw_block",
        ),
    ):
        _add_raw_hex_sha256(recipes, raw_field)

    headline = coinbase.headline
    headline_seen: _SEEN = set()
    headline_forms = (
        (
            (headline + "\n").encode("utf-8"),
            "utf8_newline",
            "headline_utf8_newline",
            "SHA256 of the exact coinbase headline UTF-8 bytes followed by a newline.",
        ),
        (
            headline.lower().encode("utf-8"),
            "utf8_lower",
            "headline_utf8_lower",
            "SHA256 of the lowercase coinbase headline UTF-8 bytes.",
        ),
        (
            headline.upper().encode("utf-8"),
            "utf8_upper",
            "headline_utf8_upper",
            "SHA256 of the uppercase coinbase headline UTF-8 bytes.",
        ),
    )
    for data, representation, name, recipe in headline_forms:
        _append(
            recipes,
            headline_seen,
            source="genesis.coinbase.headline",
            original_public_source=headline,
            representation=representation,
            public_input_bytes=data,
            transformation="sha256",
            formula=_sha256_formula(data, name),
            confidence=0.08,
            recipe=recipe,
        )

    for text, source, confidence in (
        ("Satoshi Nakamoto", "text.satoshi_nakamoto", 0.04),
        ("Bitcoin", "text.bitcoin", 0.04),
        ("genesis", "text.genesis", 0.04),
        ("genesis block", "text.genesis_block", 0.04),
    ):
        data = text.encode("utf-8")
        semantic_seen: _SEEN = set()
        _append(
            recipes,
            semantic_seen,
            source=source,
            original_public_source=text,
            representation="utf8",
            public_input_bytes=data,
            transformation="sha256",
            formula=_sha256_formula(data, source.replace(".", "_")),
            confidence=confidence,
            recipe=f"SHA256 of the exact UTF-8 string {text!r}.",
        )

    return _finalize(recipes)
