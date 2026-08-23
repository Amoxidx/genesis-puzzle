from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from genesis_puzzle.hashing import sha256d
from genesis_puzzle.model import GenesisFacts

OP_CHECKSIG = 0xAC


class ParseError(ValueError):
    pass


class ProofError(ValueError):
    pass


def compact_target(bits: int) -> int:
    exponent = bits >> 24
    coefficient = bits & 0x007FFFFF
    if bits & 0x00800000 or coefficient == 0:
        raise ProofError("negative or zero compact target")
    if exponent <= 3:
        target = coefficient >> (8 * (3 - exponent))
    else:
        target = coefficient << (8 * (exponent - 3))
    if target <= 0 or target >= 1 << 256:
        raise ProofError("compact target is outside uint256")
    return target


@dataclass(frozen=True)
class ParsedHeader:
    version: int
    prev_hash_wire: bytes
    merkle_root_wire: bytes
    timestamp: int
    bits: int
    nonce: int
    raw: bytes

    @property
    def prev_hash_display_hex(self) -> str:
        return self.prev_hash_wire[::-1].hex()

    @property
    def merkle_root_display_hex(self) -> str:
        return self.merkle_root_wire[::-1].hex()

    @property
    def bits_hex(self) -> str:
        return f"{self.bits:08x}"


@dataclass(frozen=True)
class ParsedTxIn:
    prevout_hash_wire: bytes
    prevout_index: int
    script_sig: bytes
    sequence: int


@dataclass(frozen=True)
class ParsedTxOut:
    value_sats: int
    script_pubkey: bytes


@dataclass(frozen=True)
class ParsedTransaction:
    version: int
    inputs: Tuple[ParsedTxIn, ...]
    outputs: Tuple[ParsedTxOut, ...]
    locktime: int
    raw: bytes
    headline: str
    pubkey: bytes


@dataclass(frozen=True)
class ParsedBlock:
    header: ParsedHeader
    tx_count: int
    transactions: Tuple[ParsedTransaction, ...]
    raw: bytes

    @property
    def coinbase(self) -> ParsedTransaction:
        return self.transactions[0]

    @property
    def block_hash_wire(self) -> bytes:
        return sha256d(self.header.raw)

    @property
    def block_hash_display_hex(self) -> str:
        return self.block_hash_wire[::-1].hex()

    @property
    def txid_wire(self) -> bytes:
        return sha256d(self.coinbase.raw)

    @property
    def txid_display_hex(self) -> str:
        return self.txid_wire[::-1].hex()


class Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def remaining(self) -> int:
        return len(self.data) - self.offset

    def take(self, n: int) -> bytes:
        if n < 0 or self.offset + n > len(self.data):
            raise ParseError("truncated input")
        chunk = self.data[self.offset : self.offset + n]
        self.offset += n
        return chunk

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "little")

    def u64(self) -> int:
        return int.from_bytes(self.take(8), "little")

    def compact_size(self) -> int:
        if self.remaining() < 1:
            raise ParseError("truncated compact size")
        first = self.take(1)[0]
        if first < 0xFD:
            return first
        if first == 0xFD:
            value = int.from_bytes(self.take(2), "little")
            if value < 0xFD:
                raise ParseError("non-canonical compact size")
            return value
        if first == 0xFE:
            value = int.from_bytes(self.take(4), "little")
            if value < 0x10000:
                raise ParseError("non-canonical compact size")
            return value
        value = int.from_bytes(self.take(8), "little")
        if value < 0x100000000:
            raise ParseError("non-canonical compact size")
        return value


def _parse_script_pushes(script: bytes) -> List[bytes]:
    reader = Reader(script)
    pushes: List[bytes] = []
    while reader.remaining():
        opcode = reader.take(1)[0]
        if opcode == 0:
            pushes.append(b"")
            continue
        if 1 <= opcode <= 75:
            pushes.append(reader.take(opcode))
            continue
        if opcode == 76:
            n = reader.take(1)[0]
            pushes.append(reader.take(n))
            continue
        if opcode == 77:
            n = int.from_bytes(reader.take(2), "little")
            pushes.append(reader.take(n))
            continue
        if opcode == 78:
            n = int.from_bytes(reader.take(4), "little")
            pushes.append(reader.take(n))
            continue
        raise ParseError(f"unsupported script opcode 0x{opcode:02x} in this fixed block")
    return pushes


def _parse_p2pk(script: bytes) -> bytes:
    if len(script) != 67:
        raise ParseError("unexpected P2PK script length")
    if script[0] != 65 or script[-1] != OP_CHECKSIG:
        raise ParseError("script is not 65-byte pubkey OP_CHECKSIG")
    pubkey = script[1:66]
    if len(pubkey) != 65 or pubkey[0] != 0x04:
        raise ParseError("Genesis pubkey must be an uncompressed 65-byte key")
    return pubkey


def _parse_legacy_tx(reader: Reader) -> ParsedTransaction:
    start = reader.offset
    version = reader.u32()
    if reader.remaining() >= 2 and reader.data[reader.offset : reader.offset + 2] == b"\x00\x01":
        raise ParseError("witness transactions are not supported for this block")
    n_in = reader.compact_size()
    if n_in != 1:
        raise ParseError("Genesis coinbase must have exactly one input")
    inputs = []
    for _ in range(n_in):
        prevout = reader.take(32)
        index = reader.u32()
        script_len = reader.compact_size()
        script_sig = reader.take(script_len)
        sequence = reader.u32()
        inputs.append(
            ParsedTxIn(
                prevout_hash_wire=prevout,
                prevout_index=index,
                script_sig=script_sig,
                sequence=sequence,
            )
        )
    n_out = reader.compact_size()
    if n_out != 1:
        raise ParseError("Genesis coinbase must have exactly one output")
    outputs = []
    for _ in range(n_out):
        value = reader.u64()
        script_len = reader.compact_size()
        script_pubkey = reader.take(script_len)
        outputs.append(ParsedTxOut(value_sats=value, script_pubkey=script_pubkey))
    locktime = reader.u32()
    raw = reader.data[start : reader.offset]
    coinbase = inputs[0]
    if coinbase.prevout_hash_wire != b"\x00" * 32 or coinbase.prevout_index != 0xFFFFFFFF:
        raise ParseError("coinbase prevout must be null / 0xffffffff")
    pushes = _parse_script_pushes(coinbase.script_sig)
    if not pushes:
        raise ParseError("coinbase scriptSig has no pushes")
    try:
        headline = pushes[-1].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ParseError("headline is not valid UTF-8") from exc
    pubkey = _parse_p2pk(outputs[0].script_pubkey)
    return ParsedTransaction(
        version=version,
        inputs=tuple(inputs),
        outputs=tuple(outputs),
        locktime=locktime,
        raw=raw,
        headline=headline,
        pubkey=pubkey,
    )


def parse_genesis_block(raw: bytes) -> ParsedBlock:
    if not raw:
        raise ParseError("empty block")
    reader = Reader(raw)
    header_raw = reader.take(80)
    header_reader = Reader(header_raw)
    header = ParsedHeader(
        version=header_reader.u32(),
        prev_hash_wire=header_reader.take(32),
        merkle_root_wire=header_reader.take(32),
        timestamp=header_reader.u32(),
        bits=header_reader.u32(),
        nonce=header_reader.u32(),
        raw=header_raw,
    )
    tx_count = reader.compact_size()
    if tx_count != 1:
        raise ParseError("Genesis block must contain exactly one transaction")
    tx = _parse_legacy_tx(reader)
    if reader.remaining() != 0:
        raise ParseError("trailing bytes after Genesis block")
    return ParsedBlock(header=header, tx_count=tx_count, transactions=(tx,), raw=raw)


def parse_genesis_hex(raw_hex: str) -> ParsedBlock:
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError as exc:
        raise ParseError("invalid hex") from exc
    return parse_genesis_block(raw)


def verify_against_facts(block: ParsedBlock, facts: GenesisFacts) -> None:
    header = block.header
    tx = block.coinbase
    checks = [
        (len(block.raw) == facts.raw_block_length_bytes, "raw length"),
        (header.version == facts.version, "version"),
        (header.timestamp == facts.timestamp, "timestamp"),
        (header.bits == facts.bits, "bits"),
        (header.bits_hex == facts.bits_hex, "bits hex"),
        (f"{compact_target(header.bits):064x}" == facts.target_hex, "target"),
        (header.nonce == facts.nonce, "nonce"),
        (header.prev_hash_wire.hex() == facts.previous_hash_wire_hex, "prev hash wire"),
        (header.prev_hash_display_hex == facts.previous_hash_display_hex, "prev hash display"),
        (header.merkle_root_wire.hex() == facts.merkle_root_wire_hex, "merkle wire"),
        (header.merkle_root_display_hex == facts.merkle_root_display_hex, "merkle display"),
        (tx.version == facts.tx_version, "tx version"),
        (tx.raw.hex() == facts.raw_transaction_hex, "raw transaction"),
        (len(tx.inputs) == facts.input_count, "input count"),
        (len(tx.outputs) == facts.output_count, "output count"),
        (tx.locktime == facts.locktime, "locktime"),
        (tx.outputs[0].value_sats == facts.reward_sats, "reward"),
        (tx.headline == facts.headline, "headline"),
        (tx.pubkey.hex() == facts.pubkey_uncompressed_hex, "pubkey"),
        (tx.outputs[0].script_pubkey.hex() == facts.script_pubkey_hex, "scriptPubKey"),
        (tx.inputs[0].prevout_index == facts.coinbase_prevout_index, "prevout index"),
        (tx.inputs[0].script_sig.hex() == facts.script_sig_hex, "scriptSig"),
        (tx.inputs[0].sequence == facts.sequence, "sequence"),
    ]
    for ok, name in checks:
        if not ok:
            raise ProofError(f"parsed {name} does not match canonical facts")
    block_hash_wire = sha256d(header.raw)
    if block_hash_wire[::-1].hex() != facts.block_hash_display_hex:
        raise ProofError("SHA256d(header)[::-1] does not match display block hash")
    if block_hash_wire.hex() != facts.block_hash_wire_hex:
        raise ProofError("SHA256d(header) does not match wire block hash")
    txid_wire = sha256d(tx.raw)
    if txid_wire[::-1].hex() != facts.txid_display_hex:
        raise ProofError("coinbase txid display does not match")
    if txid_wire.hex() != facts.txid_wire_hex:
        raise ProofError("coinbase txid wire does not match")
    if txid_wire != header.merkle_root_wire:
        raise ProofError("one-tx Merkle root does not equal header Merkle root")


def parse_and_verify(facts: GenesisFacts) -> ParsedBlock:
    block = parse_genesis_hex(facts.raw_block_hex)
    verify_against_facts(block, facts)
    return block
