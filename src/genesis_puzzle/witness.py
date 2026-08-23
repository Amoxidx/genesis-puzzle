from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Tuple

from genesis_puzzle.bech32 import encode_segwit_address
from genesis_puzzle.hashing import hash160, sha256

OP_DUP = 0x76
OP_EQUALVERIFY = 0x88
OP_HASH160 = 0xA9
OP_CHECKSIG = 0xAC
OP_CHECKMULTISIG = 0xAE
OP_1 = 0x51


def minimal_push(data: bytes) -> bytes:
    length = len(data)
    if length == 0 or length > 75:
        raise ValueError("Stage B only uses direct minimal pushes of 1..75 bytes")
    return bytes([length]) + data


def _require_pubkey_mode(mode: str, pubkey: bytes) -> None:
    if mode == "compressed":
        if len(pubkey) != 33 or pubkey[0] not in (2, 3):
            raise ValueError("compressed pubkey must be 33 bytes starting with 0x02 or 0x03")
        return
    if mode == "uncompressed":
        if len(pubkey) != 65 or pubkey[0] != 0x04:
            raise ValueError("uncompressed pubkey must be 65 bytes starting with 0x04")
        return
    raise ValueError("pubkey mode must be compressed or uncompressed")


def _require_pubkeys(uncompressed: bytes, compressed: bytes) -> None:
    _require_pubkey_mode("compressed", compressed)
    _require_pubkey_mode("uncompressed", uncompressed)


def _p2pk_script(pubkey: bytes) -> bytes:
    return minimal_push(pubkey) + bytes([OP_CHECKSIG])


def _multisig_1of1_script(pubkey: bytes) -> bytes:
    return bytes([OP_1]) + minimal_push(pubkey) + bytes([OP_1, OP_CHECKMULTISIG])


def _p2pkh_script(pubkey: bytes) -> bytes:
    return (
        bytes([OP_DUP, OP_HASH160])
        + minimal_push(hash160(pubkey))
        + bytes([OP_EQUALVERIFY, OP_CHECKSIG])
    )


def _p2pk_compressed(compressed: bytes, _uncompressed: bytes) -> bytes:
    return _p2pk_script(compressed)


def _p2pk_uncompressed(_compressed: bytes, uncompressed: bytes) -> bytes:
    return _p2pk_script(uncompressed)


def _multisig_1of1_compressed(compressed: bytes, _uncompressed: bytes) -> bytes:
    return _multisig_1of1_script(compressed)


def _multisig_1of1_uncompressed(_compressed: bytes, uncompressed: bytes) -> bytes:
    return _multisig_1of1_script(uncompressed)


def _p2pkh_compressed(compressed: bytes, _uncompressed: bytes) -> bytes:
    return _p2pkh_script(compressed)


def _p2pkh_uncompressed(_compressed: bytes, uncompressed: bytes) -> bytes:
    return _p2pkh_script(uncompressed)


_SCRIPT_FROM_PUBKEY = {
    "p2pk_compressed": _p2pk_script,
    "p2pk_uncompressed": _p2pk_script,
    "multisig_1of1_compressed": _multisig_1of1_script,
    "multisig_1of1_uncompressed": _multisig_1of1_script,
    "p2pkh_compressed": _p2pkh_script,
    "p2pkh_uncompressed": _p2pkh_script,
}


@dataclass(frozen=True)
class WitnessTemplate:
    template_id: str
    name: str
    priority: int
    pubkey_mode: str
    builder: Callable[[bytes, bytes], bytes]


@dataclass(frozen=True)
class P2WSHCandidate:
    template_id: str
    name: str
    priority: int
    pubkey_mode: str
    pubkey_hex: str
    witness_script: bytes
    witness_script_hex: str
    witness_program: bytes
    witness_program_hex: str
    address: str


WITNESS_TEMPLATES: Tuple[WitnessTemplate, ...] = (
    WitnessTemplate(
        template_id="p2pk_compressed",
        name="p2pk_compressed",
        priority=1,
        pubkey_mode="compressed",
        builder=_p2pk_compressed,
    ),
    WitnessTemplate(
        template_id="p2pk_uncompressed",
        name="p2pk_uncompressed",
        priority=2,
        pubkey_mode="uncompressed",
        builder=_p2pk_uncompressed,
    ),
    WitnessTemplate(
        template_id="multisig_1of1_compressed",
        name="multisig_1of1_compressed",
        priority=3,
        pubkey_mode="compressed",
        builder=_multisig_1of1_compressed,
    ),
    WitnessTemplate(
        template_id="multisig_1of1_uncompressed",
        name="multisig_1of1_uncompressed",
        priority=4,
        pubkey_mode="uncompressed",
        builder=_multisig_1of1_uncompressed,
    ),
    WitnessTemplate(
        template_id="p2pkh_compressed",
        name="p2pkh_compressed",
        priority=5,
        pubkey_mode="compressed",
        builder=_p2pkh_compressed,
    ),
    WitnessTemplate(
        template_id="p2pkh_uncompressed",
        name="p2pkh_uncompressed",
        priority=6,
        pubkey_mode="uncompressed",
        builder=_p2pkh_uncompressed,
    ),
)


def p2wsh_program_and_address(witness_script: bytes) -> Tuple[bytes, str]:
    program = sha256(witness_script)
    return program, encode_segwit_address("bc", 0, program)


def expected_witness_script(template: WitnessTemplate, pubkey: bytes) -> bytes:
    """Exact p2pk, 1-of-1, or p2pkh script from one pubkey of the template's declared mode."""
    builder = _SCRIPT_FROM_PUBKEY.get(template.template_id)
    if builder is None:
        raise ValueError(f"unknown witness template {template.template_id}")
    _require_pubkey_mode(template.pubkey_mode, pubkey)
    return builder(pubkey)


def build_witness_script(
    template: WitnessTemplate, uncompressed: bytes, compressed: bytes
) -> bytes:
    _require_pubkeys(uncompressed, compressed)
    pubkey = compressed if template.pubkey_mode == "compressed" else uncompressed
    return expected_witness_script(template, pubkey)


def build_p2wsh_candidate(
    template: WitnessTemplate, uncompressed: bytes, compressed: bytes
) -> P2WSHCandidate:
    script = build_witness_script(template, uncompressed, compressed)
    pubkey = compressed if template.pubkey_mode == "compressed" else uncompressed
    program, address = p2wsh_program_and_address(script)
    return P2WSHCandidate(
        template_id=template.template_id,
        name=template.name,
        priority=template.priority,
        pubkey_mode=template.pubkey_mode,
        pubkey_hex=pubkey.hex(),
        witness_script=script,
        witness_script_hex=script.hex(),
        witness_program=program,
        witness_program_hex=program.hex(),
        address=address,
    )


def build_p2wsh_candidates(uncompressed: bytes, compressed: bytes) -> Tuple[P2WSHCandidate, ...]:
    _require_pubkeys(uncompressed, compressed)
    return tuple(
        build_p2wsh_candidate(template, uncompressed, compressed) for template in WITNESS_TEMPLATES
    )


def compare_p2wsh_target(
    candidate: P2WSHCandidate,
    witness_program_hex: str,
    address: str,
) -> bool:
    """Exact SHA256(witnessScript) and native mainnet P2WSH address comparison."""
    return (
        candidate.witness_program == bytes.fromhex(witness_program_hex)
        and candidate.address == address
    )
