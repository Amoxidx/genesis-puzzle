from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from genesis_puzzle.model import GenesisFacts, KnownTarget


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def render_report(
    facts: GenesisFacts,
    targets: Sequence[KnownTarget],
    counts: Mapping[str, int],
    latest_run: Optional[Mapping[str, Any]],
    derivations: Sequence[Mapping[str, Any]],
    comparisons: Sequence[Mapping[str, Any]],
    checked_history: Sequence[Mapping[str, Any]],
) -> str:
    duplicate_count = 0
    if latest_run is not None:
        duplicate_count = int(latest_run.get("duplicate_count") or 0)
    invalid = counts.get("invalid", 0)
    unique_keys = counts.get("unique_keys", 0)
    deriv_n = counts.get("derivations", 0)
    match_n = counts.get("target_matches", 0)
    history_checked = len(checked_history)
    chain_state = "not checked"
    if history_checked:
        chain_state = f"checked ({history_checked} addresses)"

    history_status_counts = {
        "never_seen": 0,
        "seen_but_empty": 0,
        "currently_funded": 0,
        "spent_history": 0,
    }
    seen_lines = []
    for item in checked_history:
        status = str(item.get("history_status") or "seen_but_empty")
        if status in history_status_counts:
            history_status_counts[status] += 1
        if bool(item.get("seen_on_chain")):
            seen_lines.append(
                f"- `{item['address']}` ({item['address_type']}): {status}; "
                f"derivations={item.get('derivation_ids')}; "
                f"transactions={item.get('transaction_count')}; "
                f"balance={item.get('balance')} sats; "
                f"received={item.get('total_received')} sats; sent={item.get('total_sent')} sats"
            )

    target_lines = []
    for target in targets:
        target_lines.append(
            f"- `{target.label}` ({target.status}): {target.value_sats} sats to "
            f"`{target.address}` (`{target.script_type}`) in tx `{target.txid}` "
            f"block {target.block_height}. {target.notes}"
        )

    derivation_lines = []
    eliminated = []
    remaining = []
    for item in derivations:
        mark = "valid" if item["valid"] else "eliminated"
        derivation_lines.append(
            f"- `{item['derivation_id']}` [{mark}] {item['recipe']} "
            f"(source `{item['source']}`, transform `{item['transformation']}`, "
            f"confidence {item['confidence']})"
        )
        if item["valid"]:
            remaining.append(item["derivation_id"])
        else:
            eliminated.append(
                f"- `{item['derivation_id']}`: {item['eliminated_reason'] or 'invalid scalar'}"
            )

    comparison_note = (
        "No Stage A P2PKH/P2WPKH address equals the suspected P2WSH output. "
        "That is expected: a standard-key address cannot match a P2WSH output "
        "without knowing or hypothesizing the witness script."
    )
    if match_n:
        comparison_note = (
            f"{match_n} comparable address match(es) were recorded. "
            "Review before any further claim."
        )

    run_block = "No Stage A run stored yet."
    if latest_run is not None:
        run_block = (
            f"- status: {latest_run.get('status')}\n"
            f"- mode: {latest_run.get('mode')}\n"
            f"- elapsed_seconds: {latest_run.get('elapsed_seconds')}\n"
            f"- rate_per_second: {latest_run.get('rate_per_second')}\n"
            f"- checkpoint: {latest_run.get('notes')}\n"
        )

    return f"""# Genesis Puzzle — Stage A report

Generated {_utc_now()} from stored facts and SQLite results. Private candidate
scalars are redacted and are not stored.

## Puzzle statement

> I made a Bitcoin puzzle using information contained in the genesis block
> created by Satoshi to generate the wallet. The entropy is extremely low. I
> didn't even need to back anything up. Everything I needed was already in the
> genesis block. Good luck!

Announcement transaction:
`b691de3657880d9a1eabd2783b1a9fa8c5313ced338495bf10e85727012d7a77`,
block `963629`, publication time `2026-08-22 19:45 UTC`.

Satoshi's Genesis block is a public, narrowly scoped artifact. This researcher
asks whether any *canonical public field of that block*, taken as a secp256k1
scalar or as SHA256 of that field, produces a standard Bitcoin address that
can be compared against a later suspected puzzle output.

This is not a general private-key cracking framework. Stage B, brute force,
PBKDF2/BIP39, Metal, transaction creation, wallet import, spending, and
broadcasting are out of scope.

## Known public facts

Genesis (Bitcoin mainnet):

- version `{facts.version}`
- timestamp `{facts.timestamp}`
- bits `0x{facts.bits_hex}` / `{facts.bits}`
- target `{facts.target_hex}`
- nonce `{facts.nonce}`
- previous hash: 32 zero bytes
- block hash (display): `{facts.block_hash_display_hex}`
- block hash (wire): `{facts.block_hash_wire_hex}`
- Merkle root / coinbase txid (display): `{facts.txid_display_hex}`
- raw coinbase transaction: `{facts.raw_transaction_hex}`
- coinbase scriptSig: `{facts.script_sig_hex}`
- output `{facts.reward_sats}` sats
- headline: `{facts.headline}`
- Genesis pubkey: `{facts.pubkey_uncompressed_hex}`
- height `0`

Announcement transaction (verified 2026-08-23 as public chain data):

{chr(10).join(target_lines)}

## Verified Genesis data

The raw 285-byte Genesis block is parsed, not copied field-by-field. Independent
proofs that must hold after parse:

1. `SHA256d(header)[::-1]` equals the display block hash.
2. Coinbase txid equals the known txid.
3. The one-transaction Merkle root equals the header Merkle root.
4. Headline and uncompressed pubkey match the canonical document.

`init` re-runs these proofs before any Stage A derivation.

## Hypotheses tested in Stage A

Stage A only uses canonical public values and two justified 32-byte hash
orders (wire/internal and display). It does not expand into case folding,
separators, dates, newlines, permutations, neighborhoods, repeated hashes, or
combinations (that is Stage B representation-matrix work).

What was tested, and why:

- Direct integers of nonce, timestamp, nBits, version, and reward — they are
  the obvious small public numbers printed on the block.
- Height 0 as a direct scalar — recorded and eliminated; zero is not a valid
  secp256k1 secret and is never passed to coincurve.
- SHA256 of those canonical ASCII/hex encodings, of the headline, of the raw
  header, of both justified block-hash/Merkle byte orders, and of the Genesis
  public key — a one-way fold of a public artifact into a 256-bit scalar.
- Direct 32-byte integer interpretation of the block hash and Merkle root in
  wire order and display order, where the integer falls inside `[1, n)`.

The private scalar of every derivation is redacted. SQLite stores provenance,
fingerprints, public keys, and addresses only.

## Stage A results

{run_block}

- total derivations: {deriv_n}
- invalid derivations: {invalid}
- unique valid keys: {unique_keys}
- duplicates (extra provenance paths onto an already-seen scalar): {duplicate_count}
- addresses by type:
  - uncompressed P2PKH: {counts.get("p2pkh_uncompressed", 0)}
  - compressed P2PKH: {counts.get("p2pkh_compressed", 0)}
  - compressed P2WPKH: {counts.get("p2wpkh", 0)}
- known-target matches: {match_n}
- chain-history state: {chain_state}

{comparison_note}

### Address history

- never seen: {history_status_counts["never_seen"]}
- seen but empty: {history_status_counts["seen_but_empty"]}
- currently funded: {history_status_counts["currently_funded"]}
- spent history: {history_status_counts["spent_history"]}

Addresses with blockchain history:

{chr(10).join(seen_lines) if seen_lines else "- none"}

### Interesting observations

- {counts.get("history_seen", 0)} generated address(es) have public chain history.
- {counts.get("history_funded", 0)} are currently funded; {counts.get("history_spent", 0)}
  have spent history and zero current balance.
- Public history is a research signal, not a target match. Widely known weak
  keys (for example direct scalar `1`) are expected to have unrelated test or
  sweep activity. The suspected puzzle output remains the separate P2WSH
  program recorded above.

### Derivations

{chr(10).join(derivation_lines) if derivation_lines else "- none stored yet"}

### Eliminated hypotheses

{chr(10).join(eliminated) if eliminated else "- none"}

### Remaining hypotheses

Stage A public-key hypotheses remain open unless their public address history
or the suspected target script provides evidence. Remaining valid derivation
ids: {", ".join(f"`{item}`" for item in remaining) or "none"}.

They are not claims of a match. They are simply scalars that produced standard
P2PKH/P2WPKH addresses which do not, by themselves, test a P2WSH output.

## P2WSH gap

The suspected target is P2WSH (`{targets[0].address if targets else "n/a"}`).
Standard P2PKH and P2WPKH derivations from Stage A public keys cannot directly
test its unknown witness script. A HASH160(pubkey) is the wrong program length
and the wrong script template compared with SHA256(witnessScript).

## Next highest-value Stage B experiment (not executed)

Hypothesis, not a claim: before expanding a full representation matrix, test a
narrowly bounded set of *canonical single-key witness-script templates* built
from the Stage A compressed public keys, especially:

    <compressed pubkey> OP_CHECKSIG

That preserves the Genesis P2PK motif (a single key immediately followed by
CHECKSIG) inside a P2WSH program. Compare `SHA256(witnessScript)` against the
suspected 32-byte witness program
`4dae67a9872f1402109f9670276afc2c0758f895aafddcd089795771b7964833`.

Do not execute that experiment in Milestone 1. Do not brute-force, do not
search neighborhoods, and do not treat a template miss as proof that no
puzzle exists.

## Resource and safety notes

- Balanced mode is the default. Stage A is sequential.
- Pause/resume/checkpointing are future bounded-search features and are not
  needed here (`checkpoint-not-needed`).
- GPU is disabled. No temperature is measured.
- Offline is the default. Remote history checks are explicit, batched, and
  send derived public addresses only.

## Public verification sources

- Bitcoin Core's `src/kernel/chainparams.cpp` for the canonical Genesis
  construction and asserted block/Merkle hashes:
  https://github.com/bitcoin/bitcoin/blob/master/src/kernel/chainparams.cpp
- Raw Genesis block independently fetched from:
  https://blockchain.info/rawblock/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f?format=hex
- Announcement transaction and output facts independently fetched from:
  https://mempool.space/tx/b691de3657880d9a1eabd2783b1a9fa8c5313ced338495bf10e85727012d7a77
- P2WSH semantics (`SHA256(witnessScript)` equals the 32-byte witness program):
  https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
"""


def write_report(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
