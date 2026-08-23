from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from genesis_puzzle.model import GenesisFacts, KnownTarget
from genesis_puzzle.witness import WITNESS_TEMPLATES

TEMPLATE_COUNT = len(WITNESS_TEMPLATES)
STAGE_C_SEPARATORS = (
    ("empty string", '""'),
    ("colon", '":"'),
    ("pipe", '"|"'),
    ("hyphen", '"-"'),
    ("underscore", '"_"'),
    ("ASCII space", '" "'),
    ("ASCII newline", r'"\n"'),
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def _as_int(mapping: Optional[Mapping[str, Any]], key: str, default: int = 0) -> int:
    if mapping is None:
        return default
    value = mapping.get(key)
    if value is None:
        return default
    return int(value)


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value not in ("", "0")
    return bool(value)


def _stage_rows(derivations: Sequence[Mapping[str, Any]], stage: str) -> list[Mapping[str, Any]]:
    return [item for item in derivations if str(item.get("stage") or "") == stage]


def _run_lines(title: str, run: Optional[Mapping[str, Any]], missing: str) -> str:
    if run is None:
        return missing
    return (
        f"{title}\n"
        f"- status: {run.get('status')}\n"
        f"- mode: {run.get('mode')}\n"
        f"- elapsed_seconds: {run.get('elapsed_seconds')}\n"
        f"- rate_per_second: {run.get('rate_per_second')}\n"
        f"- checkpoint: {run.get('notes')}"
    )


def _unique_fingerprints(rows: Sequence[Mapping[str, Any]]) -> set[str]:
    fingerprints = set()
    for item in rows:
        if not _truthy(item.get("valid")):
            continue
        fingerprint = item.get("fingerprint")
        if fingerprint:
            fingerprints.add(str(fingerprint))
    return fingerprints


def render_report(
    facts: GenesisFacts,
    targets: Sequence[KnownTarget],
    counts: Mapping[str, int],
    latest_run: Optional[Mapping[str, Any]],
    derivations: Sequence[Mapping[str, Any]],
    comparisons: Sequence[Mapping[str, Any]],
    checked_history: Sequence[Mapping[str, Any]],
    witness_candidates: Sequence[Mapping[str, Any]] = (),
    stage_a_run: Optional[Mapping[str, Any]] = None,
    stage_b_run: Optional[Mapping[str, Any]] = None,
) -> str:
    if (
        stage_a_run is None
        and latest_run is not None
        and str(latest_run.get("stage") or "") == "A"
    ):
        stage_a_run = latest_run
    if (
        stage_b_run is None
        and latest_run is not None
        and str(latest_run.get("stage") or "") == "B"
    ):
        stage_b_run = latest_run

    stage_a_rows = _stage_rows(derivations, "A")
    stage_b_rows = _stage_rows(derivations, "B")
    stage_a_invalid = sum(1 for item in stage_a_rows if not _truthy(item.get("valid")))
    stage_b_invalid = sum(1 for item in stage_b_rows if not _truthy(item.get("valid")))
    stage_a_unique = len(_unique_fingerprints(stage_a_rows))
    if stage_a_run is not None and stage_a_unique == 0:
        stage_a_unique = _as_int(stage_a_run, "unique_valid_keys")

    unique_keys = int(counts.get("unique_keys", 0))
    address_match_n = int(counts.get("target_matches", 0))
    witness_match_n = int(counts.get("witness_matches", 0))
    if witness_candidates:
        witness_match_n = sum(1 for item in witness_candidates if _truthy(item.get("matched")))
    tested_witness = len(witness_candidates)
    if tested_witness == 0:
        tested_witness = int(counts.get("witness_candidates", 0))

    if stage_b_run is not None:
        cumulative_unique = _as_int(stage_b_run, "unique_valid_keys", unique_keys)
        cumulative_duplicates = _as_int(stage_b_run, "duplicate_count")
        if _as_int(stage_b_run, "tested_candidate_count") and tested_witness == 0:
            tested_witness = _as_int(stage_b_run, "tested_candidate_count")
    elif stage_a_run is not None:
        cumulative_unique = _as_int(
            stage_a_run, "unique_valid_keys", unique_keys or stage_a_unique
        )
        cumulative_duplicates = _as_int(stage_a_run, "duplicate_count")
    else:
        cumulative_unique = unique_keys
        cumulative_duplicates = _as_int(latest_run, "duplicate_count")

    stage_a_only_scripts = stage_a_unique * TEMPLATE_COUNT
    combined_scripts = cumulative_unique * TEMPLATE_COUNT

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
    target_address = targets[0].address if targets else "n/a"
    target_program = (
        targets[0].witness_program_hex
        if targets
        else "4dae67a9872f1402109f9670276afc2c0758f895aafddcd089795771b7964833"
    )
    target_status = targets[0].status if targets else "suspected_not_proven"

    derivation_lines = []
    eliminated = []
    remaining = []
    for item in derivations:
        mark = "valid" if _truthy(item.get("valid")) else "eliminated"
        derivation_lines.append(
            f"- `{item['derivation_id']}` [{mark}] {item['recipe']} "
            f"(source `{item['source']}`, transform `{item['transformation']}`, "
            f"confidence {item['confidence']})"
        )
        if _truthy(item.get("valid")):
            remaining.append(str(item["derivation_id"]))
        else:
            eliminated.append(
                f"- `{item['derivation_id']}`: {item.get('eliminated_reason') or 'invalid scalar'}"
            )

    template_counts: Counter[str] = Counter()
    for item in witness_candidates:
        name = str(item.get("template_id") or item.get("template_name") or "")
        if name:
            template_counts[name] += 1
    template_lines = []
    for template in WITNESS_TEMPLATES:
        kind = (
            "compressed; modern canonical / descriptor-compatible"
            if template.pubkey_mode == "compressed"
            else (
                "uncompressed; lower-priority historical/manual possibility, "
                "not standard descriptor-compatible"
            )
        )
        template_lines.append(
            f"- priority {template.priority}: `{template.name}` ({kind}); "
            f"tested {template_counts.get(template.name, 0)}"
        )

    address_comparison_note = (
        "No Stage A P2PKH/P2WPKH address equals the suspected P2WSH output. "
        "That is expected: a standard-key address cannot match a P2WSH output "
        "without knowing or hypothesizing the witness script."
    )
    if address_match_n:
        address_comparison_note = (
            f"{address_match_n} comparable address match(es) were recorded. "
            "Review before any further claim."
        )

    if stage_b_run is None:
        stage_b_result = (
            "No Stage B run is stored in this database yet. Stage B is an implemented "
            "offline deterministic stage; it requires a completed Stage A run and is "
            "not out of scope."
        )
        subset_note = (
            f"Once Stage B is executed, the {stage_a_only_scripts} Stage-A-only "
            f"script-template subset is {stage_a_unique} unique Stage A keys "
            f"times {TEMPLATE_COUNT} templates. That subset is contained in the "
            f"combined A+B set; it is not an extra count."
        )
        witness_verdict = (
            "Stage B P2WSH template comparison has not been stored yet. "
            f"The announcement target remains `{target_status}`."
        )
    else:
        subset_note = (
            f"The {stage_a_only_scripts} Stage-A-only script-template subset is "
            f"{stage_a_unique} unique Stage A keys times {TEMPLATE_COUNT} templates. "
            f"The full combined A+B set is {combined_scripts} scripts "
            f"({cumulative_unique} cumulative unique keys times {TEMPLATE_COUNT} "
            "templates). The Stage-A-only subset is contained in the combined set; "
            "it is not an extra 132 on top of 630. "
            f"The executed Stage B run tested {tested_witness} witness candidates."
        )
        if witness_match_n:
            witness_verdict = (
                f"{witness_match_n} direct P2WSH target-script match(es) were stored. "
                "Review before any further claim. This report does not treat a "
                "template match as a solved puzzle by itself."
            )
        else:
            witness_verdict = (
                "Zero stored witness candidates equal the suspected 32-byte witness "
                "program or its native P2WSH address. That does not disprove the "
                f"puzzle. The announcement target remains `{target_status}`."
            )
        stage_b_n = len(stage_b_rows) or _as_int(stage_b_run, "derivation_count")
        stage_b_result = (
            f"- Stage B derivations: {stage_b_n}\n"
            f"- Stage B invalid derivations: "
            f"{stage_b_invalid or _as_int(stage_b_run, 'invalid_count')}\n"
            f"- cumulative unique valid keys after A+B: {cumulative_unique}\n"
            f"- cumulative duplicate provenance paths after A+B: {cumulative_duplicates}\n"
            f"- tested witness candidates: {tested_witness}\n"
            f"- P2WSH direct target matches: {witness_match_n}"
        )

    stage_a_duplicates = _as_int(stage_a_run, "duplicate_count")
    stage_a_n = len(stage_a_rows) or _as_int(stage_a_run, "derivation_count")
    stage_a_result = (
        f"- Stage A derivations: {stage_a_n}\n"
        f"- Stage A invalid derivations: "
        f"{stage_a_invalid or _as_int(stage_a_run, 'invalid_count')}\n"
        f"- Stage A unique valid keys: {stage_a_unique}\n"
        f"- Stage A duplicate provenance paths: {stage_a_duplicates}\n"
        f"- cumulative unique valid keys after Stage A: {stage_a_unique}\n"
        f"- cumulative duplicate provenance paths after Stage A: {stage_a_duplicates}\n"
        "- addresses by type:\n"
        f"  - uncompressed P2PKH: {counts.get('p2pkh_uncompressed', 0)}\n"
        f"  - compressed P2PKH: {counts.get('p2pkh_compressed', 0)}\n"
        f"  - compressed P2WPKH: {counts.get('p2wpkh', 0)}\n"
        f"- known-target address matches: {address_match_n}\n"
        f"- chain-history state: {chain_state}"
    )

    remaining_n = len(remaining)
    if remaining_n == 0:
        remaining_text = "No stored valid derivation remains."
    elif stage_b_run is not None and witness_match_n == 0:
        remaining_text = (
            f"{remaining_n} stored valid derivation ids remain open as public-key "
            "hypotheses, not as matches. They are listed once under Derivations. "
            "Stage A P2PKH/P2WPKH addresses still do not test the P2WSH program. "
            "The six generic single-key P2WSH templates did not match the target. "
            "Other scripts, combinations, and encodings remain untested."
        )
    elif stage_b_run is not None:
        remaining_text = (
            f"{remaining_n} stored valid derivation ids are listed once under "
            "Derivations. Review the stored P2WSH match(es) before any claim. "
            "This is not by itself a solved puzzle."
        )
    else:
        remaining_text = (
            f"{remaining_n} stored valid derivation ids remain open as public-key "
            "hypotheses, not as matches. They are listed once under Derivations. "
            "They produced standard P2PKH/P2WPKH addresses which do not, by "
            "themselves, test a P2WSH output."
        )

    separator_lines = [
        f"{index}. {name} `{token}`"
        for index, (name, token) in enumerate(STAGE_C_SEPARATORS, start=1)
    ]
    if stage_b_run is not None:
        audit_line = (
            f"All {tested_witness} public candidate scripts, programs, addresses, and "
            "provenance for the executed Stage B run are stored in SQLite. Scalar "
            "material is not stored. This Markdown report does not dump those rows."
        )
    else:
        audit_line = (
            "When Stage B is executed, all public candidate scripts, programs, "
            "addresses, and provenance are stored in SQLite. Scalar material is not "
            "stored. This Markdown report does not dump those rows."
        )

    if stage_b_run is None:
        remaining_followup = (
            "A miss of Stage A P2PKH/P2WPKH addresses is not a proof that no puzzle "
            "exists. The immediate next stored experiment is Stage B, not Stage C."
        )
        next_experiment = """## Next highest-value Stage B experiment (not executed)

Stage B is implemented, offline, and requires a completed Stage A result in
the same database. Run `run --stage B`. Do not execute Stage C until that
Stage B run is stored."""
    else:
        remaining_followup = (
            "A miss of these six templates is not a proof that no puzzle exists. "
            "Remaining open work is other scripts, other encodings, and the bounded "
            "Stage C experiment below."
        )
        next_experiment = f"""## Next highest-value Stage C experiment (not executed)

Hypothesis, not a claim: after the executed Stage A+B set, the single
highest-value next experiment is a *bounded pairwise combination* of the
actual nonce and timestamp ASCII decimal values (`2083236893` and
`1231006505`) in both orders (`nonce || separator || timestamp` and
`timestamp || separator || nonce`) with exactly these seven separators:

{chr(10).join(separator_lines)}

SHA256 each of those 14 public strings, then apply the same six P2WSH
templates. Do not execute Stage C here. Do not add broader combinations,
extra fields, dates, neighborhoods, or brute force."""

    return f"""# Genesis Puzzle — Stage A+B report

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
scalar or as SHA256 of that field, produces a standard Bitcoin address or a
generic single-key P2WSH program that can be compared against a later suspected
puzzle output.

This is not a general private-key cracking framework. Deterministic Stages A
and B are implemented. Stage C, brute force, PBKDF2/BIP39, Metal, transaction
creation, wallet import, spending, and broadcasting are out of scope.

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

`init` re-runs these proofs before any Stage A or Stage B derivation.

## Hypotheses tested in Stage A

Stage A only uses canonical public values and two justified 32-byte hash
orders (wire/internal and display). It does not expand into case folding,
separators, dates, newlines, permutations, neighborhoods, repeated hashes, or
combinations.

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

{_run_lines("Stage A run:", stage_a_run, "No Stage A run stored yet.")}

{stage_a_result}

{address_comparison_note}

### Address history

Stage A derived 66 standard addresses (22 unique keys times three types).
History below is that Stage A address snapshot. Direct P2WSH comparison in
Stage B uses `SHA256(witnessScript)` against the 32-byte witness program and
does not need a blockchain-history lookup.

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

## Hypotheses tested in Stage B

The suspected target is P2WSH (`{target_address}`). HASH160(pubkey) is the
wrong program length and the wrong script template compared with
`SHA256(witnessScript)`. Stage B therefore does two bounded things:

1. A representation matrix of canonical encodings of primitives physically
   present in the Genesis block (ASCII decimal with newline, hex case and `0x`
   prefixes, fixed-width and distinct minimal endian forms, justified hash
   byte orders, raw header/tx/script/key/block bytes) plus a few exact
   lower-priority semantic UTF-8 strings. Each recipe is SHA256 of a canonical
   encoding, or a direct big-endian integer of a canonical fixed 4-byte or
   8-byte endian byte sequence. No pairwise combinations, dates, typos,
   neighborhoods, PBKDF2/BIP39, or brute force.
2. Six generic single-key witness-script templates, in this global priority,
   compared by exact `SHA256(witnessScript)` and native mainnet P2WSH address
   against witness program `{target_program}`:

    <compressed pubkey> OP_CHECKSIG

Compressed templates are the modern canonical, descriptor-compatible forms.
Uncompressed P2WSH pubkeys were tested only as lower-priority
historical/manual possibilities and are not standard descriptor-compatible.

## Stage B results

{_run_lines("Stage B run:", stage_b_run, "No Stage B run stored yet.")}

{stage_b_result}

Witness templates in actual priority:

{chr(10).join(template_lines)}

{subset_note}

{witness_verdict}

{audit_line}

### Derivations

{chr(10).join(derivation_lines) if derivation_lines else "- none stored yet"}

### Eliminated hypotheses

{chr(10).join(eliminated) if eliminated else "- none"}

### Remaining hypotheses

{remaining_text}

{remaining_followup}

{next_experiment}

## Resource and safety notes

- Balanced mode is the default. Stage A and Stage B are sequential.
- Pause/resume/checkpointing are future bounded-search features and are not
  needed here (`checkpoint-not-needed`).
- GPU is disabled. No temperature is measured.
- Offline is the default. Stage B never queries chain history. Remote history
  checks are explicit, batched, and send derived public addresses only.
- Do not paste candidate scalars into a wallet. This tool will not import
  keys, build transactions, or broadcast.

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
