from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from genesis_puzzle.model import GenesisFacts, KnownTarget
from genesis_puzzle.stage_c import STAGE_C_SEPARATORS
from genesis_puzzle.witness import WITNESS_TEMPLATES

TEMPLATE_COUNT = len(WITNESS_TEMPLATES)
EXPECTED_STAGE_C_RECIPES = 14
EXPECTED_STAGE_C_NEW_UNIQUE = 14
EXPECTED_STAGE_C_SCRIPTS = EXPECTED_STAGE_C_NEW_UNIQUE * TEMPLATE_COUNT
EXPECTED_STAGE_D_RECIPES = 40
EXPECTED_STAGE_D_NEW_UNIQUE = 40
EXPECTED_STAGE_D_SCRIPTS = EXPECTED_STAGE_D_NEW_UNIQUE * TEMPLATE_COUNT
EXPECTED_STAGE_E_KEYS = 8
EXPECTED_STAGE_E_SCRIPTS = EXPECTED_STAGE_E_KEYS * TEMPLATE_COUNT
KNOWN_WITNESS_STAGES = frozenset({"B", "C", "D"})
STAGE_E_DATE_STRINGS: tuple[str, ...] = (
    "2009-01-03T18:15:05Z",
    "2009-01-03 18:15:05 UTC",
    "2009-01-03",
    "03/Jan/2009",
    "03/01/2009",
    "01/03/2009",
    "03Jan2009",
    "20090103",
)
STAGE_E_DATE_NOTES: tuple[str, ...] = (
    "",
    "",
    "",
    "",
    " (European/day-first ambiguous)",
    " (American/month-first ambiguous)",
    "",
    "",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def _as_int(mapping: Mapping[str, Any] | None, key: str, default: int = 0) -> int:
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


def _witness_stage(item: Mapping[str, Any]) -> str:
    value = item.get("first_tested_stage")
    if value is None or value == "":
        return "B"
    stage = str(value)
    if stage in KNOWN_WITNESS_STAGES:
        return stage
    return stage  # unknown must not silently become B


def _run_lines(title: str, run: Mapping[str, Any] | None, missing: str) -> str:
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


def _template_lines(candidates: Sequence[Mapping[str, Any]]) -> list[str]:
    template_counts: Counter[str] = Counter()
    for item in candidates:
        name = str(item.get("template_id") or item.get("template_name") or "")
        if name:
            template_counts[name] += 1
    lines = []
    for template in WITNESS_TEMPLATES:
        kind = (
            "compressed; modern canonical / descriptor-compatible"
            if template.pubkey_mode == "compressed"
            else (
                "uncompressed; lower-priority historical/manual possibility, "
                "not standard descriptor-compatible"
            )
        )
        lines.append(
            f"- priority {template.priority}: `{template.name}` ({kind}); "
            f"tested {template_counts.get(template.name, 0)}"
        )
    return lines


def _separator_lines() -> list[str]:
    return [
        f"{index}. {separator.name} `{separator.token}`"
        for index, separator in enumerate(STAGE_C_SEPARATORS, start=1)
    ]


def _d_formula_lines(facts: GenesisFacts) -> list[str]:
    values = {"nonce": facts.nonce, "timestamp": facts.timestamp}
    lines = []
    index = 0
    for distance in range(1, 11):
        for field in ("nonce", "timestamp"):
            public_value = values[field]
            for offset in (-distance, distance):
                index += 1
                signed = f"{offset:+d}"
                lines.append(f"{index}. `k = uint({field}={public_value}) + ({signed})`")
    return lines


def _stage_e_date_lines() -> list[str]:
    pairs = list(zip(STAGE_E_DATE_STRINGS, STAGE_E_DATE_NOTES))
    if len(pairs) != EXPECTED_STAGE_E_KEYS:
        raise ValueError("Stage E requires exactly eight date/time strings")
    return [f"{index}. `{text}`{note}" for index, (text, note) in enumerate(pairs, start=1)]


def render_report(
    facts: GenesisFacts,
    targets: Sequence[KnownTarget],
    counts: Mapping[str, int],
    latest_run: Mapping[str, Any] | None,
    derivations: Sequence[Mapping[str, Any]],
    comparisons: Sequence[Mapping[str, Any]],
    checked_history: Sequence[Mapping[str, Any]],
    witness_candidates: Sequence[Mapping[str, Any]] = (),
    stage_a_run: Mapping[str, Any] | None = None,
    stage_b_run: Mapping[str, Any] | None = None,
    stage_c_run: Mapping[str, Any] | None = None,
    stage_d_run: Mapping[str, Any] | None = None,
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
    if (
        stage_c_run is None
        and latest_run is not None
        and str(latest_run.get("stage") or "") == "C"
    ):
        stage_c_run = latest_run
    if (
        stage_d_run is None
        and latest_run is not None
        and str(latest_run.get("stage") or "") == "D"
    ):
        stage_d_run = latest_run

    stage_a_rows = _stage_rows(derivations, "A")
    stage_b_rows = _stage_rows(derivations, "B")
    stage_c_rows = _stage_rows(derivations, "C")
    stage_d_rows = _stage_rows(derivations, "D")
    b_witness = [item for item in witness_candidates if _witness_stage(item) == "B"]
    c_witness = [item for item in witness_candidates if _witness_stage(item) == "C"]
    d_witness = [item for item in witness_candidates if _witness_stage(item) == "D"]
    has_current_c = bool(stage_c_rows) or bool(c_witness)
    has_current_d = bool(stage_d_rows) or bool(d_witness)
    if not has_current_c:
        stage_c_run = None
    if not has_current_d:
        stage_d_run = None

    stage_a_invalid = sum(1 for item in stage_a_rows if not _truthy(item.get("valid")))
    stage_b_invalid = sum(1 for item in stage_b_rows if not _truthy(item.get("valid")))
    stage_c_invalid = sum(1 for item in stage_c_rows if not _truthy(item.get("valid")))
    stage_d_invalid = sum(1 for item in stage_d_rows if not _truthy(item.get("valid")))
    stage_a_unique = len(_unique_fingerprints(stage_a_rows))
    if stage_a_run is not None and stage_a_unique == 0:
        stage_a_unique = _as_int(stage_a_run, "unique_valid_keys")

    unique_keys = int(counts.get("unique_keys", 0))
    address_match_n = int(counts.get("target_matches", 0))
    b_match_n = sum(1 for item in b_witness if _truthy(item.get("matched")))
    c_match_n = sum(1 for item in c_witness if _truthy(item.get("matched")))
    d_match_n = sum(1 for item in d_witness if _truthy(item.get("matched")))
    if not witness_candidates:
        stored_matches = int(counts.get("witness_matches", 0))
        b_match_n = stored_matches
        c_match_n = 0
        d_match_n = 0
    b_tested_witness = len(b_witness)
    c_tested_witness = len(c_witness)
    d_tested_witness = len(d_witness)
    if b_tested_witness == 0:
        b_tested_witness = (
            int(counts.get("witness_candidates", 0))
            if not has_current_c and not has_current_d
            else 0
        )

    b_cumulative_unique = unique_keys
    b_cumulative_duplicates = _as_int(latest_run, "duplicate_count")
    if stage_b_run is not None:
        b_cumulative_unique = _as_int(stage_b_run, "unique_valid_keys", unique_keys)
        b_cumulative_duplicates = _as_int(stage_b_run, "duplicate_count")
        if _as_int(stage_b_run, "tested_candidate_count") and b_tested_witness == 0:
            b_tested_witness = _as_int(stage_b_run, "tested_candidate_count")
    elif stage_a_run is not None:
        b_cumulative_unique = _as_int(
            stage_a_run, "unique_valid_keys", unique_keys or stage_a_unique
        )
        b_cumulative_duplicates = _as_int(stage_a_run, "duplicate_count")

    c_cumulative_unique = _as_int(stage_c_run, "unique_valid_keys", unique_keys)
    c_cumulative_duplicates = _as_int(stage_c_run, "duplicate_count")
    if _as_int(stage_c_run, "tested_candidate_count") and c_tested_witness == 0:
        c_tested_witness = _as_int(stage_c_run, "tested_candidate_count")
    d_cumulative_unique = _as_int(stage_d_run, "unique_valid_keys", unique_keys)
    d_cumulative_duplicates = _as_int(stage_d_run, "duplicate_count")
    if _as_int(stage_d_run, "tested_candidate_count") and d_tested_witness == 0:
        d_tested_witness = _as_int(stage_d_run, "tested_candidate_count")

    ab_fingerprints = _unique_fingerprints(stage_a_rows) | _unique_fingerprints(stage_b_rows)
    c_fingerprints = _unique_fingerprints(stage_c_rows)
    if not c_fingerprints:
        c_fingerprints = {
            str(item["fingerprint"]) for item in c_witness if item.get("fingerprint")
        }
    if c_fingerprints:
        c_new_unique = (
            len(c_fingerprints - ab_fingerprints) if ab_fingerprints else len(c_fingerprints)
        )
    elif has_current_c:
        c_new_unique = max(0, c_cumulative_unique - b_cumulative_unique)
    else:
        c_new_unique = 0
    abc_fingerprints = ab_fingerprints | c_fingerprints
    d_fingerprints = _unique_fingerprints(stage_d_rows)
    if not d_fingerprints:
        d_fingerprints = {
            str(item["fingerprint"]) for item in d_witness if item.get("fingerprint")
        }
    if d_fingerprints:
        d_new_unique = (
            len(d_fingerprints - abc_fingerprints) if abc_fingerprints else len(d_fingerprints)
        )
    elif has_current_d:
        d_new_unique = max(0, d_cumulative_unique - c_cumulative_unique)
    else:
        d_new_unique = 0

    stage_a_only_scripts = stage_a_unique * TEMPLATE_COUNT
    combined_scripts = b_cumulative_unique * TEMPLATE_COUNT
    c_new_scripts = c_new_unique * TEMPLATE_COUNT
    d_new_scripts = d_new_unique * TEMPLATE_COUNT
    abc_scripts = b_tested_witness + c_tested_witness
    if has_current_c and abc_scripts == 0:
        abc_scripts = c_cumulative_unique * TEMPLATE_COUNT
    abcd_scripts = abc_scripts + d_tested_witness
    if has_current_d and abcd_scripts == 0:
        abcd_scripts = d_cumulative_unique * TEMPLATE_COUNT

    complete_no_match_c = (
        has_current_c
        and c_match_n == 0
        and c_tested_witness == EXPECTED_STAGE_C_SCRIPTS
        and c_new_unique == EXPECTED_STAGE_C_NEW_UNIQUE
    )
    complete_no_match_d = (
        has_current_d
        and d_match_n == 0
        and d_tested_witness == EXPECTED_STAGE_D_SCRIPTS
        and d_new_unique == EXPECTED_STAGE_D_NEW_UNIQUE
    )

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

    template_lines = _template_lines(b_witness)
    c_template_lines = _template_lines(c_witness)
    d_template_lines = _template_lines(d_witness)

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
            f"({b_cumulative_unique} cumulative unique keys times {TEMPLATE_COUNT} "
            "templates). The Stage-A-only subset is contained in the combined set; "
            "it is not an extra 132 on top of 630. "
            f"The executed Stage B run tested {b_tested_witness} witness candidates."
        )
        if b_match_n:
            witness_verdict = (
                f"{b_match_n} direct P2WSH target-script match(es) were stored. "
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
            f"- cumulative unique valid keys after A+B: {b_cumulative_unique}\n"
            f"- cumulative duplicate provenance paths after A+B: {b_cumulative_duplicates}\n"
            f"- tested witness candidates: {b_tested_witness}\n"
            f"- P2WSH direct target matches: {b_match_n}"
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
    elif has_current_d and d_match_n:
        remaining_text = (
            f"{remaining_n} stored valid derivation ids are listed once under "
            "Derivations. Review the stored P2WSH match(es) before any claim. "
            "This is not by itself a solved puzzle."
        )
    elif has_current_d:
        remaining_text = (
            f"{remaining_n} stored valid derivation ids remain open as public-key "
            "hypotheses, not as matches. They are listed once under Derivations. "
            "Stage A P2PKH/P2WPKH addresses still do not test the P2WSH program. "
            "The six generic single-key P2WSH templates did not match the target "
            f"on the preserved Stage B set, the {c_new_unique} new Stage C keys, "
            f"or the {d_new_unique} new Stage D keys. Other scripts and encodings "
            "remain untested."
        )
    elif has_current_c and c_match_n:
        remaining_text = (
            f"{remaining_n} stored valid derivation ids are listed once under "
            "Derivations. Review the stored P2WSH match(es) before any claim. "
            "This is not by itself a solved puzzle."
        )
    elif has_current_c:
        remaining_text = (
            f"{remaining_n} stored valid derivation ids remain open as public-key "
            "hypotheses, not as matches. They are listed once under Derivations. "
            "Stage A P2PKH/P2WPKH addresses still do not test the P2WSH program. "
            "The six generic single-key P2WSH templates did not match the target "
            f"on the preserved Stage B set or the {c_new_unique} new Stage C keys. "
            "Other scripts, encodings, and neighborhoods remain untested."
        )
    elif stage_b_run is not None and b_match_n == 0:
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

    separator_lines = _separator_lines()
    d_formula_lines = _d_formula_lines(facts)
    stage_e_date_lines = _stage_e_date_lines()
    if stage_b_run is not None:
        audit_line = (
            f"All {b_tested_witness} public candidate scripts, programs, addresses, and "
            "provenance for the executed Stage B run are stored in SQLite. Scalar "
            "material is not stored. This Markdown report does not dump those rows."
        )
    else:
        audit_line = (
            "When Stage B is executed, all public candidate scripts, programs, "
            "addresses, and provenance are stored in SQLite. Scalar material is not "
            "stored. This Markdown report does not dump those rows."
        )

    if has_current_d and d_match_n:
        remaining_followup = (
            "A stored P2WSH template match is not by itself a solved puzzle. "
            "Do not execute Stage E."
        )
        next_experiment = ""
    elif complete_no_match_d:
        remaining_followup = (
            "A miss of these six templates on the executed Stage D keys is not a "
            "proof that no puzzle exists. Remaining open work is other scripts, "
            "other encodings, and the bounded Stage E experiment below."
        )
        next_experiment = f"""## Next highest-value Stage E experiment (not executed)

Hypothesis, not a claim: after the executed Stage A+B+C+D set, the single
highest-value next experiment is SHA256 once over exactly these eight UTF-8
date/time strings, in this order:

{chr(10).join(stage_e_date_lines)}

Eight candidate keys, at most {EXPECTED_STAGE_E_SCRIPTS} scripts. Do not add
newline, case, or whitespace variants. Do not add alternate time zones or
other dates. Do not use PBKDF2, BIP39, repeated hashing, GPU, neighborhoods,
larger combinations, or brute force. Do not execute Stage E here."""
    elif has_current_d:
        remaining_followup = (
            "A miss of these six templates on the executed Stage D keys is not a "
            "proof that no puzzle exists. Remaining open work is other scripts "
            "and other encodings. Do not execute Stage E."
        )
        next_experiment = ""
    elif has_current_c and c_match_n:
        remaining_followup = (
            "A stored P2WSH template match is not by itself a solved puzzle. "
            "Do not execute Stage D. Do not execute Stage E."
        )
        next_experiment = ""
    elif complete_no_match_c:
        remaining_followup = (
            "A miss of these six templates on the executed Stage C keys is not a "
            "proof that no puzzle exists. Remaining open work is other scripts, "
            "other encodings, and the bounded Stage D experiment below."
        )
        next_experiment = f"""## Next highest-value Stage D experiment (not executed)

Hypothesis, not a claim: after the executed Stage A+B+C set, the single
highest-value next experiment is a *bounded direct-scalar neighborhood* of
the actual nonce (`{facts.nonce}`) and timestamp (`{facts.timestamp}`).
Use integer offsets -10..-1 and +1..+10, excluding zero: twenty nonce
offsets and twenty timestamp offsets, 40 keys. Apply the same six P2WSH
templates, at most 240 scripts.

Stage D is implemented, offline, and requires a completed Stage C result in
the same database. Run `run --stage D`. Do not hash. Do not form
combinations. Do not add dates. Do not enlarge the window. Do not use
PBKDF2, BIP39, GPU, or brute force. Do not execute Stage E.
Stage E and later hypotheses remain out of scope."""
    elif stage_b_run is None:
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
actual nonce and timestamp ASCII decimal values (`{facts.nonce}` and
`{facts.timestamp}`) in both orders (`nonce || separator || timestamp` and
`timestamp || separator || nonce`) with exactly these seven separators:

{chr(10).join(separator_lines)}

SHA256 each of those 14 public strings, then apply the same six P2WSH
templates. Do not execute Stage C here. Do not add broader combinations,
extra fields, dates, neighborhoods, or brute force."""

    if has_current_d:
        title_stage = "A+B+C+D"
        implemented_scope = (
            "Deterministic Stages A, B, C, and D are implemented. Stage E, brute force, "
            "PBKDF2/BIP39, Metal, transaction creation, wallet import, spending, and "
            "broadcasting are out of scope."
        )
        init_proofs = "Stage A, Stage B, Stage C, or Stage D"
        sequential_note = "Stage A, Stage B, Stage C, and Stage D are sequential."
        offline_note = (
            "Offline is the default. Stage B, Stage C, and Stage D never query chain "
            "history. Remote history checks are explicit, batched, and send derived "
            "public addresses only."
        )
    elif has_current_c:
        title_stage = "A+B+C"
        implemented_scope = (
            "Deterministic Stages A, B, C, and D are implemented. Stage E, brute force, "
            "PBKDF2/BIP39, Metal, transaction creation, wallet import, spending, and "
            "broadcasting are out of scope."
        )
        init_proofs = "Stage A, Stage B, Stage C, or Stage D"
        sequential_note = "Stage A, Stage B, Stage C, and Stage D are sequential."
        offline_note = (
            "Offline is the default. Stage B, Stage C, and Stage D never query chain "
            "history. Remote history checks are explicit, batched, and send derived "
            "public addresses only."
        )
    else:
        title_stage = "A+B"
        implemented_scope = (
            "Deterministic Stages A and B are implemented. Stage C, brute force, "
            "PBKDF2/BIP39, Metal, transaction creation, wallet import, spending, and "
            "broadcasting are out of scope."
        )
        init_proofs = "Stage A or Stage B"
        sequential_note = "Stage A and Stage B are sequential."
        offline_note = (
            "Offline is the default. Stage B never queries chain history. Remote history "
            "checks are explicit, batched, and send derived public addresses only."
        )

    stage_c_section = ""
    if has_current_c:
        stage_c_n = len(stage_c_rows) or _as_int(stage_c_run, "derivation_count")
        if c_match_n:
            c_verdict = (
                f"{c_match_n} direct P2WSH target-script match(es) were stored for "
                "Stage C keys. Review before any further claim. This report does not "
                "treat a template match as a solved puzzle by itself."
            )
        else:
            c_verdict = (
                "Zero stored Stage C witness candidates equal the suspected 32-byte "
                "witness program or its native P2WSH address. That does not disprove "
                f"the puzzle. The announcement target remains `{target_status}`."
            )
        c_subset = (
            f"The {c_new_scripts} new Stage C scripts are {c_new_unique} unique Stage C "
            f"keys times {TEMPLATE_COUNT} templates. The full combined A+B+C set is "
            f"{abc_scripts} scripts ({c_cumulative_unique} cumulative unique keys times "
            f"{TEMPLATE_COUNT} templates). The executed Stage B run still tested "
            f"{b_tested_witness} first_tested_stage=B rows; those {b_tested_witness} are "
            "preserved and are not replaced. "
            f"The executed Stage C run tested {c_tested_witness} first_tested_stage=C "
            f"rows. Combined B+C is {abc_scripts}; it is not an extra {c_new_scripts} "
            f"on top of {abc_scripts}."
        )
        c_audit = (
            f"All {c_tested_witness} public Stage C candidate scripts, programs, "
            "addresses, and provenance are stored in SQLite alongside the preserved "
            "Stage B rows. Scalar material is not stored. This Markdown report does "
            "not dump those rows."
        )
        stage_c_result = (
            f"- Stage C derivations: {stage_c_n}\n"
            f"- Stage C invalid derivations: "
            f"{stage_c_invalid or _as_int(stage_c_run, 'invalid_count')}\n"
            f"- Stage C new unique valid keys: {c_new_unique}\n"
            f"- cumulative unique valid keys after A+B+C: {c_cumulative_unique}\n"
            f"- cumulative duplicate provenance paths after A+B+C: "
            f"{c_cumulative_duplicates}\n"
            f"- new Stage C witness candidates: {c_tested_witness}\n"
            f"- cumulative B+C witness candidates: {abc_scripts}\n"
            f"- P2WSH direct target matches: {c_match_n}"
        )
        stage_c_section = f"""
## Hypotheses tested in Stage C

Stage C is the implemented bounded pairwise combination of the actual nonce
and timestamp ASCII decimal values (`{facts.nonce}` and `{facts.timestamp}`)
in both orders (`nonce || separator || timestamp` and
`timestamp || separator || nonce`) with exactly these seven separators:

{chr(10).join(separator_lines)}

Each of those {EXPECTED_STAGE_C_RECIPES} public strings is SHA256'd, then the
same six P2WSH templates are applied. No extra fields, dates, neighborhoods,
PBKDF2/BIP39, or brute force.

## Stage C results

{_run_lines("Stage C run:", stage_c_run, "No Stage C run stored yet.")}

{stage_c_result}

Witness templates in actual priority (Stage C keys only; six templates times
{c_new_unique} keys):

{chr(10).join(c_template_lines)}

{c_subset}

{c_verdict}

{c_audit}

"""

    stage_d_section = ""
    if has_current_d:
        stage_d_n = len(stage_d_rows) or _as_int(stage_d_run, "derivation_count")
        if d_match_n:
            d_verdict = (
                f"{d_match_n} direct P2WSH target-script match(es) were stored for "
                "Stage D keys. Review before any further claim. This report does not "
                "treat a template match as a solved puzzle by itself."
            )
        else:
            d_verdict = (
                "Zero stored Stage D witness candidates equal the suspected 32-byte "
                "witness program or its native P2WSH address. That does not disprove "
                f"the puzzle. The announcement target remains `{target_status}`."
            )
        d_subset = (
            f"The {d_new_scripts} new Stage D scripts are {d_new_unique} unique Stage D "
            f"keys times {TEMPLATE_COUNT} templates. The full combined A+B+C+D set is "
            f"{abcd_scripts} scripts ({d_cumulative_unique} cumulative unique keys times "
            f"{TEMPLATE_COUNT} templates). The executed Stage B run still tested "
            f"{b_tested_witness} first_tested_stage=B rows; those {b_tested_witness} are "
            "preserved and are not replaced. "
            f"The executed Stage C run still tested {c_tested_witness} "
            f"first_tested_stage=C rows; those {c_tested_witness} are preserved and are "
            "not replaced. "
            f"The executed Stage D run tested {d_tested_witness} first_tested_stage=D "
            f"rows. Combined B+C remains {abc_scripts}. Combined B+C+D is {abcd_scripts}; "
            f"it is not an extra {d_new_scripts} on top of {abcd_scripts}."
        )
        d_audit = (
            f"All {d_tested_witness} public Stage D candidate scripts, programs, "
            "addresses, and provenance are stored in SQLite alongside the preserved "
            "Stage B and Stage C rows. Scalar material is not stored. public_input "
            "bytes stay empty. The raw scalar is not stored or logged. Formula, signed "
            "offset, and fingerprint are sufficient to recompute. This Markdown report "
            "does not dump those rows."
        )
        stage_d_result = (
            f"- Stage D derivations: {stage_d_n}\n"
            f"- Stage D invalid derivations: "
            f"{stage_d_invalid or _as_int(stage_d_run, 'invalid_count')}\n"
            f"- Stage D new unique valid keys: {d_new_unique}\n"
            f"- cumulative unique valid keys after A+B+C+D: {d_cumulative_unique}\n"
            f"- cumulative duplicate provenance paths after A+B+C+D: "
            f"{d_cumulative_duplicates}\n"
            f"- new Stage D witness candidates: {d_tested_witness}\n"
            f"- cumulative B+C+D witness candidates: {abcd_scripts}\n"
            f"- P2WSH direct target matches: {d_match_n}"
        )
        stage_d_section = f"""
## Hypotheses tested in Stage D

Stage D is the implemented bounded direct integer-scalar neighborhood of the
actual Genesis nonce (`{facts.nonce}`) and timestamp (`{facts.timestamp}`).
Canonical direct nonce and timestamp values were already Stage A, so offset
zero is excluded. Offsets are ±1..±10. Priority is distance-first: for each
distance d from 1 to 10, nonce-d, nonce+d, timestamp-d, timestamp+d. No hashing.

Each of those {EXPECTED_STAGE_D_RECIPES} recipes is the identity integer
`k = uint(field=public_value) + (signed_offset)`. public_input bytes stay
empty. The raw scalar is not stored or logged. The formula, signed offset,
and fingerprint are sufficient to recompute the same public key.

Exact order:

{chr(10).join(d_formula_lines)}

The same six P2WSH templates are applied. No extra fields, dates, combinations,
PBKDF2/BIP39, or brute force.

## Stage D results

{_run_lines("Stage D run:", stage_d_run, "No Stage D run stored yet.")}

{stage_d_result}

Witness templates in actual priority (Stage D keys only; six templates times
{d_new_unique} keys):

{chr(10).join(d_template_lines)}

{d_subset}

{d_verdict}

{d_audit}

"""

    return f"""# Genesis Puzzle — Stage {title_stage} report

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

This is not a general private-key cracking framework. {implemented_scope}

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

`init` re-runs these proofs before any {init_proofs} derivation.

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
{stage_c_section}{stage_d_section}
### Derivations

{chr(10).join(derivation_lines) if derivation_lines else "- none stored yet"}

### Eliminated hypotheses

{chr(10).join(eliminated) if eliminated else "- none"}

### Remaining hypotheses

{remaining_text}

{remaining_followup}

{next_experiment}

## Resource and safety notes

- Balanced mode is the default. {sequential_note}
- Pause/resume/checkpointing are future bounded-search features and are not
  needed here (`checkpoint-not-needed`).
- GPU is disabled. No temperature is measured.
- {offline_note}
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
