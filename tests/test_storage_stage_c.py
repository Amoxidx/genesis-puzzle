from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path

import pytest

import genesis_puzzle.storage as storage_mod
from genesis_puzzle.storage import (
    connect,
    dump_text,
    insert_run,
    invalidate_stage_c_current_state,
    list_witness_candidates,
    replace_stage_c_witness_candidates,
    replace_witness_candidates,
    transaction,
    upsert_address,
    upsert_derivation,
    upsert_key,
    upsert_witness_candidate,
    witness_candidate_count,
)

OLD_WITNESS_SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    stage TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    derivation_count INTEGER,
    invalid_count INTEGER,
    unique_valid_keys INTEGER,
    duplicate_count INTEGER,
    address_count INTEGER,
    tested_candidate_count INTEGER,
    elapsed_seconds REAL,
    rate_per_second REAL,
    notes TEXT NOT NULL DEFAULT 'checkpoint-not-needed'
);

CREATE TABLE IF NOT EXISTS keys (
    fingerprint TEXT PRIMARY KEY,
    first_run_id INTEGER NOT NULL REFERENCES runs(id),
    valid INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS witness_candidates (
    id INTEGER PRIMARY KEY,
    fingerprint TEXT NOT NULL REFERENCES keys(fingerprint),
    target_id TEXT NOT NULL,
    template_id TEXT NOT NULL,
    template_name TEXT NOT NULL,
    priority INTEGER NOT NULL,
    pubkey_mode TEXT NOT NULL,
    pubkey_hex TEXT NOT NULL,
    witness_script_hex TEXT NOT NULL,
    witness_program_hex TEXT NOT NULL,
    address TEXT NOT NULL,
    derivation_ids TEXT NOT NULL,
    matched INTEGER NOT NULL,
    run_id INTEGER NOT NULL REFERENCES runs(id),
    UNIQUE(fingerprint, target_id, template_id)
);
"""

FORBIDDEN_COLUMN_FRAGMENTS = ("scalar", "private", "secret", "seed")


def _db(isolated: Path) -> Path:
    return isolated / "state" / "research.sqlite"


def _column_map(conn: sqlite3.Connection) -> dict:
    return {
        str(row[1]): row
        for row in conn.execute("PRAGMA table_info(witness_candidates)").fetchall()
    }


def _assert_public_witness_columns(conn: sqlite3.Connection) -> None:
    names = [str(row[1]) for row in conn.execute("PRAGMA table_info(witness_candidates)")]
    for name in names:
        lowered = name.lower()
        for fragment in FORBIDDEN_COLUMN_FRAGMENTS:
            assert fragment not in lowered
    fks = conn.execute("PRAGMA foreign_key_list(witness_candidates)").fetchall()
    assert any(str(row[3]) == "fingerprint" and str(row[2]) == "keys" for row in fks)
    assert any(str(row[3]) == "run_id" and str(row[2]) == "runs" for row in fks)


def _base_witness(
    fingerprint: str,
    target_id: str,
    template_id: str,
    run_id: int,
    first_tested_stage: str = "B",
    derivation_ids: str = "B-001",
) -> dict:
    payload = {
        "fingerprint": fingerprint,
        "target_id": target_id,
        "template_id": template_id,
        "template_name": template_id,
        "priority": 1,
        "pubkey_mode": "compressed",
        "pubkey_hex": "02" + "ab" * 32,
        "witness_script_hex": "21" + "02" + "ab" * 32 + "ac",
        "witness_program_hex": "cd" * 32,
        "address": f"bc1q{template_id[:8]}{fingerprint[:8]}",
        "derivation_ids": derivation_ids,
        "matched": False,
        "run_id": run_id,
    }
    if first_tested_stage is not None:
        payload["first_tested_stage"] = first_tested_stage
    return payload


def _add_derivation(
    conn: sqlite3.Connection, derivation_id: str, fingerprint: str, run_id: int
) -> None:
    upsert_derivation(
        conn,
        derivation_id=derivation_id,
        fingerprint=fingerprint,
        source="test",
        original_public_source="test",
        representation="test",
        public_input_hex="00",
        transformation="none",
        formula="k = 1",
        recipe="test recipe",
        confidence=0.1,
        stage=derivation_id[0],
        valid=True,
        eliminated_reason="",
        run_id=run_id,
    )


def _seed_store(store) -> dict:
    conn = store.conn
    run_a = insert_run(conn, "2026-01-01T00:00:00", "A", "balanced", "ok")
    run_b = insert_run(conn, "2026-01-01T00:01:00", "B", "balanced", "ok")
    run_c = insert_run(conn, "2026-01-01T00:02:00", "C", "balanced", "ok")
    upsert_key(conn, "fp-a", run_a)
    upsert_key(conn, "fp-b", run_b)
    upsert_key(conn, "fp-c", run_c)
    _add_derivation(conn, "A-01", "fp-a", run_a)
    _add_derivation(conn, "B-001", "fp-b", run_b)
    _add_derivation(conn, "C-001", "fp-c", run_c)
    upsert_address(
        conn,
        "fp-a",
        "1AseedAddressxxxxxxxxxxxx",
        "p2pkh_compressed",
        "02" + "11" * 32,
        "compressed",
    )
    upsert_witness_candidate(
        conn, **_base_witness("fp-b", "t1", "p2pk_compressed", run_b, "B", "B-001")
    )
    upsert_witness_candidate(
        conn, **_base_witness("fp-c", "t1", "p2pk_compressed", run_c, "C", "C-001")
    )
    conn.commit()
    return {"run_a": run_a, "run_b": run_b, "run_c": run_c}


def test_old_schema_witness_row_migrates_to_stage_b(isolated):
    path = _db(isolated)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = sqlite3.connect(str(path))
    raw.executescript(OLD_WITNESS_SCHEMA)
    raw.execute(
        "INSERT INTO runs (started_at, stage, mode, status) VALUES (?, ?, ?, ?)",
        ("2026-01-01T00:00:00", "B", "balanced", "ok"),
    )
    run_id = int(raw.execute("SELECT id FROM runs").fetchone()[0])
    raw.execute(
        "INSERT INTO keys (fingerprint, first_run_id, valid) VALUES (?, ?, 1)",
        ("fp-old", run_id),
    )
    raw.execute(
        """
        INSERT INTO witness_candidates (
            fingerprint, target_id, template_id, template_name, priority,
            pubkey_mode, pubkey_hex, witness_script_hex, witness_program_hex,
            address, derivation_ids, matched, run_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "fp-old",
            "t-old",
            "p2pk_compressed",
            "p2pk_compressed",
            1,
            "compressed",
            "02" + "ab" * 32,
            "21ac",
            "cd" * 32,
            "bc1qold",
            "B-001",
            0,
            run_id,
        ),
    )
    raw.commit()
    raw.close()
    assert "first_tested_stage" not in {
        str(row[1])
        for row in sqlite3.connect(str(path)).execute("PRAGMA table_info(witness_candidates)")
    }

    store = connect(path)
    columns = _column_map(store.conn)
    stage_col = columns["first_tested_stage"]
    assert str(stage_col[2]).upper() == "TEXT"
    assert int(stage_col[3]) == 1
    assert "B" in str(stage_col[4])
    sql = store.conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='witness_candidates'"
    ).fetchone()[0]
    assert "CHECK (first_tested_stage IN ('B', 'C', 'D', 'E'))" in sql.replace("\n", " ")
    rows = list_witness_candidates(store.conn)
    assert len(rows) == 1
    assert rows[0]["first_tested_stage"] == "B"
    assert rows[0]["fingerprint"] == "fp-old"
    assert witness_candidate_count(store.conn) == 1
    assert witness_candidate_count(store.conn, "B") == 1
    assert witness_candidate_count(store.conn, "C") == 0
    _assert_public_witness_columns(store.conn)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600


def test_new_database_creates_first_tested_stage_column(isolated):
    store = connect(_db(isolated))
    sql = store.conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='witness_candidates'"
    ).fetchone()[0]
    assert "first_tested_stage TEXT NOT NULL DEFAULT 'B'" in " ".join(sql.split())
    columns = _column_map(store.conn)
    assert int(columns["first_tested_stage"][3]) == 1
    _assert_public_witness_columns(store.conn)


def test_first_tested_stage_rejects_non_b_and_c(isolated):
    store = connect(_db(isolated))
    run_id = insert_run(store.conn, "2026-01-01T00:00:00", "B", "balanced", "ok")
    upsert_key(store.conn, "fp-b", run_id)
    store.conn.commit()
    omitted = _base_witness("fp-b", "t1", "p2pk_compressed", run_id)
    omitted.pop("first_tested_stage")
    upsert_witness_candidate(store.conn, **omitted)
    defaulted = list_witness_candidates(store.conn)
    assert defaulted[0]["first_tested_stage"] == "B"
    upsert_witness_candidate(
        store.conn, **_base_witness("fp-b", "t1", "p2pk_uncompressed", run_id, "C", "C-001")
    )
    assert [row["first_tested_stage"] for row in list_witness_candidates(store.conn)] == ["B", "C"]
    store.conn.commit()
    with pytest.raises(ValueError, match="first_tested_stage must be 'B', 'C', 'D', or 'E'"):
        upsert_witness_candidate(
            store.conn, **_base_witness("fp-b", "t1", "p2pkh_compressed", run_id, "A")
        )
    with pytest.raises(ValueError, match="first_tested_stage must be 'B', 'C', 'D', or 'E'"):
        upsert_witness_candidate(
            store.conn, **_base_witness("fp-b", "t1", "p2pkh_uncompressed", run_id, "b")
        )
    with pytest.raises(sqlite3.IntegrityError):
        store.conn.execute(
            """
            INSERT INTO witness_candidates (
                fingerprint, target_id, template_id, template_name, priority,
                pubkey_mode, pubkey_hex, witness_script_hex, witness_program_hex,
                address, derivation_ids, matched, run_id, first_tested_stage
            ) VALUES (?, ?, 'bad-stage', 'bad-stage', 1, 'compressed', '02aa',
                      '21ac', 'cd', 'bc1q', 'B-001', 0, ?, 'A')
            """,
            ("fp-b", "t1", run_id),
        )
    store.conn.rollback()
    stages = {row["first_tested_stage"] for row in list_witness_candidates(store.conn)}
    assert stages == {"B", "C"}
    dumped = dump_text(store.conn)
    assert "first_tested_stage" in dumped or "'B'" in dumped
    assert "fp-b" in dumped


def test_replace_stage_c_preserves_b_and_is_idempotent(isolated):
    store = connect(_db(isolated))
    ids = _seed_store(store)
    before_b = list_witness_candidates(store.conn, "B")
    assert len(before_b) == 1
    b_snapshot = (
        int(before_b[0]["id"]),
        before_b[0]["fingerprint"],
        before_b[0]["derivation_ids"],
        before_b[0]["first_tested_stage"],
    )
    replacement = _base_witness("fp-c", "t1", "p2pk_compressed", ids["run_c"], "C", "C-001,C-002")
    with transaction(store) as conn:
        replace_stage_c_witness_candidates(conn, ["t1"], [replacement])
    assert witness_candidate_count(store.conn, "B") == 1
    assert witness_candidate_count(store.conn, "C") == 1
    b_rows = list_witness_candidates(store.conn, "B")
    assert (
        int(b_rows[0]["id"]),
        b_rows[0]["fingerprint"],
        b_rows[0]["derivation_ids"],
        b_rows[0]["first_tested_stage"],
    ) == b_snapshot
    assert list_witness_candidates(store.conn, "C")[0]["derivation_ids"] == "C-001,C-002"
    with transaction(store) as conn:
        replace_stage_c_witness_candidates(conn, ["t1"], [replacement])
    after = list_witness_candidates(store.conn)
    assert len(after) == 2
    b_rows = list_witness_candidates(store.conn, "B")
    assert (
        int(b_rows[0]["id"]),
        b_rows[0]["fingerprint"],
        b_rows[0]["derivation_ids"],
        b_rows[0]["first_tested_stage"],
    ) == b_snapshot
    assert list_witness_candidates(store.conn, "C")[0]["derivation_ids"] == "C-001,C-002"
    after_ids = [int(row["id"]) for row in after]
    bad = _base_witness("fp-c", "t1", "p2pk_uncompressed", ids["run_c"], "B")
    with pytest.raises(ValueError, match="first_tested_stage='C'"):
        with transaction(store) as conn:
            replace_stage_c_witness_candidates(conn, ["t1"], [bad])
    assert [int(row["id"]) for row in list_witness_candidates(store.conn)] == after_ids
    b_row = _base_witness("fp-b", "t1", "p2pk_compressed", ids["run_b"], "B", "B-001")
    with transaction(store) as conn:
        replace_witness_candidates(conn, ["t1"], [b_row])
    remaining = list_witness_candidates(store.conn)
    assert len(remaining) == 1
    assert remaining[0]["first_tested_stage"] == "B"
    assert remaining[0]["fingerprint"] == "fp-b"


def test_replace_stage_c_rejects_collision_with_existing_b_without_mutation(isolated):
    store = connect(_db(isolated))
    ids = _seed_store(store)
    before = [(int(row["id"]), dict(row)) for row in list_witness_candidates(store.conn)]
    b_rows = list_witness_candidates(store.conn, "B")
    assert len(b_rows) == 1
    colliding = _base_witness(
        b_rows[0]["fingerprint"],
        b_rows[0]["target_id"],
        b_rows[0]["template_id"],
        ids["run_c"],
        "C",
        "C-collide",
    )
    with pytest.raises(ValueError, match="collide with an existing B row"):
        with transaction(store) as conn:
            replace_stage_c_witness_candidates(conn, ["t1"], [colliding])
    after = list_witness_candidates(store.conn)
    assert [(int(row["id"]), dict(row)) for row in after] == before
    assert witness_candidate_count(store.conn, "B") == 1
    assert witness_candidate_count(store.conn, "C") == 1
    assert all(row["derivation_ids"] != "C-collide" for row in after)


def test_replace_stage_c_rolls_back_on_mid_insert_failure(isolated, monkeypatch):
    store = connect(_db(isolated))
    ids = _seed_store(store)
    original = [(int(row["id"]), dict(row)) for row in list_witness_candidates(store.conn)]
    replacements = [
        _base_witness("fp-c", "t1", "p2pk_compressed", ids["run_c"], "C", "C-001"),
        _base_witness("fp-c", "t1", "p2pk_uncompressed", ids["run_c"], "C", "C-001"),
    ]
    real_upsert = storage_mod.upsert_witness_candidate
    inserted = {"count": 0}

    def flaky(conn, **kwargs):
        inserted["count"] += 1
        result = real_upsert(conn, **kwargs)
        if inserted["count"] >= 2:
            raise RuntimeError("injected stage C replacement failure")
        return result

    monkeypatch.setattr(storage_mod, "upsert_witness_candidate", flaky)
    with pytest.raises(RuntimeError, match="injected stage C replacement failure"):
        with transaction(store) as conn:
            replace_stage_c_witness_candidates(conn, ["t1"], replacements)
    assert inserted["count"] >= 2
    after = list_witness_candidates(store.conn)
    assert [(int(row["id"]), dict(row)) for row in after] == original


def test_invalidate_stage_c_retains_a_and_b_and_drops_orphan_c_keys(isolated):
    store = connect(_db(isolated))
    ids = _seed_store(store)
    run_count = store.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
    assert run_count == 3
    with transaction(store) as conn:
        invalidate_stage_c_current_state(conn)
    assert list_witness_candidates(store.conn, "C") == []
    assert witness_candidate_count(store.conn, "B") == 1
    assert (
        store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'C'").fetchone()[0] == 0
    )
    assert (
        store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'A'").fetchone()[0] == 1
    )
    assert (
        store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'B'").fetchone()[0] == 1
    )
    fingerprints = {
        str(row[0]) for row in store.conn.execute("SELECT fingerprint FROM keys").fetchall()
    }
    assert fingerprints == {"fp-a", "fp-b"}
    assert (
        store.conn.execute("SELECT COUNT(*) FROM addresses WHERE fingerprint = 'fp-a'").fetchone()[
            0
        ]
        == 1
    )
    assert store.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == run_count
    assert {row["id"] for row in store.conn.execute("SELECT id FROM runs")} == {
        ids["run_a"],
        ids["run_b"],
        ids["run_c"],
    }
    b_rows = list_witness_candidates(store.conn)
    assert len(b_rows) == 1
    assert b_rows[0]["first_tested_stage"] == "B"
    assert b_rows[0]["fingerprint"] == "fp-b"
