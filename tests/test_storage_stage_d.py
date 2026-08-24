from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path

import pytest

import genesis_puzzle.storage as storage_mod
from genesis_puzzle.storage import (
    ALLOWED_WITNESS_STAGES,
    connect,
    dump_text,
    insert_run,
    invalidate_stage_c_current_state,
    invalidate_stage_d_current_state,
    list_witness_candidates,
    replace_stage_d_witness_candidates,
    transaction,
    upsert_address,
    upsert_derivation,
    upsert_key,
    upsert_witness_candidate,
    validate_first_tested_stage,
    witness_candidate_count,
)

FORBIDDEN_COLUMN_FRAGMENTS = ("scalar", "private", "secret", "seed")

WITNESS_INSERT_COLUMNS = """
    id, fingerprint, target_id, template_id, template_name, priority,
    pubkey_mode, pubkey_hex, witness_script_hex, witness_program_hex,
    address, derivation_ids, matched, run_id
"""

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

BC_WITNESS_SCHEMA = """
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
    first_tested_stage TEXT NOT NULL DEFAULT 'B'
        CHECK (first_tested_stage IN ('B', 'C')),
    UNIQUE(fingerprint, target_id, template_id)
);
"""


def _db(isolated: Path) -> Path:
    return isolated / "state" / "research.sqlite"


def _column_map(conn: sqlite3.Connection) -> dict:
    return {
        str(row[1]): row
        for row in conn.execute("PRAGMA table_info(witness_candidates)").fetchall()
    }


def _witness_sql(conn: sqlite3.Connection) -> str:
    sql = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='witness_candidates'"
    ).fetchone()[0]
    return " ".join(str(sql).split())


def _assert_bcd_schema(conn: sqlite3.Connection) -> None:
    sql = _witness_sql(conn)
    assert "first_tested_stage TEXT NOT NULL DEFAULT 'B'" in sql
    assert "CHECK (first_tested_stage IN ('B', 'C', 'D'))" in sql
    columns = _column_map(conn)
    stage_col = columns["first_tested_stage"]
    assert str(stage_col[2]).upper() == "TEXT"
    assert int(stage_col[3]) == 1
    assert "B" in str(stage_col[4])
    names = [str(row[1]) for row in conn.execute("PRAGMA table_info(witness_candidates)")]
    for name in names:
        lowered = name.lower()
        for fragment in FORBIDDEN_COLUMN_FRAGMENTS:
            assert fragment not in lowered
    fks = conn.execute("PRAGMA foreign_key_list(witness_candidates)").fetchall()
    assert any(str(row[3]) == "fingerprint" and str(row[2]) == "keys" for row in fks)
    assert any(str(row[3]) == "run_id" and str(row[2]) == "runs" for row in fks)
    indexes = conn.execute("PRAGMA index_list(witness_candidates)").fetchall()
    assert any(int(row[2]) == 1 for row in indexes)


def _named_witness_rows(conn: sqlite3.Connection) -> list:
    columns = [str(row[1]) for row in conn.execute("PRAGMA table_info(witness_candidates)")]
    rows = conn.execute("SELECT * FROM witness_candidates ORDER BY id").fetchall()
    return [{columns[i]: row[i] for i in range(len(columns))} for row in rows]


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
        "first_tested_stage": first_tested_stage,
    }
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


def _snapshot_rows(conn: sqlite3.Connection, stage: str | None = None) -> list:
    rows = list_witness_candidates(conn, stage) if stage else list_witness_candidates(conn)
    return [(int(row["id"]), dict(row)) for row in rows]


def _seed_store(store) -> dict:
    conn = store.conn
    run_a = insert_run(conn, "2026-01-01T00:00:00", "A", "balanced", "ok")
    run_b = insert_run(conn, "2026-01-01T00:01:00", "B", "balanced", "ok")
    run_c = insert_run(conn, "2026-01-01T00:02:00", "C", "balanced", "ok")
    run_d = insert_run(conn, "2026-01-01T00:03:00", "D", "balanced", "ok")
    upsert_key(conn, "fp-a", run_a)
    upsert_key(conn, "fp-b", run_b)
    upsert_key(conn, "fp-c", run_c)
    upsert_key(conn, "fp-d", run_d)
    _add_derivation(conn, "A-01", "fp-a", run_a)
    _add_derivation(conn, "B-001", "fp-b", run_b)
    _add_derivation(conn, "C-001", "fp-c", run_c)
    _add_derivation(conn, "D-001", "fp-d", run_d)
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
    upsert_witness_candidate(
        conn, **_base_witness("fp-d", "t1", "p2pk_compressed", run_d, "D", "D-001")
    )
    conn.commit()
    return {"run_a": run_a, "run_b": run_b, "run_c": run_c, "run_d": run_d}


def _open_legacy(path: Path, schema: str) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = sqlite3.connect(str(path))
    raw.execute("PRAGMA foreign_keys = ON")
    raw.executescript(schema)
    return raw


def test_new_database_creates_bcd_first_tested_stage_schema(isolated):
    path = _db(isolated)
    store = connect(path)
    assert ALLOWED_WITNESS_STAGES == frozenset({"B", "C", "D"})
    _assert_bcd_schema(store.conn)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600
    dumped = dump_text(store.conn)
    assert "witness_candidates" in dumped


def test_legacy_schema_without_stage_column_migrates_to_b_with_bcd_check(isolated):
    path = _db(isolated)
    raw = _open_legacy(path, OLD_WITNESS_SCHEMA)
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
        f"""
        INSERT INTO witness_candidates (
            {WITNESS_INSERT_COLUMNS}
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            7,
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
    _assert_bcd_schema(store.conn)
    rows = list_witness_candidates(store.conn)
    assert len(rows) == 1
    assert int(rows[0]["id"]) == 7
    assert rows[0]["first_tested_stage"] == "B"
    assert rows[0]["fingerprint"] == "fp-old"
    assert rows[0]["run_id"] == run_id
    assert witness_candidate_count(store.conn) == 1
    assert witness_candidate_count(store.conn, "B") == 1
    assert witness_candidate_count(store.conn, "C") == 0
    assert witness_candidate_count(store.conn, "D") == 0
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600


def test_bc_schema_rebuilds_to_bcd_preserving_rows_ids_and_fks(isolated):
    path = _db(isolated)
    raw = _open_legacy(path, BC_WITNESS_SCHEMA)
    raw.execute(
        "INSERT INTO runs (id, started_at, stage, mode, status) VALUES (?, ?, ?, ?, ?)",
        (3, "2026-01-01T00:00:00", "B", "balanced", "ok"),
    )
    raw.execute(
        "INSERT INTO runs (id, started_at, stage, mode, status) VALUES (?, ?, ?, ?, ?)",
        (4, "2026-01-01T00:01:00", "C", "balanced", "ok"),
    )
    raw.execute(
        "INSERT INTO keys (fingerprint, first_run_id, valid) VALUES (?, ?, 1)",
        ("fp-b", 3),
    )
    raw.execute(
        "INSERT INTO keys (fingerprint, first_run_id, valid) VALUES (?, ?, 1)",
        ("fp-c", 4),
    )
    raw.execute(
        f"""
        INSERT INTO witness_candidates (
            {WITNESS_INSERT_COLUMNS}, first_tested_stage
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            11,
            "fp-b",
            "t1",
            "p2pk_compressed",
            "p2pk_compressed",
            4,
            "compressed",
            "02" + "11" * 32,
            "21aa",
            "aa" * 32,
            "bc1qbrow",
            "B-001,B-002",
            0,
            3,
            "B",
        ),
    )
    raw.execute(
        f"""
        INSERT INTO witness_candidates (
            {WITNESS_INSERT_COLUMNS}, first_tested_stage
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            23,
            "fp-c",
            "t1",
            "p2wsh_p2pk",
            "p2wsh_p2pk",
            9,
            "uncompressed",
            "04" + "22" * 64,
            "41ac",
            "bb" * 32,
            "bc1qcrow",
            "C-001",
            1,
            4,
            "C",
        ),
    )
    raw.commit()
    before = _named_witness_rows(raw)
    assert [row["id"] for row in before] == [11, 23]
    assert before[0]["first_tested_stage"] == "B"
    assert before[1]["first_tested_stage"] == "C"
    bc_sql = raw.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='witness_candidates'"
    ).fetchone()[0]
    assert "CHECK (first_tested_stage IN ('B', 'C'))" in " ".join(str(bc_sql).split())
    assert "CHECK (first_tested_stage IN ('B', 'C', 'D'))" not in " ".join(str(bc_sql).split())
    raw.close()

    store = connect(path)
    _assert_bcd_schema(store.conn)
    after = _named_witness_rows(store.conn)
    assert after == before
    assert int(after[0]["id"]) == 11
    assert int(after[1]["id"]) == 23
    assert after[0]["run_id"] == 3
    assert after[1]["run_id"] == 4
    assert after[0]["fingerprint"] == "fp-b"
    assert after[1]["fingerprint"] == "fp-c"
    fk_rows = store.conn.execute("PRAGMA foreign_key_check").fetchall()
    assert fk_rows == []
    with pytest.raises(sqlite3.IntegrityError):
        store.conn.execute(
            f"""
            INSERT INTO witness_candidates (
                {WITNESS_INSERT_COLUMNS}, first_tested_stage
            ) VALUES (99, 'fp-b', 't1', 'p2pk_compressed', 'dup', 1, 'compressed',
                      '02aa', '21ac', 'cd', 'bc1q', 'B-009', 0, 3, 'D')
            """
        )
    store.conn.rollback()
    with pytest.raises(sqlite3.IntegrityError):
        store.conn.execute(
            f"""
            INSERT INTO witness_candidates (
                {WITNESS_INSERT_COLUMNS}, first_tested_stage
            ) VALUES (100, 'missing-fp', 't9', 'p2pk_compressed', 'x', 1, 'compressed',
                      '02aa', '21ac', 'cd', 'bc1q', 'D-001', 0, 3, 'D')
            """
        )
    store.conn.rollback()
    with pytest.raises(sqlite3.IntegrityError):
        store.conn.execute(
            f"""
            INSERT INTO witness_candidates (
                {WITNESS_INSERT_COLUMNS}, first_tested_stage
            ) VALUES (101, 'fp-b', 't9', 'p2pk_uncompressed', 'x', 1, 'compressed',
                      '02aa', '21ac', 'cd', 'bc1q', 'D-001', 0, 999, 'D')
            """
        )
    store.conn.rollback()
    assert _named_witness_rows(store.conn) == before


def test_connect_migration_is_idempotent(isolated):
    path = _db(isolated)
    raw = _open_legacy(path, BC_WITNESS_SCHEMA)
    raw.execute(
        "INSERT INTO runs (started_at, stage, mode, status) VALUES (?, ?, ?, ?)",
        ("2026-01-01T00:00:00", "B", "balanced", "ok"),
    )
    run_id = int(raw.execute("SELECT id FROM runs").fetchone()[0])
    raw.execute(
        "INSERT INTO keys (fingerprint, first_run_id, valid) VALUES (?, ?, 1)",
        ("fp-b", run_id),
    )
    raw.execute(
        f"""
        INSERT INTO witness_candidates (
            {WITNESS_INSERT_COLUMNS}, first_tested_stage
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            5,
            "fp-b",
            "t1",
            "p2pk_compressed",
            "p2pk_compressed",
            1,
            "compressed",
            "02aa",
            "21ac",
            "cd",
            "bc1q",
            "B-001",
            0,
            run_id,
            "B",
        ),
    )
    raw.commit()
    raw.close()

    first = connect(path)
    sql_once = _witness_sql(first.conn)
    rows_once = _named_witness_rows(first.conn)
    first.conn.close()
    second = connect(path)
    assert _witness_sql(second.conn) == sql_once
    assert _named_witness_rows(second.conn) == rows_once
    _assert_bcd_schema(second.conn)
    second.conn.close()
    third = connect(path)
    assert _named_witness_rows(third.conn) == rows_once
    assert witness_candidate_count(third.conn, "B") == 1


def test_invalid_stages_rejected_by_validation_list_count_and_check(isolated):
    store = connect(_db(isolated))
    run_id = insert_run(store.conn, "2026-01-01T00:00:00", "B", "balanced", "ok")
    upsert_key(store.conn, "fp-b", run_id)
    store.conn.commit()
    omitted = _base_witness("fp-b", "t1", "p2pk_compressed", run_id)
    omitted.pop("first_tested_stage")
    upsert_witness_candidate(store.conn, **omitted)
    assert list_witness_candidates(store.conn)[0]["first_tested_stage"] == "B"
    upsert_witness_candidate(
        store.conn, **_base_witness("fp-b", "t1", "p2pk_uncompressed", run_id, "C", "C-001")
    )
    upsert_witness_candidate(
        store.conn, **_base_witness("fp-b", "t1", "p2wsh_p2pk", run_id, "D", "D-001")
    )
    assert [row["first_tested_stage"] for row in list_witness_candidates(store.conn)] == [
        "B",
        "C",
        "D",
    ]
    store.conn.commit()
    for bad in ("A", "E", "b", "d", "", "C "):
        with pytest.raises(ValueError, match="first_tested_stage must be 'B', 'C', or 'D'"):
            validate_first_tested_stage(bad)
        with pytest.raises(ValueError, match="first_tested_stage must be 'B', 'C', or 'D'"):
            list_witness_candidates(store.conn, bad)
        with pytest.raises(ValueError, match="first_tested_stage must be 'B', 'C', or 'D'"):
            witness_candidate_count(store.conn, bad)
        with pytest.raises(ValueError, match="first_tested_stage must be 'B', 'C', or 'D'"):
            upsert_witness_candidate(
                store.conn, **_base_witness("fp-b", "t1", f"bad-{bad!r}", run_id, bad)
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
    assert stages == {"B", "C", "D"}
    assert witness_candidate_count(store.conn, "D") == 1


def test_replace_stage_d_preserves_b_and_c_and_is_idempotent(isolated):
    store = connect(_db(isolated))
    ids = _seed_store(store)
    before_b = _snapshot_rows(store.conn, "B")
    before_c = _snapshot_rows(store.conn, "C")
    assert len(before_b) == 1
    assert len(before_c) == 1
    replacement = _base_witness("fp-d", "t1", "p2pk_compressed", ids["run_d"], "D", "D-001,D-002")
    with transaction(store) as conn:
        replace_stage_d_witness_candidates(conn, ["t1"], [replacement])
    assert _snapshot_rows(store.conn, "B") == before_b
    assert _snapshot_rows(store.conn, "C") == before_c
    assert list_witness_candidates(store.conn, "D")[0]["derivation_ids"] == "D-001,D-002"
    with transaction(store) as conn:
        replace_stage_d_witness_candidates(conn, ["t1"], [replacement])
    assert _snapshot_rows(store.conn, "B") == before_b
    assert _snapshot_rows(store.conn, "C") == before_c
    assert witness_candidate_count(store.conn, "D") == 1
    assert list_witness_candidates(store.conn, "D")[0]["derivation_ids"] == "D-001,D-002"
    after_ids = [int(row["id"]) for row in list_witness_candidates(store.conn)]
    bad = _base_witness("fp-d", "t1", "p2pk_uncompressed", ids["run_d"], "C")
    with pytest.raises(ValueError, match="first_tested_stage='D'"):
        with transaction(store) as conn:
            replace_stage_d_witness_candidates(conn, ["t1"], [bad])
    assert [int(row["id"]) for row in list_witness_candidates(store.conn)] == after_ids
    assert _snapshot_rows(store.conn, "B") == before_b
    assert _snapshot_rows(store.conn, "C") == before_c


def test_replace_stage_d_rejects_b_or_c_collision_without_mutation(isolated):
    store = connect(_db(isolated))
    ids = _seed_store(store)
    before = _snapshot_rows(store.conn)
    b_rows = list_witness_candidates(store.conn, "B")
    c_rows = list_witness_candidates(store.conn, "C")
    colliding_b = _base_witness(
        b_rows[0]["fingerprint"],
        b_rows[0]["target_id"],
        b_rows[0]["template_id"],
        ids["run_d"],
        "D",
        "D-collide-b",
    )
    with pytest.raises(ValueError, match="collide with an existing B or C row"):
        with transaction(store) as conn:
            replace_stage_d_witness_candidates(conn, ["t1"], [colliding_b])
    assert _snapshot_rows(store.conn) == before
    colliding_c = _base_witness(
        c_rows[0]["fingerprint"],
        c_rows[0]["target_id"],
        c_rows[0]["template_id"],
        ids["run_d"],
        "D",
        "D-collide-c",
    )
    with pytest.raises(ValueError, match="collide with an existing B or C row"):
        with transaction(store) as conn:
            replace_stage_d_witness_candidates(conn, ["t1"], [colliding_c])
    assert _snapshot_rows(store.conn) == before
    assert all("D-collide" not in str(row["derivation_ids"]) for _, row in before)
    assert witness_candidate_count(store.conn, "B") == 1
    assert witness_candidate_count(store.conn, "C") == 1
    assert witness_candidate_count(store.conn, "D") == 1


def test_replace_stage_d_rolls_back_on_mid_insert_failure(isolated, monkeypatch):
    store = connect(_db(isolated))
    ids = _seed_store(store)
    original = _snapshot_rows(store.conn)
    replacements = [
        _base_witness("fp-d", "t1", "p2pk_compressed", ids["run_d"], "D", "D-001"),
        _base_witness("fp-d", "t1", "p2pk_uncompressed", ids["run_d"], "D", "D-001"),
    ]
    real_upsert = storage_mod.upsert_witness_candidate
    inserted = {"count": 0}

    def flaky(conn, **kwargs):
        inserted["count"] += 1
        result = real_upsert(conn, **kwargs)
        if inserted["count"] >= 2:
            raise RuntimeError("injected stage D replacement failure")
        return result

    monkeypatch.setattr(storage_mod, "upsert_witness_candidate", flaky)
    with pytest.raises(RuntimeError, match="injected stage D replacement failure"):
        with transaction(store) as conn:
            replace_stage_d_witness_candidates(conn, ["t1"], replacements)
    assert inserted["count"] >= 2
    assert _snapshot_rows(store.conn) == original


def test_invalidate_stage_d_retains_abc_addresses_and_runs(isolated):
    store = connect(_db(isolated))
    ids = _seed_store(store)
    run_ids = {row["id"] for row in store.conn.execute("SELECT id FROM runs")}
    assert run_ids == {ids["run_a"], ids["run_b"], ids["run_c"], ids["run_d"]}
    before_b = _snapshot_rows(store.conn, "B")
    before_c = _snapshot_rows(store.conn, "C")
    with transaction(store) as conn:
        invalidate_stage_d_current_state(conn)
    assert list_witness_candidates(store.conn, "D") == []
    assert _snapshot_rows(store.conn, "B") == before_b
    assert _snapshot_rows(store.conn, "C") == before_c
    assert (
        store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'D'").fetchone()[0] == 0
    )
    assert (
        store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'A'").fetchone()[0] == 1
    )
    assert (
        store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'B'").fetchone()[0] == 1
    )
    assert (
        store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'C'").fetchone()[0] == 1
    )
    fingerprints = {
        str(row[0]) for row in store.conn.execute("SELECT fingerprint FROM keys").fetchall()
    }
    assert fingerprints == {"fp-a", "fp-b", "fp-c"}
    assert (
        store.conn.execute("SELECT COUNT(*) FROM addresses WHERE fingerprint = 'fp-a'").fetchone()[
            0
        ]
        == 1
    )
    assert {row["id"] for row in store.conn.execute("SELECT id FROM runs")} == run_ids


def test_invalidate_stage_c_removes_c_and_downstream_d(isolated):
    store = connect(_db(isolated))
    ids = _seed_store(store)
    run_ids = {ids["run_a"], ids["run_b"], ids["run_c"], ids["run_d"]}
    assert {row["id"] for row in store.conn.execute("SELECT id FROM runs")} == run_ids
    before_b = _snapshot_rows(store.conn, "B")
    with transaction(store) as conn:
        invalidate_stage_c_current_state(conn)
    assert list_witness_candidates(store.conn, "C") == []
    assert list_witness_candidates(store.conn, "D") == []
    assert _snapshot_rows(store.conn, "B") == before_b
    stages = {str(row[0]) for row in store.conn.execute("SELECT DISTINCT stage FROM derivations")}
    assert stages == {"A", "B"}
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
    assert {row["id"] for row in store.conn.execute("SELECT id FROM runs")} == run_ids
    assert store.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 4
