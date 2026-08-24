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
    transaction,
    upsert_address,
    upsert_derivation,
    upsert_key,
    upsert_witness_candidate,
    validate_first_tested_stage,
    witness_candidate_count,
)


def invalidate_stage_e_current_state(*args, **kwargs):
    fn = getattr(storage_mod, "invalidate_stage_e_current_state", None)
    assert fn is not None, "invalidate_stage_e_current_state is not implemented on this tree"
    return fn(*args, **kwargs)


def replace_stage_e_witness_candidates(*args, **kwargs):
    fn = getattr(storage_mod, "replace_stage_e_witness_candidates", None)
    assert fn is not None, "replace_stage_e_witness_candidates is not implemented on this tree"
    return fn(*args, **kwargs)


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

BCD_WITNESS_SCHEMA = """
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
        CHECK (first_tested_stage IN ('B', 'C', 'D')),
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


def _assert_bcde_schema(conn: sqlite3.Connection) -> None:
    sql = _witness_sql(conn)
    assert "first_tested_stage TEXT NOT NULL DEFAULT 'B'" in sql
    assert "CHECK (first_tested_stage IN ('B', 'C', 'D', 'E'))" in sql
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


def _index_info(conn: sqlite3.Connection, name: str) -> tuple:
    return tuple(tuple(row) for row in conn.execute(f"PRAGMA index_info({name})").fetchall())


def _witness_rebuild_snapshot(conn: sqlite3.Connection) -> dict:
    rows = _named_witness_rows(conn)
    indexes = [tuple(row) for row in conn.execute("PRAGMA index_list(witness_candidates)")]
    return {
        "sql": _witness_sql(conn),
        "rows": rows,
        "ids": [int(row["id"]) for row in rows],
        "fks": [tuple(row) for row in conn.execute("PRAGMA foreign_key_list(witness_candidates)")],
        "indexes": indexes,
        "index_info": [(str(index[1]), _index_info(conn, str(index[1]))) for index in indexes],
        "tables": [
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name LIKE 'witness_candidates%' ORDER BY name"
            ).fetchall()
        ],
    }


def _base_witness(
    fingerprint: str,
    target_id: str,
    template_id: str,
    run_id: int,
    first_tested_stage: str = "B",
    derivation_ids: str = "B-001",
) -> dict:
    return {
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
    run_e = insert_run(conn, "2026-01-01T00:04:00", "E", "balanced", "ok")
    upsert_key(conn, "fp-a", run_a)
    upsert_key(conn, "fp-b", run_b)
    upsert_key(conn, "fp-c", run_c)
    upsert_key(conn, "fp-d", run_d)
    upsert_key(conn, "fp-e", run_e)
    _add_derivation(conn, "A-01", "fp-a", run_a)
    _add_derivation(conn, "B-001", "fp-b", run_b)
    _add_derivation(conn, "C-001", "fp-c", run_c)
    _add_derivation(conn, "D-001", "fp-d", run_d)
    _add_derivation(conn, "E-001", "fp-e", run_e)
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
    upsert_witness_candidate(
        conn, **_base_witness("fp-e", "t1", "p2pk_compressed", run_e, "E", "E-001")
    )
    conn.commit()
    return {
        "run_a": run_a,
        "run_b": run_b,
        "run_c": run_c,
        "run_d": run_d,
        "run_e": run_e,
    }


def _open_legacy(path: Path, schema: str) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = sqlite3.connect(str(path))
    raw.execute("PRAGMA foreign_keys = ON")
    raw.executescript(schema)
    return raw


def _insert_legacy_row(
    raw: sqlite3.Connection,
    row_id: int,
    fingerprint: str,
    run_id: int,
    stage: str | None,
    derivation_ids: str,
) -> None:
    if stage is None:
        raw.execute(
            f"""
            INSERT INTO witness_candidates (
                {WITNESS_INSERT_COLUMNS}
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row_id,
                fingerprint,
                "t1",
                "p2pk_compressed",
                "p2pk_compressed",
                1,
                "compressed",
                "02aa",
                "21ac",
                "cd",
                f"bc1q{fingerprint}",
                derivation_ids,
                0,
                run_id,
            ),
        )
        return
    raw.execute(
        f"""
        INSERT INTO witness_candidates (
            {WITNESS_INSERT_COLUMNS}, first_tested_stage
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            row_id,
            fingerprint,
            "t1",
            "p2pk_compressed",
            "p2pk_compressed",
            1,
            "compressed",
            "02aa",
            "21ac",
            "cd",
            f"bc1q{fingerprint}",
            derivation_ids,
            0,
            run_id,
            stage,
        ),
    )


def test_new_database_creates_bcde_first_tested_stage_schema(isolated):
    path = _db(isolated)
    store = connect(path)
    assert ALLOWED_WITNESS_STAGES == frozenset({"B", "C", "D", "E"})
    _assert_bcde_schema(store.conn)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600
    dumped = dump_text(store.conn)
    assert "witness_candidates" in dumped
    for fragment in FORBIDDEN_COLUMN_FRAGMENTS:
        assert fragment not in dumped.lower() or "witness" in dumped.lower()


def test_legacy_schema_without_stage_column_migrates_to_b_with_bcde_check(isolated):
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
    _insert_legacy_row(raw, 7, "fp-old", run_id, None, "B-001")
    raw.commit()
    raw.close()
    store = connect(path)
    _assert_bcde_schema(store.conn)
    rows = list_witness_candidates(store.conn)
    assert len(rows) == 1
    assert int(rows[0]["id"]) == 7
    assert rows[0]["first_tested_stage"] == "B"
    assert rows[0]["fingerprint"] == "fp-old"
    assert witness_candidate_count(store.conn, "E") == 0


def test_bc_and_bcd_schemas_rebuild_to_bcde_preserving_rows_ids_and_fks(isolated):
    for name, schema, stages in (
        ("bc", BC_WITNESS_SCHEMA, (("fp-b", "B", 11, 3), ("fp-c", "C", 23, 4))),
        ("bcd", BCD_WITNESS_SCHEMA, (("fp-b", "B", 11, 3), ("fp-d", "D", 29, 5))),
    ):
        path = _db(isolated / name)
        raw = _open_legacy(path, schema)
        raw.execute(
            "INSERT INTO runs (id, started_at, stage, mode, status) VALUES (?, ?, ?, ?, ?)",
            (3, "2026-01-01T00:00:00", "B", "balanced", "ok"),
        )
        raw.execute(
            "INSERT INTO runs (id, started_at, stage, mode, status) VALUES (?, ?, ?, ?, ?)",
            (4, "2026-01-01T00:01:00", "C", "balanced", "ok"),
        )
        raw.execute(
            "INSERT INTO runs (id, started_at, stage, mode, status) VALUES (?, ?, ?, ?, ?)",
            (5, "2026-01-01T00:02:00", "D", "balanced", "ok"),
        )
        before_rows = []
        for fingerprint, stage, row_id, run_id in stages:
            raw.execute(
                "INSERT INTO keys (fingerprint, first_run_id, valid) VALUES (?, ?, 1)",
                (fingerprint, run_id),
            )
            _insert_legacy_row(raw, row_id, fingerprint, run_id, stage, f"{stage}-001")
        raw.commit()
        before_rows = _named_witness_rows(raw)
        raw.close()
        store = connect(path)
        _assert_bcde_schema(store.conn)
        after = _named_witness_rows(store.conn)
        assert after == before_rows
        assert [int(row["id"]) for row in after] == [item[2] for item in stages]
        fk_rows = store.conn.execute("PRAGMA foreign_key_check").fetchall()
        assert fk_rows == []
        store.conn.close()


def test_rebuild_bcde_rename_failure_rolls_back_original_bcd_table(isolated):
    path = _db(isolated)
    raw = _open_legacy(path, BCD_WITNESS_SCHEMA)
    raw.execute(
        "INSERT INTO runs (id, started_at, stage, mode, status) VALUES (?, ?, ?, ?, ?)",
        (3, "2026-01-01T00:00:00", "B", "balanced", "ok"),
    )
    raw.execute(
        "INSERT INTO runs (id, started_at, stage, mode, status) VALUES (?, ?, ?, ?, ?)",
        (5, "2026-01-01T00:02:00", "D", "balanced", "ok"),
    )
    raw.execute(
        "INSERT INTO keys (fingerprint, first_run_id, valid) VALUES (?, ?, 1)",
        ("fp-b", 3),
    )
    raw.execute(
        "INSERT INTO keys (fingerprint, first_run_id, valid) VALUES (?, ?, 1)",
        ("fp-d", 5),
    )
    _insert_legacy_row(raw, 11, "fp-b", 3, "B", "B-001")
    _insert_legacy_row(raw, 29, "fp-d", 5, "D", "D-001")
    raw.commit()
    before = _witness_rebuild_snapshot(raw)
    assert before["sql"].count("CHECK (first_tested_stage IN ('B', 'C', 'D'))") == 1
    assert "IN ('B', 'C', 'D', 'E')" not in before["sql"]
    assert before["ids"] == [11, 29]
    assert before["tables"] == ["witness_candidates"]
    seen: list[tuple] = []

    def deny_alter_table(action, arg1, arg2, dbname, source):
        seen.append((action, arg1, arg2))
        if action == sqlite3.SQLITE_ALTER_TABLE:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    raw.set_authorizer(deny_alter_table)
    try:
        with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
            storage_mod._rebuild_witness_candidates_bcde(raw)
    finally:
        raw.set_authorizer(None)
        raw.close()
    raw = sqlite3.connect(path)
    assert any(
        action == sqlite3.SQLITE_DROP_TABLE and arg1 == "witness_candidates"
        for action, arg1, _arg2 in seen
    )
    assert any(
        action == sqlite3.SQLITE_ALTER_TABLE and storage_mod._WITNESS_MIGRATE_TEMP in (arg1, arg2)
        for action, arg1, arg2 in seen
    )
    after = _witness_rebuild_snapshot(raw)
    assert after == before
    assert after["rows"] == before["rows"]
    assert after["ids"] == [11, 29]
    assert after["fks"] == before["fks"]
    assert after["indexes"] == before["indexes"]
    assert storage_mod._WITNESS_MIGRATE_TEMP not in after["tables"]
    assert after["tables"] == ["witness_candidates"]
    assert "IN ('B', 'C', 'D', 'E')" not in after["sql"]
    raw.close()


def test_connect_bcde_migration_is_idempotent(isolated):
    path = _db(isolated)
    raw = _open_legacy(path, BCD_WITNESS_SCHEMA)
    raw.execute(
        "INSERT INTO runs (started_at, stage, mode, status) VALUES (?, ?, ?, ?)",
        ("2026-01-01T00:00:00", "D", "balanced", "ok"),
    )
    run_id = int(raw.execute("SELECT id FROM runs").fetchone()[0])
    raw.execute(
        "INSERT INTO keys (fingerprint, first_run_id, valid) VALUES (?, ?, 1)",
        ("fp-d", run_id),
    )
    _insert_legacy_row(raw, 5, "fp-d", run_id, "D", "D-001")
    raw.commit()
    raw.close()
    first = connect(path)
    sql_once = _witness_sql(first.conn)
    rows_once = _named_witness_rows(first.conn)
    first.conn.close()
    second = connect(path)
    assert _witness_sql(second.conn) == sql_once
    assert _named_witness_rows(second.conn) == rows_once
    _assert_bcde_schema(second.conn)


def test_invalid_stages_rejected_and_e_is_allowed(isolated):
    store = connect(_db(isolated))
    run_id = insert_run(store.conn, "2026-01-01T00:00:00", "B", "balanced", "ok")
    upsert_key(store.conn, "fp-b", run_id)
    store.conn.commit()
    upsert_witness_candidate(store.conn, **_base_witness("fp-b", "t1", "p2pk_compressed", run_id))
    upsert_witness_candidate(
        store.conn, **_base_witness("fp-b", "t1", "p2pk_uncompressed", run_id, "E", "E-001")
    )
    assert [row["first_tested_stage"] for row in list_witness_candidates(store.conn)] == [
        "B",
        "E",
    ]
    for bad in ("A", "F", "b", "e", "", "E "):
        with pytest.raises(ValueError, match="first_tested_stage must be 'B', 'C', 'D', or 'E'"):
            validate_first_tested_stage(bad)
        with pytest.raises(ValueError, match="first_tested_stage must be 'B', 'C', 'D', or 'E'"):
            list_witness_candidates(store.conn, bad)
        with pytest.raises(ValueError, match="first_tested_stage must be 'B', 'C', 'D', or 'E'"):
            witness_candidate_count(store.conn, bad)
        with pytest.raises(ValueError, match="first_tested_stage must be 'B', 'C', 'D', or 'E'"):
            upsert_witness_candidate(
                store.conn, **_base_witness("fp-b", "t1", f"bad-{bad!r}", run_id, bad)
            )


def test_replace_stage_e_preserves_bcd_and_is_idempotent(isolated):
    store = connect(_db(isolated))
    ids = _seed_store(store)
    before_b = _snapshot_rows(store.conn, "B")
    before_c = _snapshot_rows(store.conn, "C")
    before_d = _snapshot_rows(store.conn, "D")
    replacement = _base_witness("fp-e", "t1", "p2pk_compressed", ids["run_e"], "E", "E-001,E-002")
    with transaction(store) as conn:
        replace_stage_e_witness_candidates(conn, ["t1"], [replacement])
    assert _snapshot_rows(store.conn, "B") == before_b
    assert _snapshot_rows(store.conn, "C") == before_c
    assert _snapshot_rows(store.conn, "D") == before_d
    assert list_witness_candidates(store.conn, "E")[0]["derivation_ids"] == "E-001,E-002"
    with transaction(store) as conn:
        replace_stage_e_witness_candidates(conn, ["t1"], [replacement])
    assert _snapshot_rows(store.conn, "B") == before_b
    assert _snapshot_rows(store.conn, "D") == before_d
    assert witness_candidate_count(store.conn, "E") == 1
    bad = _base_witness("fp-e", "t1", "p2pk_uncompressed", ids["run_e"], "D")
    after_ids = [int(row["id"]) for row in list_witness_candidates(store.conn)]
    with pytest.raises(ValueError, match="first_tested_stage='E'"):
        with transaction(store) as conn:
            replace_stage_e_witness_candidates(conn, ["t1"], [bad])
    assert [int(row["id"]) for row in list_witness_candidates(store.conn)] == after_ids


def test_replace_stage_e_rejects_bcd_collision_without_mutation(isolated):
    store = connect(_db(isolated))
    ids = _seed_store(store)
    before = _snapshot_rows(store.conn)
    d_rows = list_witness_candidates(store.conn, "D")
    colliding = _base_witness(
        d_rows[0]["fingerprint"],
        d_rows[0]["target_id"],
        d_rows[0]["template_id"],
        ids["run_e"],
        "E",
        "E-collide-d",
    )
    with pytest.raises(ValueError, match="collide with an existing B, C, or D row"):
        with transaction(store) as conn:
            replace_stage_e_witness_candidates(conn, ["t1"], [colliding])
    assert _snapshot_rows(store.conn) == before


def test_replace_stage_e_rolls_back_on_mid_insert_failure(isolated, monkeypatch):
    store = connect(_db(isolated))
    ids = _seed_store(store)
    original = _snapshot_rows(store.conn)
    replacements = [
        _base_witness("fp-e", "t1", "p2pk_compressed", ids["run_e"], "E", "E-001"),
        _base_witness("fp-e", "t1", "p2pk_uncompressed", ids["run_e"], "E", "E-001"),
    ]
    real_upsert = storage_mod.upsert_witness_candidate
    inserted = {"count": 0}

    def flaky(conn, **kwargs):
        inserted["count"] += 1
        result = real_upsert(conn, **kwargs)
        if inserted["count"] >= 2:
            raise RuntimeError("injected stage E replacement failure")
        return result

    monkeypatch.setattr(storage_mod, "upsert_witness_candidate", flaky)
    with pytest.raises(RuntimeError, match="injected stage E replacement failure"):
        with transaction(store) as conn:
            replace_stage_e_witness_candidates(conn, ["t1"], replacements)
    assert inserted["count"] >= 2
    assert _snapshot_rows(store.conn) == original


def test_invalidate_stage_e_retains_abcd_addresses_and_runs(isolated):
    store = connect(_db(isolated))
    _seed_store(store)
    run_ids = {row["id"] for row in store.conn.execute("SELECT id FROM runs")}
    before_b = _snapshot_rows(store.conn, "B")
    before_c = _snapshot_rows(store.conn, "C")
    before_d = _snapshot_rows(store.conn, "D")
    with transaction(store) as conn:
        invalidate_stage_e_current_state(conn)
    assert list_witness_candidates(store.conn, "E") == []
    assert _snapshot_rows(store.conn, "B") == before_b
    assert _snapshot_rows(store.conn, "C") == before_c
    assert _snapshot_rows(store.conn, "D") == before_d
    assert (
        store.conn.execute("SELECT COUNT(*) FROM derivations WHERE stage = 'E'").fetchone()[0] == 0
    )
    fingerprints = {
        str(row[0]) for row in store.conn.execute("SELECT fingerprint FROM keys").fetchall()
    }
    assert fingerprints == {"fp-a", "fp-b", "fp-c", "fp-d"}
    assert {row["id"] for row in store.conn.execute("SELECT id FROM runs")} == run_ids


def test_invalidate_stage_d_removes_d_and_downstream_e(isolated):
    store = connect(_db(isolated))
    ids = _seed_store(store)
    before_b = _snapshot_rows(store.conn, "B")
    before_c = _snapshot_rows(store.conn, "C")
    with transaction(store) as conn:
        invalidate_stage_d_current_state(conn)
    assert list_witness_candidates(store.conn, "D") == []
    assert list_witness_candidates(store.conn, "E") == []
    assert _snapshot_rows(store.conn, "B") == before_b
    assert _snapshot_rows(store.conn, "C") == before_c
    stages = {str(row[0]) for row in store.conn.execute("SELECT DISTINCT stage FROM derivations")}
    assert stages == {"A", "B", "C"}
    fingerprints = {
        str(row[0]) for row in store.conn.execute("SELECT fingerprint FROM keys").fetchall()
    }
    assert fingerprints == {"fp-a", "fp-b", "fp-c"}
    assert {row["id"] for row in store.conn.execute("SELECT id FROM runs")} == {
        ids["run_a"],
        ids["run_b"],
        ids["run_c"],
        ids["run_d"],
        ids["run_e"],
    }


def test_invalidate_stage_c_removes_c_and_downstream_d_and_e(isolated):
    store = connect(_db(isolated))
    ids = _seed_store(store)
    before_b = _snapshot_rows(store.conn, "B")
    with transaction(store) as conn:
        invalidate_stage_c_current_state(conn)
    assert list_witness_candidates(store.conn, "C") == []
    assert list_witness_candidates(store.conn, "D") == []
    assert list_witness_candidates(store.conn, "E") == []
    assert _snapshot_rows(store.conn, "B") == before_b
    stages = {str(row[0]) for row in store.conn.execute("SELECT DISTINCT stage FROM derivations")}
    assert stages == {"A", "B"}
    fingerprints = {
        str(row[0]) for row in store.conn.execute("SELECT fingerprint FROM keys").fetchall()
    }
    assert fingerprints == {"fp-a", "fp-b"}
    assert {row["id"] for row in store.conn.execute("SELECT id FROM runs")} == {
        ids["run_a"],
        ids["run_b"],
        ids["run_c"],
        ids["run_d"],
        ids["run_e"],
    }
