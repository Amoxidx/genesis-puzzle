from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence

_WITNESS_CANDIDATES_BODY = """
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
        CHECK (first_tested_stage IN ('B', 'C', 'D', 'E')),
    UNIQUE(fingerprint, target_id, template_id)
"""

SCHEMA = (
    """
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

CREATE TABLE IF NOT EXISTS derivations (
    derivation_id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL,
    fingerprint TEXT,
    source TEXT NOT NULL,
    original_public_source TEXT NOT NULL,
    representation TEXT NOT NULL,
    public_input_hex TEXT NOT NULL,
    transformation TEXT NOT NULL,
    formula TEXT NOT NULL,
    recipe TEXT NOT NULL,
    confidence REAL NOT NULL,
    stage TEXT NOT NULL,
    valid INTEGER NOT NULL,
    eliminated_reason TEXT NOT NULL DEFAULT '',
    first_run_id INTEGER NOT NULL REFERENCES runs(id)
);

CREATE TABLE IF NOT EXISTS addresses (
    id INTEGER PRIMARY KEY,
    fingerprint TEXT NOT NULL REFERENCES keys(fingerprint),
    address TEXT NOT NULL,
    address_type TEXT NOT NULL,
    pubkey_hex TEXT NOT NULL,
    pubkey_mode TEXT NOT NULL,
    UNIQUE(fingerprint, address_type)
);

CREATE TABLE IF NOT EXISTS history (
    address TEXT PRIMARY KEY,
    address_type TEXT,
    checked INTEGER NOT NULL DEFAULT 0,
    seen_on_chain INTEGER,
    balance INTEGER,
    total_received INTEGER,
    total_sent INTEGER,
    transaction_count INTEGER,
    history_status TEXT NOT NULL DEFAULT 'not_checked',
    first_seen TEXT,
    last_checked TEXT
);

CREATE TABLE IF NOT EXISTS target_comparisons (
    id INTEGER PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    address TEXT NOT NULL,
    address_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    comparable INTEGER NOT NULL,
    matched INTEGER NOT NULL,
    note TEXT NOT NULL,
    UNIQUE(address, target_id)
);

CREATE TABLE IF NOT EXISTS witness_candidates (
"""
    + _WITNESS_CANDIDATES_BODY
    + """
);
"""
)

ALLOWED_WITNESS_STAGES = frozenset({"B", "C", "D", "E"})
_WITNESS_BCDE_CHECK = "CHECK (first_tested_stage IN ('B', 'C', 'D', 'E'))"
_WITNESS_PUBLIC_COLUMNS = (
    "id",
    "fingerprint",
    "target_id",
    "template_id",
    "template_name",
    "priority",
    "pubkey_mode",
    "pubkey_hex",
    "witness_script_hex",
    "witness_program_hex",
    "address",
    "derivation_ids",
    "matched",
    "run_id",
    "first_tested_stage",
)
_WITNESS_MIGRATE_TEMP = "witness_candidates__migrate_bcde"


def restrict_owner_only(path: Path) -> None:
    if path.is_dir():
        os.chmod(path, 0o700)
    else:
        os.chmod(path, 0o600)


@dataclass
class Store:
    path: Path
    conn: sqlite3.Connection


def connect(path: Path) -> Store:
    path.parent.mkdir(parents=True, exist_ok=True)
    restrict_owner_only(path.parent)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    existing_history_columns = {
        str(row[1]) for row in conn.execute("PRAGMA table_info(history)").fetchall()
    }
    history_migrations = {
        "total_received": "ALTER TABLE history ADD COLUMN total_received INTEGER",
        "total_sent": "ALTER TABLE history ADD COLUMN total_sent INTEGER",
        "transaction_count": "ALTER TABLE history ADD COLUMN transaction_count INTEGER",
        "history_status": (
            "ALTER TABLE history ADD COLUMN history_status TEXT NOT NULL DEFAULT 'not_checked'"
        ),
    }
    for column, statement in history_migrations.items():
        if column not in existing_history_columns:
            conn.execute(statement)
    existing_run_columns = {
        str(row[1]) for row in conn.execute("PRAGMA table_info(runs)").fetchall()
    }
    if "tested_candidate_count" not in existing_run_columns:
        conn.execute("ALTER TABLE runs ADD COLUMN tested_candidate_count INTEGER")
    _migrate_witness_candidates_first_tested_stage(conn)
    conn.commit()
    restrict_owner_only(path)
    return Store(path=path, conn=conn)


def validate_first_tested_stage(stage: str) -> str:
    if stage not in ALLOWED_WITNESS_STAGES:
        raise ValueError(f"first_tested_stage must be 'B', 'C', 'D', or 'E', got {stage!r}")
    return stage


def _normalized_witness_table_sql(conn: sqlite3.Connection) -> Optional[str]:
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='witness_candidates'"
    ).fetchone()
    if row is None or row[0] is None:
        return None
    return " ".join(str(row[0]).split())


def _run_savepoint(conn: sqlite3.Connection, name: str, callback: Callable[[], None]) -> None:
    conn.execute(f"SAVEPOINT {name}")
    try:
        callback()
        conn.execute(f"RELEASE SAVEPOINT {name}")
    except Exception:
        conn.execute(f"ROLLBACK TO SAVEPOINT {name}")
        conn.execute(f"RELEASE SAVEPOINT {name}")
        raise


def _rebuild_witness_candidates_bcde(conn: sqlite3.Connection) -> None:
    def rebuild() -> None:
        conn.execute(f"DROP TABLE IF EXISTS {_WITNESS_MIGRATE_TEMP}")
        conn.execute(f"CREATE TABLE {_WITNESS_MIGRATE_TEMP} ({_WITNESS_CANDIDATES_BODY})")
        columns = ", ".join(_WITNESS_PUBLIC_COLUMNS)
        conn.execute(
            f"INSERT INTO {_WITNESS_MIGRATE_TEMP} ({columns}) "
            f"SELECT {columns} FROM witness_candidates"
        )
        conn.execute("DROP TABLE witness_candidates")
        conn.execute(f"ALTER TABLE {_WITNESS_MIGRATE_TEMP} RENAME TO witness_candidates")

    _run_savepoint(conn, "migrate_witness_bcde_rebuild", rebuild)


def _migrate_witness_candidates_first_tested_stage(conn: sqlite3.Connection) -> None:
    existing_columns = {
        str(row[1]) for row in conn.execute("PRAGMA table_info(witness_candidates)").fetchall()
    }
    if "first_tested_stage" not in existing_columns:

        def add_column() -> None:
            conn.execute(
                """
                ALTER TABLE witness_candidates
                ADD COLUMN first_tested_stage TEXT NOT NULL DEFAULT 'B'
                CHECK (first_tested_stage IN ('B', 'C', 'D', 'E'))
                """
            )

        _run_savepoint(conn, "migrate_witness_first_tested_stage", add_column)
        return
    table_sql = _normalized_witness_table_sql(conn)
    if table_sql is not None and _WITNESS_BCDE_CHECK in table_sql:
        return
    _rebuild_witness_candidates_bcde(conn)


@contextmanager
def transaction(store: Store) -> Iterator[sqlite3.Connection]:
    try:
        yield store.conn
        store.conn.commit()
    except Exception:
        store.conn.rollback()
        raise


def insert_run(
    conn: sqlite3.Connection,
    started_at: str,
    stage: str,
    mode: str,
    status: str = "running",
) -> int:
    cur = conn.execute(
        """
        INSERT INTO runs (started_at, stage, mode, status)
        VALUES (?, ?, ?, ?)
        """,
        (started_at, stage, mode, status),
    )
    lastrowid = cur.lastrowid
    if lastrowid is None:
        raise RuntimeError("failed to insert run")
    return int(lastrowid)


def finish_run(
    conn: sqlite3.Connection,
    run_id: int,
    finished_at: str,
    status: str,
    derivation_count: int,
    invalid_count: int,
    unique_valid_keys: int,
    duplicate_count: int,
    address_count: int,
    elapsed_seconds: float,
    tested_candidate_count: int = 0,
) -> None:
    rate = derivation_count / elapsed_seconds if elapsed_seconds > 0 else 0.0
    conn.execute(
        """
        UPDATE runs
        SET finished_at = ?, status = ?, derivation_count = ?, invalid_count = ?,
            unique_valid_keys = ?, duplicate_count = ?, address_count = ?,
            tested_candidate_count = ?, elapsed_seconds = ?, rate_per_second = ?,
            notes = 'checkpoint-not-needed'
        WHERE id = ?
        """,
        (
            finished_at,
            status,
            derivation_count,
            invalid_count,
            unique_valid_keys,
            duplicate_count,
            address_count,
            tested_candidate_count,
            elapsed_seconds,
            rate,
            run_id,
        ),
    )


def upsert_derivation(
    conn: sqlite3.Connection,
    *,
    derivation_id: str,
    fingerprint: Optional[str],
    source: str,
    original_public_source: str,
    representation: str,
    public_input_hex: str,
    transformation: str,
    formula: str,
    recipe: str,
    confidence: float,
    stage: str,
    valid: bool,
    eliminated_reason: str,
    run_id: int,
) -> None:
    conn.execute(
        """
        INSERT INTO derivations (
            derivation_id, candidate_id, fingerprint, source, original_public_source,
            representation, public_input_hex, transformation, formula, recipe,
            confidence, stage, valid, eliminated_reason, first_run_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(derivation_id) DO UPDATE SET
            candidate_id = excluded.candidate_id,
            fingerprint = excluded.fingerprint,
            source = excluded.source,
            original_public_source = excluded.original_public_source,
            representation = excluded.representation,
            public_input_hex = excluded.public_input_hex,
            transformation = excluded.transformation,
            formula = excluded.formula,
            recipe = excluded.recipe,
            confidence = excluded.confidence,
            stage = excluded.stage,
            valid = excluded.valid,
            eliminated_reason = excluded.eliminated_reason
        """,
        (
            derivation_id,
            derivation_id,
            fingerprint,
            source,
            original_public_source,
            representation,
            public_input_hex,
            transformation,
            formula,
            recipe,
            confidence,
            stage,
            int(valid),
            eliminated_reason,
            run_id,
        ),
    )


def upsert_key(conn: sqlite3.Connection, fingerprint: str, run_id: int) -> None:
    conn.execute(
        """
        INSERT INTO keys (fingerprint, first_run_id, valid)
        VALUES (?, ?, 1)
        ON CONFLICT(fingerprint) DO NOTHING
        """,
        (fingerprint, run_id),
    )


def upsert_address(
    conn: sqlite3.Connection,
    fingerprint: str,
    address: str,
    address_type: str,
    pubkey_hex: str,
    pubkey_mode: str,
) -> None:
    conn.execute(
        """
        INSERT INTO addresses (fingerprint, address, address_type, pubkey_hex, pubkey_mode)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(fingerprint, address_type) DO NOTHING
        """,
        (fingerprint, address, address_type, pubkey_hex, pubkey_mode),
    )
    conn.execute(
        """
        INSERT INTO history (
            address, address_type, checked, seen_on_chain, balance, total_received,
            total_sent, transaction_count, history_status, first_seen, last_checked
        )
        VALUES (?, ?, 0, NULL, NULL, NULL, NULL, NULL, 'not_checked', NULL, NULL)
        ON CONFLICT(address) DO NOTHING
        """,
        (address, address_type),
    )


def upsert_comparison(
    conn: sqlite3.Connection,
    fingerprint: str,
    address: str,
    address_type: str,
    target_id: str,
    comparable: bool,
    matched: bool,
    note: str,
) -> None:
    conn.execute(
        """
        INSERT INTO target_comparisons (
            fingerprint, address, address_type, target_id, comparable, matched, note
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(address, target_id) DO UPDATE SET
            matched = excluded.matched,
            comparable = excluded.comparable,
            note = excluded.note
        """,
        (fingerprint, address, address_type, target_id, int(comparable), int(matched), note),
    )


def upsert_witness_candidate(
    conn: sqlite3.Connection,
    *,
    fingerprint: str,
    target_id: str,
    template_id: str,
    template_name: str,
    priority: int,
    pubkey_mode: str,
    pubkey_hex: str,
    witness_script_hex: str,
    witness_program_hex: str,
    address: str,
    derivation_ids: str,
    matched: bool,
    run_id: int,
    first_tested_stage: str = "B",
) -> None:
    stage = validate_first_tested_stage(first_tested_stage)
    conn.execute(
        """
        INSERT INTO witness_candidates (
            fingerprint, target_id, template_id, template_name, priority,
            pubkey_mode, pubkey_hex, witness_script_hex, witness_program_hex,
            address, derivation_ids, matched, run_id, first_tested_stage
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(fingerprint, target_id, template_id) DO UPDATE SET
            template_name = excluded.template_name,
            priority = excluded.priority,
            pubkey_mode = excluded.pubkey_mode,
            pubkey_hex = excluded.pubkey_hex,
            witness_script_hex = excluded.witness_script_hex,
            witness_program_hex = excluded.witness_program_hex,
            address = excluded.address,
            derivation_ids = excluded.derivation_ids,
            matched = excluded.matched,
            run_id = excluded.run_id,
            first_tested_stage = excluded.first_tested_stage
        """,
        (
            fingerprint,
            target_id,
            template_id,
            template_name,
            priority,
            pubkey_mode,
            pubkey_hex,
            witness_script_hex,
            witness_program_hex,
            address,
            derivation_ids,
            int(matched),
            run_id,
            stage,
        ),
    )


def list_witness_candidates(
    conn: sqlite3.Connection,
    first_tested_stage: Optional[str] = None,
) -> List[sqlite3.Row]:
    if first_tested_stage is None:
        return fetchall(conn, "SELECT * FROM witness_candidates ORDER BY id")
    stage = validate_first_tested_stage(first_tested_stage)
    return fetchall(
        conn,
        "SELECT * FROM witness_candidates WHERE first_tested_stage = ? ORDER BY id",
        (stage,),
    )


def witness_candidate_count(
    conn: sqlite3.Connection,
    first_tested_stage: Optional[str] = None,
) -> int:
    if first_tested_stage is None:
        row = conn.execute("SELECT COUNT(*) FROM witness_candidates").fetchone()
    else:
        stage = validate_first_tested_stage(first_tested_stage)
        row = conn.execute(
            "SELECT COUNT(*) FROM witness_candidates WHERE first_tested_stage = ?",
            (stage,),
        ).fetchone()
    return int(row[0])


def witness_match_count(conn: sqlite3.Connection) -> int:
    return int(
        conn.execute("SELECT COUNT(*) FROM witness_candidates WHERE matched = 1").fetchone()[0]
    )


def replace_witness_candidates(
    conn: sqlite3.Connection,
    target_ids: Sequence[str],
    rows: Sequence[Dict[str, Any]],
) -> None:
    """Delete current-target rows then upsert replacements. Call inside a transaction."""
    if target_ids:
        placeholders = ",".join("?" for _ in target_ids)
        conn.execute(
            f"DELETE FROM witness_candidates WHERE target_id IN ({placeholders})",
            tuple(target_ids),
        )
    for row in rows:
        upsert_witness_candidate(conn, **row)


def replace_stage_c_witness_candidates(
    conn: sqlite3.Connection,
    target_ids: Sequence[str],
    rows: Sequence[Dict[str, Any]],
) -> None:
    """Replace Stage C rows for targets only. Preserve B rows. Call inside a transaction."""
    for row in rows:
        if row.get("first_tested_stage") != "C":
            raise ValueError(
                "Stage C replacement requires first_tested_stage='C' on every payload row"
            )
        existing_b = conn.execute(
            """
            SELECT 1 FROM witness_candidates
            WHERE first_tested_stage = 'B'
              AND fingerprint = ?
              AND target_id = ?
              AND template_id = ?
            """,
            (row["fingerprint"], row["target_id"], row["template_id"]),
        ).fetchone()
        if existing_b is not None:
            raise ValueError(
                "Stage C replacement would collide with an existing B row for "
                f"fingerprint={row['fingerprint']!r} target_id={row['target_id']!r} "
                f"template_id={row['template_id']!r}"
            )
    if target_ids:
        placeholders = ",".join("?" for _ in target_ids)
        conn.execute(
            f"""
            DELETE FROM witness_candidates
            WHERE first_tested_stage = 'C' AND target_id IN ({placeholders})
            """,
            tuple(target_ids),
        )
    for row in rows:
        upsert_witness_candidate(conn, **row)


def replace_stage_d_witness_candidates(
    conn: sqlite3.Connection,
    target_ids: Sequence[str],
    rows: Sequence[Dict[str, Any]],
) -> None:
    """Replace Stage D rows for targets only. Preserve B/C rows. Call inside a transaction."""
    for row in rows:
        if row.get("first_tested_stage") != "D":
            raise ValueError(
                "Stage D replacement requires first_tested_stage='D' on every payload row"
            )
        existing_preserved = conn.execute(
            """
            SELECT 1 FROM witness_candidates
            WHERE first_tested_stage IN ('B', 'C')
              AND fingerprint = ?
              AND target_id = ?
              AND template_id = ?
            """,
            (row["fingerprint"], row["target_id"], row["template_id"]),
        ).fetchone()
        if existing_preserved is not None:
            raise ValueError(
                "Stage D replacement would collide with an existing B or C row for "
                f"fingerprint={row['fingerprint']!r} target_id={row['target_id']!r} "
                f"template_id={row['template_id']!r}"
            )
    if target_ids:
        placeholders = ",".join("?" for _ in target_ids)
        conn.execute(
            f"""
            DELETE FROM witness_candidates
            WHERE first_tested_stage = 'D' AND target_id IN ({placeholders})
            """,
            tuple(target_ids),
        )
    for row in rows:
        upsert_witness_candidate(conn, **row)


def replace_stage_e_witness_candidates(
    conn: sqlite3.Connection,
    target_ids: Sequence[str],
    rows: Sequence[Dict[str, Any]],
) -> None:
    """Replace Stage E rows for targets only. Preserve B/C/D rows. Call inside a transaction."""
    for row in rows:
        if row.get("first_tested_stage") != "E":
            raise ValueError(
                "Stage E replacement requires first_tested_stage='E' on every payload row"
            )
        existing_preserved = conn.execute(
            """
            SELECT 1 FROM witness_candidates
            WHERE first_tested_stage IN ('B', 'C', 'D')
              AND fingerprint = ?
              AND target_id = ?
              AND template_id = ?
            """,
            (row["fingerprint"], row["target_id"], row["template_id"]),
        ).fetchone()
        if existing_preserved is not None:
            raise ValueError(
                "Stage E replacement would collide with an existing B, C, or D row for "
                f"fingerprint={row['fingerprint']!r} target_id={row['target_id']!r} "
                f"template_id={row['template_id']!r}"
            )
    if target_ids:
        placeholders = ",".join("?" for _ in target_ids)
        conn.execute(
            f"""
            DELETE FROM witness_candidates
            WHERE first_tested_stage = 'E' AND target_id IN ({placeholders})
            """,
            tuple(target_ids),
        )
    for row in rows:
        upsert_witness_candidate(conn, **row)


def _delete_unreferenced_keys(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        DELETE FROM keys
        WHERE NOT EXISTS (
            SELECT 1 FROM derivations AS d WHERE d.fingerprint = keys.fingerprint
        )
          AND NOT EXISTS (
            SELECT 1 FROM addresses AS a WHERE a.fingerprint = keys.fingerprint
        )
          AND NOT EXISTS (
            SELECT 1 FROM witness_candidates AS w WHERE w.fingerprint = keys.fingerprint
        )
        """
    )


def invalidate_stage_c_current_state(conn: sqlite3.Connection) -> None:
    """Drop current Stage C and downstream D/E witness/derivations and orphan keys.

    This is the rollback-to-B operation. Caller owns the transaction.
    """
    conn.execute("DELETE FROM witness_candidates WHERE first_tested_stage IN ('C', 'D', 'E')")
    conn.execute("DELETE FROM derivations WHERE stage IN ('C', 'D', 'E')")
    _delete_unreferenced_keys(conn)


def invalidate_stage_d_current_state(conn: sqlite3.Connection) -> None:
    """Drop current Stage D/E witness/derivations and orphan keys. Caller owns the transaction."""
    conn.execute("DELETE FROM witness_candidates WHERE first_tested_stage IN ('D', 'E')")
    conn.execute("DELETE FROM derivations WHERE stage IN ('D', 'E')")
    _delete_unreferenced_keys(conn)


def invalidate_stage_e_current_state(conn: sqlite3.Connection) -> None:
    """Drop current Stage E witness/derivations and orphan keys. Caller owns the transaction."""
    conn.execute("DELETE FROM witness_candidates WHERE first_tested_stage = 'E'")
    conn.execute("DELETE FROM derivations WHERE stage = 'E'")
    _delete_unreferenced_keys(conn)


def latest_run(conn: sqlite3.Connection) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 1").fetchone()


def latest_run_for_stage(conn: sqlite3.Connection, stage: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM runs WHERE stage = ? ORDER BY id DESC LIMIT 1",
        (stage,),
    ).fetchone()


def fetchall(conn: sqlite3.Connection, sql: str, params: Sequence[Any] = ()) -> List[sqlite3.Row]:
    return list(conn.execute(sql, params).fetchall())


def counts(conn: sqlite3.Connection) -> Dict[str, int]:
    derivation_count = conn.execute("SELECT COUNT(*) FROM derivations").fetchone()[0]
    invalid_count = conn.execute("SELECT COUNT(*) FROM derivations WHERE valid = 0").fetchone()[0]
    unique_keys = conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
    address_count = conn.execute("SELECT COUNT(*) FROM addresses").fetchone()[0]
    p2pkh_u = conn.execute(
        "SELECT COUNT(*) FROM addresses WHERE address_type = 'p2pkh_uncompressed'"
    ).fetchone()[0]
    p2pkh_c = conn.execute(
        "SELECT COUNT(*) FROM addresses WHERE address_type = 'p2pkh_compressed'"
    ).fetchone()[0]
    p2wpkh = conn.execute(
        "SELECT COUNT(*) FROM addresses WHERE address_type = 'p2wpkh'"
    ).fetchone()[0]
    matches = conn.execute("SELECT COUNT(*) FROM target_comparisons WHERE matched = 1").fetchone()[
        0
    ]
    checked = conn.execute("SELECT COUNT(*) FROM history WHERE checked = 1").fetchone()[0]
    seen = conn.execute("SELECT COUNT(*) FROM history WHERE seen_on_chain = 1").fetchone()[0]
    funded = conn.execute(
        "SELECT COUNT(*) FROM history WHERE history_status = 'currently_funded'"
    ).fetchone()[0]
    spent = conn.execute(
        "SELECT COUNT(*) FROM history WHERE history_status = 'spent_history'"
    ).fetchone()[0]
    return {
        "derivations": int(derivation_count),
        "invalid": int(invalid_count),
        "unique_keys": int(unique_keys),
        "addresses": int(address_count),
        "p2pkh_uncompressed": int(p2pkh_u),
        "p2pkh_compressed": int(p2pkh_c),
        "p2wpkh": int(p2wpkh),
        "target_matches": int(matches),
        "history_checked": int(checked),
        "history_seen": int(seen),
        "history_funded": int(funded),
        "history_spent": int(spent),
        "witness_candidates": witness_candidate_count(conn),
        "witness_matches": witness_match_count(conn),
    }


def dump_text(conn: sqlite3.Connection) -> str:
    chunks = []
    for table in (
        "runs",
        "keys",
        "derivations",
        "addresses",
        "history",
        "target_comparisons",
        "witness_candidates",
    ):
        rows = conn.execute(f"SELECT * FROM {table}").fetchall()
        chunks.append(f"[{table}]")
        for row in rows:
            chunks.append(str(tuple(row)))
    return "\n".join(chunks)


def list_addresses(conn: sqlite3.Connection) -> List[sqlite3.Row]:
    return fetchall(conn, "SELECT address, address_type FROM addresses ORDER BY id")


def update_history(
    conn: sqlite3.Connection,
    address: str,
    seen_on_chain: bool,
    balance: int,
    total_received: int,
    total_sent: int,
    transaction_count: int,
    history_status: str,
    first_seen: Optional[str],
    last_checked: str,
) -> None:
    conn.execute(
        """
        UPDATE history
        SET checked = 1, seen_on_chain = ?, balance = ?, total_received = ?,
            total_sent = ?, transaction_count = ?, history_status = ?,
            first_seen = ?, last_checked = ?
        WHERE address = ?
        """,
        (
            int(seen_on_chain),
            balance,
            total_received,
            total_sent,
            transaction_count,
            history_status,
            first_seen,
            last_checked,
            address,
        ),
    )


def history_rows(conn: sqlite3.Connection) -> List[sqlite3.Row]:
    return fetchall(
        conn,
        """
        SELECT h.address, h.address_type, h.seen_on_chain, h.balance,
               h.total_received, h.total_sent, h.transaction_count,
               h.history_status, h.first_seen, h.last_checked,
               GROUP_CONCAT(d.derivation_id, ',') AS derivation_ids,
               GROUP_CONCAT(d.recipe, ' | ') AS derivation_recipes
        FROM history AS h
        JOIN addresses AS a ON a.address = h.address
        LEFT JOIN derivations AS d ON d.fingerprint = a.fingerprint
        WHERE h.checked = 1
        GROUP BY h.address, h.address_type, h.seen_on_chain, h.balance,
                 h.total_received, h.total_sent, h.transaction_count,
                 h.history_status, h.first_seen, h.last_checked
        ORDER BY h.seen_on_chain DESC, h.balance DESC, h.address
        """,
    )
