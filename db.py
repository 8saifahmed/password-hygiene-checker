"""SQLite storage for scan history.

Only outcomes are stored. The password and any hash of it are deliberately
never written to disk.

SCHEMA MIGRATION NOTE
---------------------
The scan_history schema changed when the -1 sentinel was removed. It used to
be `pwned_status INTEGER` (a bool) plus `breach_count INTEGER NOT NULL`, where
a failed lookup was encoded as pwned_status=0 with breach_count=-1. That
encoding is indistinguishable from a genuine "safe" row unless you test the
sentinel first, which is exactly why it is gone.

The current schema stores `pwned_status TEXT` holding a PwnedStatus value
('PWNED' / 'SAFE' / 'LOOKUP_FAILED'), with `breach_count` NULL for anything
but a real breach.

There is no automatic migration: this is a local scan-history cache with no
irreplaceable data, so the supported upgrade path is simply to DELETE THE OLD
password_checks.db AND LET IT BE RECREATED. init_db() detects an old-schema
database and raises with that instruction rather than failing cryptically or
silently misreading legacy rows.
"""

import os
import sqlite3
from contextlib import closing
from datetime import datetime

from hibp_client import PwnedStatus

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "password_checks.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    pwned_status TEXT NOT NULL,
    breach_count INTEGER,
    strength_score INTEGER NOT NULL,
    crack_time_display TEXT NOT NULL,
    CHECK (
        (pwned_status = 'PWNED' AND breach_count >= 1)
        OR (pwned_status IN ('SAFE', 'LOOKUP_FAILED') AND breach_count IS NULL)
    )
)
"""

_LEGACY_MESSAGE = (
    "{path} uses the old scan_history schema (integer pwned_status with a -1 "
    "breach_count sentinel). There is no migration for this local cache: "
    "delete the file and it will be recreated on the next run."
)


def _connect(db_path: str = DB_PATH) -> sqlite3.Connection:
    """Open a connection with a busy timeout so concurrent writes wait."""
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def _is_legacy_schema(conn: sqlite3.Connection) -> bool:
    """True if scan_history exists but predates the TEXT status column."""
    columns = {
        row["name"]: (row["type"] or "").upper()
        for row in conn.execute("PRAGMA table_info(scan_history)")
    }
    if not columns:
        return False
    return columns.get("pwned_status") != "TEXT"


def init_db(db_path: str = DB_PATH) -> None:
    """Create the scan_history table if it does not already exist.

    Raises RuntimeError if the database predates the status-column schema;
    see the migration note at the top of this module.
    """
    with closing(_connect(db_path)) as conn:
        if _is_legacy_schema(conn):
            raise RuntimeError(_LEGACY_MESSAGE.format(path=db_path))
        with conn:
            conn.execute(_SCHEMA)


def _coerce_status(value) -> PwnedStatus:
    """Accept a PwnedStatus or its stored string value."""
    if isinstance(value, PwnedStatus):
        return value
    try:
        return PwnedStatus(value)
    except ValueError:
        raise ValueError("unrecognised pwned_status: {!r}".format(value)) from None


def save_scan(result: dict, db_path: str = DB_PATH) -> int:
    """Persist one scan result and return its row id.

    Expects `pwned_status` as a PwnedStatus (or its string value) and
    `breach_count` as an int only for PWNED, mirroring PwnedResult.
    """
    if not isinstance(result, dict):
        raise ValueError("result must be a dictionary")

    status = _coerce_status(result.get("pwned_status"))
    breach_count = result.get("breach_count")

    if status is PwnedStatus.PWNED:
        if not isinstance(breach_count, int) or breach_count < 1:
            raise ValueError("a PWNED result requires a positive breach_count")
    elif breach_count is not None:
        raise ValueError("breach_count must be None unless the status is PWNED")

    row = (
        result.get("timestamp") or datetime.now().isoformat(timespec="seconds"),
        status.value,
        breach_count,
        int(result.get("strength_score", 0)),
        str(result.get("crack_time_display", "unknown")),
    )

    with closing(_connect(db_path)) as conn:
        with conn:
            cursor = conn.execute(
                "INSERT INTO scan_history "
                "(timestamp, pwned_status, breach_count, strength_score, crack_time_display) "
                "VALUES (?, ?, ?, ?, ?)",
                row,
            )
            return cursor.lastrowid


def get_scan_history(db_path: str = DB_PATH) -> list:
    """Return every stored scan, newest first, as a list of dictionaries.

    `pwned_status` comes back as a PwnedStatus member and `breach_count` as
    an int only for PWNED rows, matching PwnedResult.
    """
    with closing(_connect(db_path)) as conn:
        rows = conn.execute(
            "SELECT id, timestamp, pwned_status, breach_count, strength_score, "
            "crack_time_display FROM scan_history ORDER BY id DESC"
        ).fetchall()

    return [
        {
            "id": r["id"],
            "timestamp": r["timestamp"],
            "pwned_status": _coerce_status(r["pwned_status"]),
            "breach_count": r["breach_count"],
            "strength_score": r["strength_score"],
            "crack_time_display": r["crack_time_display"],
        }
        for r in rows
    ]
