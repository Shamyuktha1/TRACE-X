
import sqlite3
from pathlib import Path


# Database location
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "evidence" / "trace_x_evidence.db"


def get_connection():
    """Create a connection to the TRACE-X evidence database."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():
    """Create the evidence table if it does not exist."""

    with get_connection() as connection:

                connection.execute("""
            CREATE TABLE IF NOT EXISTS evidence_records (

                evidence_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                upload_time TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                integrity_status TEXT NOT NULL

            )
        """)
                connection.execute("""
            CREATE TABLE IF NOT EXISTS custody_logs (

                log_id INTEGER PRIMARY KEY AUTOINCREMENT,

                evidence_id TEXT NOT NULL,

                action TEXT NOT NULL,

                performed_by TEXT NOT NULL,

                timestamp TEXT NOT NULL,

                details TEXT,

                previous_hash TEXT,

                current_hash TEXT

            )
        """)

def save_evidence_record(record):
    """Save or update an evidence record."""

    with get_connection() as connection:

                connection.execute("""
            INSERT OR REPLACE INTO evidence_records (

                evidence_id,
                filename,
                sha256,
                upload_time,
                evidence_type,
                integrity_status

            )

            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            record["Evidence ID"],
            record["Filename"],
            record["SHA-256"],
            record["Upload Time"],
            record["Evidence Type"],
            record["Integrity Status"]
        ))


def get_all_evidence():
    """Retrieve all stored evidence records."""

    with get_connection() as connection:

        rows = connection.execute("""
            SELECT *
            FROM evidence_records
            ORDER BY upload_time DESC
        """).fetchall()

    return [dict(row) for row in rows]

from datetime import datetime, timezone


def record_custody_event(
    evidence_id,
    action,
    performed_by="TRACE-X Investigator",
    details="",
    previous_hash=None,
    current_hash=None
):
    """Record an evidence-handling event in the custody log."""

    event_time = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    with get_connection() as connection:

                connection.execute("""
            INSERT INTO custody_logs (

                evidence_id,
                action,
                performed_by,
                timestamp,
                details,
                previous_hash,
                current_hash

            )

            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            evidence_id,
            action,
            performed_by,
            event_time,
            details,
            previous_hash,
            current_hash
        ))

def get_custody_history(evidence_id=None):
    """Retrieve chain-of-custody events."""

    with get_connection() as connection:

        if evidence_id:

            rows = connection.execute("""
                SELECT *
                FROM custody_logs
                WHERE evidence_id = ?
                ORDER BY log_id ASC
            """, (evidence_id,)).fetchall()

        else:

            rows = connection.execute("""
                SELECT *
                FROM custody_logs
                ORDER BY log_id ASC
            """).fetchall()

    return [dict(row) for row in rows]


