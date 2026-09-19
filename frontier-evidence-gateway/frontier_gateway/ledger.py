from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


GENESIS_HASH = "0" * 64
HASH_VERSION = "szl.frontier.receipt_hash.v1"
LEGACY_UNBOUND_HASH_VERSION = "szl.frontier.receipt_hash.unbound.v0"


class LedgerError(RuntimeError):
    pass


class LedgerIntegrityError(LedgerError):
    pass


class LedgerUnavailableError(LedgerError):
    pass


def _canonical(value: dict[str, Any]) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _hash_envelope(
    *,
    sequence: int,
    event_id: str,
    created_at: str,
    previous_hash: str,
    canonical_event: str,
) -> str:
    envelope = {
        "schema_version": HASH_VERSION,
        "sequence": sequence,
        "event_id": event_id,
        "created_at": created_at,
        "previous_hash": previous_hash,
        "canonical_event": canonical_event,
    }
    return hashlib.sha256(_canonical(envelope).encode("utf-8")).hexdigest()


class ReceiptLedger:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        try:
            with closing(self._connect()) as connection, connection:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS receipts (
                        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT NOT NULL UNIQUE,
                        created_at TEXT NOT NULL,
                        previous_hash TEXT NOT NULL,
                        event_hash TEXT NOT NULL UNIQUE,
                        canonical_event TEXT NOT NULL,
                        hash_version TEXT NOT NULL
                    );
                    CREATE TRIGGER IF NOT EXISTS receipts_no_update
                    BEFORE UPDATE ON receipts BEGIN SELECT RAISE(ABORT, 'receipts are append-only'); END;
                    CREATE TRIGGER IF NOT EXISTS receipts_no_delete
                    BEFORE DELETE ON receipts BEGIN SELECT RAISE(ABORT, 'receipts are append-only'); END;
                    """
                )
                columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(receipts)").fetchall()
                }
                if "hash_version" not in columns:
                    connection.execute(
                        "ALTER TABLE receipts ADD COLUMN hash_version TEXT NOT NULL "
                        f"DEFAULT '{LEGACY_UNBOUND_HASH_VERSION}'"
                    )
        except sqlite3.Error as exc:
            raise LedgerUnavailableError("receipt ledger could not be initialized") from exc

    def append(self, event: dict[str, Any]) -> dict[str, object]:
        canonical = _canonical(event)
        try:
            with self._lock, closing(self._connect()) as connection, connection:
                # Never extend a chain that already fails verification.
                self.verify()
                connection.execute("BEGIN IMMEDIATE")
                previous = connection.execute(
                    "SELECT sequence, event_hash FROM receipts ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                sequence = int(previous[0]) + 1 if previous else 1
                previous_hash = previous[1] if previous else GENESIS_HASH
                event_id = str(uuid.uuid4())
                created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                event_hash = _hash_envelope(
                    sequence=sequence,
                    event_id=event_id,
                    created_at=created_at,
                    previous_hash=previous_hash,
                    canonical_event=canonical,
                )
                connection.execute(
                    """INSERT INTO receipts(
                           sequence, event_id, created_at, previous_hash, event_hash,
                           canonical_event, hash_version
                       ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        sequence,
                        event_id,
                        created_at,
                        previous_hash,
                        event_hash,
                        canonical,
                        HASH_VERSION,
                    ),
                )
        except sqlite3.Error as exc:
            raise LedgerUnavailableError("receipt could not be appended") from exc
        return {
            "schema_version": "szl.frontier.receipt.v2",
            "hash_version": HASH_VERSION,
            "sequence": sequence,
            "event_id": event_id,
            "created_at": created_at,
            "previous_hash": previous_hash,
            "event_hash": event_hash,
        }

    @staticmethod
    def _verify_envelope_fields(
        sequence: int, event_id: object, created_at: object, canonical: object
    ) -> None:
        try:
            if not isinstance(event_id, str) or str(uuid.UUID(event_id)) != event_id:
                raise ValueError
        except ValueError as exc:
            raise LedgerIntegrityError(f"receipt {sequence} has an invalid event_id") from exc
        try:
            if not isinstance(created_at, str) or not created_at.endswith("Z"):
                raise ValueError
            parsed_created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            canonical_created_at = (
                parsed_created_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            )
            if parsed_created_at.utcoffset() != timezone.utc.utcoffset(None):
                raise ValueError
            if canonical_created_at != created_at:
                raise ValueError
        except ValueError as exc:
            raise LedgerIntegrityError(
                f"receipt {sequence} has an invalid or non-canonical created_at"
            ) from exc
        try:
            if not isinstance(canonical, str) or _canonical(json.loads(canonical)) != canonical:
                raise ValueError
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise LedgerIntegrityError(
                f"receipt {sequence} event is not canonical JSON"
            ) from exc

    def verify(self) -> dict[str, object]:
        previous_hash = GENESIS_HASH
        count = 0
        head = GENESIS_HASH
        expected_sequence = 1
        try:
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    """SELECT sequence, event_id, created_at, previous_hash, event_hash,
                              canonical_event, hash_version
                       FROM receipts ORDER BY sequence"""
                )
                for row in rows:
                    (
                        sequence,
                        event_id,
                        created_at,
                        stored_previous,
                        stored_hash,
                        canonical,
                        hash_version,
                    ) = row
                    count += 1
                    if sequence != expected_sequence:
                        raise LedgerIntegrityError(
                            f"receipt sequence is not contiguous at {sequence}"
                        )
                    if hash_version != HASH_VERSION:
                        raise LedgerIntegrityError(
                            f"receipt {sequence} uses unsupported hash version {hash_version!r}"
                        )
                    if stored_previous != previous_hash:
                        raise LedgerIntegrityError(
                            f"receipt {sequence} has a broken previous_hash link"
                        )
                    self._verify_envelope_fields(sequence, event_id, created_at, canonical)
                    expected = _hash_envelope(
                        sequence=sequence,
                        event_id=event_id,
                        created_at=created_at,
                        previous_hash=stored_previous,
                        canonical_event=canonical,
                    )
                    if stored_hash != expected:
                        raise LedgerIntegrityError(
                            f"receipt {sequence} hash does not match its immutable envelope"
                        )
                    previous_hash = stored_hash
                    head = stored_hash
                    expected_sequence += 1
        except LedgerIntegrityError:
            raise
        except sqlite3.Error as exc:
            raise LedgerUnavailableError("receipt ledger could not be read") from exc
        return {
            "schema_version": "szl.frontier.ledger.verification.v2",
            "hash_version": HASH_VERSION,
            "status": "VERIFIED",
            "receipt_count": count,
            "head_hash": head,
        }
