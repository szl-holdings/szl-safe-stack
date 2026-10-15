from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import tempfile
import threading
import uuid
from collections.abc import Callable
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

# Restore measurement contract ported from private szl-holdings/szl-estate-os
# estate/evidence_contract.py at 899a5b365a2b4eb01849eb3fec51e3b63ffd8ca2
# (Apache-2.0). Only the isolated SQLite restore transcript is ported.
# The donor production-deployment evidence index is not ported.
# This contract does not apply to Safe QA's PostgreSQL ledger.
# A passing local measurement is unsigned and is not production approval.

RESTORE_MEASUREMENT_SCHEMA = "szl.sqlite-restore-measurement/v2"
MAX_RESTORE_SOURCE_BYTES = 5_000_000
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_RUN_ID_PATTERN = re.compile(r"restore-[a-z0-9][a-z0-9._-]{0,126}")
_TABLE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SQLITE_SIDECAR_SUFFIXES = {"-wal", "-shm", "-journal"}
_RESTORE_MEASUREMENT_KEYS = {
    "schema",
    "status",
    "run_id",
    "tool_sha256",
    "recovery_point_at",
    "started_at",
    "completed_at",
    "rto_seconds",
    "rpo_seconds",
    "source",
    "backup",
    "restore_target",
    "validation",
    "failure_scenarios",
}
_RESTORE_SOURCE_KEYS = {
    "database_sha256_before",
    "database_sha256_after",
    "size_bytes_before",
    "size_bytes_after",
    "mtime_ns_before",
    "mtime_ns_after",
    "data_version_before",
    "data_version_after",
    "sidecars",
    "query_only",
    "unchanged",
}
_RESTORE_SIDECAR_KEYS = {"before", "after"}
_RESTORE_FILE_ATTESTATION_KEYS = {
    "exists",
    "sha256",
    "size_bytes",
    "mtime_ns",
    "device_id",
    "file_id",
}
_RESTORE_BACKUP_KEYS = {"sha256", "size_bytes", "created_at"}
_RESTORE_TARGET_KEYS = {
    "isolation",
    "loopback_only",
    "production_writes",
    "path_disclosed",
    "cleaned_up",
}
_RESTORE_VALIDATION_KEYS = {
    "integrity_check",
    "foreign_key_violation_count",
    "source_schema_sha256",
    "restored_schema_sha256",
    "source_content_sha256",
    "restored_content_sha256",
    "source_row_counts",
    "restored_row_counts",
    "receipt_chain_valid",
    "receipt_count",
}
_RESTORE_FAILURE_KEYS = {"corrupt_backup_rejected", "missing_backup_rejected"}


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _utc_z(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise LedgerError("restore timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _valid_nonnegative_number(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
        and value >= 0
    )


def _valid_nonnegative_int(value: Any) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 0


def _valid_row_counts(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and bool(value)
        and all(
            isinstance(name, str) and bool(name) and _valid_nonnegative_int(count)
            for name, count in value.items()
        )
    )


def _valid_file_attestation(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != _RESTORE_FILE_ATTESTATION_KEYS:
        return False
    exists = value.get("exists")
    if not isinstance(exists, bool):
        return False
    detail_fields = ("sha256", "size_bytes", "mtime_ns", "device_id", "file_id")
    if exists is False:
        return all(value.get(field) is None for field in detail_fields)
    return _SHA256_PATTERN.fullmatch(str(value.get("sha256") or "")) is not None and all(
        _valid_nonnegative_int(value.get(field))
        for field in ("size_bytes", "mtime_ns", "device_id", "file_id")
    )


def _valid_sidecar_attestations(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == _SQLITE_SIDECAR_SUFFIXES
        and all(
            isinstance(record, dict)
            and set(record) == _RESTORE_SIDECAR_KEYS
            and _valid_file_attestation(record.get("before"))
            and _valid_file_attestation(record.get("after"))
            for record in value.values()
        )
    )


def validate_restore_measurement(value: Any) -> tuple[str, str]:
    """Validate an isolated SQLite restore transcript.

    ``PASS`` means the transcript's own timestamps, hashes, and failure
    drills agree. It does not sign the transcript and it is not production
    approval. PostgreSQL measurements are outside this schema.
    """

    if not isinstance(value, dict) or set(value) != _RESTORE_MEASUREMENT_KEYS:
        return "FAIL", "restore measurement shape is invalid"
    if (
        value.get("schema") != RESTORE_MEASUREMENT_SCHEMA
        or value.get("status") != "PASS"
        or _RUN_ID_PATTERN.fullmatch(str(value.get("run_id") or "")) is None
        or _SHA256_PATTERN.fullmatch(str(value.get("tool_sha256") or "")) is None
    ):
        return "FAIL", "restore measurement identity/status is invalid"
    recovery_point = _parse_timestamp(value.get("recovery_point_at"))
    started = _parse_timestamp(value.get("started_at"))
    completed = _parse_timestamp(value.get("completed_at"))
    if (
        recovery_point is None
        or started is None
        or completed is None
        or started < recovery_point
        or completed < started
    ):
        return "FAIL", "restore measurement timestamps are missing or invalid"
    if not _valid_nonnegative_number(value.get("rto_seconds")) or not _valid_nonnegative_number(
        value.get("rpo_seconds")
    ):
        return "FAIL", "restore measurement RTO/RPO is missing or invalid"
    observed_rto = (completed - started).total_seconds()
    observed_rpo = (started - recovery_point).total_seconds()
    if not math.isclose(float(value["rto_seconds"]), observed_rto, abs_tol=1e-6):
        return "FAIL", "restore measurement RTO does not match its timestamps"
    if not math.isclose(float(value["rpo_seconds"]), observed_rpo, abs_tol=1e-6):
        return "FAIL", "restore measurement RPO does not match its timestamps"
    source = value.get("source")
    if not isinstance(source, dict) or set(source) != _RESTORE_SOURCE_KEYS:
        return "FAIL", "restore measurement source shape is invalid"
    for field in ("database_sha256_before", "database_sha256_after"):
        if _SHA256_PATTERN.fullmatch(str(source.get(field) or "")) is None:
            return "FAIL", f"restore measurement {field} is invalid"
    for field in (
        "size_bytes_before",
        "size_bytes_after",
        "mtime_ns_before",
        "mtime_ns_after",
        "data_version_before",
        "data_version_after",
    ):
        if not _valid_nonnegative_int(source.get(field)):
            return "FAIL", f"restore measurement {field} is invalid"
    sidecars = source.get("sidecars")
    if not _valid_sidecar_attestations(sidecars):
        return "FAIL", "restore measurement sidecar attestations are invalid"
    sidecars_unchanged = all(record["before"] == record["after"] for record in sidecars.values())
    if not sidecars_unchanged:
        return "FAIL", "restore drill did not preserve every SQLite sidecar"
    source_unchanged = (
        source.get("query_only") is True
        and source.get("unchanged") is True
        and source["database_sha256_before"] == source["database_sha256_after"]
        and source["size_bytes_before"] == source["size_bytes_after"]
        and source["mtime_ns_before"] == source["mtime_ns_after"]
        and source["data_version_before"] == source["data_version_after"]
        and sidecars_unchanged
    )
    if not source_unchanged:
        return "FAIL", "restore drill did not prove the source database remained unchanged"
    backup = value.get("backup")
    if not isinstance(backup, dict) or set(backup) != _RESTORE_BACKUP_KEYS:
        return "FAIL", "restore measurement backup shape is invalid"
    backup_created = _parse_timestamp(backup.get("created_at"))
    if (
        _SHA256_PATTERN.fullmatch(str(backup.get("sha256") or "")) is None
        or not _valid_nonnegative_int(backup.get("size_bytes"))
        or backup["size_bytes"] <= 0
        or backup_created is None
        or backup_created < recovery_point
        or backup_created > started
    ):
        return "FAIL", "restore measurement backup values are invalid"
    target = value.get("restore_target")
    if not isinstance(target, dict) or set(target) != _RESTORE_TARGET_KEYS:
        return "FAIL", "restore measurement target shape is invalid"
    if not (
        target.get("isolation") == "EPHEMERAL_TEMP_DIRECTORY"
        and target.get("loopback_only") is True
        and target.get("production_writes") == 0
        and not isinstance(target.get("production_writes"), bool)
        and target.get("path_disclosed") is False
        and target.get("cleaned_up") is True
    ):
        return "FAIL", "restore target is not proven isolated and non-destructive"
    validation = value.get("validation")
    if not isinstance(validation, dict) or set(validation) != _RESTORE_VALIDATION_KEYS:
        return "FAIL", "restore measurement validation shape is invalid"
    for field in (
        "source_schema_sha256",
        "restored_schema_sha256",
        "source_content_sha256",
        "restored_content_sha256",
    ):
        if _SHA256_PATTERN.fullmatch(str(validation.get(field) or "")) is None:
            return "FAIL", f"restore measurement validation {field} is invalid"
    if not _valid_row_counts(validation.get("source_row_counts")) or not _valid_row_counts(
        validation.get("restored_row_counts")
    ):
        return "FAIL", "restore measurement row-count evidence is invalid"
    if not (
        validation.get("integrity_check") == "ok"
        and validation.get("foreign_key_violation_count") == 0
        and not isinstance(validation.get("foreign_key_violation_count"), bool)
        and validation["source_schema_sha256"] == validation["restored_schema_sha256"]
        and validation["source_content_sha256"] == validation["restored_content_sha256"]
        and validation["source_row_counts"] == validation["restored_row_counts"]
        and validation.get("receipt_chain_valid") is True
        and _valid_nonnegative_int(validation.get("receipt_count"))
        and validation["receipt_count"] > 0
    ):
        return "FAIL", "restored database integrity or logical equivalence failed"
    scenarios = value.get("failure_scenarios")
    if not isinstance(scenarios, dict) or set(scenarios) != _RESTORE_FAILURE_KEYS:
        return "FAIL", "restore failure-scenario evidence shape is invalid"
    if not all(scenarios.get(field) is True for field in _RESTORE_FAILURE_KEYS):
        return "FAIL", "restore failure scenarios were not rejected fail-closed"
    return "PASS", (
        f"isolated restore run_id={value['run_id']} rto_seconds={value['rto_seconds']} "
        f"rpo_seconds={value['rpo_seconds']}"
    )


def _attest_file(path: Path) -> dict[str, object]:
    if path.is_symlink():
        raise LedgerError("restore attestation refuses a symlink")
    if not path.exists():
        return {
            "exists": False,
            "sha256": None,
            "size_bytes": None,
            "mtime_ns": None,
            "device_id": None,
            "file_id": None,
        }
    if not path.is_file():
        raise LedgerError("restore attestation expected a regular file")
    data = path.read_bytes()
    stat = path.stat()
    mtime_ns = stat.st_mtime_ns
    if not isinstance(mtime_ns, int) or stat.st_size != len(data):
        raise LedgerError("restore attestation observed an unstable file")
    if len(data) > MAX_RESTORE_SOURCE_BYTES:
        raise LedgerError("restore source exceeds the byte limit")
    return {
        "exists": True,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
        "mtime_ns": mtime_ns,
        "device_id": int(stat.st_dev),
        "file_id": int(stat.st_ino),
    }


def _sidecar_attestations(database: Path) -> dict[str, dict[str, object]]:
    return {
        suffix: _attest_file(Path(str(database) + suffix))
        for suffix in _SQLITE_SIDECAR_SUFFIXES
    }


def _data_version(database: Path) -> int:
    uri = database.resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        row = connection.execute("PRAGMA data_version").fetchone()
    if row is None or isinstance(row[0], bool) or not isinstance(row[0], int) or row[0] < 0:
        raise LedgerError("SQLite data_version was unavailable")
    return int(row[0])


def _json_cell(value: object) -> object:
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise LedgerError("SQLite cell is outside the restore content profile")
    if isinstance(value, float) and not math.isfinite(value):
        raise LedgerError("SQLite cell is non-finite")
    return value


def _logical_snapshot(database: Path) -> tuple[str, str, dict[str, int]]:
    uri = database.resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        schema_rows = [
            list(row)
            for row in connection.execute(
                """SELECT type, name, tbl_name, sql
                   FROM sqlite_master
                   WHERE sql IS NOT NULL
                   ORDER BY type, name, tbl_name"""
            )
        ]
        table_names = [
            row[0]
            for row in connection.execute(
                """SELECT name FROM sqlite_master
                   WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                   ORDER BY name"""
            )
        ]
        counts: dict[str, int] = {}
        tables: list[dict[str, object]] = []
        for name in table_names:
            if not isinstance(name, str) or _TABLE_NAME.fullmatch(name) is None:
                raise LedgerError("SQLite table name is outside the restore profile")
            rows = [
                [_json_cell(cell) for cell in row]
                for row in connection.execute(f'SELECT * FROM "{name}" ORDER BY rowid')
            ]
            counts[name] = len(rows)
            tables.append({"table": name, "rows": rows})
    schema_digest = hashlib.sha256(
        _canonical(
            {"profile": "szl.frontier.sqlite-schema.v1", "rows": schema_rows}
        ).encode("utf-8")
    ).hexdigest()
    content_digest = hashlib.sha256(
        _canonical(
            {"profile": "szl.frontier.sqlite-content.v1", "tables": tables}
        ).encode("utf-8")
    ).hexdigest()
    return schema_digest, content_digest, counts


def _failure_scenarios(backup_bytes: bytes, directory: Path) -> tuple[bool, bool]:
    corrupt_path = directory / "corrupt.sqlite3"
    mutated = bytearray(backup_bytes)
    mutated[:16] = b"NOTASQLITEHEADER!"
    corrupt_path.write_bytes(mutated)
    corrupt_rejected = False
    try:
        with closing(sqlite3.connect(corrupt_path)) as connection:
            rows = connection.execute("PRAGMA integrity_check").fetchall()
        corrupt_rejected = rows != [("ok",)]
    except sqlite3.DatabaseError:
        corrupt_rejected = True
    missing = directory / "missing.sqlite3"
    missing_rejected = False
    try:
        with closing(sqlite3.connect(missing.resolve().as_uri() + "?mode=ro", uri=True)) as connection:
            connection.execute("SELECT 1").fetchone()
    except sqlite3.OperationalError:
        missing_rejected = not missing.exists()
    return corrupt_rejected, missing_rejected


def _refused_restore(detail: str) -> dict[str, object]:
    return {
        "schema": "szl.frontier.sqlite-restore-result.v1",
        "production_approval": False,
        "signature": None,
        "engine": "sqlite",
        "postgresql_ledger": "NOT_APPLICABLE",
        "measurement": None,
        "measurement_verdict": "FAIL",
        "measurement_detail": detail,
    }


def isolated_restore_measurement(
    source: Path,
    *,
    recovery_point_at: datetime,
    started_at: datetime,
    clock: Callable[[], datetime] | None = None,
    run_id: str = "restore-gateway-synthetic",
) -> dict[str, object]:
    """Back up and restore a disposable copy of one quiescent SQLite file.

    The source path is read as bytes and is not opened with SQLite, because a
    read-only connection on this host can create ``-wal`` and ``-shm`` sidecars.
    ``data_version`` is read from two isolated byte copies of that file, not by
    opening the source path. Non-empty sidecars are refused so a main-file copy
    cannot drop WAL frames.
    RTO and RPO are computed from ``recovery_point_at``, ``started_at``, and the
    completion clock. Callers do not supply those durations.

    The result is local and unsigned. ``production_approval`` stays false.
    Safe QA PostgreSQL migrations are refused.
    """

    if _RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise LedgerError("restore run_id is invalid")
    try:
        recovery_text = _utc_z(recovery_point_at)
        started_text = _utc_z(started_at)
    except LedgerError as exc:
        return _refused_restore(str(exc))
    if started_at < recovery_point_at:
        return _refused_restore("started_at is before recovery_point_at")
    source = Path(source)
    if source.suffix.lower() == ".sql":
        return _refused_restore(
            "SQLite restore contract does not apply to SQL scripts or the Safe QA PostgreSQL ledger"
        )
    if source.is_symlink() or not source.is_file():
        return _refused_restore("restore source is not a regular SQLite file")
    try:
        before = _attest_file(source)
        sidecars_before = _sidecar_attestations(source)
    except (OSError, LedgerError) as exc:
        return _refused_restore(f"restore source could not be attested: {exc}")
    for suffix, attestation in sidecars_before.items():
        if attestation["exists"] is True and attestation["size_bytes"] != 0:
            return _refused_restore(
                f"source sidecar {suffix} is non-empty; checkpoint and close it before restore"
            )
    source_bytes = source.read_bytes()
    if hashlib.sha256(source_bytes).hexdigest() != before["sha256"]:
        return _refused_restore("restore source changed while it was being read")
    completion_clock = clock if clock is not None else lambda: datetime.now(timezone.utc)
    directory = tempfile.TemporaryDirectory(prefix="szl-gateway-restore-")
    cleaned = False
    measurement: dict[str, Any] | None = None
    try:
        root = Path(directory.name)
        copy_a = root / "copy-a.sqlite3"
        copy_b = root / "copy-b.sqlite3"
        copy_a.write_bytes(source_bytes)
        copy_b.write_bytes(source_bytes)
        version_before = _data_version(copy_a)
        version_after = _data_version(copy_b)
        backup_path = root / "backup.sqlite3"
        with closing(sqlite3.connect(copy_a)) as origin, closing(sqlite3.connect(backup_path)) as backup:
            origin.backup(backup)
        backup_bytes = backup_path.read_bytes()
        if hashlib.sha256(backup_path.read_bytes()).hexdigest() != hashlib.sha256(backup_bytes).hexdigest():
            return _refused_restore("backup bytes changed before restore")
        restored = root / "restored.sqlite3"
        with closing(sqlite3.connect(backup_path)) as backup, closing(sqlite3.connect(restored)) as target:
            backup.backup(target)
        source_schema, source_content, source_counts = _logical_snapshot(copy_a)
        restored_schema, restored_content, restored_counts = _logical_snapshot(restored)
        with closing(sqlite3.connect(restored.resolve().as_uri() + "?mode=ro", uri=True)) as connection:
            integrity_rows = connection.execute("PRAGMA integrity_check").fetchall()
            foreign_key_rows = connection.execute("PRAGMA foreign_key_check").fetchall()
        integrity = integrity_rows[0][0] if len(integrity_rows) == 1 else "fail"
        try:
            chain = ReceiptLedger(restored).verify()
            receipt_count = int(chain["receipt_count"])
            chain_valid = (
                chain["status"] == "VERIFIED"
                and receipt_count > 0
                and receipt_count == restored_counts.get("receipts", -1)
            )
        except LedgerError:
            receipt_count = int(restored_counts.get("receipts", 0))
            chain_valid = False
        corrupt_rejected, missing_rejected = _failure_scenarios(backup_bytes, root)
        after = _attest_file(source)
        sidecars_after = _sidecar_attestations(source)
        try:
            completed_at = completion_clock()
            completed_text = _utc_z(completed_at)
        except LedgerError as exc:
            return _refused_restore(str(exc))
        rto_seconds = (completed_at - started_at).total_seconds()
        rpo_seconds = (started_at - recovery_point_at).total_seconds()
        unchanged = (
            before == after
            and sidecars_before == sidecars_after
            and version_before == version_after
        )
        locally_ok = (
            unchanged
            and source_schema == restored_schema
            and source_content == restored_content
            and source_counts == restored_counts
            and integrity == "ok"
            and foreign_key_rows == []
            and chain_valid
            and corrupt_rejected
            and missing_rejected
            and len(backup_bytes) > 0
            and completed_at >= started_at
        )
        measurement = {
            "schema": RESTORE_MEASUREMENT_SCHEMA,
            "status": "PASS" if locally_ok else "FAIL",
            "run_id": run_id,
            "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "recovery_point_at": recovery_text,
            "started_at": started_text,
            "completed_at": completed_text,
            "rto_seconds": rto_seconds,
            "rpo_seconds": rpo_seconds,
            "source": {
                "database_sha256_before": before["sha256"],
                "database_sha256_after": after["sha256"],
                "size_bytes_before": before["size_bytes"],
                "size_bytes_after": after["size_bytes"],
                "mtime_ns_before": before["mtime_ns"],
                "mtime_ns_after": after["mtime_ns"],
                "data_version_before": version_before,
                "data_version_after": version_after,
                "sidecars": {
                    suffix: {"before": sidecars_before[suffix], "after": sidecars_after[suffix]}
                    for suffix in _SQLITE_SIDECAR_SUFFIXES
                },
                "query_only": True,
                "unchanged": unchanged,
            },
            "backup": {
                "sha256": hashlib.sha256(backup_bytes).hexdigest(),
                "size_bytes": len(backup_bytes),
                "created_at": started_text,
            },
            "restore_target": {
                "isolation": "EPHEMERAL_TEMP_DIRECTORY",
                "loopback_only": True,
                "production_writes": 0,
                "path_disclosed": False,
                "cleaned_up": False,
            },
            "validation": {
                "integrity_check": integrity if isinstance(integrity, str) else "fail",
                "foreign_key_violation_count": len(foreign_key_rows),
                "source_schema_sha256": source_schema,
                "restored_schema_sha256": restored_schema,
                "source_content_sha256": source_content,
                "restored_content_sha256": restored_content,
                "source_row_counts": source_counts,
                "restored_row_counts": restored_counts,
                "receipt_chain_valid": chain_valid,
                "receipt_count": receipt_count,
            },
            "failure_scenarios": {
                "corrupt_backup_rejected": corrupt_rejected,
                "missing_backup_rejected": missing_rejected,
            },
        }
    except (OSError, sqlite3.Error, LedgerError) as exc:
        return _refused_restore(f"isolated restore failed: {type(exc).__name__}")
    finally:
        try:
            directory.cleanup()
        except OSError:
            # A cleanup error cannot attest that every temporary copy was removed.
            # Keep the local measurement fail-closed without exposing its path.
            cleaned = False
        else:
            cleaned = not Path(directory.name).exists()
    if measurement is None:
        return _refused_restore("isolated restore did not produce a measurement")
    measurement["restore_target"]["cleaned_up"] = cleaned
    if measurement["status"] == "PASS" and cleaned is not True:
        measurement["status"] = "FAIL"
    verdict, detail = validate_restore_measurement(measurement)
    return {
        "schema": "szl.frontier.sqlite-restore-result.v1",
        "production_approval": False,
        "signature": None,
        "engine": "sqlite",
        "postgresql_ledger": "NOT_APPLICABLE",
        "measurement": measurement,
        "measurement_verdict": verdict,
        "measurement_detail": detail,
    }
