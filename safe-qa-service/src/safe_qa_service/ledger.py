"""Append-only, hash-chained PostgreSQL audit ledger."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID, uuid4

import psycopg
from psycopg.rows import dict_row

GENESIS_HASH = "0" * 64
LEDGER_LOCK_ID = 8_147_359_009


class LedgerUnavailable(RuntimeError):
    """Raised when a mandatory ledger operation cannot complete."""


@dataclass(frozen=True)
class LedgerReceipt:
    event_id: UUID
    sequence_id: int
    event_hash: str


@dataclass(frozen=True)
class LedgerVerification:
    valid: bool
    event_count: int
    first_invalid_sequence: int | None = None


class AuditLedger(Protocol):
    def append(
        self,
        *,
        actor_subject: str,
        action: str,
        request_id: UUID,
        payload: dict[str, Any],
    ) -> LedgerReceipt: ...

    def healthcheck(self) -> bool: ...

    def verify_head(self) -> bool: ...

    def verify_chain(self) -> LedgerVerification: ...


def _iso_z(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonical_event_bytes(
    *,
    event_id: UUID,
    occurred_at: datetime,
    actor_subject: str,
    action: str,
    request_id: UUID,
    payload: dict[str, Any],
    previous_hash: str,
) -> bytes:
    body = {
        "action": action,
        "actor_subject": actor_subject,
        "event_id": str(event_id),
        "occurred_at": _iso_z(occurred_at),
        "payload": payload,
        "previous_hash": previous_hash,
        "request_id": str(request_id),
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def event_hash(**event: Any) -> str:
    return hashlib.sha256(canonical_event_bytes(**event)).hexdigest()


class PostgresAuditLedger:
    def __init__(self, connection_url: str):
        self.connection_url = connection_url

    def _connect(self, **kwargs: Any):
        return psycopg.connect(
            self.connection_url,
            connect_timeout=3,
            options=(
                "-c statement_timeout=5000 -c lock_timeout=2000 "
                "-c idle_in_transaction_session_timeout=10000"
            ),
            **kwargs,
        )

    def append(
        self,
        *,
        actor_subject: str,
        action: str,
        request_id: UUID,
        payload: dict[str, Any],
    ) -> LedgerReceipt:
        event_id = uuid4()
        occurred_at = datetime.now(UTC)
        if not actor_subject or len(actor_subject) > 256 or not action or len(action) > 128:
            raise LedgerUnavailable("audit ledger event metadata is invalid")
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        if len(payload_json.encode("utf-8")) > 512_000:
            raise LedgerUnavailable("audit ledger payload exceeds the safety bound")
        raw_outbox_id = payload.get("control_outbox_id")
        outbox_id: UUID | None = None
        if raw_outbox_id is not None:
            try:
                outbox_id = UUID(str(raw_outbox_id))
            except ValueError as exc:
                raise LedgerUnavailable(
                    "audit ledger control outbox identifier is invalid"
                ) from exc
            if str(outbox_id) != raw_outbox_id:
                raise LedgerUnavailable("audit ledger control outbox identifier is not canonical")
        try:
            with (
                self._connect() as connection,
                connection.cursor(row_factory=dict_row) as cursor,
            ):
                cursor.execute("SELECT pg_advisory_xact_lock(%s)", (LEDGER_LOCK_ID,))
                if outbox_id is not None:
                    cursor.execute(
                        """
                        SELECT event_id, sequence_id, event_hash
                        FROM audit_events
                        WHERE payload ->> 'control_outbox_id' = %s
                        """,
                        (str(outbox_id),),
                    )
                    existing = cursor.fetchone()
                    if existing is not None:
                        return LedgerReceipt(
                            existing["event_id"],
                            int(existing["sequence_id"]),
                            existing["event_hash"],
                        )
                cursor.execute(
                    "SELECT event_hash FROM audit_events ORDER BY sequence_id DESC LIMIT 1"
                )
                previous = cursor.fetchone()
                previous_hash = previous["event_hash"] if previous else GENESIS_HASH
                digest = event_hash(
                    event_id=event_id,
                    occurred_at=occurred_at,
                    actor_subject=actor_subject,
                    action=action,
                    request_id=request_id,
                    payload=payload,
                    previous_hash=previous_hash,
                )
                cursor.execute(
                    """
                    INSERT INTO audit_events (
                        event_id, occurred_at, actor_subject, action, request_id,
                        payload, previous_hash, event_hash
                    ) VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                    RETURNING sequence_id
                    """,
                    (
                        event_id,
                        occurred_at,
                        actor_subject,
                        action,
                        request_id,
                        payload_json,
                        previous_hash,
                        digest,
                    ),
                )
                sequence_id = int(cursor.fetchone()["sequence_id"])
            return LedgerReceipt(event_id, sequence_id, digest)
        except (psycopg.Error, KeyError, TypeError, ValueError) as exc:
            raise LedgerUnavailable("audit ledger append failed") from exc

    def healthcheck(self) -> bool:
        try:
            with self._connect() as connection:
                row = connection.execute(
                    """
                    SELECT
                        to_regclass('public.audit_events') IS NOT NULL
                        AND to_regclass('public.control_plans') IS NOT NULL
                        AND to_regclass('public.control_executions') IS NOT NULL
                        AND to_regclass('public.control_execution_events') IS NOT NULL
                        AND to_regclass('public.control_audit_outbox') IS NOT NULL
                        AND to_regclass('public.control_audit_leases') IS NOT NULL
                        AND to_regclass('public.control_audit_exports') IS NOT NULL
                        AND to_regclass(
                            'public.control_execution_one_terminal_state_idx'
                        ) IS NOT NULL
                        AND to_regclass('public.audit_events_control_outbox_id_idx') IS NOT NULL
                        AND to_regclass('public.control_audit_leases_expiry_idx') IS NOT NULL
                        AND (
                            SELECT count(*) = 3
                            FROM information_schema.columns
                            WHERE table_schema = 'public'
                              AND table_name = 'control_executions'
                              AND column_name IN (
                                  'evidence_persistence_version',
                                  'approval_bundle',
                                  'normalized_approval_evidence'
                              )
                        )
                        AND EXISTS (
                            SELECT 1
                            FROM pg_constraint AS constraint_record
                            WHERE constraint_record.conrelid =
                                'public.control_executions'::regclass
                              AND constraint_record.conname =
                                'control_executions_evidence_version_check'
                              AND constraint_record.convalidated
                        )
                        AND (
                            SELECT count(DISTINCT trigger_record.tgname) = 13
                            FROM pg_trigger AS trigger_record
                            JOIN pg_class AS relation
                              ON relation.oid = trigger_record.tgrelid
                            JOIN pg_namespace AS namespace
                              ON namespace.oid = relation.relnamespace
                            WHERE namespace.nspname = 'public'
                              AND NOT trigger_record.tgisinternal
                              AND trigger_record.tgenabled <> 'D'
                              AND trigger_record.tgname IN (
                                  'audit_events_reject_update_delete',
                                  'audit_events_reject_truncate',
                                  'control_plans_reject_update_delete',
                                  'control_plans_reject_truncate',
                                  'control_executions_reject_update_delete',
                                  'control_executions_reject_truncate',
                                  'control_events_reject_update_delete',
                                  'control_events_reject_truncate',
                                  'control_events_reject_after_terminal',
                                  'control_outbox_reject_update_delete',
                                  'control_outbox_reject_truncate',
                                  'control_exports_reject_update_delete',
                                  'control_exports_reject_truncate'
                              )
                        )
                    """
                ).fetchone()
                return bool(row and row[0])
        except psycopg.Error:
            return False

    @staticmethod
    def _row_hash_is_valid(row: dict[str, Any]) -> bool:
        expected_hash = event_hash(
            event_id=row["event_id"],
            occurred_at=row["occurred_at"],
            actor_subject=row["actor_subject"],
            action=row["action"],
            request_id=row["request_id"],
            payload=row["payload"],
            previous_hash=row["previous_hash"],
        )
        return hmac.compare_digest(expected_hash, row["event_hash"])

    def verify_head(self) -> bool:
        """Verify the bounded ledger tail used by unauthenticated readiness.

        This intentionally does not claim whole-chain verification.  The full,
        authenticated audit endpoint remains the integrity authority for every
        historical record.
        """

        try:
            with self._connect(row_factory=dict_row) as connection:
                rows = connection.execute(
                    """
                    SELECT sequence_id, event_id, occurred_at, actor_subject, action,
                           request_id, payload, previous_hash, event_hash
                    FROM audit_events
                    ORDER BY sequence_id DESC
                    LIMIT 2
                    """
                ).fetchall()
        except psycopg.Error as exc:
            raise LedgerUnavailable("audit ledger head verification failed") from exc
        if not rows:
            return True
        newest = rows[0]
        try:
            if not self._row_hash_is_valid(newest):
                return False
            if len(rows) == 1:
                return (
                    int(newest["sequence_id"]) == 1
                    and newest["previous_hash"] == GENESIS_HASH
                )
            previous = rows[1]
            return (
                self._row_hash_is_valid(previous)
                and int(newest["sequence_id"]) == int(previous["sequence_id"]) + 1
                and hmac.compare_digest(
                    newest["previous_hash"], previous["event_hash"]
                )
            )
        except (KeyError, TypeError, ValueError):
            return False

    def verify_chain(self) -> LedgerVerification:
        try:
            with (
                self._connect(row_factory=dict_row) as connection,
                connection.cursor(name="safe_qa_ledger_verification") as cursor,
            ):
                cursor.itersize = 1000
                cursor.execute(
                    """
                    SELECT sequence_id, event_id, occurred_at, actor_subject, action,
                           request_id, payload, previous_hash, event_hash
                    FROM audit_events
                    ORDER BY sequence_id
                    """
                )
                expected_previous = GENESIS_HASH
                count = 0
                for row in cursor:
                    count += 1
                    sequence_id = int(row["sequence_id"])
                    if row["previous_hash"] != expected_previous:
                        return LedgerVerification(False, count, sequence_id)
                    if not self._row_hash_is_valid(row):
                        return LedgerVerification(False, count, sequence_id)
                    expected_previous = row["event_hash"]
        except psycopg.Error as exc:
            raise LedgerUnavailable("audit ledger verification failed") from exc
        return LedgerVerification(True, count)
