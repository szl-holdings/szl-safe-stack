from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import psycopg
import pytest

from safe_qa_service.ledger import (
    GENESIS_HASH,
    LedgerUnavailable,
    PostgresAuditLedger,
    event_hash,
)


class Result:
    def __init__(self, *, one=None, many=None):
        self.one = one
        self.many = many or []

    def fetchone(self):
        return self.one

    def fetchall(self):
        return self.many


class AppendCursor:
    def __init__(self):
        self.last_query = ""

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, query, _parameters=None):
        self.last_query = str(query)

    def fetchone(self):
        if "INSERT INTO" in self.last_query:
            return {"sequence_id": 1}
        return None


class StreamCursor:
    def __init__(self, rows):
        self.rows = rows
        self.itersize = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, _query):
        return None

    def __iter__(self):
        return iter(self.rows)


class FakeConnection:
    def __init__(self, *, result: Result | None = None):
        self.result = result or Result(one=(True,))
        self.cursor_instance = AppendCursor()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def cursor(self, **kwargs):
        if kwargs.get("name"):
            return StreamCursor(self.result.many)
        return self.cursor_instance

    def execute(self, _query):
        return self.result


def test_append_returns_receipt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(psycopg, "connect", lambda *_args, **_kwargs: FakeConnection())
    ledger = PostgresAuditLedger("postgresql://example.invalid/db")
    receipt = ledger.append(
        actor_subject="actor",
        action="evaluation.withheld",
        request_id=uuid4(),
        payload={"release_authorized": False},
    )
    assert receipt.sequence_id == 1
    assert len(receipt.event_hash) == 64


def test_append_returns_existing_receipt_for_the_same_control_outbox(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    existing_event_id = UUID("11111111-1111-4111-8111-111111111111")
    outbox_id = UUID("22222222-2222-4222-8222-222222222222")

    class ExistingCursor(AppendCursor):
        def __init__(self) -> None:
            super().__init__()
            self.insert_attempted = False

        def execute(self, query, _parameters=None):
            self.last_query = str(query)
            if "INSERT INTO" in self.last_query:
                self.insert_attempted = True

        def fetchone(self):
            if "control_outbox_id" in self.last_query:
                return {
                    "event_id": existing_event_id,
                    "sequence_id": 7,
                    "event_hash": "a" * 64,
                }
            return super().fetchone()

    connection = FakeConnection()
    connection.cursor_instance = ExistingCursor()
    monkeypatch.setattr(psycopg, "connect", lambda *_args, **_kwargs: connection)
    ledger = PostgresAuditLedger("postgresql://example.invalid/db")

    receipt = ledger.append(
        actor_subject="actor",
        action="control.execution.completed",
        request_id=uuid4(),
        payload={"control_outbox_id": str(outbox_id)},
    )

    assert receipt.event_id == existing_event_id
    assert receipt.sequence_id == 7
    assert connection.cursor_instance.insert_attempted is False


def test_healthcheck_true_and_false(monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = PostgresAuditLedger("postgresql://example.invalid/db")
    monkeypatch.setattr(psycopg, "connect", lambda *_args, **_kwargs: FakeConnection())
    assert ledger.healthcheck() is True

    def unavailable(*_args, **_kwargs):
        raise psycopg.OperationalError("offline")

    monkeypatch.setattr(psycopg, "connect", unavailable)
    assert ledger.healthcheck() is False
    with pytest.raises(LedgerUnavailable, match="append failed"):
        ledger.append(
            actor_subject="actor",
            action="evaluation.withheld",
            request_id=uuid4(),
            payload={},
        )
    with pytest.raises(LedgerUnavailable, match="verification failed"):
        ledger.verify_chain()


def test_verify_chain_accepts_valid_row_and_rejects_tampering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id = UUID("11111111-1111-4111-8111-111111111111")
    request_id = UUID("22222222-2222-4222-8222-222222222222")
    occurred_at = datetime(2026, 8, 9, 12, tzinfo=UTC)
    payload = {"release_authorized": False}
    digest = event_hash(
        event_id=event_id,
        occurred_at=occurred_at,
        actor_subject="actor",
        action="evaluation.withheld",
        request_id=request_id,
        payload=payload,
        previous_hash=GENESIS_HASH,
    )
    row = {
        "sequence_id": 1,
        "event_id": event_id,
        "occurred_at": occurred_at,
        "actor_subject": "actor",
        "action": "evaluation.withheld",
        "request_id": request_id,
        "payload": payload,
        "previous_hash": GENESIS_HASH,
        "event_hash": digest,
    }
    ledger = PostgresAuditLedger("postgresql://example.invalid/db")

    monkeypatch.setattr(
        psycopg,
        "connect",
        lambda *_args, **_kwargs: FakeConnection(result=Result(many=[row])),
    )
    assert ledger.verify_chain().valid is True

    wrong_previous = {**row, "previous_hash": "f" * 64}
    monkeypatch.setattr(
        psycopg,
        "connect",
        lambda *_args, **_kwargs: FakeConnection(result=Result(many=[wrong_previous])),
    )
    assert ledger.verify_chain().first_invalid_sequence == 1

    wrong_hash = {**row, "event_hash": "e" * 64}
    monkeypatch.setattr(
        psycopg,
        "connect",
        lambda *_args, **_kwargs: FakeConnection(result=Result(many=[wrong_hash])),
    )
    assert ledger.verify_chain().first_invalid_sequence == 1


def test_verify_head_is_bounded_and_rejects_tail_gaps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_event_id = UUID("11111111-1111-4111-8111-111111111111")
    second_event_id = UUID("33333333-3333-4333-8333-333333333333")
    request_id = UUID("22222222-2222-4222-8222-222222222222")
    occurred_at = datetime(2026, 8, 9, 12, tzinfo=UTC)
    first_payload = {"sequence": 1}
    first_hash = event_hash(
        event_id=first_event_id,
        occurred_at=occurred_at,
        actor_subject="actor",
        action="first",
        request_id=request_id,
        payload=first_payload,
        previous_hash=GENESIS_HASH,
    )
    first = {
        "sequence_id": 1,
        "event_id": first_event_id,
        "occurred_at": occurred_at,
        "actor_subject": "actor",
        "action": "first",
        "request_id": request_id,
        "payload": first_payload,
        "previous_hash": GENESIS_HASH,
        "event_hash": first_hash,
    }
    second_payload = {"sequence": 2}
    second_hash = event_hash(
        event_id=second_event_id,
        occurred_at=occurred_at,
        actor_subject="actor",
        action="second",
        request_id=request_id,
        payload=second_payload,
        previous_hash=first_hash,
    )
    second = {
        "sequence_id": 2,
        "event_id": second_event_id,
        "occurred_at": occurred_at,
        "actor_subject": "actor",
        "action": "second",
        "request_id": request_id,
        "payload": second_payload,
        "previous_hash": first_hash,
        "event_hash": second_hash,
    }
    ledger = PostgresAuditLedger("postgresql://example.invalid/db")

    monkeypatch.setattr(
        psycopg,
        "connect",
        lambda *_args, **_kwargs: FakeConnection(result=Result(many=[second, first])),
    )
    assert ledger.verify_head() is True

    gap = {**second, "sequence_id": 3}
    monkeypatch.setattr(
        psycopg,
        "connect",
        lambda *_args, **_kwargs: FakeConnection(result=Result(many=[gap, first])),
    )
    assert ledger.verify_head() is False
