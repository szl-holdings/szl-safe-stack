from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest

from safe_qa_service.ledger import PostgresAuditLedger

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.integration


@pytest.mark.skipif(not TEST_DATABASE_URL, reason="TEST_DATABASE_URL is not configured")
def test_postgres_ledger_is_hash_chained_and_append_only() -> None:
    assert TEST_DATABASE_URL is not None
    migration_dir = Path(__file__).resolve().parents[2] / "db" / "migrations"
    ledger_migration = (migration_dir / "001_audit_ledger.sql").read_text(encoding="utf-8")
    durable_outbox_migration = (migration_dir / "003_durable_evidence_outbox.sql").read_text(
        encoding="utf-8"
    )
    with psycopg.connect(TEST_DATABASE_URL, autocommit=True) as connection:
        # CASCADE also removes migration 003's expression index on audit_events.
        # Reapplying 003 keeps the disposable database at the current complete
        # schema regardless of integration-test file order.
        connection.execute("DROP TABLE IF EXISTS audit_events CASCADE")
        connection.execute(ledger_migration)
        connection.execute(durable_outbox_migration)

    ledger = PostgresAuditLedger(TEST_DATABASE_URL)
    first = ledger.append(
        actor_subject="integration-test",
        action="evaluation.withheld",
        request_id=uuid4(),
        payload={"release_authorized": False, "ordinal": 1},
    )
    second = ledger.append(
        actor_subject="integration-test",
        action="evaluation.withheld",
        request_id=uuid4(),
        payload={"release_authorized": False, "ordinal": 2},
    )

    assert first.sequence_id == 1
    assert second.sequence_id == 2
    assert first.event_hash != second.event_hash
    assert ledger.verify_chain().valid is True
    assert ledger.healthcheck() is True

    with (
        pytest.raises(psycopg.Error, match="append-only"),
        psycopg.connect(TEST_DATABASE_URL) as connection,
    ):
        connection.execute("UPDATE audit_events SET action = 'tampered' WHERE sequence_id = 1")

    with (
        pytest.raises(psycopg.Error, match="append-only"),
        psycopg.connect(TEST_DATABASE_URL) as connection,
    ):
        connection.execute("TRUNCATE audit_events")
