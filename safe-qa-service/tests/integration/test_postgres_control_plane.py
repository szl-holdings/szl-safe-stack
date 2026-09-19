from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
import pytest

from safe_qa_service.approval_verification import (
    ApprovalVerification,
    canonical_json_bytes,
    deployment_plan_digest,
)
from safe_qa_service.control_plane import (
    ControlPlaneError,
    PlanReplayError,
    PostgresControlRepository,
)
from safe_qa_service.ledger import LedgerReceipt
from safe_qa_service.schemas.v2 import (
    ApprovalBundleV2,
    DeploymentPlanV2,
    EksIsolateNamespaceActionV2,
)

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.integration


@pytest.mark.skipif(not TEST_DATABASE_URL, reason="TEST_DATABASE_URL is not configured")
def test_postgres_control_plan_is_single_use_and_append_only() -> None:
    assert TEST_DATABASE_URL is not None
    migration_dir = Path(__file__).resolve().parents[2] / "db" / "migrations"
    migrations = [
        (migration_dir / name).read_text(encoding="utf-8")
        for name in ("002_control_plane.sql", "003_durable_evidence_outbox.sql")
    ]
    with psycopg.connect(TEST_DATABASE_URL, autocommit=True) as connection:
        connection.execute("DROP TABLE IF EXISTS control_audit_exports CASCADE")
        connection.execute("DROP TABLE IF EXISTS control_audit_leases CASCADE")
        connection.execute("DROP TABLE IF EXISTS control_audit_outbox CASCADE")
        connection.execute("DROP TABLE IF EXISTS control_execution_events CASCADE")
        connection.execute("DROP TABLE IF EXISTS control_executions CASCADE")
        connection.execute("DROP TABLE IF EXISTS control_plans CASCADE")
        for migration in migrations:
            connection.execute(migration)
        connection.execute(migrations[1])

    now = datetime.now(UTC)
    plan = DeploymentPlanV2(
        plan_id=uuid4(),
        nonce="a" * 43,
        source_revision="abcdef1234567890",
        container_digest="sha256:" + "a" * 64,
        evidence_manifest_sha256="b" * 64,
        policy_bundle_sha256="c" * 64,
        provider_state_sha256="d" * 64,
        environment="aws/eks/integration",
        requester_issuer="https://issuer.example.test",
        requester_subject="integration-requester",
        created_at=now,
        expires_at=now + timedelta(minutes=10),
        provider_actions=(
            EksIsolateNamespaceActionV2(
                action_id=UUID(int=1, version=4),
                cluster_name="integration",
                namespace="safe-qa",
            ),
        ),
    )
    digest = deployment_plan_digest(plan)
    repository = PostgresControlRepository(TEST_DATABASE_URL)
    repository.save_plan(
        plan=plan,
        plan_digest=digest,
        requester_subject="integration-requester",
    )
    verification = ApprovalVerification(
        verified=True,
        plan_digest=digest,
        approval_ids=(str(uuid4()), str(uuid4())),
        approver_user_ids=("security-user", "release-user"),
        witness_id=str(uuid4()),
        witness_user_id="witness-user",
        witness_account_id="333333333333",
        verified_at=now,
    )
    bundle = ApprovalBundleV2.model_construct(
        schema_version="2.0",
        plan=plan,
        approvals=(),
        witness=None,
    )
    bundle_digest = hashlib.sha256(canonical_json_bytes(bundle)).hexdigest()
    repository.claim_plan(
        bundle=bundle,
        plan_digest=digest,
        bundle_digest=bundle_digest,
        executor_subject="integration-executor",
        verification=verification,
    )
    receipt_event = repository.record_event(
        plan_id=plan.plan_id,
        event_type="INTEGRATION_RECEIPT",
        payload={"verified": True},
        actor_subject="integration-executor",
        audit_action="control.integration.receipt",
    )
    with pytest.raises(PlanReplayError, match="already consumed"):
        repository.claim_plan(
            bundle=bundle,
            plan_digest=digest,
            bundle_digest=bundle_digest,
            executor_subject="integration-executor",
            verification=verification,
        )

    with psycopg.connect(TEST_DATABASE_URL) as connection:
        persisted = connection.execute(
            """
            SELECT bundle_digest, evidence_persistence_version,
                   approval_bundle, normalized_approval_evidence
            FROM control_executions
            WHERE plan_id = %s
            """,
            (plan.plan_id,),
        ).fetchone()
        assert persisted is not None
        assert persisted[0] == bundle_digest
        assert persisted[1] == 2
        assert persisted[2] == bundle.model_dump(mode="json")
        assert persisted[3]["evidence_format"] == ("safe-qa-normalized-approval-evidence/v2")
        assert repository.audit_outbox_status(plan_id=plan.plan_id).pending_count == 3

    lease_owner = uuid4()
    leased = repository.lease_audit_exports(
        lease_owner=lease_owner,
        lease_seconds=30,
        limit=1,
        only_outbox_id=receipt_event.outbox_id,
    )
    assert len(leased) == 1
    assert (
        repository.lease_audit_exports(
            lease_owner=uuid4(),
            lease_seconds=30,
            limit=1,
            only_outbox_id=receipt_event.outbox_id,
        )
        == ()
    )
    repository.record_audit_export(
        outbox_id=receipt_event.outbox_id,
        lease_owner=lease_owner,
        lease_token=leased[0].lease_token,
        receipt=LedgerReceipt(
            event_id=uuid4(),
            sequence_id=1,
            event_hash="f" * 64,
        ),
    )
    assert repository.audit_outbox_status(plan_id=plan.plan_id).pending_count == 2

    repository.record_event(
        plan_id=plan.plan_id,
        event_type="EXECUTION_COMPLETED",
        payload={"durable_receipt_count": 1},
        actor_subject="integration-executor",
        audit_action="control.execution.completed",
    )
    with pytest.raises(ControlPlaneError, match="already terminal"):
        repository.record_event(
            plan_id=plan.plan_id,
            event_type="EXECUTION_FAILED_CLOSED",
            payload={"failure": "contradiction"},
            actor_subject="integration-executor",
            audit_action="control.execution.failed_closed",
        )

    with (
        pytest.raises(psycopg.Error, match="append-only"),
        psycopg.connect(TEST_DATABASE_URL) as connection,
    ):
        connection.execute(
            "UPDATE control_plans SET requester_subject = 'tampered' WHERE plan_id = %s",
            (plan.plan_id,),
        )
    with (
        pytest.raises(psycopg.Error, match="cannot be truncated"),
        psycopg.connect(TEST_DATABASE_URL) as connection,
    ):
        connection.execute(
            "TRUNCATE control_audit_exports, control_audit_leases, control_audit_outbox"
        )
