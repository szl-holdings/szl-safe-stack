"""Fail-closed orchestration for signed, exact-target provider actions.

PostgreSQL is the primary durability boundary.  Every control event and its
secondary-ledger export request are committed in one database transaction.
The hash-chained audit ledger is deliberately treated as an at-least-once
secondary sink: an outage can leave a recoverable outbox item, but cannot
rewrite a successful provider operation as a contradictory failure.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from uuid import UUID, uuid4

import psycopg

from .approval_verification import (
    ApprovalVerification,
    ApprovalVerificationError,
    CloudTrailLookupProvider,
    KmsVerifyProvider,
    SignerPolicy,
    canonical_json_bytes,
    deployment_plan_digest,
    verify_approval_bundle,
)
from .auth import Principal
from .aws_control import AwsControlError, AwsControlProvider, provider_state_digest
from .ledger import AuditLedger, LedgerReceipt, LedgerUnavailable
from .schemas.v2 import (
    ApprovalBundleV2,
    ApprovalRole,
    ControlExecutionResponseV2,
    DeploymentPlanV2,
    ProviderActionReceiptV2,
    UnsignedPlanRequestV2,
    UnsignedPlanResponseV2,
)

TERMINAL_EVENT_TYPES = frozenset({"EXECUTION_COMPLETED", "EXECUTION_FAILED_CLOSED"})


class ControlPlaneError(RuntimeError):
    """The operation was not safely authorized, recorded, executed, or verified."""


class PlanReplayError(ControlPlaneError):
    """A plan was not issued here or was already consumed."""


@dataclass(frozen=True)
class AuditOutboxRecord:
    """A durable, retryable request to export one primary control event."""

    outbox_id: UUID
    plan_id: UUID
    control_event_id: UUID | None
    actor_subject: str
    audit_action: str
    request_id: UUID
    payload: dict[str, Any]


@dataclass(frozen=True)
class AuditOutboxLease:
    """Exclusive, expiring ownership of one secondary-ledger delivery attempt."""

    record: AuditOutboxRecord
    lease_owner: UUID
    lease_token: UUID
    leased_until: datetime
    attempt_count: int


@dataclass(frozen=True)
class AuditOutboxStatus:
    """Readiness data for the durable secondary-audit backlog."""

    pending_count: int
    oldest_pending_age_seconds: float


class ControlRepository(Protocol):
    def save_plan(
        self,
        *,
        plan: DeploymentPlanV2,
        plan_digest: str,
        requester_subject: str,
    ) -> AuditOutboxRecord: ...

    def claim_plan(
        self,
        *,
        bundle: ApprovalBundleV2,
        plan_digest: str,
        bundle_digest: str,
        executor_subject: str,
        verification: ApprovalVerification,
    ) -> AuditOutboxRecord: ...

    def record_event(
        self,
        *,
        plan_id: UUID,
        event_type: str,
        payload: dict[str, Any],
        actor_subject: str,
        audit_action: str,
    ) -> AuditOutboxRecord: ...

    def lease_audit_exports(
        self,
        *,
        lease_owner: UUID,
        lease_seconds: int = 30,
        limit: int = 100,
        only_outbox_id: UUID | None = None,
    ) -> tuple[AuditOutboxLease, ...]: ...

    def release_audit_lease(
        self,
        *,
        outbox_id: UUID,
        lease_owner: UUID,
        lease_token: UUID,
    ) -> None: ...

    def audit_outbox_status(self, *, plan_id: UUID | None = None) -> AuditOutboxStatus: ...

    def record_audit_export(
        self,
        *,
        outbox_id: UUID,
        lease_owner: UUID,
        lease_token: UUID,
        receipt: LedgerReceipt,
    ) -> None: ...


class EvidenceProvider(KmsVerifyProvider, CloudTrailLookupProvider, Protocol):
    """Combined verify-only KMS and independent CloudTrail lookup boundary."""


def _bounded_json(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(raw.encode("utf-8")) > 256_000:
        raise ControlPlaneError("control-plane persistence payload exceeds the safety bound")
    return raw


def _validate_audit_metadata(*, actor_subject: str, audit_action: str) -> None:
    if not actor_subject or len(actor_subject) > 256:
        raise ControlPlaneError("control audit actor identity is invalid")
    if not audit_action or len(audit_action) > 128:
        raise ControlPlaneError("control audit action is invalid")


def _signature_evidence(signed: Any) -> dict[str, Any]:
    """Normalize provider evidence while binding, but not duplicating, raw signature bytes.

    The complete raw detached signature remains in ``approval_bundle``.  This
    derivative makes identity and CloudTrail review convenient and binds the
    exact signature through its length and SHA-256 digest.
    """

    raw_signature = base64.b64decode(signed.signature.signature_b64, validate=True)
    return {
        "statement": signed.statement.model_dump(mode="json"),
        "signature": {
            "key_arn": signed.signature.key_arn,
            "algorithm": signed.signature.algorithm,
            "message_type": signed.signature.message_type,
            "provider_request_id": str(signed.signature.provider_request_id),
            "signature_length_bytes": len(raw_signature),
            "signature_sha256": hashlib.sha256(raw_signature).hexdigest(),
        },
        "cloudtrail_sign_event": signed.cloudtrail_sign_event.model_dump(mode="json"),
    }


def _normalized_approval_evidence(
    bundle: ApprovalBundleV2,
    verification: ApprovalVerification,
) -> dict[str, Any]:
    approvals = [_signature_evidence(item) for item in bundle.approvals]
    witness = _signature_evidence(bundle.witness) if bundle.witness is not None else None
    return {
        "evidence_format": "safe-qa-normalized-approval-evidence/v2",
        "normalization_basis": (
            "KMS_VERIFY_ACCEPTED_AND_CLOUDTRAIL_STABLE_FIELDS_MATCHED_PROVIDER_LOOKUP"
        ),
        "verification": {
            "verified": verification.verified,
            "plan_digest": verification.plan_digest,
            "approval_ids": list(verification.approval_ids),
            "approver_user_ids": list(verification.approver_user_ids),
            "witness_id": verification.witness_id,
            "witness_user_id": verification.witness_user_id,
            "witness_account_id": verification.witness_account_id,
            "verified_at": verification.verified_at.isoformat(),
        },
        "approvals": approvals,
        "witness": witness,
    }


class PostgresControlRepository:
    """Append-only issued-plan, execution-evidence, terminal-state, and outbox store."""

    def __init__(self, connection_url: str):
        self.connection_url = connection_url

    def _connect(self):
        return psycopg.connect(
            self.connection_url,
            connect_timeout=3,
            options=(
                "-c statement_timeout=5000 -c lock_timeout=2000 "
                "-c idle_in_transaction_session_timeout=10000"
            ),
        )

    @staticmethod
    def _insert_outbox_in_transaction(
        connection: Any,
        *,
        outbox_id: UUID,
        plan_id: UUID,
        control_event_id: UUID | None,
        actor_subject: str,
        audit_action: str,
        request_id: UUID,
        payload: dict[str, Any],
    ) -> AuditOutboxRecord:
        _validate_audit_metadata(actor_subject=actor_subject, audit_action=audit_action)
        payload_json = _bounded_json(payload)
        connection.execute(
            """
            INSERT INTO control_audit_outbox (
                outbox_id, plan_id, control_event_id, actor_subject,
                audit_action, request_id, payload
            ) VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
            """,
            (
                outbox_id,
                plan_id,
                control_event_id,
                actor_subject,
                audit_action,
                request_id,
                payload_json,
            ),
        )
        return AuditOutboxRecord(
            outbox_id=outbox_id,
            plan_id=plan_id,
            control_event_id=control_event_id,
            actor_subject=actor_subject,
            audit_action=audit_action,
            request_id=request_id,
            payload=payload,
        )

    def save_plan(
        self,
        *,
        plan: DeploymentPlanV2,
        plan_digest: str,
        requester_subject: str,
    ) -> AuditOutboxRecord:
        if len(requester_subject) > 256:
            raise ControlPlaneError("requester identity exceeds the persistence bound")
        outbox_id = uuid4()
        payload = {
            "plan": plan.model_dump(mode="json"),
            "plan_digest": plan_digest,
            "authorization_status": "UNSIGNED_NOT_EXECUTABLE",
        }
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO control_plans (
                        plan_id, plan_digest, requester_subject, expires_at, plan
                    ) VALUES (%s, %s, %s, %s, %s::jsonb)
                    """,
                    (
                        plan.plan_id,
                        plan_digest,
                        requester_subject,
                        plan.expires_at,
                        _bounded_json(plan.model_dump(mode="json")),
                    ),
                )
                return self._insert_outbox_in_transaction(
                    connection,
                    outbox_id=outbox_id,
                    plan_id=plan.plan_id,
                    control_event_id=None,
                    actor_subject=requester_subject,
                    audit_action="control.plan.issued",
                    request_id=plan.plan_id,
                    payload=payload,
                )
        except psycopg.errors.UniqueViolation as exc:
            raise ControlPlaneError("control plan identifier collision") from exc
        except ControlPlaneError:
            raise
        except psycopg.Error as exc:
            raise ControlPlaneError("control plan could not be durably issued") from exc

    def claim_plan(
        self,
        *,
        bundle: ApprovalBundleV2,
        plan_digest: str,
        bundle_digest: str,
        executor_subject: str,
        verification: ApprovalVerification,
    ) -> AuditOutboxRecord:
        plan = bundle.plan
        if not verification.verified or verification.plan_digest != plan_digest:
            raise ControlPlaneError("approval verification result does not bind the claimed plan")
        calculated_bundle_digest = hashlib.sha256(canonical_json_bytes(bundle)).hexdigest()
        if calculated_bundle_digest != bundle_digest:
            raise ControlPlaneError("approval bundle digest changed before persistence")
        bundle_payload = bundle.model_dump(mode="json")
        normalized_evidence = _normalized_approval_evidence(bundle, verification)
        try:
            with self._connect() as connection:
                issued = connection.execute(
                    """
                    SELECT plan_digest, expires_at
                    FROM control_plans
                    WHERE plan_id = %s
                    FOR UPDATE
                    """,
                    (plan.plan_id,),
                ).fetchone()
                if (
                    issued is None
                    or issued[0] != plan_digest
                    or issued[1].astimezone(UTC) <= verification.verified_at.astimezone(UTC)
                ):
                    raise PlanReplayError("plan was not issued here or is no longer executable")
                connection.execute(
                    """
                    INSERT INTO control_executions (
                        plan_id, plan_digest, bundle_digest, executor_subject,
                        approval_verification, evidence_persistence_version,
                        approval_bundle, normalized_approval_evidence
                    ) VALUES (%s, %s, %s, %s, %s::jsonb, 2, %s::jsonb, %s::jsonb)
                    """,
                    (
                        plan.plan_id,
                        plan_digest,
                        bundle_digest,
                        executor_subject,
                        _bounded_json(normalized_evidence["verification"]),
                        _bounded_json(bundle_payload),
                        _bounded_json(normalized_evidence),
                    ),
                )
                return self._record_event_in_transaction(
                    connection,
                    plan_id=plan.plan_id,
                    event_type="EXECUTION_CLAIMED",
                    payload={
                        "plan_digest": plan_digest,
                        "bundle_digest": bundle_digest,
                        "evidence_persistence_version": 2,
                    },
                    actor_subject=executor_subject,
                    audit_action="control.execution.authorized",
                )
        except PlanReplayError:
            raise
        except psycopg.errors.UniqueViolation as exc:
            raise PlanReplayError("control plan was already consumed") from exc
        except ControlPlaneError:
            raise
        except psycopg.Error as exc:
            raise ControlPlaneError("control plan could not be atomically claimed") from exc

    @classmethod
    def _record_event_in_transaction(
        cls,
        connection: Any,
        *,
        plan_id: UUID,
        event_type: str,
        payload: dict[str, Any],
        actor_subject: str,
        audit_action: str,
    ) -> AuditOutboxRecord:
        execution = connection.execute(
            "SELECT plan_id FROM control_executions WHERE plan_id = %s FOR UPDATE",
            (plan_id,),
        ).fetchone()
        if execution is None:
            raise PlanReplayError("control execution is not durably claimed")
        terminal = connection.execute(
            """
            SELECT event_type
            FROM control_execution_events
            WHERE plan_id = %s
              AND event_type IN ('EXECUTION_COMPLETED', 'EXECUTION_FAILED_CLOSED')
            """,
            (plan_id,),
        ).fetchone()
        if terminal is not None:
            raise ControlPlaneError(f"control execution is already terminal: {terminal[0]}")
        row = connection.execute(
            """
            SELECT COALESCE(MAX(sequence_id), 0) + 1
            FROM control_execution_events
            WHERE plan_id = %s
            """,
            (plan_id,),
        ).fetchone()
        sequence_id = int(row[0])
        event_id = uuid4()
        connection.execute(
            """
            INSERT INTO control_execution_events (
                event_id, plan_id, sequence_id, event_type, payload
            ) VALUES (%s, %s, %s, %s, %s::jsonb)
            """,
            (event_id, plan_id, sequence_id, event_type, _bounded_json(payload)),
        )
        return cls._insert_outbox_in_transaction(
            connection,
            outbox_id=event_id,
            plan_id=plan_id,
            control_event_id=event_id,
            actor_subject=actor_subject,
            audit_action=audit_action,
            request_id=plan_id,
            payload=payload,
        )

    def record_event(
        self,
        *,
        plan_id: UUID,
        event_type: str,
        payload: dict[str, Any],
        actor_subject: str,
        audit_action: str,
    ) -> AuditOutboxRecord:
        if not event_type or len(event_type) > 80:
            raise ControlPlaneError("control event type is invalid")
        try:
            with self._connect() as connection:
                return self._record_event_in_transaction(
                    connection,
                    plan_id=plan_id,
                    event_type=event_type,
                    payload=payload,
                    actor_subject=actor_subject,
                    audit_action=audit_action,
                )
        except ControlPlaneError:
            raise
        except psycopg.errors.UniqueViolation as exc:
            if event_type in TERMINAL_EVENT_TYPES:
                raise ControlPlaneError("control execution already has a terminal state") from exc
            raise ControlPlaneError("control execution event identifier collided") from exc
        except psycopg.Error as exc:
            raise ControlPlaneError("control execution event could not be recorded") from exc

    def lease_audit_exports(
        self,
        *,
        lease_owner: UUID,
        lease_seconds: int = 30,
        limit: int = 100,
        only_outbox_id: UUID | None = None,
    ) -> tuple[AuditOutboxLease, ...]:
        if not 1 <= limit <= 1000:
            raise ControlPlaneError("audit outbox limit must be between 1 and 1000")
        if not 5 <= lease_seconds <= 300:
            raise ControlPlaneError("audit lease must be between 5 and 300 seconds")
        leased: list[AuditOutboxLease] = []
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    """
                    SELECT o.outbox_id, o.plan_id, o.control_event_id,
                           o.actor_subject, o.audit_action, o.request_id, o.payload
                    FROM control_audit_outbox AS o
                    LEFT JOIN control_audit_exports AS e ON e.outbox_id = o.outbox_id
                    LEFT JOIN control_audit_leases AS l ON l.outbox_id = o.outbox_id
                    WHERE e.outbox_id IS NULL
                      AND (l.outbox_id IS NULL OR l.leased_until <= clock_timestamp())
                      AND (%s::uuid IS NULL OR o.outbox_id = %s::uuid)
                    ORDER BY o.created_at, o.outbox_id
                    FOR UPDATE OF o SKIP LOCKED
                    LIMIT %s
                    """,
                    (only_outbox_id, only_outbox_id, limit),
                ).fetchall()
                for row in rows:
                    lease_token = uuid4()
                    lease_row = connection.execute(
                        """
                        INSERT INTO control_audit_leases (
                            outbox_id, lease_owner, lease_token, leased_until,
                            attempt_count, last_leased_at
                        ) VALUES (
                            %s, %s, %s,
                            clock_timestamp() + (%s * interval '1 second'),
                            1, clock_timestamp()
                        )
                        ON CONFLICT (outbox_id) DO UPDATE SET
                            lease_owner = EXCLUDED.lease_owner,
                            lease_token = EXCLUDED.lease_token,
                            leased_until = EXCLUDED.leased_until,
                            attempt_count = control_audit_leases.attempt_count + 1,
                            last_leased_at = EXCLUDED.last_leased_at
                        RETURNING leased_until, attempt_count
                        """,
                        (row[0], lease_owner, lease_token, lease_seconds),
                    ).fetchone()
                    record = AuditOutboxRecord(
                        outbox_id=row[0],
                        plan_id=row[1],
                        control_event_id=row[2],
                        actor_subject=row[3],
                        audit_action=row[4],
                        request_id=row[5],
                        payload=row[6],
                    )
                    leased.append(
                        AuditOutboxLease(
                            record=record,
                            lease_owner=lease_owner,
                            lease_token=lease_token,
                            leased_until=lease_row[0],
                            attempt_count=int(lease_row[1]),
                        )
                    )
        except psycopg.Error as exc:
            raise ControlPlaneError("control audit outbox could not be leased") from exc
        return tuple(leased)

    def release_audit_lease(
        self,
        *,
        outbox_id: UUID,
        lease_owner: UUID,
        lease_token: UUID,
    ) -> None:
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    DELETE FROM control_audit_leases
                    WHERE outbox_id = %s AND lease_owner = %s AND lease_token = %s
                    """,
                    (outbox_id, lease_owner, lease_token),
                )
        except psycopg.Error as exc:
            raise ControlPlaneError("control audit lease could not be released") from exc

    def audit_outbox_status(self, *, plan_id: UUID | None = None) -> AuditOutboxStatus:
        try:
            with self._connect() as connection:
                row = connection.execute(
                    """
                    SELECT
                        COUNT(*),
                        COALESCE(
                            GREATEST(
                                0,
                                EXTRACT(EPOCH FROM (clock_timestamp() - MIN(o.created_at)))
                            ),
                            0
                        )
                    FROM control_audit_outbox AS o
                    LEFT JOIN control_audit_exports AS e ON e.outbox_id = o.outbox_id
                    WHERE e.outbox_id IS NULL
                      AND (%s::uuid IS NULL OR o.plan_id = %s::uuid)
                    """,
                    (plan_id, plan_id),
                ).fetchone()
        except psycopg.Error as exc:
            raise ControlPlaneError("control audit outbox status could not be read") from exc
        return AuditOutboxStatus(
            pending_count=int(row[0]),
            oldest_pending_age_seconds=float(row[1]),
        )

    def record_audit_export(
        self,
        *,
        outbox_id: UUID,
        lease_owner: UUID,
        lease_token: UUID,
        receipt: LedgerReceipt,
    ) -> None:
        try:
            with self._connect() as connection:
                lease = connection.execute(
                    """
                    SELECT 1
                    FROM control_audit_leases
                    WHERE outbox_id = %s AND lease_owner = %s AND lease_token = %s
                    FOR UPDATE
                    """,
                    (outbox_id, lease_owner, lease_token),
                ).fetchone()
                if lease is None:
                    raise ControlPlaneError("audit export lease is missing, expired, or superseded")
                connection.execute(
                    """
                    INSERT INTO control_audit_exports (
                        export_id, outbox_id, ledger_event_id,
                        ledger_sequence_id, ledger_event_hash
                    ) VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        uuid4(),
                        outbox_id,
                        receipt.event_id,
                        receipt.sequence_id,
                        receipt.event_hash,
                    ),
                )
                connection.execute(
                    """
                    DELETE FROM control_audit_leases
                    WHERE outbox_id = %s AND lease_owner = %s AND lease_token = %s
                    """,
                    (outbox_id, lease_owner, lease_token),
                )
        except ControlPlaneError:
            raise
        except psycopg.errors.UniqueViolation as exc:
            raise ControlPlaneError("audit outbox item was already exported") from exc
        except psycopg.Error as exc:
            raise ControlPlaneError("audit export receipt could not be persisted") from exc


@dataclass
class InMemoryControlRepository:
    """Deterministic test repository; never selected by production configuration."""

    def __post_init__(self) -> None:
        self.plans: dict[UUID, tuple[str, datetime]] = {}
        self.plan_payloads: dict[UUID, dict[str, Any]] = {}
        self.claimed: set[UUID] = set()
        self.execution_evidence: dict[UUID, dict[str, Any]] = {}
        self.events: dict[UUID, list[tuple[UUID, str, dict[str, Any]]]] = {}
        self.outbox: dict[UUID, AuditOutboxRecord] = {}
        self.outbox_created_at: dict[UUID, datetime] = {}
        self.audit_exports: dict[UUID, LedgerReceipt] = {}
        self.audit_leases: dict[UUID, tuple[UUID, UUID, datetime, int]] = {}

    def _queue_audit(
        self,
        *,
        outbox_id: UUID,
        plan_id: UUID,
        control_event_id: UUID | None,
        actor_subject: str,
        audit_action: str,
        payload: dict[str, Any],
    ) -> AuditOutboxRecord:
        _validate_audit_metadata(actor_subject=actor_subject, audit_action=audit_action)
        _bounded_json(payload)
        record = AuditOutboxRecord(
            outbox_id=outbox_id,
            plan_id=plan_id,
            control_event_id=control_event_id,
            actor_subject=actor_subject,
            audit_action=audit_action,
            request_id=plan_id,
            payload=payload,
        )
        self.outbox[outbox_id] = record
        self.outbox_created_at[outbox_id] = datetime.now(UTC)
        return record

    def save_plan(
        self,
        *,
        plan: DeploymentPlanV2,
        plan_digest: str,
        requester_subject: str,
    ) -> AuditOutboxRecord:
        if plan.plan_id in self.plans:
            raise ControlPlaneError("control plan identifier collision")
        self.plans[plan.plan_id] = (plan_digest, plan.expires_at)
        self.plan_payloads[plan.plan_id] = plan.model_dump(mode="json")
        return self._queue_audit(
            outbox_id=uuid4(),
            plan_id=plan.plan_id,
            control_event_id=None,
            actor_subject=requester_subject,
            audit_action="control.plan.issued",
            payload={
                "plan": plan.model_dump(mode="json"),
                "plan_digest": plan_digest,
                "authorization_status": "UNSIGNED_NOT_EXECUTABLE",
            },
        )

    def claim_plan(
        self,
        *,
        bundle: ApprovalBundleV2,
        plan_digest: str,
        bundle_digest: str,
        executor_subject: str,
        verification: ApprovalVerification,
    ) -> AuditOutboxRecord:
        plan = bundle.plan
        if not verification.verified or verification.plan_digest != plan_digest:
            raise ControlPlaneError("approval verification result does not bind the claimed plan")
        issued = self.plans.get(plan.plan_id)
        if (
            issued is None
            or issued[0] != plan_digest
            or issued[1].astimezone(UTC) <= verification.verified_at.astimezone(UTC)
            or plan.plan_id in self.claimed
        ):
            raise PlanReplayError("plan was not issued here, expired, or was already consumed")
        if hashlib.sha256(canonical_json_bytes(bundle)).hexdigest() != bundle_digest:
            raise ControlPlaneError("approval bundle digest changed before persistence")
        self.claimed.add(plan.plan_id)
        self.execution_evidence[plan.plan_id] = {
            "bundle_digest": bundle_digest,
            "approval_bundle": bundle.model_dump(mode="json"),
            "normalized_approval_evidence": _normalized_approval_evidence(bundle, verification),
        }
        return self.record_event(
            plan_id=plan.plan_id,
            event_type="EXECUTION_CLAIMED",
            payload={
                "plan_digest": plan_digest,
                "bundle_digest": bundle_digest,
                "evidence_persistence_version": 2,
            },
            actor_subject=executor_subject,
            audit_action="control.execution.authorized",
        )

    def record_event(
        self,
        *,
        plan_id: UUID,
        event_type: str,
        payload: dict[str, Any],
        actor_subject: str,
        audit_action: str,
    ) -> AuditOutboxRecord:
        if plan_id not in self.claimed:
            raise PlanReplayError("control execution is not claimed")
        existing = self.events.get(plan_id, [])
        terminal = next((item[1] for item in existing if item[1] in TERMINAL_EVENT_TYPES), None)
        if terminal is not None:
            raise ControlPlaneError(f"control execution is already terminal: {terminal}")
        event_id = uuid4()
        self.events.setdefault(plan_id, []).append((event_id, event_type, payload))
        return self._queue_audit(
            outbox_id=event_id,
            plan_id=plan_id,
            control_event_id=event_id,
            actor_subject=actor_subject,
            audit_action=audit_action,
            payload=payload,
        )

    def lease_audit_exports(
        self,
        *,
        lease_owner: UUID,
        lease_seconds: int = 30,
        limit: int = 100,
        only_outbox_id: UUID | None = None,
    ) -> tuple[AuditOutboxLease, ...]:
        if not 1 <= limit <= 1000:
            raise ControlPlaneError("audit outbox limit must be between 1 and 1000")
        if not 5 <= lease_seconds <= 300:
            raise ControlPlaneError("audit lease must be between 5 and 300 seconds")
        now = datetime.now(UTC)
        leased: list[AuditOutboxLease] = []
        for outbox_id, record in self.outbox.items():
            if len(leased) >= limit:
                break
            if only_outbox_id is not None and outbox_id != only_outbox_id:
                continue
            if outbox_id in self.audit_exports:
                continue
            existing = self.audit_leases.get(outbox_id)
            if existing is not None and existing[2] > now:
                continue
            attempt_count = (existing[3] if existing is not None else 0) + 1
            lease_token = uuid4()
            leased_until = now + timedelta(seconds=lease_seconds)
            self.audit_leases[outbox_id] = (
                lease_owner,
                lease_token,
                leased_until,
                attempt_count,
            )
            leased.append(
                AuditOutboxLease(
                    record=record,
                    lease_owner=lease_owner,
                    lease_token=lease_token,
                    leased_until=leased_until,
                    attempt_count=attempt_count,
                )
            )
        return tuple(leased)

    def release_audit_lease(
        self,
        *,
        outbox_id: UUID,
        lease_owner: UUID,
        lease_token: UUID,
    ) -> None:
        existing = self.audit_leases.get(outbox_id)
        if existing is not None and existing[:2] == (lease_owner, lease_token):
            del self.audit_leases[outbox_id]

    def audit_outbox_status(self, *, plan_id: UUID | None = None) -> AuditOutboxStatus:
        now = datetime.now(UTC)
        pending = [
            outbox_id
            for outbox_id, record in self.outbox.items()
            if outbox_id not in self.audit_exports
            and (plan_id is None or record.plan_id == plan_id)
        ]
        oldest = (
            max(
                0.0,
                (
                    now - min(self.outbox_created_at[outbox_id] for outbox_id in pending)
                ).total_seconds(),
            )
            if pending
            else 0.0
        )
        return AuditOutboxStatus(
            pending_count=len(pending),
            oldest_pending_age_seconds=oldest,
        )

    def record_audit_export(
        self,
        *,
        outbox_id: UUID,
        lease_owner: UUID,
        lease_token: UUID,
        receipt: LedgerReceipt,
    ) -> None:
        if outbox_id not in self.outbox:
            raise ControlPlaneError("audit export does not reference a durable outbox item")
        if outbox_id in self.audit_exports:
            raise ControlPlaneError("audit outbox item was already exported")
        existing = self.audit_leases.get(outbox_id)
        if existing is None or existing[:2] != (lease_owner, lease_token):
            raise ControlPlaneError("audit export lease is missing, expired, or superseded")
        self.audit_exports[outbox_id] = receipt
        del self.audit_leases[outbox_id]


def _deliver_audit_lease(
    *,
    repository: ControlRepository,
    ledger: AuditLedger,
    lease: AuditOutboxLease,
) -> bool:
    """Deliver one exclusively leased outbox item to the secondary ledger."""

    item = lease.record
    export_payload = {
        **item.payload,
        "control_outbox_id": str(item.outbox_id),
        "control_event_id": (
            str(item.control_event_id) if item.control_event_id is not None else None
        ),
    }
    try:
        receipt = ledger.append(
            actor_subject=item.actor_subject,
            action=item.audit_action,
            request_id=item.request_id,
            payload=export_payload,
        )
    except LedgerUnavailable:
        with suppress(ControlPlaneError):
            repository.release_audit_lease(
                outbox_id=item.outbox_id,
                lease_owner=lease.lease_owner,
                lease_token=lease.lease_token,
            )
        return False
    try:
        repository.record_audit_export(
            outbox_id=item.outbox_id,
            lease_owner=lease.lease_owner,
            lease_token=lease.lease_token,
            receipt=receipt,
        )
    except ControlPlaneError:
        # The durable outbox remains the recovery authority. This includes the
        # ambiguous crash window after the ledger accepted an event but before
        # its receipt could be committed locally.
        return False
    return True


def flush_audit_outbox(
    *,
    repository: ControlRepository,
    ledger: AuditLedger,
    limit: int = 100,
    lease_seconds: int = 30,
    worker_id: UUID | None = None,
) -> tuple[UUID, ...]:
    """Drain a bounded leased batch; safe for concurrent application replicas."""

    if not 1 <= limit <= 1000:
        raise ControlPlaneError("audit outbox limit must be between 1 and 1000")
    exported: list[UUID] = []
    owner = worker_id or uuid4()
    for _ in range(limit):
        leases = repository.lease_audit_exports(
            lease_owner=owner,
            lease_seconds=lease_seconds,
            limit=1,
        )
        if not leases:
            break
        lease = leases[0]
        if not _deliver_audit_lease(repository=repository, ledger=ledger, lease=lease):
            break
        exported.append(lease.record.outbox_id)
    return tuple(exported)


def audit_outbox_readiness(
    *,
    repository: ControlRepository,
    maximum_pending_count: int = 0,
    maximum_oldest_age_seconds: float = 0,
) -> tuple[bool, AuditOutboxStatus]:
    """Read the durable backlog without mutating it or claiming delivery."""

    if maximum_pending_count < 0 or maximum_oldest_age_seconds < 0:
        raise ControlPlaneError("audit outbox readiness thresholds cannot be negative")
    outbox_status = repository.audit_outbox_status()
    ready = (
        outbox_status.pending_count <= maximum_pending_count
        and outbox_status.oldest_pending_age_seconds <= maximum_oldest_age_seconds
    )
    return ready, outbox_status


class ControlPlane:
    """The only path that can invoke the consequential provider methods."""

    def __init__(
        self,
        *,
        provider: AwsControlProvider,
        evidence: EvidenceProvider,
        repository: ControlRepository,
        ledger: AuditLedger,
        approver_policies: dict[ApprovalRole, SignerPolicy],
        witness_policy: SignerPolicy,
        production_account_id: str,
    ):
        self.provider = provider
        self.evidence = evidence
        self.repository = repository
        self.ledger = ledger
        self.approver_policies = approver_policies
        self.witness_policy = witness_policy
        self.production_account_id = production_account_id

    def _deliver_audit_lease(self, lease: AuditOutboxLease) -> bool:
        """Deliver one exclusively leased outbox item to the secondary ledger."""
        return _deliver_audit_lease(
            repository=self.repository,
            ledger=self.ledger,
            lease=lease,
        )

    def _export_audit(self, item: AuditOutboxRecord) -> bool:
        """Lease and attempt one newly committed outbox delivery.

        A crash after ledger append but before export-receipt persistence can
        produce a duplicate after lease expiry. ``control_outbox_id`` is stable
        so a downstream consumer can deterministically de-duplicate it.
        """

        try:
            leases = self.repository.lease_audit_exports(
                lease_owner=uuid4(),
                lease_seconds=30,
                limit=1,
                only_outbox_id=item.outbox_id,
            )
        except ControlPlaneError:
            return False
        return bool(leases and self._deliver_audit_lease(leases[0]))

    def flush_audit_outbox(
        self,
        *,
        limit: int = 100,
        lease_seconds: int = 30,
        worker_id: UUID | None = None,
    ) -> tuple[UUID, ...]:
        """Retry a bounded leased batch; safe for concurrent replica workers."""

        return flush_audit_outbox(
            repository=self.repository,
            ledger=self.ledger,
            limit=limit,
            lease_seconds=lease_seconds,
            worker_id=worker_id,
        )

    def audit_outbox_readiness(
        self,
        *,
        maximum_pending_count: int = 0,
        maximum_oldest_age_seconds: float = 0,
    ) -> tuple[bool, AuditOutboxStatus]:
        """Return bounded backlog readiness without mutating or draining the queue."""

        return audit_outbox_readiness(
            repository=self.repository,
            maximum_pending_count=maximum_pending_count,
            maximum_oldest_age_seconds=maximum_oldest_age_seconds,
        )

    def create_unsigned_plan(
        self,
        request: UnsignedPlanRequestV2,
        *,
        requester: Principal,
        now: datetime | None = None,
    ) -> UnsignedPlanResponseV2:
        issued_at = (now or datetime.now(UTC)).astimezone(UTC)
        previews = self.provider.preview_all(request.provider_actions)
        state_digest = provider_state_digest(previews)
        plan = DeploymentPlanV2(
            plan_id=uuid4(),
            nonce=secrets.token_urlsafe(32),
            source_revision=request.source_revision,
            container_digest=request.container_digest,
            evidence_manifest_sha256=request.evidence_manifest_sha256,
            policy_bundle_sha256=request.policy_bundle_sha256,
            provider_state_sha256=state_digest,
            environment=request.environment,
            requester_issuer=requester.issuer,
            requester_subject=requester.subject,
            created_at=issued_at,
            expires_at=issued_at + timedelta(seconds=request.expires_in_seconds),
            provider_actions=request.provider_actions,
        )
        plan_digest = deployment_plan_digest(plan)
        outbox = self.repository.save_plan(
            plan=plan,
            plan_digest=plan_digest,
            requester_subject=requester.subject,
        )
        self._export_audit(outbox)
        return UnsignedPlanResponseV2(
            plan=plan,
            plan_digest=plan_digest,
            previews=previews,
        )

    def execute(
        self,
        bundle: ApprovalBundleV2,
        *,
        executor: Principal,
        now: datetime | None = None,
    ) -> ControlExecutionResponseV2:
        checked_at = (now or datetime.now(UTC)).astimezone(UTC)
        try:
            verification = verify_approval_bundle(
                bundle,
                kms=self.evidence,
                cloudtrail=self.evidence,
                approver_policies=self.approver_policies,
                witness_policy=self.witness_policy,
                production_account_id=self.production_account_id,
                now=checked_at,
            )
            previews = self.provider.preview_all(bundle.plan.provider_actions)
            if provider_state_digest(previews) != bundle.plan.provider_state_sha256:
                raise ControlPlaneError(
                    "provider state changed after signing; no mutation was attempted"
                )
            plan_digest = deployment_plan_digest(bundle.plan)
            bundle_digest = hashlib.sha256(canonical_json_bytes(bundle)).hexdigest()
            claimed = self.repository.claim_plan(
                bundle=bundle,
                plan_digest=plan_digest,
                bundle_digest=bundle_digest,
                executor_subject=executor.subject,
                verification=verification,
            )
        except (ApprovalVerificationError, AwsControlError) as exc:
            raise ControlPlaneError("detached authorization or provider preflight failed") from exc

        durable_outbox_ids: list[UUID] = [claimed.outbox_id]
        observed_export_failures = int(not self._export_audit(claimed))
        receipts: list[ProviderActionReceiptV2] = []
        provider_confirmed_action_count = 0
        provider_outcome_unknown_count = 0
        last_unpersisted_receipt: ProviderActionReceiptV2 | None = None
        preview_by_id = {item.action_id: item for item in previews}
        try:
            for action in bundle.plan.provider_actions:
                intent = {
                    "action_id": str(action.action_id),
                    "action_type": action.action_type.value,
                    "expected_before_sha256": preview_by_id[action.action_id].current_state_sha256,
                }
                intent_event = self.repository.record_event(
                    plan_id=bundle.plan.plan_id,
                    event_type="PROVIDER_ACTION_INTENT",
                    payload=intent,
                    actor_subject=executor.subject,
                    audit_action="control.provider_action.intent",
                )
                durable_outbox_ids.append(intent_event.outbox_id)
                observed_export_failures += int(not self._export_audit(intent_event))
                try:
                    receipt = self.provider.apply(
                        action,
                        expected_before_sha256=(
                            preview_by_id[action.action_id].current_state_sha256
                        ),
                    )
                except (ControlPlaneError, AwsControlError) as provider_exc:
                    # Retain uncertainty even if its dedicated primary event cannot
                    # be recorded; the already-durable intent still identifies it.
                    provider_outcome_unknown_count += 1
                    unknown_payload = {
                        "action_id": str(action.action_id),
                        "action_type": action.action_type.value,
                        "expected_before_sha256": (
                            preview_by_id[action.action_id].current_state_sha256
                        ),
                        "failure_class": type(provider_exc).__name__,
                        "mutation_may_have_occurred": True,
                        "automatic_rollback_attempted": False,
                        "recovery_disposition": (
                            "MANUAL_PROVIDER_READBACK_REQUIRED_BEFORE_RETRY"
                        ),
                    }
                    unknown_event = self.repository.record_event(
                        plan_id=bundle.plan.plan_id,
                        event_type="PROVIDER_OUTCOME_UNKNOWN",
                        payload=unknown_payload,
                        actor_subject=executor.subject,
                        audit_action="control.provider_action.outcome_unknown",
                    )
                    durable_outbox_ids.append(unknown_event.outbox_id)
                    observed_export_failures += int(not self._export_audit(unknown_event))
                    raise
                provider_confirmed_action_count += 1
                last_unpersisted_receipt = receipt
                receipt_payload = receipt.model_dump(mode="json")
                receipt_event = self.repository.record_event(
                    plan_id=bundle.plan.plan_id,
                    event_type="PROVIDER_ACTION_RECEIPT",
                    payload=receipt_payload,
                    actor_subject=executor.subject,
                    audit_action="control.provider_action.enforced",
                )
                receipts.append(receipt)
                last_unpersisted_receipt = None
                durable_outbox_ids.append(receipt_event.outbox_id)
                # The provider receipt and outbox item are committed before this
                # secondary sink is called.
                observed_export_failures += int(not self._export_audit(receipt_event))
            completed = self.repository.record_event(
                plan_id=bundle.plan.plan_id,
                event_type="EXECUTION_COMPLETED",
                payload={
                    "plan_digest": plan_digest,
                    "provider_mutation_count": provider_confirmed_action_count,
                    "durable_receipt_count": len(receipts),
                },
                actor_subject=executor.subject,
                audit_action="control.execution.completed",
            )
            durable_outbox_ids.append(completed.outbox_id)
            observed_export_failures += int(not self._export_audit(completed))
        except (ControlPlaneError, AwsControlError) as exc:
            failure_payload: dict[str, Any] = {
                "provider_action_readback_confirmed_count": provider_confirmed_action_count,
                "provider_outcome_unknown_count": provider_outcome_unknown_count,
                "durable_receipt_count": len(receipts),
                "failure_class": type(exc).__name__,
                "mutation_may_have_occurred": bool(
                    provider_confirmed_action_count or provider_outcome_unknown_count
                ),
                "automatic_rollback_attempted": False,
                "recovery_disposition": "MANUAL_PROVIDER_READBACK_REQUIRED_BEFORE_RETRY",
            }
            if last_unpersisted_receipt is not None:
                failure_payload["last_provider_receipt_recovery_copy"] = (
                    last_unpersisted_receipt.model_dump(mode="json")
                )
            try:
                failed = self.repository.record_event(
                    plan_id=bundle.plan.plan_id,
                    event_type="EXECUTION_FAILED_CLOSED",
                    payload=failure_payload,
                    actor_subject=executor.subject,
                    audit_action="control.execution.failed_closed",
                )
            except ControlPlaneError:
                # A unique terminal-state constraint prevents a contradictory
                # result even if a commit acknowledgement was lost.
                pass
            else:
                self._export_audit(failed)
            raise ControlPlaneError(
                "provider execution failed closed; inspect durable receipts before recovery"
            ) from exc
        try:
            audit_status = self.repository.audit_outbox_status(plan_id=bundle.plan.plan_id)
        except ControlPlaneError:
            # Do not hide a completed provider operation merely because the
            # post-completion status query failed. The count is a conservative
            # retry floor in this exceptional path; normal responses use the
            # exact durable query result.
            pending_audit_export_count = max(1, observed_export_failures)
        else:
            pending_audit_export_count = audit_status.pending_count
        return ControlExecutionResponseV2(
            plan_id=bundle.plan.plan_id,
            plan_digest=plan_digest,
            receipts=tuple(receipts),
            audit_export_status=(
                "ALL_EXPORTED" if pending_audit_export_count == 0 else "PENDING_RETRY"
            ),
            pending_audit_export_count=pending_audit_export_count,
            control_outbox_ids=tuple(durable_outbox_ids),
        )
