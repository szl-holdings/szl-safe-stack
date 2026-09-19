from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

import safe_qa_service.control_plane as control_plane_module
from safe_qa_service.approval_verification import ApprovalVerification
from safe_qa_service.auth import Principal
from safe_qa_service.aws_control import AwsControlError, provider_state_digest
from safe_qa_service.control_plane import (
    ControlPlane,
    ControlPlaneError,
    InMemoryControlRepository,
    PlanReplayError,
)
from safe_qa_service.ledger import LedgerReceipt, LedgerUnavailable
from safe_qa_service.schemas.v2 import (
    ApprovalBundleV2,
    ApprovalDecision,
    ApprovalRole,
    ApprovalStatementV2,
    CloudTrailSignEventV2,
    EksIsolateNamespaceActionV2,
    HumanIdentityV2,
    KmsSignatureV2,
    ProviderActionPreviewV2,
    ProviderActionReceiptV2,
    SignedApprovalV2,
    SignedWitnessV2,
    UnsignedPlanRequestV2,
    WitnessStatementV2,
)

NOW = datetime(2026, 8, 11, 16, 0, tzinfo=UTC)


class FakeLedger:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []
        self.attempts: list[dict[str, object]] = []
        self.fail_actions: set[str] = set()
        self.before_append: Callable[[dict[str, object]], None] | None = None

    def append(self, **event: object) -> LedgerReceipt:
        self.attempts.append(dict(event))
        if self.before_append is not None:
            self.before_append(dict(event))
        if event["action"] in self.fail_actions:
            raise LedgerUnavailable("simulated secondary ledger outage")
        self.events.append(dict(event))
        return LedgerReceipt(event_id=uuid4(), sequence_id=len(self.events), event_hash="a" * 64)


class FakeProvider:
    def __init__(self) -> None:
        self.state = "before"
        self.apply_calls = 0
        self.fail_apply = False
        self.mutate_then_readback_fail = False
        self.repository: InMemoryControlRepository | None = None
        self.ledger: FakeLedger | None = None

    def preview_all(self, actions: tuple[object, ...]) -> tuple[ProviderActionPreviewV2, ...]:
        return tuple(
            ProviderActionPreviewV2(
                action_id=action.action_id,
                action_type=action.action_type,
                current_state_sha256=("1" * 64 if self.state == "before" else "2" * 64),
                current_state={"state": self.state},
            )
            for action in actions
        )

    def apply(self, action: object, *, expected_before_sha256: str) -> ProviderActionReceiptV2:
        self.apply_calls += 1
        assert self.repository is not None
        assert self.ledger is not None
        plan_id = next(iter(self.repository.claimed))
        assert self.repository.events[plan_id][-1][1] == "PROVIDER_ACTION_INTENT"
        assert next(reversed(self.repository.outbox.values())).audit_action == (
            "control.provider_action.intent"
        )
        if self.fail_apply:
            raise AwsControlError("simulated provider failure")
        if self.mutate_then_readback_fail:
            self.state = "mutated"
            raise AwsControlError("simulated provider readback failure after mutation")
        return ProviderActionReceiptV2(
            action_id=action.action_id,
            action_type=action.action_type,
            status="ISOLATION_POLICY_OBJECT_APPLIED",
            before_state_sha256=expected_before_sha256,
            after_state_sha256="3" * 64,
            provider_receipt_ids=("provider-request-1",),
            enforced_at=NOW,
        )


def _principal(subject: str) -> Principal:
    return Principal(
        subject=subject,
        scopes=frozenset({"control:execute"}),
        token_fingerprint="fingerprint",
        issuer="https://issuer.example.test",
        principal_type="workload",
    )


def _request() -> UnsignedPlanRequestV2:
    return UnsignedPlanRequestV2(
        source_revision="abcdef1234567890",
        container_digest="sha256:" + "a" * 64,
        evidence_manifest_sha256="b" * 64,
        policy_bundle_sha256="c" * 64,
        environment="aws/eks/production",
        expires_in_seconds=600,
        provider_actions=(
            EksIsolateNamespaceActionV2(
                action_id=UUID(int=1, version=4),
                cluster_name="production",
                namespace="safe-qa",
            ),
        ),
    )


def _verification(plan_digest: str, *, verified_at: datetime = NOW) -> ApprovalVerification:
    return ApprovalVerification(
        verified=True,
        plan_digest=plan_digest,
        approval_ids=(str(uuid4()), str(uuid4())),
        approver_user_ids=("security-user", "release-user"),
        witness_id=str(uuid4()),
        witness_user_id="witness-user",
        witness_account_id="333333333333",
        verified_at=verified_at,
    )


def _control_plane(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[ControlPlane, FakeProvider, InMemoryControlRepository, FakeLedger]:
    provider = FakeProvider()
    repository = InMemoryControlRepository()
    ledger = FakeLedger()
    provider.repository = repository
    provider.ledger = ledger

    def verify(bundle: ApprovalBundleV2, **kwargs: object) -> ApprovalVerification:
        from safe_qa_service.approval_verification import deployment_plan_digest

        return _verification(deployment_plan_digest(bundle.plan))

    monkeypatch.setattr(control_plane_module, "verify_approval_bundle", verify)
    plane = ControlPlane(
        provider=provider,
        evidence=object(),
        repository=repository,
        ledger=ledger,
        approver_policies={},
        witness_policy=object(),
        production_account_id="999999999999",
    )
    return plane, provider, repository, ledger


def _issued_bundle(
    plane: ControlPlane,
    *,
    requester: Principal,
) -> ApprovalBundleV2:
    response = plane.create_unsigned_plan(_request(), requester=requester, now=NOW)
    return ApprovalBundleV2.model_construct(
        schema_version="2.0",
        plan=response.plan,
        approvals=(),
        witness=None,
    )


@pytest.mark.parametrize("verification_offset", [599, 600, 601])
def test_claim_expiry_uses_verified_time_not_later_wall_clock(
    monkeypatch: pytest.MonkeyPatch,
    verification_offset: int,
) -> None:
    from safe_qa_service.approval_verification import (
        canonical_json_bytes,
        deployment_plan_digest,
    )

    plane, _, repository, _ = _control_plane(monkeypatch)
    # Use a fixed historical issue window; do not replace the system clock.
    issued_at = datetime(2000, 1, 1, tzinfo=UTC)
    response = plane.create_unsigned_plan(
        _request(), requester=_principal("requester"), now=issued_at
    )
    bundle = ApprovalBundleV2.model_construct(
        schema_version="2.0", plan=response.plan, approvals=(), witness=None
    )
    digest = deployment_plan_digest(bundle.plan)
    claim = {
        "bundle": bundle,
        "plan_digest": digest,
        "bundle_digest": hashlib.sha256(canonical_json_bytes(bundle)).hexdigest(),
        "executor_subject": "executor",
        "verification": _verification(
            digest, verified_at=issued_at + timedelta(seconds=verification_offset)
        ),
    }
    if verification_offset >= 600:
        with pytest.raises(PlanReplayError, match="expired"):
            repository.claim_plan(**claim)
        assert bundle.plan.plan_id not in repository.claimed
    else:
        record = repository.claim_plan(**claim)
        assert record.audit_action == "control.execution.authorized"
        assert bundle.plan.plan_id in repository.claimed


def _complete_issued_bundle(
    plane: ControlPlane,
    *,
    requester: Principal,
) -> ApprovalBundleV2:
    from safe_qa_service.approval_verification import deployment_plan_digest

    response = plane.create_unsigned_plan(_request(), requester=requester, now=NOW)
    plan = response.plan
    plan_digest = deployment_plan_digest(plan)

    def signed_approval(
        *, role: ApprovalRole, account: str, user_id: str, marker: str
    ) -> SignedApprovalV2:
        key_arn = f"arn:aws:kms:us-east-1:{account}:key/{uuid4()}"
        identity_store_arn = f"arn:aws:identitystore::{account}:identitystore/d-1234567890"
        identity = HumanIdentityV2(
            display_name=f"{role.value} human",
            identity_store_arn=identity_store_arn,
            identity_center_user_id=user_id,
        )
        request_id = uuid4()
        statement = ApprovalStatementV2(
            approval_id=uuid4(),
            plan_id=plan.plan_id,
            plan_digest=plan_digest,
            plan_nonce=plan.nonce,
            decision=ApprovalDecision.APPROVE,
            role=role,
            approver=identity,
            key_arn=key_arn,
            signed_at=NOW + timedelta(seconds=10),
            expires_at=NOW + timedelta(minutes=5),
        )
        return SignedApprovalV2(
            statement=statement,
            signature=KmsSignatureV2(
                key_arn=key_arn,
                signature_b64=base64.b64encode(f"signature-{marker}".encode()).decode(),
                provider_request_id=request_id,
            ),
            cloudtrail_sign_event=CloudTrailSignEventV2(
                event_id=uuid4(),
                request_id=request_id,
                event_time=NOW + timedelta(seconds=10),
                key_arn=key_arn,
                aws_region="us-east-1",
                recipient_account_id=account,
                principal_arn=f"arn:aws:iam::{account}:role/{marker}-signer",
                identity_store_arn=identity_store_arn,
                on_behalf_of_user_id=user_id,
                event_payload_sha256=("a" if marker == "security" else "b") * 64,
                lookup_retrieved_at=NOW + timedelta(seconds=20),
            ),
        )

    security = signed_approval(
        role=ApprovalRole.SECURITY_OWNER,
        account="111111111111",
        user_id="10000000-0000-4000-8000-000000000001",
        marker="security",
    )
    release = signed_approval(
        role=ApprovalRole.RELEASE_OWNER,
        account="222222222222",
        user_id="20000000-0000-4000-8000-000000000002",
        marker="release",
    )
    witness_account = "333333333333"
    witness_key_arn = f"arn:aws:kms:us-east-1:{witness_account}:key/{uuid4()}"
    witness_store_arn = f"arn:aws:identitystore::{witness_account}:identitystore/d-1234567890"
    witness_request_id = uuid4()
    witness = SignedWitnessV2(
        statement=WitnessStatementV2(
            witness_id=uuid4(),
            witness_name="Independent witness",
            witness_account_id=witness_account,
            witness_key_arn=witness_key_arn,
            witness_identity=HumanIdentityV2(
                display_name="Witness human",
                identity_store_arn=witness_store_arn,
                identity_center_user_id="30000000-0000-4000-8000-000000000003",
            ),
            plan_id=plan.plan_id,
            plan_digest=plan_digest,
            approval_ids=(security.statement.approval_id, release.statement.approval_id),
            approval_record_digests=("d" * 64, "e" * 64),
            witnessed_at=NOW + timedelta(seconds=30),
            expires_at=NOW + timedelta(minutes=5),
        ),
        signature=KmsSignatureV2(
            key_arn=witness_key_arn,
            signature_b64=base64.b64encode(b"signature-witness").decode(),
            provider_request_id=witness_request_id,
        ),
        cloudtrail_sign_event=CloudTrailSignEventV2(
            event_id=uuid4(),
            request_id=witness_request_id,
            event_time=NOW + timedelta(seconds=30),
            key_arn=witness_key_arn,
            aws_region="us-east-1",
            recipient_account_id=witness_account,
            principal_arn=f"arn:aws:iam::{witness_account}:role/witness-signer",
            identity_store_arn=witness_store_arn,
            on_behalf_of_user_id="30000000-0000-4000-8000-000000000003",
            event_payload_sha256="f" * 64,
            lookup_retrieved_at=NOW + timedelta(seconds=40),
        ),
    )
    return ApprovalBundleV2(
        plan=plan,
        approvals=(security, release),
        witness=witness,
    )


def test_provider_state_digest_is_order_independent_and_detects_change() -> None:
    first = ProviderActionPreviewV2(
        action_id=UUID(int=1, version=4),
        action_type="EKS_ISOLATE_NAMESPACE",
        current_state_sha256="1" * 64,
        current_state={"state": "first"},
    )
    second = first.model_copy(
        update={"action_id": UUID(int=2, version=4), "current_state_sha256": "2" * 64}
    )

    assert provider_state_digest((first, second)) == provider_state_digest((second, first))
    changed = second.model_copy(update={"current_state": {"state": "changed"}})
    assert provider_state_digest((first, second)) != provider_state_digest((first, changed))


def test_state_drift_prevents_claim_and_provider_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plane, provider, repository, _ = _control_plane(monkeypatch)
    bundle = _issued_bundle(plane, requester=_principal("requester"))
    provider.state = "drifted"

    with pytest.raises(ControlPlaneError, match="provider state changed"):
        plane.execute(bundle, executor=_principal("executor"), now=NOW + timedelta(minutes=1))

    assert bundle.plan.plan_id not in repository.claimed
    assert provider.apply_calls == 0


def test_claim_rejects_verification_result_for_another_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plane, provider, repository, _ = _control_plane(monkeypatch)
    bundle = _issued_bundle(plane, requester=_principal("requester"))

    monkeypatch.setattr(
        control_plane_module,
        "verify_approval_bundle",
        lambda *args, **kwargs: _verification("f" * 64),
    )
    with pytest.raises(ControlPlaneError, match="does not bind the claimed plan"):
        plane.execute(bundle, executor=_principal("executor"), now=NOW + timedelta(minutes=1))

    assert bundle.plan.plan_id not in repository.claimed
    assert provider.apply_calls == 0


def test_replay_is_rejected_without_a_second_mutation(monkeypatch: pytest.MonkeyPatch) -> None:
    plane, provider, _, _ = _control_plane(monkeypatch)
    bundle = _issued_bundle(plane, requester=_principal("requester"))

    plane.execute(bundle, executor=_principal("executor"), now=NOW + timedelta(minutes=1))
    with pytest.raises(PlanReplayError, match="already consumed"):
        plane.execute(bundle, executor=_principal("executor"), now=NOW + timedelta(minutes=2))

    assert provider.apply_calls == 1


def test_intent_precedes_mutation_and_provider_receipt_is_recorded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plane, provider, repository, ledger = _control_plane(monkeypatch)
    bundle = _issued_bundle(plane, requester=_principal("requester"))

    result = plane.execute(
        bundle,
        executor=_principal("executor"),
        now=NOW + timedelta(minutes=1),
    )

    event_types = [item[1] for item in repository.events[bundle.plan.plan_id]]
    assert event_types == [
        "EXECUTION_CLAIMED",
        "PROVIDER_ACTION_INTENT",
        "PROVIDER_ACTION_RECEIPT",
        "EXECUTION_COMPLETED",
    ]
    assert provider.apply_calls == 1
    assert result.receipts[0].provider_receipt_ids == ("provider-request-1",)
    assert result.audit_export_status == "ALL_EXPORTED"
    assert result.pending_audit_export_count == 0
    assert [event["action"] for event in ledger.events] == [
        "control.plan.issued",
        "control.execution.authorized",
        "control.provider_action.intent",
        "control.provider_action.enforced",
        "control.execution.completed",
    ]


def test_full_bundle_and_normalized_provider_evidence_are_retained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plane, _, repository, _ = _control_plane(monkeypatch)
    bundle = _complete_issued_bundle(plane, requester=_principal("requester"))

    plane.execute(bundle, executor=_principal("executor"), now=NOW + timedelta(minutes=1))

    stored = repository.execution_evidence[bundle.plan.plan_id]
    expected_digest = hashlib.sha256(control_plane_module.canonical_json_bytes(bundle)).hexdigest()
    assert stored["bundle_digest"] == expected_digest
    assert stored["approval_bundle"] == bundle.model_dump(mode="json")
    normalized = stored["normalized_approval_evidence"]
    assert normalized["evidence_format"] == "safe-qa-normalized-approval-evidence/v2"
    assert len(normalized["approvals"]) == 2
    first_raw = base64.b64decode(bundle.approvals[0].signature.signature_b64)
    assert (
        normalized["approvals"][0]["signature"]["signature_sha256"]
        == hashlib.sha256(first_raw).hexdigest()
    )
    assert normalized["approvals"][0]["cloudtrail_sign_event"]["event_name"] == "Sign"
    assert normalized["witness"]["cloudtrail_sign_event"]["on_behalf_of_user_id"] == (
        "30000000-0000-4000-8000-000000000003"
    )


def test_receipt_is_primary_durable_before_secondary_export(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plane, _, repository, ledger = _control_plane(monkeypatch)
    bundle = _issued_bundle(plane, requester=_principal("requester"))

    def observe(event: dict[str, object]) -> None:
        if event["action"] != "control.provider_action.enforced":
            return
        durable_events = repository.events[bundle.plan.plan_id]
        assert durable_events[-1][1] == "PROVIDER_ACTION_RECEIPT"
        outbox_id = durable_events[-1][0]
        assert repository.outbox[outbox_id].audit_action == "control.provider_action.enforced"

    ledger.before_append = observe
    plane.execute(bundle, executor=_principal("executor"), now=NOW + timedelta(minutes=1))


def test_secondary_ledger_outage_leaves_outbox_without_contradictory_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plane, _, repository, ledger = _control_plane(monkeypatch)
    bundle = _issued_bundle(plane, requester=_principal("requester"))
    ledger.fail_actions.update({"control.provider_action.enforced", "control.execution.completed"})

    result = plane.execute(
        bundle,
        executor=_principal("executor"),
        now=NOW + timedelta(minutes=1),
    )

    event_types = [item[1] for item in repository.events[bundle.plan.plan_id]]
    assert event_types.count("EXECUTION_COMPLETED") == 1
    assert "EXECUTION_FAILED_CLOSED" not in event_types
    assert result.execution_status == "PROVIDER_ACTIONS_APPLIED_AND_READ_BACK"
    assert result.audit_export_status == "PENDING_RETRY"
    assert result.pending_audit_export_count == 2
    pending = tuple(
        record
        for outbox_id, record in repository.outbox.items()
        if outbox_id not in repository.audit_exports
    )
    assert [item.audit_action for item in pending] == [
        "control.provider_action.enforced",
        "control.execution.completed",
    ]

    ledger.fail_actions.clear()
    assert plane.flush_audit_outbox() == tuple(item.outbox_id for item in pending)
    assert repository.audit_outbox_status().pending_count == 0


def test_provider_failure_has_one_failure_terminal_and_remains_single_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plane, provider, repository, _ = _control_plane(monkeypatch)
    bundle = _issued_bundle(plane, requester=_principal("requester"))
    provider.fail_apply = True

    with pytest.raises(ControlPlaneError, match="failed closed"):
        plane.execute(bundle, executor=_principal("executor"), now=NOW + timedelta(minutes=1))

    event_types = [item[1] for item in repository.events[bundle.plan.plan_id]]
    assert event_types[-1] == "EXECUTION_FAILED_CLOSED"
    assert event_types.count("EXECUTION_FAILED_CLOSED") == 1
    assert "EXECUTION_COMPLETED" not in event_types
    with pytest.raises(PlanReplayError, match="already consumed"):
        plane.execute(bundle, executor=_principal("executor"), now=NOW + timedelta(minutes=2))
    assert provider.apply_calls == 1


def test_mutate_then_readback_failure_records_durable_unknown_outcome(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plane, provider, repository, ledger = _control_plane(monkeypatch)
    bundle = _issued_bundle(plane, requester=_principal("requester"))
    provider.mutate_then_readback_fail = True

    with pytest.raises(ControlPlaneError, match="failed closed"):
        plane.execute(bundle, executor=_principal("executor"), now=NOW + timedelta(minutes=1))

    assert provider.state == "mutated"
    events = repository.events[bundle.plan.plan_id]
    assert [item[1] for item in events] == [
        "EXECUTION_CLAIMED",
        "PROVIDER_ACTION_INTENT",
        "PROVIDER_OUTCOME_UNKNOWN",
        "EXECUTION_FAILED_CLOSED",
    ]
    unknown = events[-2][2]
    assert unknown == {
        "action_id": str(bundle.plan.provider_actions[0].action_id),
        "action_type": "EKS_ISOLATE_NAMESPACE",
        "expected_before_sha256": "1" * 64,
        "failure_class": "AwsControlError",
        "mutation_may_have_occurred": True,
        "automatic_rollback_attempted": False,
        "recovery_disposition": "MANUAL_PROVIDER_READBACK_REQUIRED_BEFORE_RETRY",
    }
    failure = events[-1][2]
    assert "provider_mutation_count" not in failure
    assert failure["provider_action_readback_confirmed_count"] == 0
    assert failure["provider_outcome_unknown_count"] == 1
    assert failure["mutation_may_have_occurred"] is True
    assert failure["automatic_rollback_attempted"] is False
    assert [event["action"] for event in ledger.events][-2:] == [
        "control.provider_action.outcome_unknown",
        "control.execution.failed_closed",
    ]


def test_unknown_outcome_primary_write_failure_retains_uncertain_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plane, provider, repository, ledger = _control_plane(monkeypatch)
    bundle = _issued_bundle(plane, requester=_principal("requester"))
    provider.mutate_then_readback_fail = True
    record_event = repository.record_event

    def fail_unknown_write(**kwargs: object) -> object:
        if kwargs["event_type"] == "PROVIDER_OUTCOME_UNKNOWN":
            raise ControlPlaneError("simulated primary unknown-outcome write failure")
        return record_event(**kwargs)

    monkeypatch.setattr(repository, "record_event", fail_unknown_write)

    with pytest.raises(ControlPlaneError, match="failed closed"):
        plane.execute(bundle, executor=_principal("executor"), now=NOW + timedelta(minutes=1))

    assert provider.apply_calls == 1
    assert provider.state == "mutated"
    events = repository.events[bundle.plan.plan_id]
    assert [item[1] for item in events] == [
        "EXECUTION_CLAIMED",
        "PROVIDER_ACTION_INTENT",
        "EXECUTION_FAILED_CLOSED",
    ]
    intent_id, _, intent = events[-2]
    assert intent["action_id"] == str(bundle.plan.provider_actions[0].action_id)
    assert repository.outbox[intent_id].audit_action == "control.provider_action.intent"
    failure = events[-1][2]
    assert failure["provider_action_readback_confirmed_count"] == 0
    assert failure["provider_outcome_unknown_count"] == 1
    assert failure["mutation_may_have_occurred"] is True
    assert failure["automatic_rollback_attempted"] is False
    assert failure["recovery_disposition"] == "MANUAL_PROVIDER_READBACK_REQUIRED_BEFORE_RETRY"
    assert ledger.events[-1]["action"] == "control.execution.failed_closed"
    assert ledger.events[-1]["payload"]["mutation_may_have_occurred"] is True
    assert ledger.events[-1]["payload"]["provider_outcome_unknown_count"] == 1


def test_unknown_outcome_secondary_export_failure_remains_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plane, provider, repository, ledger = _control_plane(monkeypatch)
    bundle = _issued_bundle(plane, requester=_principal("requester"))
    provider.mutate_then_readback_fail = True
    ledger.fail_actions.add("control.provider_action.outcome_unknown")

    with pytest.raises(ControlPlaneError, match="failed closed"):
        plane.execute(bundle, executor=_principal("executor"), now=NOW + timedelta(minutes=1))

    unknown_outbox = next(
        item
        for item in repository.outbox.values()
        if item.audit_action == "control.provider_action.outcome_unknown"
    )
    assert unknown_outbox.outbox_id not in repository.audit_exports
    assert unknown_outbox.payload["mutation_may_have_occurred"] is True

    ledger.fail_actions.clear()
    assert unknown_outbox.outbox_id in plane.flush_audit_outbox()
    assert unknown_outbox.outbox_id in repository.audit_exports


def test_no_event_can_be_appended_after_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    plane, _, repository, _ = _control_plane(monkeypatch)
    bundle = _issued_bundle(plane, requester=_principal("requester"))
    plane.execute(bundle, executor=_principal("executor"), now=NOW + timedelta(minutes=1))

    with pytest.raises(ControlPlaneError, match="already terminal: EXECUTION_COMPLETED"):
        repository.record_event(
            plan_id=bundle.plan.plan_id,
            event_type="EXECUTION_FAILED_CLOSED",
            payload={"should_not_exist": True},
            actor_subject="executor",
            audit_action="control.execution.failed_closed",
        )


def test_outbox_leases_are_exclusive_expiring_and_readiness_visible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plane, _, repository, ledger = _control_plane(monkeypatch)
    ledger.fail_actions.add("control.plan.issued")
    _issued_bundle(plane, requester=_principal("requester"))

    ready, status = plane.audit_outbox_readiness()
    assert ready is False
    assert status.pending_count == 1
    assert status.oldest_pending_age_seconds >= 0

    first_owner = uuid4()
    first = repository.lease_audit_exports(
        lease_owner=first_owner,
        lease_seconds=30,
        limit=10,
    )
    assert len(first) == 1
    assert first[0].attempt_count == 1
    assert (
        repository.lease_audit_exports(
            lease_owner=uuid4(),
            lease_seconds=30,
            limit=10,
        )
        == ()
    )
    with pytest.raises(ControlPlaneError, match="lease is missing"):
        repository.record_audit_export(
            outbox_id=first[0].record.outbox_id,
            lease_owner=first_owner,
            lease_token=uuid4(),
            receipt=LedgerReceipt(uuid4(), 1, "a" * 64),
        )

    repository.audit_leases[first[0].record.outbox_id] = (
        first_owner,
        first[0].lease_token,
        datetime.now(UTC) - timedelta(seconds=1),
        first[0].attempt_count,
    )
    second = repository.lease_audit_exports(
        lease_owner=uuid4(),
        lease_seconds=30,
        limit=10,
    )
    assert len(second) == 1
    assert second[0].attempt_count == 2
