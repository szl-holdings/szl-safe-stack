from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from safe_qa_service.approval_verification import (
    ApprovalVerificationError,
    KmsVerifyResult,
    SignerPolicy,
    approval_record_digest,
    deployment_plan_digest,
    verify_approval_bundle,
)
from safe_qa_service.schemas.v2 import (
    ApprovalBundleV2,
    ApprovalDecision,
    ApprovalRole,
    ApprovalStatementV2,
    CloudTrailSignEventV2,
    DeploymentPlanV2,
    EksIsolateNamespaceActionV2,
    HumanIdentityV2,
    KmsSignatureV2,
    SignedApprovalV2,
    SignedWitnessV2,
    WitnessStatementV2,
)

NOW = datetime(2026, 8, 11, 16, 0, tzinfo=UTC)
PRODUCTION_ACCOUNT = "999999999999"
IDENTITY_STORE = "arn:aws:identitystore::999999999999:identitystore/d-1234567890"
WITNESS_IDENTITY_STORE = (
    "arn:aws:identitystore::333333333333:identitystore/d-3333333333"
)


def _uuid(value: int) -> UUID:
    return UUID(int=value, version=4)


def _key_arn(account: str, marker: str) -> str:
    key_id = f"{marker * 8}-{marker * 4}-4{marker * 3}-8{marker * 3}-{marker * 12}"
    return f"arn:aws:kms:us-east-1:{account}:key/{key_id}"


SECURITY_KEY = _key_arn(PRODUCTION_ACCOUNT, "a")
RELEASE_KEY = _key_arn(PRODUCTION_ACCOUNT, "b")
WITNESS_KEY = _key_arn("333333333333", "c")


@dataclass
class FakeKms:
    valid: bool = True
    error: Exception | None = None

    def __post_init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def verify_digest(self, **kwargs: object) -> KmsVerifyResult:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return KmsVerifyResult(
            signature_valid=self.valid,
            key_arn=str(kwargs["key_arn"]),
            signing_algorithm=str(kwargs["signing_algorithm"]),
            verification_request_id="kms-verify-request",
        )


@dataclass
class FakeCloudTrail:
    events: dict[str, CloudTrailSignEventV2]
    error: Exception | None = None

    def __post_init__(self) -> None:
        self.calls: list[str] = []

    def lookup_kms_sign_event(
        self,
        event_id: str,
        *,
        account_id: str | None = None,
        region: str | None = None,
    ) -> CloudTrailSignEventV2:
        self.calls.append(event_id)
        if self.error is not None:
            raise self.error
        return self.events[event_id]


def _identity(
    name: str,
    user_id: str,
    identity_store_arn: str = IDENTITY_STORE,
) -> HumanIdentityV2:
    return HumanIdentityV2(
        display_name=name,
        identity_store_arn=identity_store_arn,
        identity_center_user_id=user_id,
    )


def _principal(account: str, role: str) -> str:
    return f"arn:aws:sts::{account}:assumed-role/{role}/identity-center-session"


def _cloudtrail_event(
    *,
    event_id: UUID,
    request_id: UUID,
    key_arn: str,
    account: str,
    user_id: str,
    principal_arn: str,
    identity_store_arn: str,
    signed_at: datetime,
) -> CloudTrailSignEventV2:
    return CloudTrailSignEventV2(
        event_id=event_id,
        request_id=request_id,
        event_time=signed_at,
        key_arn=key_arn,
        aws_region="us-east-1",
        recipient_account_id=account,
        principal_arn=principal_arn,
        identity_store_arn=identity_store_arn,
        on_behalf_of_user_id=user_id,
        event_payload_sha256="e" * 64,
        lookup_retrieved_at=NOW,
    )


def _signed_approval(
    *,
    role: ApprovalRole,
    approval_id: UUID,
    key_arn: str,
    account: str,
    identity: HumanIdentityV2,
    plan: DeploymentPlanV2,
    principal_arn: str,
    event_id: UUID,
    request_id: UUID,
) -> SignedApprovalV2:
    signed_at = NOW - timedelta(minutes=5)
    statement = ApprovalStatementV2(
        approval_id=approval_id,
        plan_id=plan.plan_id,
        plan_digest=deployment_plan_digest(plan),
        plan_nonce=plan.nonce,
        decision=ApprovalDecision.APPROVE,
        role=role,
        approver=identity,
        key_arn=key_arn,
        signed_at=signed_at,
        expires_at=NOW + timedelta(minutes=30),
    )
    return SignedApprovalV2(
        statement=statement,
        signature=KmsSignatureV2(
            key_arn=key_arn,
            signature_b64=base64.b64encode(f"signature-{role}".encode()).decode(),
            provider_request_id=request_id,
        ),
        cloudtrail_sign_event=_cloudtrail_event(
            event_id=event_id,
            request_id=request_id,
            key_arn=key_arn,
            account=account,
            user_id=identity.identity_center_user_id,
            principal_arn=principal_arn,
            identity_store_arn=identity.identity_store_arn,
            signed_at=signed_at,
        ),
    )


def _bundle_and_policies() -> tuple[
    ApprovalBundleV2,
    dict[ApprovalRole, SignerPolicy],
    SignerPolicy,
]:
    action = EksIsolateNamespaceActionV2(
        action_id=_uuid(2),
        cluster_name="safe-qa-production",
        namespace="safe-qa",
    )
    plan = DeploymentPlanV2(
        plan_id=_uuid(1),
        nonce="n" * 43,
        source_revision="abcdef1234567890",
        container_digest=f"sha256:{'1' * 64}",
        evidence_manifest_sha256="2" * 64,
        policy_bundle_sha256="3" * 64,
        provider_state_sha256="4" * 64,
        environment="aws/eks/production",
        requester_issuer="https://id.example.test",
        requester_subject="release-requester",
        created_at=NOW - timedelta(minutes=10),
        expires_at=NOW + timedelta(hours=2),
        provider_actions=(action,),
    )
    security_identity = _identity(
        "Security Owner", "11111111-1111-4111-8111-111111111111"
    )
    release_identity = _identity(
        "Release Owner", "22222222-2222-4222-8222-222222222222"
    )
    witness_identity = _identity(
        "Independent Witness",
        "33333333-3333-4333-8333-333333333333",
        WITNESS_IDENTITY_STORE,
    )
    security_principal = _principal(PRODUCTION_ACCOUNT, "AWSReservedSSO_SecurityOwner")
    release_principal = _principal(PRODUCTION_ACCOUNT, "AWSReservedSSO_ReleaseOwner")
    witness_principal = _principal("333333333333", "AWSReservedSSO_Witness")
    approvals = (
        _signed_approval(
            role=ApprovalRole.SECURITY_OWNER,
            approval_id=_uuid(10),
            key_arn=SECURITY_KEY,
            account=PRODUCTION_ACCOUNT,
            identity=security_identity,
            plan=plan,
            principal_arn=security_principal,
            event_id=_uuid(11),
            request_id=_uuid(12),
        ),
        _signed_approval(
            role=ApprovalRole.RELEASE_OWNER,
            approval_id=_uuid(20),
            key_arn=RELEASE_KEY,
            account=PRODUCTION_ACCOUNT,
            identity=release_identity,
            plan=plan,
            principal_arn=release_principal,
            event_id=_uuid(21),
            request_id=_uuid(22),
        ),
    )
    ordered = tuple(sorted(approvals, key=lambda item: item.statement.role.value))
    witnessed_at = NOW - timedelta(minutes=1)
    witness_statement = WitnessStatementV2(
        witness_id=_uuid(30),
        witness_name="Independent AWS account witness",
        witness_account_id="333333333333",
        witness_key_arn=WITNESS_KEY,
        witness_identity=witness_identity,
        plan_id=plan.plan_id,
        plan_digest=deployment_plan_digest(plan),
        approval_ids=tuple(item.statement.approval_id for item in ordered),
        approval_record_digests=tuple(approval_record_digest(item) for item in ordered),
        witnessed_at=witnessed_at,
        expires_at=NOW + timedelta(minutes=30),
    )
    witness_request_id = _uuid(32)
    witness = SignedWitnessV2(
        statement=witness_statement,
        signature=KmsSignatureV2(
            key_arn=WITNESS_KEY,
            signature_b64=base64.b64encode(b"signature-witness").decode(),
            provider_request_id=witness_request_id,
        ),
        cloudtrail_sign_event=_cloudtrail_event(
            event_id=_uuid(31),
            request_id=witness_request_id,
            key_arn=WITNESS_KEY,
            account="333333333333",
            user_id=witness_identity.identity_center_user_id,
            principal_arn=witness_principal,
            identity_store_arn=witness_identity.identity_store_arn,
            signed_at=witnessed_at,
        ),
    )
    approver_policies = {
        ApprovalRole.SECURITY_OWNER: SignerPolicy(
            role=ApprovalRole.SECURITY_OWNER,
            key_arn=SECURITY_KEY,
            identity_store_arn=IDENTITY_STORE,
            identity_center_user_id=security_identity.identity_center_user_id,
            principal_arn=security_principal,
        ),
        ApprovalRole.RELEASE_OWNER: SignerPolicy(
            role=ApprovalRole.RELEASE_OWNER,
            key_arn=RELEASE_KEY,
            identity_store_arn=IDENTITY_STORE,
            identity_center_user_id=release_identity.identity_center_user_id,
            principal_arn=release_principal,
        ),
    }
    witness_policy = SignerPolicy(
        role=None,
        key_arn=WITNESS_KEY,
        identity_store_arn=WITNESS_IDENTITY_STORE,
        identity_center_user_id=witness_identity.identity_center_user_id,
        principal_arn=witness_principal,
    )
    return (
        ApprovalBundleV2(plan=plan, approvals=approvals, witness=witness),
        approver_policies,
        witness_policy,
    )


def test_plan_rejects_duplicate_provider_mutation_targets() -> None:
    bundle, _policies, _witness_policy = _bundle_and_policies()
    action = bundle.plan.provider_actions[0]
    duplicate_target = action.model_copy(update={"action_id": _uuid(999)})

    with pytest.raises(ValueError, match="provider mutation targets must be distinct"):
        DeploymentPlanV2(
            **{
                **bundle.plan.model_dump(exclude={"provider_actions"}),
                "provider_actions": (action, duplicate_target),
            }
        )


def _providers(bundle: ApprovalBundleV2) -> tuple[FakeKms, FakeCloudTrail]:
    events = {
        str(item.cloudtrail_sign_event.event_id): item.cloudtrail_sign_event
        for item in (*bundle.approvals, bundle.witness)
    }
    return FakeKms(), FakeCloudTrail(events)


def _verify(
    bundle: ApprovalBundleV2,
    policies: dict[ApprovalRole, SignerPolicy],
    witness_policy: SignerPolicy,
    *,
    kms: FakeKms | None = None,
    cloudtrail: FakeCloudTrail | None = None,
):
    default_kms, default_cloudtrail = _providers(bundle)
    return verify_approval_bundle(
        bundle,
        kms=kms or default_kms,
        cloudtrail=cloudtrail or default_cloudtrail,
        approver_policies=policies,
        witness_policy=witness_policy,
        production_account_id=PRODUCTION_ACCOUNT,
        now=NOW,
    )


def test_positive_quorum_verifies_three_distinct_humans_and_keys() -> None:
    bundle, policies, witness_policy = _bundle_and_policies()
    kms, cloudtrail = _providers(bundle)

    result = _verify(bundle, policies, witness_policy, kms=kms, cloudtrail=cloudtrail)

    assert result.verified is True
    assert result.plan_digest == deployment_plan_digest(bundle.plan)
    assert set(result.approver_user_ids) == {
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
    }
    assert result.witness_user_id == "33333333-3333-4333-8333-333333333333"
    assert result.witness_account_id == "333333333333"
    assert len(kms.calls) == 3
    assert len(cloudtrail.calls) == 3


@pytest.mark.parametrize("duplicate", ["human", "key"])
def test_approvers_must_not_share_human_or_key(duplicate: str) -> None:
    bundle, policies, witness_policy = _bundle_and_policies()
    security, release = bundle.approvals
    if duplicate == "human":
        release_statement = release.statement.model_copy(
            update={"approver": security.statement.approver}
        )
    else:
        release_statement = release.statement.model_copy(update={"key_arn": SECURITY_KEY})
    changed = release.model_copy(update={"statement": release_statement})
    bundle = bundle.model_copy(update={"approvals": (security, changed)})

    message = "distinct Identity Center humans" if duplicate == "human" else "keys must be distinct"
    with pytest.raises(ApprovalVerificationError, match=message):
        _verify(bundle, policies, witness_policy)


def test_expired_plan_is_rejected_before_any_provider_call() -> None:
    bundle, policies, witness_policy = _bundle_and_policies()
    bundle = bundle.model_copy(update={"plan": bundle.plan.model_copy(update={"expires_at": NOW})})
    kms, cloudtrail = _providers(bundle)

    with pytest.raises(ApprovalVerificationError, match="deployment plan has expired"):
        _verify(bundle, policies, witness_policy, kms=kms, cloudtrail=cloudtrail)
    assert kms.calls == []
    assert cloudtrail.calls == []


def test_approval_with_mismatched_plan_digest_is_rejected() -> None:
    bundle, policies, witness_policy = _bundle_and_policies()
    first, second = bundle.approvals
    changed = first.model_copy(
        update={"statement": first.statement.model_copy(update={"plan_digest": "f" * 64})}
    )
    bundle = bundle.model_copy(update={"approvals": (changed, second)})

    with pytest.raises(ApprovalVerificationError, match="not bound to the exact deployment plan"):
        _verify(bundle, policies, witness_policy)


def test_deny_decision_is_terminal_before_any_provider_call() -> None:
    bundle, policies, witness_policy = _bundle_and_policies()
    first, second = bundle.approvals
    changed = first.model_copy(
        update={"statement": first.statement.model_copy(update={"decision": ApprovalDecision.DENY})}
    )
    bundle = bundle.model_copy(update={"approvals": (changed, second)})
    kms, cloudtrail = _providers(bundle)

    with pytest.raises(ApprovalVerificationError, match="denial or non-approval is terminal"):
        _verify(bundle, policies, witness_policy, kms=kms, cloudtrail=cloudtrail)
    assert kms.calls == []
    assert cloudtrail.calls == []


@pytest.mark.parametrize(
    ("kms", "message"),
    [
        (FakeKms(valid=False), "AWS KMS rejected"),
        (FakeKms(error=ApprovalVerificationError("KMS unavailable")), "KMS unavailable"),
    ],
)
def test_kms_false_or_unavailable_fails_closed(kms: FakeKms, message: str) -> None:
    bundle, policies, witness_policy = _bundle_and_policies()

    with pytest.raises(ApprovalVerificationError, match=message):
        _verify(bundle, policies, witness_policy, kms=kms)


def test_cloudtrail_mismatch_fails_closed() -> None:
    bundle, policies, witness_policy = _bundle_and_policies()
    _kms, cloudtrail = _providers(bundle)
    first_event_id = str(bundle.approvals[0].cloudtrail_sign_event.event_id)
    event = cloudtrail.events[first_event_id]
    cloudtrail.events[first_event_id] = event.model_copy(update={"event_payload_sha256": "0" * 64})

    with pytest.raises(ApprovalVerificationError, match="differs from provider lookup"):
        _verify(bundle, policies, witness_policy, cloudtrail=cloudtrail)


def test_cloudtrail_unavailable_fails_closed() -> None:
    bundle, policies, witness_policy = _bundle_and_policies()
    cloudtrail = FakeCloudTrail({}, error=ApprovalVerificationError("CloudTrail unavailable"))

    with pytest.raises(ApprovalVerificationError, match="CloudTrail unavailable"):
        _verify(bundle, policies, witness_policy, cloudtrail=cloudtrail)


@pytest.mark.parametrize("colliding_account", [PRODUCTION_ACCOUNT])
def test_witness_must_use_cross_account_key(colliding_account: str) -> None:
    bundle, policies, witness_policy = _bundle_and_policies()
    colliding_key = _key_arn(colliding_account, "d")
    changed_statement = bundle.witness.statement.model_copy(
        update={
            "witness_account_id": colliding_account,
            "witness_key_arn": colliding_key,
        }
    )
    changed_signature = bundle.witness.signature.model_copy(update={"key_arn": colliding_key})
    changed_witness = bundle.witness.model_copy(
        update={"statement": changed_statement, "signature": changed_signature}
    )
    changed_policy = SignerPolicy(
        role=None,
        key_arn=colliding_key,
        identity_store_arn=witness_policy.identity_store_arn,
        identity_center_user_id=witness_policy.identity_center_user_id,
        principal_arn=witness_policy.principal_arn,
    )
    bundle = bundle.model_copy(update={"witness": changed_witness})

    with pytest.raises(ApprovalVerificationError, match="separate AWS account"):
        _verify(bundle, policies, changed_policy)


def test_witness_must_bind_exact_complete_approval_records() -> None:
    bundle, policies, witness_policy = _bundle_and_policies()
    digests = bundle.witness.statement.approval_record_digests
    changed_statement = bundle.witness.statement.model_copy(
        update={"approval_record_digests": (digests[0], "f" * 64)}
    )
    bundle = bundle.model_copy(
        update={"witness": bundle.witness.model_copy(update={"statement": changed_statement})}
    )

    with pytest.raises(ApprovalVerificationError, match="exact approval records"):
        _verify(bundle, policies, witness_policy)


def test_witness_identity_cannot_reuse_a_production_identity_store() -> None:
    bundle, policies, witness_policy = _bundle_and_policies()
    approval_identity = bundle.approvals[0].statement.approver
    changed_statement = bundle.witness.statement.model_copy(
        update={"witness_identity": approval_identity}
    )
    bundle = bundle.model_copy(
        update={"witness": bundle.witness.model_copy(update={"statement": changed_statement})}
    )
    changed_policy = SignerPolicy(
        role=None,
        key_arn=witness_policy.key_arn,
        identity_store_arn=approval_identity.identity_store_arn,
        identity_center_user_id=approval_identity.identity_center_user_id,
        principal_arn=witness_policy.principal_arn,
    )

    with pytest.raises(ApprovalVerificationError, match="witness account"):
        _verify(bundle, policies, changed_policy)
