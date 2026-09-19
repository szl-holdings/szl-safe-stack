"""Version 2 detached-approval and independent-witness contracts.

These schemas carry evidence of approvals.  They do not create signatures and do
not grant a release on their own.  The verification module binds every approval
to an exact deployment plan, AWS KMS key, CloudTrail Sign event, and immutable
IAM Identity Center user identifier.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

SCHEMA_VERSION_V2 = "2.0"

Sha256Hex = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
AccountId = Annotated[str, Field(pattern=r"^[0-9]{12}$")]
KmsKeyArn = Annotated[
    str,
    Field(
        min_length=50,
        max_length=256,
        pattern=(
            r"^arn:(?:aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:[0-9]{12}:"
            r"key/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
        ),
    ),
]
IdentityStoreArn = Annotated[
    str,
    Field(
        min_length=45,
        max_length=180,
        pattern=(
            r"^arn:(?:aws|aws-us-gov|aws-cn):identitystore::[0-9]{12}:"
            r"identitystore/d-[a-z0-9]{10,32}$"
        ),
    ),
]
IdentityCenterUserId = Annotated[
    str,
    Field(
        min_length=36,
        max_length=47,
        pattern=(
            r"^(?:[0-9a-f]{10}-)?[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-"
            r"[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$"
        ),
    ),
]


class ApprovalDecision(StrEnum):
    """A denial is terminal; only APPROVE can contribute to a quorum."""

    APPROVE = "APPROVE"
    DENY = "DENY"


class ApprovalRole(StrEnum):
    """The two non-interchangeable human slots in the base deployment gate."""

    SECURITY_OWNER = "security_owner"
    RELEASE_OWNER = "release_owner"


class ProviderActionType(StrEnum):
    """Consequential AWS operations supported by the production controller."""

    EKS_DEPLOY_IMMUTABLE_IMAGE = "EKS_DEPLOY_IMMUTABLE_IMAGE"
    EKS_ISOLATE_NAMESPACE = "EKS_ISOLATE_NAMESPACE"
    IAM_DISABLE_ACCESS_KEY = "IAM_DISABLE_ACCESS_KEY"
    IAM_REVOKE_ROLE_SESSIONS = "IAM_REVOKE_ROLE_SESSIONS"


class StrictV2Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class EksDeployImmutableImageActionV2(StrictV2Model):
    action_type: Literal[ProviderActionType.EKS_DEPLOY_IMMUTABLE_IMAGE] = (
        ProviderActionType.EKS_DEPLOY_IMMUTABLE_IMAGE
    )
    action_id: UUID
    cluster_name: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
    namespace: str = Field(min_length=1, max_length=63, pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
    deployment_name: str = Field(
        min_length=1, max_length=63, pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"
    )
    container_name: str = Field(
        min_length=1, max_length=63, pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"
    )
    image_repository: str = Field(min_length=3, max_length=512, pattern=r"^[A-Za-z0-9._:/-]+$")
    image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    source_revision: str = Field(
        min_length=7, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$"
    )
    replicas: int = Field(ge=1, le=100)


class EksIsolateNamespaceActionV2(StrictV2Model):
    action_type: Literal[ProviderActionType.EKS_ISOLATE_NAMESPACE] = (
        ProviderActionType.EKS_ISOLATE_NAMESPACE
    )
    action_id: UUID
    cluster_name: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
    namespace: str = Field(min_length=1, max_length=63, pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
    policy_name: Literal["safe-qa-approved-egress"] = "safe-qa-approved-egress"


class IamDisableAccessKeyActionV2(StrictV2Model):
    action_type: Literal[ProviderActionType.IAM_DISABLE_ACCESS_KEY] = (
        ProviderActionType.IAM_DISABLE_ACCESS_KEY
    )
    action_id: UUID
    user_name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9+=,.@_-]+$")
    access_key_id: str = Field(min_length=16, max_length=128, pattern=r"^[A-Z0-9]+$")


class IamRevokeRoleSessionsActionV2(StrictV2Model):
    action_type: Literal[ProviderActionType.IAM_REVOKE_ROLE_SESSIONS] = (
        ProviderActionType.IAM_REVOKE_ROLE_SESSIONS
    )
    action_id: UUID
    role_name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9+=,.@_-]+$")
    policy_name: Literal["AWSRevokeOlderSessions"] = "AWSRevokeOlderSessions"
    revoke_sessions_issued_before: AwareDatetime


ProviderActionV2 = Annotated[
    EksDeployImmutableImageActionV2
    | EksIsolateNamespaceActionV2
    | IamDisableAccessKeyActionV2
    | IamRevokeRoleSessionsActionV2,
    Field(discriminator="action_type"),
]


class DeploymentPlanV2(StrictV2Model):
    """Immutable scope that every approval and witness must cover exactly."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "$id": "https://schemas.example.invalid/safe-qa/v2/deployment-plan.json",
            "x-truth-boundary": (
                "A plan is not authorized until detached approvals and an independent "
                "witness have been verified and atomically consumed."
            ),
        },
    )

    schema_version: Literal["2.0"] = SCHEMA_VERSION_V2
    statement_type: Literal["safe-qa-deployment-plan/v2"] = "safe-qa-deployment-plan/v2"
    plan_id: UUID
    nonce: str = Field(min_length=43, max_length=86, pattern=r"^[A-Za-z0-9_-]+$")
    operation: Literal["EXECUTE_EXACT_PROVIDER_ACTIONS"] = "EXECUTE_EXACT_PROVIDER_ACTIONS"
    source_revision: str = Field(min_length=7, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    container_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    evidence_manifest_sha256: Sha256Hex
    policy_bundle_sha256: Sha256Hex
    provider_state_sha256: Sha256Hex
    environment: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:/-]+$")
    requester_issuer: str = Field(min_length=1, max_length=512)
    requester_subject: str = Field(min_length=1, max_length=256)
    created_at: AwareDatetime
    expires_at: AwareDatetime
    provider_actions: tuple[ProviderActionV2, ...] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def bind_deployment_digest(self) -> DeploymentPlanV2:
        action_ids = {action.action_id for action in self.provider_actions}
        if len(action_ids) != len(self.provider_actions):
            raise ValueError("provider action IDs must be distinct")
        mutation_targets: set[tuple[str, ...]] = set()
        for action in self.provider_actions:
            if isinstance(action, EksDeployImmutableImageActionV2):
                mutation_target = (
                    "eks-deployment",
                    action.cluster_name,
                    action.namespace,
                    action.deployment_name,
                )
            elif isinstance(action, EksIsolateNamespaceActionV2):
                mutation_target = (
                    "eks-network-policy",
                    action.cluster_name,
                    action.namespace,
                    action.policy_name,
                )
            elif isinstance(action, IamDisableAccessKeyActionV2):
                mutation_target = (
                    "iam-access-key",
                    action.user_name,
                    action.access_key_id,
                )
            else:
                mutation_target = (
                    "iam-role-inline-policy",
                    action.role_name,
                    action.policy_name,
                )
            if mutation_target in mutation_targets:
                raise ValueError("provider mutation targets must be distinct")
            mutation_targets.add(mutation_target)
            if (
                isinstance(action, EksDeployImmutableImageActionV2)
                and action.image_digest != self.container_digest
            ):
                raise ValueError("EKS deployment action must use the plan container digest")
            if (
                isinstance(action, EksDeployImmutableImageActionV2)
                and action.source_revision != self.source_revision
            ):
                raise ValueError("EKS deployment action must use the plan source revision")
            if (
                isinstance(action, IamRevokeRoleSessionsActionV2)
                and action.revoke_sessions_issued_before > self.created_at
            ):
                raise ValueError("IAM session-revocation cutoff cannot postdate plan creation")
        return self


class UnsignedPlanRequestV2(StrictV2Model):
    """Human-authenticated request for a read-only provider preview and unsigned plan."""

    schema_version: Literal["2.0"] = SCHEMA_VERSION_V2
    source_revision: str = Field(min_length=7, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    container_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    evidence_manifest_sha256: Sha256Hex
    policy_bundle_sha256: Sha256Hex
    environment: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:/-]+$")
    expires_in_seconds: int = Field(ge=300, le=3600)
    provider_actions: tuple[ProviderActionV2, ...] = Field(min_length=1, max_length=20)


class ProviderActionPreviewV2(StrictV2Model):
    action_id: UUID
    action_type: ProviderActionType
    current_state_sha256: Sha256Hex
    current_state: dict[str, str | int | bool | None]


class UnsignedPlanResponseV2(StrictV2Model):
    schema_version: Literal["2.0"] = SCHEMA_VERSION_V2
    authorization_status: Literal["AWAITING_DETACHED_APPROVALS"] = "AWAITING_DETACHED_APPROVALS"
    plan: DeploymentPlanV2
    plan_digest: Sha256Hex
    previews: tuple[ProviderActionPreviewV2, ...]


class ProviderActionReceiptV2(StrictV2Model):
    action_id: UUID
    action_type: ProviderActionType
    status: Literal[
        "DEPLOYED",
        "ISOLATION_POLICY_OBJECT_APPLIED",
        "CREDENTIAL_DISABLED",
        "SESSIONS_REVOKED",
    ]
    before_state_sha256: Sha256Hex
    after_state_sha256: Sha256Hex
    provider_receipt_ids: tuple[str, ...] = Field(min_length=1, max_length=10)
    enforced_at: AwareDatetime


class ControlExecutionResponseV2(StrictV2Model):
    schema_version: Literal["2.0"] = SCHEMA_VERSION_V2
    plan_id: UUID
    plan_digest: Sha256Hex
    execution_status: Literal["PROVIDER_ACTIONS_APPLIED_AND_READ_BACK"] = (
        "PROVIDER_ACTIONS_APPLIED_AND_READ_BACK"
    )
    receipts: tuple[ProviderActionReceiptV2, ...] = Field(min_length=1, max_length=20)
    audit_export_status: Literal["ALL_EXPORTED", "PENDING_RETRY"]
    pending_audit_export_count: int = Field(ge=0)
    control_outbox_ids: tuple[UUID, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def audit_export_status_matches_count(self) -> ControlExecutionResponseV2:
        if (self.pending_audit_export_count == 0) != (self.audit_export_status == "ALL_EXPORTED"):
            raise ValueError("audit export status contradicts the pending export count")
        return self


class HumanIdentityV2(StrictV2Model):
    """Named human identity bound to an immutable Identity Center identifier."""

    display_name: str = Field(min_length=1, max_length=200)
    identity_store_arn: IdentityStoreArn
    identity_center_user_id: IdentityCenterUserId


class KmsSignatureV2(StrictV2Model):
    """Detached AWS asymmetric KMS signature metadata."""

    key_arn: KmsKeyArn
    algorithm: Literal["ECDSA_SHA_256"] = "ECDSA_SHA_256"
    message_type: Literal["DIGEST"] = "DIGEST"
    signature_b64: str = Field(min_length=8, max_length=8192, pattern=r"^[A-Za-z0-9+/]+={0,2}$")
    provider_request_id: UUID


class CloudTrailSignEventV2(StrictV2Model):
    """Normalized fields from the CloudTrail management event for KMS Sign."""

    event_id: UUID
    request_id: UUID
    event_time: AwareDatetime
    event_source: Literal["kms.amazonaws.com"] = "kms.amazonaws.com"
    event_name: Literal["Sign"] = "Sign"
    event_category: Literal["Management"] = "Management"
    key_arn: KmsKeyArn
    signing_algorithm: Literal["ECDSA_SHA_256"] = "ECDSA_SHA_256"
    message_type: Literal["DIGEST"] = "DIGEST"
    aws_region: str = Field(min_length=3, max_length=32, pattern=r"^[a-z0-9-]+$")
    recipient_account_id: AccountId
    principal_arn: str = Field(
        min_length=20,
        max_length=512,
        pattern=r"^arn:(?:aws|aws-us-gov|aws-cn):(?:iam|sts)::[0-9]{12}:.+$",
    )
    identity_store_arn: IdentityStoreArn
    on_behalf_of_user_id: IdentityCenterUserId
    event_payload_sha256: Sha256Hex
    lookup_retrieved_at: AwareDatetime
    evidence_status: Literal["AWS_CLOUDTRAIL_LOOKUP_VERIFIED"] = "AWS_CLOUDTRAIL_LOOKUP_VERIFIED"


class ApprovalStatementV2(StrictV2Model):
    """Canonical statement signed by exactly one human approval key."""

    schema_version: Literal["2.0"] = SCHEMA_VERSION_V2
    statement_type: Literal["safe-qa-approval/v2"] = "safe-qa-approval/v2"
    approval_id: UUID
    plan_id: UUID
    plan_digest: Sha256Hex
    plan_nonce: str = Field(min_length=43, max_length=86, pattern=r"^[A-Za-z0-9_-]+$")
    decision: ApprovalDecision
    role: ApprovalRole
    approver: HumanIdentityV2
    key_arn: KmsKeyArn
    signed_at: AwareDatetime
    expires_at: AwareDatetime


class SignedApprovalV2(StrictV2Model):
    statement: ApprovalStatementV2
    signature: KmsSignatureV2
    cloudtrail_sign_event: CloudTrailSignEventV2


class WitnessStatementV2(StrictV2Model):
    """Third-account witness statement over the complete signed approval records."""

    schema_version: Literal["2.0"] = SCHEMA_VERSION_V2
    statement_type: Literal["safe-qa-witness/v2"] = "safe-qa-witness/v2"
    witness_id: UUID
    witness_name: str = Field(min_length=1, max_length=200)
    witness_account_id: AccountId
    witness_key_arn: KmsKeyArn
    witness_identity: HumanIdentityV2
    plan_id: UUID
    plan_digest: Sha256Hex
    approval_ids: tuple[UUID, UUID]
    approval_record_digests: tuple[Sha256Hex, Sha256Hex]
    witnessed_at: AwareDatetime
    expires_at: AwareDatetime


class SignedWitnessV2(StrictV2Model):
    statement: WitnessStatementV2
    signature: KmsSignatureV2
    cloudtrail_sign_event: CloudTrailSignEventV2


class ApprovalBundleV2(StrictV2Model):
    """Portable verification input; authorization is not asserted by this schema."""

    schema_version: Literal["2.0"] = SCHEMA_VERSION_V2
    plan: DeploymentPlanV2
    approvals: tuple[SignedApprovalV2, SignedApprovalV2]
    witness: SignedWitnessV2
