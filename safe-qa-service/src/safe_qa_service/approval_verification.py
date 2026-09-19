"""Detached AWS KMS approval and independent witness verification.

This module deliberately has no signing operation. Production runtime permissions
must allow ``kms:Verify`` and CloudTrail lookup while explicitly denying ``kms:Sign``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from .schemas.v2 import (
    ApprovalBundleV2,
    ApprovalDecision,
    ApprovalRole,
    ApprovalStatementV2,
    CloudTrailSignEventV2,
    DeploymentPlanV2,
    SignedApprovalV2,
    SignedWitnessV2,
    WitnessStatementV2,
)


class ApprovalVerificationError(RuntimeError):
    """Raised whenever identity, signature, quorum, or witness evidence is incomplete."""


@dataclass(frozen=True)
class KmsVerifyResult:
    signature_valid: bool
    key_arn: str
    signing_algorithm: str
    verification_request_id: str


class KmsVerifyProvider(Protocol):
    def verify_digest(
        self,
        *,
        key_arn: str,
        digest: bytes,
        signature: bytes,
        signing_algorithm: str,
    ) -> KmsVerifyResult: ...


class CloudTrailLookupProvider(Protocol):
    def lookup_kms_sign_event(
        self,
        event_id: str,
        *,
        account_id: str | None = None,
        region: str | None = None,
    ) -> CloudTrailSignEventV2: ...


@dataclass(frozen=True)
class SignerPolicy:
    role: ApprovalRole | None
    key_arn: str
    identity_store_arn: str
    identity_center_user_id: str
    principal_arn: str


@dataclass(frozen=True)
class ApprovalVerification:
    verified: bool
    plan_digest: str
    approval_ids: tuple[str, str]
    approver_user_ids: tuple[str, str]
    witness_id: str
    witness_user_id: str
    witness_account_id: str
    verified_at: datetime


def canonical_json_bytes(value: Any) -> bytes:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def deployment_plan_digest(plan: DeploymentPlanV2) -> str:
    return _sha256_hex(canonical_json_bytes(plan))


def approval_signing_digest(statement: ApprovalStatementV2) -> bytes:
    return _sha256_bytes(canonical_json_bytes(statement))


def witness_signing_digest(statement: WitnessStatementV2) -> bytes:
    return _sha256_bytes(canonical_json_bytes(statement))


def approval_record_digest(approval: SignedApprovalV2) -> str:
    return _sha256_hex(canonical_json_bytes(approval))


def _kms_account(key_arn: str) -> str:
    try:
        account = key_arn.split(":", 5)[4]
    except IndexError as exc:
        raise ApprovalVerificationError("KMS key ARN is malformed") from exc
    if len(account) != 12 or not account.isdigit():
        raise ApprovalVerificationError("KMS key ARN account is malformed")
    return account


def _arn_account(arn: str, label: str) -> str:
    parts = arn.split(":", 5)
    account = parts[4] if len(parts) == 6 else ""
    if len(account) != 12 or not account.isdigit():
        raise ApprovalVerificationError(f"{label} ARN account is malformed")
    return account


def _kms_region(key_arn: str) -> str:
    try:
        region = key_arn.split(":", 5)[3]
    except IndexError as exc:
        raise ApprovalVerificationError("KMS key ARN is malformed") from exc
    if not region:
        raise ApprovalVerificationError("KMS key ARN region is malformed")
    return region


def _principal_matches(observed: str, configured: str) -> bool:
    if observed == configured:
        return True
    configured_parts = configured.split(":", 5)
    observed_parts = observed.split(":", 5)
    if (
        len(configured_parts) != 6
        or len(observed_parts) != 6
        or configured_parts[2] != "iam"
        or not configured_parts[5].startswith("role/")
        or observed_parts[2] != "sts"
        or not observed_parts[5].startswith("assumed-role/")
        or configured_parts[:2] != observed_parts[:2]
        or configured_parts[4] != observed_parts[4]
    ):
        return False
    configured_role = configured_parts[5].rsplit("/", 1)[-1]
    observed_role = observed_parts[5].split("/", 2)[1]
    return configured_role == observed_role


def _decode_signature(value: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ApprovalVerificationError("signature is not canonical Base64") from exc
    if not 8 <= len(raw) <= 6144:
        raise ApprovalVerificationError("signature byte length is invalid")
    return raw


def _time_window(
    *, issued: datetime, expires: datetime, now: datetime, maximum: timedelta, label: str
) -> None:
    issued = issued.astimezone(UTC)
    expires = expires.astimezone(UTC)
    now = now.astimezone(UTC)
    if issued > now + timedelta(seconds=30):
        raise ApprovalVerificationError(f"{label} issuance time is in the future")
    if expires <= now:
        raise ApprovalVerificationError(f"{label} has expired")
    if expires <= issued or expires - issued > maximum:
        raise ApprovalVerificationError(f"{label} validity window exceeds policy")


def _compare_cloudtrail_event(
    supplied: CloudTrailSignEventV2,
    observed: CloudTrailSignEventV2,
    *,
    key_arn: str,
    provider_request_id: str,
    identity_store_arn: str,
    identity_center_user_id: str,
    principal_arn: str,
    signed_at: datetime,
) -> None:
    supplied_stable = supplied.model_dump(exclude={"lookup_retrieved_at"})
    observed_stable = observed.model_dump(exclude={"lookup_retrieved_at"})
    if supplied_stable != observed_stable:
        raise ApprovalVerificationError("submitted CloudTrail event differs from provider lookup")
    if str(observed.request_id) != provider_request_id:
        raise ApprovalVerificationError("CloudTrail request ID does not bind the KMS signature")
    if observed.key_arn != key_arn:
        raise ApprovalVerificationError("CloudTrail event references a different KMS key")
    if observed.recipient_account_id != _kms_account(key_arn) or observed.aws_region != _kms_region(
        key_arn
    ):
        raise ApprovalVerificationError("CloudTrail account or region differs from the KMS key")
    if observed.signing_algorithm != "ECDSA_SHA_256" or observed.message_type != "DIGEST":
        raise ApprovalVerificationError("CloudTrail event uses an unapproved signing profile")
    if observed.identity_store_arn != identity_store_arn:
        raise ApprovalVerificationError("CloudTrail identity store does not match policy")
    if observed.on_behalf_of_user_id != identity_center_user_id:
        raise ApprovalVerificationError("CloudTrail user does not match the named human")
    if not _principal_matches(observed.principal_arn, principal_arn):
        raise ApprovalVerificationError("CloudTrail principal does not match policy")
    if abs((observed.event_time.astimezone(UTC) - signed_at.astimezone(UTC)).total_seconds()) > 300:
        raise ApprovalVerificationError("CloudTrail Sign event is outside the approval time bound")


def _verify_signature(
    *,
    statement: ApprovalStatementV2 | WitnessStatementV2,
    signed: SignedApprovalV2 | SignedWitnessV2,
    identity_store_arn: str,
    identity_center_user_id: str,
    principal_arn: str,
    kms: KmsVerifyProvider,
    cloudtrail: CloudTrailLookupProvider,
) -> None:
    signature = signed.signature
    key_arn = (
        statement.key_arn
        if isinstance(statement, ApprovalStatementV2)
        else statement.witness_key_arn
    )
    if signature.key_arn != key_arn:
        raise ApprovalVerificationError("statement and detached signature key differ")
    digest = (
        approval_signing_digest(statement)
        if isinstance(statement, ApprovalStatementV2)
        else witness_signing_digest(statement)
    )
    result = kms.verify_digest(
        key_arn=key_arn,
        digest=digest,
        signature=_decode_signature(signature.signature_b64),
        signing_algorithm=signature.algorithm,
    )
    if (
        not result.signature_valid
        or result.key_arn != key_arn
        or result.signing_algorithm != signature.algorithm
    ):
        raise ApprovalVerificationError("AWS KMS rejected the detached signature")
    if not result.verification_request_id:
        raise ApprovalVerificationError("KMS Verify did not return a provider request ID")
    observed = cloudtrail.lookup_kms_sign_event(
        str(signed.cloudtrail_sign_event.event_id),
        account_id=_kms_account(key_arn),
        region=_kms_region(key_arn),
    )
    signed_at = (
        statement.signed_at
        if isinstance(statement, ApprovalStatementV2)
        else statement.witnessed_at
    )
    _compare_cloudtrail_event(
        signed.cloudtrail_sign_event,
        observed,
        key_arn=key_arn,
        provider_request_id=str(signature.provider_request_id),
        identity_store_arn=identity_store_arn,
        identity_center_user_id=identity_center_user_id,
        principal_arn=principal_arn,
        signed_at=signed_at,
    )


def verify_approval_bundle(
    bundle: ApprovalBundleV2,
    *,
    kms: KmsVerifyProvider,
    cloudtrail: CloudTrailLookupProvider,
    approver_policies: dict[ApprovalRole, SignerPolicy],
    witness_policy: SignerPolicy,
    production_account_id: str,
    now: datetime | None = None,
) -> ApprovalVerification:
    """Verify two independent human approvals plus one cross-account witness."""
    checked_at = (now or datetime.now(UTC)).astimezone(UTC)
    plan = bundle.plan
    expected_plan_digest = deployment_plan_digest(plan)
    _time_window(
        issued=plan.created_at,
        expires=plan.expires_at,
        now=checked_at,
        maximum=timedelta(hours=24),
        label="deployment plan",
    )
    if set(approver_policies) != {ApprovalRole.SECURITY_OWNER, ApprovalRole.RELEASE_OWNER}:
        raise ApprovalVerificationError("exact security and release signer policies are required")

    ordered = sorted(bundle.approvals, key=lambda item: item.statement.role.value)
    if {item.statement.role for item in ordered} != {
        ApprovalRole.SECURITY_OWNER,
        ApprovalRole.RELEASE_OWNER,
    }:
        raise ApprovalVerificationError("exactly one approval per required role is required")
    if any(item.statement.decision != ApprovalDecision.APPROVE for item in ordered):
        raise ApprovalVerificationError("a denial or non-approval is terminal")
    if len({item.statement.approval_id for item in ordered}) != 2:
        raise ApprovalVerificationError("approval IDs must be distinct")
    if len({item.statement.key_arn for item in ordered}) != 2:
        raise ApprovalVerificationError("approval KMS keys must be distinct")
    approver_identities = {
        (
            item.statement.approver.identity_store_arn,
            item.statement.approver.identity_center_user_id,
        )
        for item in ordered
    }
    if len(approver_identities) != 2:
        raise ApprovalVerificationError("two distinct Identity Center humans are required")
    approval_accounts = {_kms_account(item.statement.key_arn) for item in ordered}
    if approval_accounts != {production_account_id}:
        raise ApprovalVerificationError("approval KMS keys must be in the production account")
    for approval in ordered:
        policy = approver_policies[approval.statement.role]
        if {
            _arn_account(policy.identity_store_arn, "approval identity store"),
            _arn_account(policy.principal_arn, "approval principal"),
        } != {production_account_id}:
            raise ApprovalVerificationError(
                "approval identity store and principal must be in production"
            )

    for approval in ordered:
        statement = approval.statement
        policy = approver_policies[statement.role]
        _time_window(
            issued=statement.signed_at,
            expires=statement.expires_at,
            now=checked_at,
            maximum=timedelta(hours=1),
            label=f"{statement.role.value} approval",
        )
        if (
            statement.plan_id != plan.plan_id
            or statement.plan_digest != expected_plan_digest
            or statement.plan_nonce != plan.nonce
        ):
            raise ApprovalVerificationError("approval is not bound to the exact deployment plan")
        if statement.expires_at > plan.expires_at:
            raise ApprovalVerificationError("approval outlives its deployment plan")
        if (
            policy.role != statement.role
            or policy.key_arn != statement.key_arn
            or policy.identity_store_arn != statement.approver.identity_store_arn
            or policy.identity_center_user_id != statement.approver.identity_center_user_id
        ):
            raise ApprovalVerificationError("approval signer is not the configured authority")
        _verify_signature(
            statement=statement,
            signed=approval,
            identity_store_arn=policy.identity_store_arn,
            identity_center_user_id=policy.identity_center_user_id,
            principal_arn=policy.principal_arn,
            kms=kms,
            cloudtrail=cloudtrail,
        )

    witness = bundle.witness
    witness_statement = witness.statement
    _time_window(
        issued=witness_statement.witnessed_at,
        expires=witness_statement.expires_at,
        now=checked_at,
        maximum=timedelta(hours=1),
        label="independent witness",
    )
    expected_ids = tuple(item.statement.approval_id for item in ordered)
    expected_records = tuple(approval_record_digest(item) for item in ordered)
    if (
        witness_statement.plan_id != plan.plan_id
        or witness_statement.plan_digest != expected_plan_digest
        or witness_statement.approval_ids != expected_ids
        or witness_statement.approval_record_digests != expected_records
    ):
        raise ApprovalVerificationError("witness does not bind the exact approval records")
    if witness_statement.expires_at > plan.expires_at:
        raise ApprovalVerificationError("witness outlives its deployment plan")
    if (
        witness_statement.witness_account_id == production_account_id
        or witness_statement.witness_account_id in approval_accounts
        or _kms_account(witness_statement.witness_key_arn) != witness_statement.witness_account_id
    ):
        raise ApprovalVerificationError("witness must use a separate AWS account")
    if {
        _arn_account(witness_policy.identity_store_arn, "witness identity store"),
        _arn_account(witness_policy.principal_arn, "witness principal"),
    } != {witness_statement.witness_account_id}:
        raise ApprovalVerificationError(
            "witness identity store and principal must be in the witness account"
        )
    if (
        witness_policy.role is not None
        or witness_policy.key_arn != witness_statement.witness_key_arn
        or witness_policy.identity_store_arn
        != witness_statement.witness_identity.identity_store_arn
        or witness_policy.identity_center_user_id
        != witness_statement.witness_identity.identity_center_user_id
    ):
        raise ApprovalVerificationError("witness identity is not the configured authority")
    witness_identity = (
        witness_statement.witness_identity.identity_store_arn,
        witness_statement.witness_identity.identity_center_user_id,
    )
    if witness_identity in approver_identities:
        raise ApprovalVerificationError("witness must be distinct from both approvers")
    _verify_signature(
        statement=witness_statement,
        signed=witness,
        identity_store_arn=witness_policy.identity_store_arn,
        identity_center_user_id=witness_policy.identity_center_user_id,
        principal_arn=witness_policy.principal_arn,
        kms=kms,
        cloudtrail=cloudtrail,
    )
    return ApprovalVerification(
        verified=True,
        plan_digest=expected_plan_digest,
        approval_ids=tuple(str(item.statement.approval_id) for item in ordered),
        approver_user_ids=tuple(
            item.statement.approver.identity_center_user_id for item in ordered
        ),
        witness_id=str(witness_statement.witness_id),
        witness_user_id=witness_statement.witness_identity.identity_center_user_id,
        witness_account_id=witness_statement.witness_account_id,
        verified_at=checked_at,
    )
