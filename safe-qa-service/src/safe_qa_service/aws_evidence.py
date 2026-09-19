"""AWS KMS Verify and CloudTrail identity-evidence adapters."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from .approval_verification import ApprovalVerificationError, KmsVerifyResult
from .production_settings import AwsEvidenceRoute
from .schemas.v2 import CloudTrailSignEventV2


class AwsEvidenceProvider:
    """Verify signatures and independently retrieve the corresponding Sign events.

    The runtime role needs only ``kms:Verify`` and ``cloudtrail:LookupEvents``.
    It never receives ``kms:Sign`` permission or private key material.
    """

    def __init__(self, kms_client: Any, cloudtrail_client: Any):
        self.kms_client = kms_client
        self.cloudtrail_client = cloudtrail_client

    @classmethod
    def from_boto3(cls, *, region_name: str) -> AwsEvidenceProvider:
        try:
            import boto3
            from botocore.config import Config
        except ModuleNotFoundError as exc:  # pragma: no cover - production dependency guard
            raise ApprovalVerificationError(
                "boto3 is required for AWS evidence verification"
            ) from exc
        config = Config(
            connect_timeout=3,
            read_timeout=5,
            retries={"mode": "standard", "max_attempts": 3},
            user_agent_extra="safe-qa-control-plane/0.2.0",
        )
        session = boto3.session.Session(region_name=region_name)
        return cls(
            session.client("kms", config=config),
            session.client("cloudtrail", config=config),
        )

    def verify_digest(
        self,
        *,
        key_arn: str,
        digest: bytes,
        signature: bytes,
        signing_algorithm: str,
    ) -> KmsVerifyResult:
        if len(digest) != 32 or signing_algorithm != "ECDSA_SHA_256":
            raise ApprovalVerificationError("AWS KMS verification profile is invalid")
        try:
            response = self.kms_client.verify(
                KeyId=key_arn,
                Message=digest,
                MessageType="DIGEST",
                Signature=signature,
                SigningAlgorithm=signing_algorithm,
            )
        except Exception as exc:
            raise ApprovalVerificationError("AWS KMS Verify was unavailable or rejected") from exc
        metadata = response.get("ResponseMetadata")
        request_id = metadata.get("RequestId") if isinstance(metadata, dict) else None
        observed_key = response.get("KeyId")
        observed_algorithm = response.get("SigningAlgorithm")
        if not all(
            isinstance(item, str) and item
            for item in (request_id, observed_key, observed_algorithm)
        ):
            raise ApprovalVerificationError("AWS KMS Verify returned an incomplete receipt")
        return KmsVerifyResult(
            signature_valid=response.get("SignatureValid") is True,
            key_arn=observed_key,
            signing_algorithm=observed_algorithm,
            verification_request_id=request_id,
        )

    def lookup_kms_sign_event(
        self,
        event_id: str,
        *,
        account_id: str | None = None,
        region: str | None = None,
    ) -> CloudTrailSignEventV2:
        try:
            event_uuid = UUID(event_id)
        except ValueError as exc:
            raise ApprovalVerificationError("CloudTrail event ID is invalid") from exc
        try:
            response = self.cloudtrail_client.lookup_events(
                LookupAttributes=[{"AttributeKey": "EventId", "AttributeValue": str(event_uuid)}],
                MaxResults=2,
            )
        except Exception as exc:
            raise ApprovalVerificationError("AWS CloudTrail lookup was unavailable") from exc
        events = response.get("Events")
        if response.get("NextToken") is not None:
            raise ApprovalVerificationError("CloudTrail Sign event lookup was truncated")
        if not isinstance(events, list) or len(events) != 1:
            raise ApprovalVerificationError("CloudTrail Sign event was missing or ambiguous")
        outer = events[0]
        raw_text = outer.get("CloudTrailEvent") if isinstance(outer, dict) else None
        if not isinstance(raw_text, str) or len(raw_text.encode("utf-8")) > 256_000:
            raise ApprovalVerificationError("CloudTrail event payload is missing or oversized")
        try:
            raw = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise ApprovalVerificationError("CloudTrail event payload is malformed") from exc
        if not isinstance(raw, dict):
            raise ApprovalVerificationError("CloudTrail event payload is not an object")
        request = raw.get("requestParameters")
        identity = raw.get("userIdentity")
        on_behalf = identity.get("onBehalfOf") if isinstance(identity, dict) else None
        session_context = identity.get("sessionContext") if isinstance(identity, dict) else None
        session_issuer = (
            session_context.get("sessionIssuer") if isinstance(session_context, dict) else None
        )
        resources = raw.get("resources")
        if not isinstance(request, dict) or not isinstance(identity, dict):
            raise ApprovalVerificationError("CloudTrail Sign event fields are incomplete")
        if not isinstance(on_behalf, dict):
            raise ApprovalVerificationError("CloudTrail event lacks Identity Center attribution")
        if identity.get("type") != "AssumedRole" or not isinstance(session_issuer, dict):
            raise ApprovalVerificationError(
                "CloudTrail Sign event is not an identity-enhanced assumed-role session"
            )
        key_arns = (
            {item.get("ARN") or item.get("arn") for item in resources if isinstance(item, dict)}
            if isinstance(resources, list)
            else set()
        )
        key_arns.discard(None)
        if len(key_arns) != 1:
            raise ApprovalVerificationError("CloudTrail event has an ambiguous KMS resource")
        try:
            raw_event_id = UUID(str(raw.get("eventID")))
            outer_event_id = UUID(str(outer.get("EventId")))
        except ValueError as exc:
            raise ApprovalVerificationError("CloudTrail event identifiers are malformed") from exc
        if raw_event_id != event_uuid or outer_event_id != event_uuid:
            raise ApprovalVerificationError("CloudTrail lookup returned a different event ID")
        if raw.get("errorCode") is not None or raw.get("errorMessage") is not None:
            raise ApprovalVerificationError("CloudTrail Sign event records a provider failure")
        event_time = outer.get("EventTime")
        if not isinstance(event_time, datetime):
            raw_time = raw.get("eventTime")
            if not isinstance(raw_time, str):
                raise ApprovalVerificationError("CloudTrail event time is missing")
            try:
                event_time = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ApprovalVerificationError("CloudTrail event time is malformed") from exc
        if event_time.tzinfo is None or event_time.utcoffset() is None:
            raise ApprovalVerificationError("CloudTrail event time is not timezone-aware")
        canonical = json.dumps(
            raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        try:
            event = CloudTrailSignEventV2(
                event_id=event_uuid,
                request_id=UUID(str(raw.get("requestID"))),
                event_time=event_time.astimezone(UTC),
                event_source=raw.get("eventSource"),
                event_name=raw.get("eventName"),
                event_category=raw.get("eventCategory"),
                key_arn=next(iter(key_arns)),
                signing_algorithm=request.get("signingAlgorithm"),
                message_type=request.get("messageType"),
                aws_region=raw.get("awsRegion"),
                recipient_account_id=str(raw.get("recipientAccountId", "")),
                principal_arn=session_issuer.get("arn"),
                identity_store_arn=on_behalf.get("identityStoreArn"),
                on_behalf_of_user_id=on_behalf.get("userId"),
                event_payload_sha256=hashlib.sha256(canonical).hexdigest(),
                lookup_retrieved_at=datetime.now(UTC),
                evidence_status="AWS_CLOUDTRAIL_LOOKUP_VERIFIED",
            )
        except (TypeError, ValueError) as exc:
            raise ApprovalVerificationError(
                "CloudTrail Sign event failed schema validation"
            ) from exc
        if account_id is not None and event.recipient_account_id != account_id:
            raise ApprovalVerificationError("CloudTrail event belongs to a different AWS account")
        if region is not None and event.aws_region != region:
            raise ApprovalVerificationError("CloudTrail event belongs to a different AWS Region")
        return event


class AwsEvidenceRouter:
    """Route verification to exact cross-account, regional read-only roles."""

    def __init__(self, providers: dict[tuple[str, str], AwsEvidenceProvider]):
        if not providers:
            raise ApprovalVerificationError("at least one AWS evidence route is required")
        self.providers = providers

    @classmethod
    def from_boto3(
        cls,
        routes: dict[tuple[str, str], AwsEvidenceRoute],
    ) -> AwsEvidenceRouter:
        try:
            import boto3
            from botocore.config import Config
        except ModuleNotFoundError as exc:  # pragma: no cover - production dependency guard
            raise ApprovalVerificationError("boto3 is required for AWS evidence routing") from exc
        config = Config(
            connect_timeout=3,
            read_timeout=5,
            retries={"mode": "standard", "max_attempts": 3},
            user_agent_extra="safe-qa-evidence-router/0.2.0",
        )
        base = boto3.session.Session()
        sts = base.client("sts", config=config)
        try:
            base_identity = sts.get_caller_identity()
        except Exception as exc:
            raise ApprovalVerificationError("AWS base identity check failed") from exc
        base_account = base_identity.get("Account")
        if not isinstance(base_account, str):
            raise ApprovalVerificationError("AWS base identity receipt is incomplete")
        providers: dict[tuple[str, str], AwsEvidenceProvider] = {}
        for key, route in routes.items():
            try:
                if route.reader_role_arn is None:
                    if route.account_id != base_account:
                        raise ApprovalVerificationError(
                            "direct AWS evidence route is outside the runtime account"
                        )
                    session = boto3.session.Session(region_name=route.region)
                else:
                    arguments: dict[str, Any] = {
                        "RoleArn": route.reader_role_arn,
                        "RoleSessionName": "safe-qa-evidence-reader",
                        "DurationSeconds": 900,
                    }
                    if route.external_id:
                        arguments["ExternalId"] = route.external_id
                    assumed = sts.assume_role(**arguments)
                    credentials = assumed["Credentials"]
                    session = boto3.session.Session(
                        aws_access_key_id=credentials["AccessKeyId"],
                        aws_secret_access_key=credentials["SecretAccessKey"],
                        aws_session_token=credentials["SessionToken"],
                        region_name=route.region,
                    )
                identity = session.client("sts", config=config).get_caller_identity()
            except ApprovalVerificationError:
                raise
            except Exception as exc:
                raise ApprovalVerificationError(
                    "AWS evidence-reader role assumption or identity check failed"
                ) from exc
            if identity.get("Account") != route.account_id:
                raise ApprovalVerificationError("AWS evidence route assumed the wrong account")
            providers[key] = AwsEvidenceProvider(
                session.client("kms", config=config),
                session.client("cloudtrail", config=config),
            )
        return cls(providers)

    @staticmethod
    def _key_route(key_arn: str) -> tuple[str, str]:
        parts = key_arn.split(":", 5)
        if len(parts) != 6 or not parts[3] or not parts[4]:
            raise ApprovalVerificationError("KMS key ARN cannot be routed")
        return parts[4], parts[3]

    def verify_digest(
        self,
        *,
        key_arn: str,
        digest: bytes,
        signature: bytes,
        signing_algorithm: str,
    ) -> KmsVerifyResult:
        route = self._key_route(key_arn)
        provider = self.providers.get(route)
        if provider is None:
            raise ApprovalVerificationError("no exact AWS evidence route exists for the KMS key")
        return provider.verify_digest(
            key_arn=key_arn,
            digest=digest,
            signature=signature,
            signing_algorithm=signing_algorithm,
        )

    def lookup_kms_sign_event(
        self,
        event_id: str,
        *,
        account_id: str | None = None,
        region: str | None = None,
    ) -> CloudTrailSignEventV2:
        if account_id is None or region is None:
            raise ApprovalVerificationError(
                "CloudTrail lookup requires an exact account and region"
            )
        provider = self.providers.get((account_id, region))
        if provider is None:
            raise ApprovalVerificationError("no exact AWS route exists for the CloudTrail event")
        return provider.lookup_kms_sign_event(
            event_id,
            account_id=account_id,
            region=region,
        )
