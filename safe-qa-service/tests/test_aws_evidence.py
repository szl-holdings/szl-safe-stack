from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID

import pytest

from safe_qa_service.approval_verification import ApprovalVerificationError
from safe_qa_service.aws_evidence import AwsEvidenceProvider, AwsEvidenceRouter
from safe_qa_service.production_settings import AwsEvidenceRoute

ACCOUNT = "111111111111"
REGION = "us-east-1"
KEY_ARN = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/11111111-1111-4111-8111-111111111111"
EVENT_ID = UUID("22222222-2222-4222-8222-222222222222")
REQUEST_ID = UUID("33333333-3333-4333-8333-333333333333")
IDENTITY_STORE = f"arn:aws:identitystore::{ACCOUNT}:identitystore/d-1234567890"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/security-owner"


class FakeKms:
    def __init__(self, response: dict[str, object] | None = None, failure: Exception | None = None):
        self.response = response
        self.failure = failure
        self.calls: list[dict[str, object]] = []

    def verify(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(kwargs)
        if self.failure:
            raise self.failure
        return self.response or {
            "SignatureValid": True,
            "KeyId": KEY_ARN,
            "SigningAlgorithm": "ECDSA_SHA_256",
            "ResponseMetadata": {"RequestId": "kms-verify-request"},
        }


class FakeCloudTrail:
    def __init__(
        self,
        events: list[dict[str, object]] | None = None,
        failure: Exception | None = None,
    ):
        self.events = events
        self.failure = failure

    def lookup_events(self, **kwargs: object) -> dict[str, object]:
        if self.failure:
            raise self.failure
        return {"Events": self.events if self.events is not None else [_cloudtrail_event()]}


def _cloudtrail_event() -> dict[str, object]:
    event_time = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
    raw = {
        "eventVersion": "1.09",
        "userIdentity": {
            "type": "AssumedRole",
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/security-owner/session",
            "sessionContext": {
                "sessionIssuer": {"arn": ROLE_ARN},
            },
            "onBehalfOf": {
                "userId": "44444444-4444-4444-8444-444444444444",
                "identityStoreArn": IDENTITY_STORE,
            },
        },
        "eventTime": event_time.isoformat().replace("+00:00", "Z"),
        "eventSource": "kms.amazonaws.com",
        "eventName": "Sign",
        "eventCategory": "Management",
        "awsRegion": REGION,
        "requestParameters": {
            "messageType": "DIGEST",
            "signingAlgorithm": "ECDSA_SHA_256",
        },
        "requestID": str(REQUEST_ID),
        "eventID": str(EVENT_ID),
        "recipientAccountId": ACCOUNT,
        "resources": [{"ARN": KEY_ARN, "type": "AWS::KMS::Key"}],
    }
    return {
        "EventId": str(EVENT_ID),
        "EventName": "Sign",
        "EventTime": event_time,
        "CloudTrailEvent": json.dumps(raw),
    }


def test_kms_verify_and_cloudtrail_lookup_return_bounded_receipts() -> None:
    kms = FakeKms()
    provider = AwsEvidenceProvider(kms, FakeCloudTrail())
    result = provider.verify_digest(
        key_arn=KEY_ARN,
        digest=b"a" * 32,
        signature=b"signature",
        signing_algorithm="ECDSA_SHA_256",
    )
    assert result.signature_valid is True
    assert result.verification_request_id == "kms-verify-request"
    assert kms.calls[0]["MessageType"] == "DIGEST"

    event = provider.lookup_kms_sign_event(
        str(EVENT_ID), account_id=ACCOUNT, region=REGION
    )
    assert event.event_id == EVENT_ID
    assert event.request_id == REQUEST_ID
    assert event.principal_arn == ROLE_ARN
    assert event.identity_store_arn == IDENTITY_STORE
    assert event.event_payload_sha256 != "0" * 64


def test_cloudtrail_lookup_rejects_truncation_and_naive_time() -> None:
    class TruncatedCloudTrail:
        def lookup_events(self, **kwargs: object) -> dict[str, object]:
            return {"Events": [_cloudtrail_event()], "NextToken": "more"}

    provider = AwsEvidenceProvider(FakeKms(), TruncatedCloudTrail())
    with pytest.raises(ApprovalVerificationError, match="truncated"):
        provider.lookup_kms_sign_event(str(EVENT_ID), account_id=ACCOUNT, region=REGION)

    outer = _cloudtrail_event()
    outer["EventTime"] = datetime(2026, 8, 11, 12, 0)
    provider = AwsEvidenceProvider(FakeKms(), FakeCloudTrail([outer]))
    with pytest.raises(ApprovalVerificationError, match="timezone-aware"):
        provider.lookup_kms_sign_event(str(EVENT_ID), account_id=ACCOUNT, region=REGION)


def test_cloudtrail_lookup_binds_exact_account_and_region() -> None:
    provider = AwsEvidenceProvider(FakeKms(), FakeCloudTrail())
    with pytest.raises(ApprovalVerificationError, match="different AWS account"):
        provider.lookup_kms_sign_event(
            str(EVENT_ID), account_id="999999999999", region=REGION
        )
    with pytest.raises(ApprovalVerificationError, match="different AWS Region"):
        provider.lookup_kms_sign_event(
            str(EVENT_ID), account_id=ACCOUNT, region="us-west-2"
        )


@pytest.mark.parametrize(
    ("digest", "algorithm"),
    [(b"short", "ECDSA_SHA_256"), (b"a" * 32, "RSASSA_PSS_SHA_256")],
)
def test_kms_verify_rejects_wrong_profile(digest: bytes, algorithm: str) -> None:
    provider = AwsEvidenceProvider(FakeKms(), FakeCloudTrail())
    with pytest.raises(ApprovalVerificationError, match="profile"):
        provider.verify_digest(
            key_arn=KEY_ARN,
            digest=digest,
            signature=b"signature",
            signing_algorithm=algorithm,
        )


def test_kms_and_cloudtrail_provider_failures_are_closed() -> None:
    provider = AwsEvidenceProvider(FakeKms(failure=RuntimeError("offline")), FakeCloudTrail())
    with pytest.raises(ApprovalVerificationError, match="unavailable or rejected"):
        provider.verify_digest(
            key_arn=KEY_ARN,
            digest=b"a" * 32,
            signature=b"signature",
            signing_algorithm="ECDSA_SHA_256",
        )
    provider = AwsEvidenceProvider(FakeKms(), FakeCloudTrail(events=[]))
    with pytest.raises(ApprovalVerificationError, match="missing or ambiguous"):
        provider.lookup_kms_sign_event(str(EVENT_ID), account_id=ACCOUNT, region=REGION)


def test_cloudtrail_requires_identity_enhancement_and_exact_event() -> None:
    item = _cloudtrail_event()
    raw = json.loads(str(item["CloudTrailEvent"]))
    del raw["userIdentity"]["onBehalfOf"]
    item["CloudTrailEvent"] = json.dumps(raw)
    provider = AwsEvidenceProvider(FakeKms(), FakeCloudTrail(events=[item]))
    with pytest.raises(ApprovalVerificationError, match="Identity Center attribution"):
        provider.lookup_kms_sign_event(str(EVENT_ID), account_id=ACCOUNT, region=REGION)

    item = _cloudtrail_event()
    item["EventId"] = str(UUID("55555555-5555-4555-8555-555555555555"))
    provider = AwsEvidenceProvider(FakeKms(), FakeCloudTrail(events=[item]))
    with pytest.raises(ApprovalVerificationError, match="different event ID"):
        provider.lookup_kms_sign_event(str(EVENT_ID), account_id=ACCOUNT, region=REGION)


def test_router_requires_exact_account_and_region() -> None:
    provider = AwsEvidenceProvider(FakeKms(), FakeCloudTrail())
    router = AwsEvidenceRouter({(ACCOUNT, REGION): provider})
    assert router.verify_digest(
        key_arn=KEY_ARN,
        digest=b"a" * 32,
        signature=b"signature",
        signing_algorithm="ECDSA_SHA_256",
    ).signature_valid
    assert router.lookup_kms_sign_event(
        str(EVENT_ID), account_id=ACCOUNT, region=REGION
    ).event_id == EVENT_ID
    with pytest.raises(ApprovalVerificationError, match="exact account and region"):
        router.lookup_kms_sign_event(str(EVENT_ID))
    with pytest.raises(ApprovalVerificationError, match="no exact AWS route"):
        router.lookup_kms_sign_event(
            str(EVENT_ID), account_id="999999999999", region=REGION
        )
    with pytest.raises(ApprovalVerificationError, match="cannot be routed"):
        router.verify_digest(
            key_arn="not-an-arn",
            digest=b"a" * 32,
            signature=b"signature",
            signing_algorithm="ECDSA_SHA_256",
        )


def test_kms_verify_rejects_incomplete_receipt() -> None:
    provider = AwsEvidenceProvider(
        FakeKms(response={"SignatureValid": True, "KeyId": KEY_ARN}),
        FakeCloudTrail(),
    )
    with pytest.raises(ApprovalVerificationError, match="incomplete receipt"):
        provider.verify_digest(
            key_arn=KEY_ARN,
            digest=b"a" * 32,
            signature=b"signature",
            signing_algorithm="ECDSA_SHA_256",
        )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda raw, outer: raw.update(errorCode="AccessDenied"), "provider failure"),
        (lambda raw, outer: raw.update(resources=[]), "ambiguous KMS resource"),
        (lambda raw, outer: raw.update(userIdentity={}), "Identity Center attribution"),
        (lambda raw, outer: raw.update(requestParameters=[]), "fields are incomplete"),
        (lambda raw, outer: raw.update(eventTime="not-a-time"), "time is malformed"),
        (lambda raw, outer: raw.update(requestID="not-a-uuid"), "schema validation"),
    ],
)
def test_cloudtrail_malformed_or_failed_events_are_rejected(
    mutate, message: str
) -> None:
    outer = _cloudtrail_event()
    raw = json.loads(str(outer["CloudTrailEvent"]))
    mutate(raw, outer)
    if "eventTime" in raw:
        outer.pop("EventTime", None)
    outer["CloudTrailEvent"] = json.dumps(raw)
    provider = AwsEvidenceProvider(FakeKms(), FakeCloudTrail(events=[outer]))

    with pytest.raises(ApprovalVerificationError, match=message):
        provider.lookup_kms_sign_event(str(EVENT_ID), account_id=ACCOUNT, region=REGION)


def test_cloudtrail_rejects_invalid_event_id_and_transport_failure() -> None:
    provider = AwsEvidenceProvider(FakeKms(), FakeCloudTrail())
    with pytest.raises(ApprovalVerificationError, match="event ID is invalid"):
        provider.lookup_kms_sign_event("not-a-uuid")

    provider = AwsEvidenceProvider(
        FakeKms(), FakeCloudTrail(failure=RuntimeError("offline"))
    )
    with pytest.raises(ApprovalVerificationError, match="lookup was unavailable"):
        provider.lookup_kms_sign_event(str(EVENT_ID), account_id=ACCOUNT, region=REGION)


class FakeProviderRoute:
    def __init__(self) -> None:
        self.verify_calls = 0
        self.lookup_calls = 0

    def verify_digest(self, **kwargs: object):
        self.verify_calls += 1
        return "verified"

    def lookup_kms_sign_event(self, event_id: str, **kwargs: object):
        self.lookup_calls += 1
        return "event"


def test_router_dispatches_only_to_exact_route() -> None:
    provider = FakeProviderRoute()
    router = AwsEvidenceRouter({(ACCOUNT, REGION): provider})

    assert router.verify_digest(
        key_arn=KEY_ARN,
        digest=b"a" * 32,
        signature=b"signature",
        signing_algorithm="ECDSA_SHA_256",
    ) == "verified"
    assert router.lookup_kms_sign_event(
        str(EVENT_ID), account_id=ACCOUNT, region=REGION
    ) == "event"
    assert provider.verify_calls == 1
    assert provider.lookup_calls == 1


def test_from_boto3_builds_bounded_provider_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import boto3

    clients: list[str] = []

    class Session:
        def __init__(self, **kwargs: object) -> None:
            assert kwargs == {"region_name": REGION}

        def client(self, name: str, **kwargs: object) -> str:
            clients.append(name)
            return name

    monkeypatch.setattr(boto3.session, "Session", Session)
    provider = AwsEvidenceProvider.from_boto3(region_name=REGION)

    assert provider.kms_client == "kms"
    assert provider.cloudtrail_client == "cloudtrail"
    assert clients == ["kms", "cloudtrail"]


def test_router_from_boto3_assumes_exact_route_and_checks_account(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import boto3

    route = AwsEvidenceRoute(
        account_id=ACCOUNT,
        region=REGION,
        reader_role_arn=f"arn:aws:iam::{ACCOUNT}:role/evidence-reader",
        external_id="external-evidence-id",
    )
    assume_calls: list[dict[str, object]] = []

    class Client:
        def __init__(self, name: str, account: str = ACCOUNT) -> None:
            self.name = name
            self.account = account

        def assume_role(self, **kwargs: object) -> dict[str, object]:
            assume_calls.append(kwargs)
            return {
                "Credentials": {
                    "AccessKeyId": "access",
                    "SecretAccessKey": "secret",
                    "SessionToken": "token",
                }
            }

        def get_caller_identity(self) -> dict[str, str]:
            return {"Account": self.account}

    class Session:
        def __init__(self, **kwargs: object) -> None:
            self.assumed = bool(kwargs)

        def client(self, name: str, **kwargs: object) -> Client:
            return Client(name)

    monkeypatch.setattr(boto3.session, "Session", Session)
    router = AwsEvidenceRouter.from_boto3({(ACCOUNT, REGION): route})

    assert (ACCOUNT, REGION) in router.providers
    assert assume_calls == [
        {
            "RoleArn": route.reader_role_arn,
            "RoleSessionName": "safe-qa-evidence-reader",
            "DurationSeconds": 900,
            "ExternalId": "external-evidence-id",
        }
    ]
