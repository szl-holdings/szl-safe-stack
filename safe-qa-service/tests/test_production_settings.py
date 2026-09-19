from __future__ import annotations

import json

import pytest

from safe_qa_service.production_settings import (
    load_approval_runtime_config,
    load_aws_evidence_routes,
)
from safe_qa_service.schemas.v2 import ApprovalRole
from safe_qa_service.settings import ConfigurationError

PRODUCTION_ACCOUNT = "999999999999"
REGION = "us-east-1"


def _key(account: str, marker: str) -> str:
    return (
        f"arn:aws:kms:{REGION}:{account}:key/"
        f"{marker * 8}-{marker * 4}-4{marker * 3}-8{marker * 3}-{marker * 12}"
    )


def _signer(account: str, marker: str, user_id: str) -> dict[str, str]:
    return {
        "key_arn": _key(account, marker),
        "identity_store_arn": (
            f"arn:aws:identitystore::{account}:identitystore/d-{marker * 10}"
        ),
        "identity_center_user_id": user_id,
        "principal_arn": f"arn:aws:iam::{account}:role/{marker}-signer",
    }


def _approval_config() -> dict[str, object]:
    return {
        "schema_version": "2.0",
        "production_account_id": PRODUCTION_ACCOUNT,
        "security_owner": _signer(
            PRODUCTION_ACCOUNT, "a", "01234567-89ab-4cde-8fab-0123456789ab"
        ),
        "release_owner": _signer(
            PRODUCTION_ACCOUNT, "b", "11234567-89ab-4cde-8fab-0123456789ab"
        ),
        "witness": _signer(
            "333333333333", "c", "21234567-89ab-4cde-8fab-0123456789ab"
        ),
    }


def test_approval_policy_parses_exact_distinct_authorities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SAFE_QA_APPROVAL_POLICY_JSON", json.dumps(_approval_config()))

    result = load_approval_runtime_config()

    assert result.production_account_id == PRODUCTION_ACCOUNT
    assert set(result.approvers) == {
        ApprovalRole.SECURITY_OWNER,
        ApprovalRole.RELEASE_OWNER,
    }
    assert result.approvers[ApprovalRole.SECURITY_OWNER].role is ApprovalRole.SECURITY_OWNER
    assert result.witness.role is None
    assert len(set(result.key_arns)) == 3


@pytest.mark.parametrize("raw", [None, "{", "{}"])
def test_approval_policy_absent_malformed_or_incomplete_fails_closed(
    monkeypatch: pytest.MonkeyPatch, raw: str | None
) -> None:
    if raw is None:
        monkeypatch.delenv("SAFE_QA_APPROVAL_POLICY_JSON", raising=False)
    else:
        monkeypatch.setenv("SAFE_QA_APPROVAL_POLICY_JSON", raw)

    with pytest.raises(ConfigurationError):
        load_approval_runtime_config()


@pytest.mark.parametrize("collision", ["human", "key", "witness-account"])
def test_approval_policy_rejects_non_independent_authorities(
    monkeypatch: pytest.MonkeyPatch, collision: str
) -> None:
    config = _approval_config()
    if collision == "human":
        config["release_owner"]["identity_store_arn"] = config["security_owner"][
            "identity_store_arn"
        ]
        config["release_owner"]["identity_center_user_id"] = config["security_owner"][
            "identity_center_user_id"
        ]
    elif collision == "key":
        config["release_owner"]["key_arn"] = config["security_owner"]["key_arn"]
    else:
        config["witness"] = _signer(
            PRODUCTION_ACCOUNT, "d", "31234567-89ab-4cde-8fab-0123456789ab"
        )
    monkeypatch.setenv("SAFE_QA_APPROVAL_POLICY_JSON", json.dumps(config))

    with pytest.raises(ConfigurationError, match="failed validation"):
        load_approval_runtime_config()


def _routes() -> list[dict[str, str | None]]:
    return [
        {
            "account_id": PRODUCTION_ACCOUNT,
            "region": REGION,
            "reader_role_arn": None,
            "external_id": None,
        },
        {
            "account_id": "333333333333",
            "region": REGION,
            "reader_role_arn": "arn:aws:iam::333333333333:role/evidence-reader",
            "external_id": "external-333333333333",
        },
    ]


def test_evidence_routes_cover_every_key_and_preserve_external_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _approval_config()
    keys = tuple(config[name]["key_arn"] for name in ("security_owner", "release_owner", "witness"))
    monkeypatch.setenv("SAFE_QA_AWS_EVIDENCE_ROUTES_JSON", json.dumps(_routes()))

    result = load_aws_evidence_routes(keys)

    assert set(result) == {
        (PRODUCTION_ACCOUNT, REGION),
        ("333333333333", REGION),
    }
    assert result[(PRODUCTION_ACCOUNT, REGION)].reader_role_arn is None
    assert result[("333333333333", REGION)].external_id == "external-333333333333"


def test_evidence_routes_reject_duplicate_wrong_account_and_missing_coverage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = (_key(PRODUCTION_ACCOUNT, "a"), _key("333333333333", "b"))
    routes = _routes()
    routes.append(dict(routes[0]))
    monkeypatch.setenv("SAFE_QA_AWS_EVIDENCE_ROUTES_JSON", json.dumps(routes))
    with pytest.raises(ConfigurationError, match="duplicate"):
        load_aws_evidence_routes(keys)

    routes = _routes()
    routes[1]["reader_role_arn"] = "arn:aws:iam::444444444444:role/evidence-reader"
    monkeypatch.setenv("SAFE_QA_AWS_EVIDENCE_ROUTES_JSON", json.dumps(routes))
    with pytest.raises(ConfigurationError, match="failed validation"):
        load_aws_evidence_routes(keys)

    monkeypatch.setenv("SAFE_QA_AWS_EVIDENCE_ROUTES_JSON", json.dumps(routes[:1]))
    with pytest.raises(ConfigurationError, match="do not cover"):
        load_aws_evidence_routes(keys)
