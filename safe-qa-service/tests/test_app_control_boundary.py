from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import safe_qa_service.app as app_module
from safe_qa_service.control_plane import ControlPlane


def _configure_all_control_inputs(monkeypatch: pytest.MonkeyPatch, *, production: bool) -> None:
    monkeypatch.setenv("SAFE_QA_PRODUCTION_MODE", str(production).lower())
    monkeypatch.setenv("SAFE_QA_AUTH_MODE", "oidc")
    monkeypatch.setenv("SAFE_QA_OIDC_ISSUERS_JSON", '{"https://id.example.test": {}}')
    monkeypatch.setenv("SAFE_QA_AWS_TARGET_POLICY_JSON", '{"all_inputs": "present"}')
    monkeypatch.setenv("SAFE_QA_APPROVAL_POLICY_JSON", '{"all_inputs": "present"}')
    monkeypatch.setenv("SAFE_QA_AWS_EVIDENCE_ROUTES_JSON", '[{"all_inputs": "present"}]')


def test_all_oidc_and_provider_inputs_cannot_enable_control_when_production_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_all_control_inputs(monkeypatch, production=False)
    monkeypatch.setattr(
        app_module,
        "load_aws_target_policy",
        lambda: pytest.fail("disabled control must not parse provider targets"),
    )
    monkeypatch.setattr(
        app_module.AwsControlProvider,
        "from_runtime",
        lambda *_args, **_kwargs: pytest.fail("disabled control must not construct AWS clients"),
    )
    monkeypatch.setattr(
        app_module.AwsEvidenceRouter,
        "from_boto3",
        lambda *_args, **_kwargs: pytest.fail("disabled control must not construct AWS clients"),
    )

    with pytest.raises(HTTPException) as error:
        app_module.get_control_plane(ledger=object(), repository=object())

    assert error.value.status_code == 503
    assert error.value.detail == "production control boundary is not completely configured"


def test_production_true_constructs_test_doubles_without_external_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_all_control_inputs(monkeypatch, production=True)
    provider = object()
    evidence = object()
    routes = object()
    approval = SimpleNamespace(
        production_account_id="999999999999",
        key_arns=("key-1", "key-2", "key-3"),
        approvers={},
        witness=object(),
    )
    monkeypatch.setattr(
        app_module,
        "load_aws_target_policy",
        lambda: SimpleNamespace(account_id="999999999999"),
    )
    monkeypatch.setattr(app_module, "load_approval_runtime_config", lambda: approval)
    monkeypatch.setattr(app_module, "load_aws_evidence_routes", lambda _keys: routes)
    monkeypatch.setattr(app_module.AwsControlProvider, "from_runtime", lambda _policy: provider)
    monkeypatch.setattr(app_module.AwsEvidenceRouter, "from_boto3", lambda value: evidence)

    result = app_module.get_control_plane(ledger=object(), repository=object())

    assert isinstance(result, ControlPlane)
    assert result.provider is provider
    assert result.evidence is evidence
