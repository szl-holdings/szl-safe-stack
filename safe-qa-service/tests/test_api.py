from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

from fastapi.testclient import TestClient

from safe_qa_service.app import app, get_ledger
from safe_qa_service.ledger import LedgerUnavailable


def _request_body() -> dict:
    return {
        "schema_version": "1.0",
        "trace_id": "OB-ROCHE-001",
        "domain": "clinical",
        "proposed_decision": "Negative",
        "claims": ["diagnostic result is correct"],
        "evidence": [
            {
                "evidence_id": "source-1",
                "kind": "caller-output",
                "sha256": "c" * 64,
                "metadata_provenance": "unverified_caller_supplied",
            }
        ],
    }


def test_evaluation_is_withheld_and_audited(
    client: TestClient, auth_headers: dict[str, str], fake_ledger
) -> None:
    response = client.post("/api/v1/evaluations", headers=auth_headers, json=_request_body())

    assert response.status_code == 202
    body = response.json()
    assert body["disposition"] == "WITHHOLD_PENDING_EVIDENCE_AND_APPROVALS"
    assert body["release_authorized"] is False
    assert body["simulation_only"] is True
    assert body["clinical_claim_verified"] is False
    assert body["biological_claim_verified"] is False
    assert body["evidence_status"] == "UNVERIFIED_CALLER_SUPPLIED"
    assert body["approval_status"] == "NOT_GRANTED"
    assert "clinical_validation_authority" in body["required_approvals"]
    assert len(fake_ledger.events) == 1
    assert fake_ledger.events[0]["action"] == "evaluation.withheld"
    assert fake_ledger.events[0]["payload"]["policy"]["release_authorized"] is False


def test_caller_cannot_inject_approvals(client: TestClient, auth_headers: dict[str, str]) -> None:
    request = _request_body()
    request["approvals"] = [{"status": "APPROVED"}]
    response = client.post("/api/v1/evaluations", headers=auth_headers, json=request)
    assert response.status_code == 422


def test_authentication_is_mandatory(client: TestClient) -> None:
    response = client.post("/api/v1/evaluations", json=_request_body())
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_invalid_token_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/v1/evaluations",
        headers={"Authorization": "Bearer wrong-token"},
        json=_request_body(),
    )
    assert response.status_code == 401


def test_malformed_authorization_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/v1/evaluations",
        headers={"Authorization": "Basic value"},
        json=_request_body(),
    )
    assert response.status_code == 401


def test_unconfigured_authentication_fails_closed(client: TestClient, monkeypatch) -> None:
    monkeypatch.delenv("SAFE_QA_AUTH_TOKEN_HASHES_JSON")
    response = client.post(
        "/api/v1/evaluations",
        headers={"Authorization": "Bearer anything"},
        json=_request_body(),
    )
    assert response.status_code == 503


def test_scope_is_enforced(client: TestClient, monkeypatch) -> None:
    token = "audit-only"
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    monkeypatch.setenv(
        "SAFE_QA_AUTH_TOKEN_HASHES_JSON",
        json.dumps({token_hash: {"subject": "auditor", "scopes": ["audit:read"]}}),
    )
    response = client.post(
        "/api/v1/evaluations",
        headers={"Authorization": f"Bearer {token}"},
        json=_request_body(),
    )
    assert response.status_code == 403


def test_mandatory_ledger_failure_returns_no_decision(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    class FailingLedger:
        def append(self, **_event):
            raise LedgerUnavailable("database unavailable")

    app.dependency_overrides[get_ledger] = FailingLedger
    response = client.post("/api/v1/evaluations", headers=auth_headers, json=_request_body())
    assert response.status_code == 503
    assert "withheld" in response.json()["detail"]


def test_versioned_schemas_publish_truth_boundary(client: TestClient) -> None:
    request_schema = client.get("/api/v1/schemas/evaluation-request")
    response_schema = client.get("/api/v1/schemas/evaluation-response")

    assert request_schema.status_code == 200
    assert response_schema.status_code == 200
    assert request_schema.json()["$id"].endswith("/v1/evaluation-request.json")
    assert response_schema.json()["$id"].endswith("/v1/evaluation-response.json")
    assert response_schema.json()["x-release-semantics"].startswith("This schema cannot")


def test_ledger_verification_requires_scope_and_returns_result(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    unauthorized = client.get("/api/v1/audit/verify")
    authorized = client.get("/api/v1/audit/verify", headers=auth_headers)
    assert unauthorized.status_code == 401
    assert authorized.status_code == 200
    assert authorized.json() == {
        "valid": True,
        "event_count": 0,
        "first_invalid_sequence": None,
    }


def test_ledger_verification_failure_is_fail_closed(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    class FailingLedger:
        def verify_chain(self):
            raise LedgerUnavailable("database unavailable")

    app.dependency_overrides[get_ledger] = FailingLedger
    response = client.get("/api/v1/audit/verify", headers=auth_headers)
    assert response.status_code == 503


def test_liveness_is_process_only(client: TestClient) -> None:
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "live"}


def test_readiness_fails_when_database_is_not_configured(client: TestClient) -> None:
    response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json()["checks"] == {
        "postgres_schema": False,
        "postgres_audit_head": False,
        "control_audit_outbox_drained": False,
    }
    assert response.json()["audit_outbox"] == {
        "pending_count": -1,
        "oldest_pending_age_seconds": -1.0,
    }


def test_readiness_passes_only_with_ledger(monkeypatch, client: TestClient) -> None:
    class HealthyLedger:
        def __init__(self, _url: str) -> None:
            pass

        def healthcheck(self) -> bool:
            return True

        def verify_head(self) -> bool:
            return True

    monkeypatch.setenv("DATABASE_URL", "postgresql://db.example.invalid/safeqa")
    monkeypatch.setattr("safe_qa_service.app.PostgresAuditLedger", HealthyLedger)
    monkeypatch.setattr(
        "safe_qa_service.app.audit_outbox_readiness",
        lambda **_kwargs: (
            True,
            SimpleNamespace(pending_count=0, oldest_pending_age_seconds=0.0),
        ),
    )
    response = client.get("/health/ready")
    assert response.status_code == 200
    assert response.json()["checks"] == {
        "postgres_schema": True,
        "postgres_audit_head": True,
        "control_audit_outbox_drained": True,
    }
    assert response.json()["audit_outbox"] == {
        "pending_count": 0,
        "oldest_pending_age_seconds": 0.0,
    }


def test_declared_oversized_request_is_rejected_before_authentication(
    client: TestClient,
) -> None:
    response = client.post(
        "/api/v1/evaluations",
        headers={"Content-Length": "512001"},
        content=b"{}",
    )
    assert response.status_code == 413
