"""Independent contract oracles for synthetic scoring and its audit boundary."""

from __future__ import annotations

import hashlib
import json
import random
from fractions import Fraction

import pytest

from safe_qa_service.app import app
from safe_qa_service.auth import Principal, authenticate
from safe_qa_service.synthetic_kernel import SyntheticRequest, evaluate_synthetic

ENDPOINT = "/api/v1/synthetic/evaluations"


def request_document(**changes):
    return {
        "schema_version": "synthetic-software-qa/1",
        "kind": "synthetic_software_qa",
        "case_id": "independent-fixture",
        "sample_scores_ppm": [900_000, 950_000, 1_000_000],
        "mode": "defensive",
        **changes,
    }


def independent_digest(document):
    # Serialize plain recorded data, without model_dump or a production hash helper.
    serialized = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def authentication_dependency(principal):
    return lambda: principal


def assert_independent_outcome(document, outcome):
    samples = document["sample_scores_ppm"]
    score = sum((Fraction(value, 1_000_000) for value in samples), Fraction()) / len(samples)
    if len(samples) > 3:
        expected_route = "STEP_BUDGET_REJECTED"
    elif score >= Fraction(95, 100):
        expected_route = "SELF_REPORTED_THRESHOLD_MET"
    else:
        expected_route = "REVIEW_REQUIRED"
    expected_priority = (
        "elevated"
        if expected_route == "REVIEW_REQUIRED" and document["mode"] == "adaptive_review"
        else "normal"
    )
    assert outcome["case_id"] == document["case_id"]
    assert Fraction(outcome["score_numerator"], outcome["score_denominator"]) == score
    assert outcome["steps_used"] == len(samples)
    assert outcome["step_budget"] == 3
    assert outcome["threshold_ppm"] == 950_000
    assert outcome["routing_status"] == expected_route
    assert outcome["review_priority"] == expected_priority
    assert outcome["input_sha256"] == independent_digest(document)
    assert outcome["release_authorized"] is False
    assert outcome["evidence_verified"] is False
    assert outcome["simulation_only"] is True
    assert outcome["metadata_provenance"] == "unverified_caller_supplied"


def test_seeded_10000_cases_against_fraction_oracle():
    generator = random.Random(19_731_007)
    checked = 0
    for count in range(1, 101):
        for case_index in range(100):
            if case_index == 0:
                samples = [950_000] * count
            elif case_index == 1:
                samples = [950_000] * (count - 1) + [949_999]
            elif case_index == 2:
                samples = [1_000_000] * count
            elif case_index == 3:
                samples = [0] * count
            else:
                samples = [generator.randrange(1_000_001) for _ in range(count)]
            results = []
            for mode in ("defensive", "adaptive_review"):
                document = request_document(sample_scores_ppm=samples, mode=mode)
                result = evaluate_synthetic(SyntheticRequest(**document)).model_dump(mode="json")
                assert_independent_outcome(document, result)
                results.append(result)
            assert results[0]["routing_status"] == results[1]["routing_status"]
            assert results[0]["score_numerator"] == results[1]["score_numerator"]
            assert results[0]["score_denominator"] == results[1]["score_denominator"]
            assert results[0]["input_sha256"] != results[1]["input_sha256"]
            checked += 1
    assert checked == 10_000


def test_known_canonical_request_bytes_and_default_equivalence():
    canonical = (
        b'{"case_id":"independent-fixture","kind":"synthetic_software_qa",'
        b'"mode":"defensive","sample_scores_ppm":[900000,950000,1000000],'
        b'"schema_version":"synthetic-software-qa/1"}'
    )
    expected_hash = hashlib.sha256(canonical).hexdigest()
    explicit = request_document()
    implicit = {
        key: value for key, value in reversed(list(explicit.items()))
        if key not in {"mode", "schema_version"}
    }
    assert independent_digest(explicit) == expected_hash
    for document in (explicit, implicit):
        outcome = evaluate_synthetic(SyntheticRequest(**document))
        assert outcome.input_sha256 == expected_hash


@pytest.mark.parametrize("changes", [
    {"case_id": "different-fixture"},
    {"mode": "adaptive_review"},
    {"sample_scores_ppm": [1_000_000, 950_000, 900_000]},
    {"sample_scores_ppm": [900_001, 950_000, 1_000_000]},
])
def test_digest_binds_each_variable_request_field(changes):
    original = request_document()
    changed = request_document(**changes)
    original_hash = evaluate_synthetic(SyntheticRequest(**original)).input_sha256
    changed_hash = evaluate_synthetic(SyntheticRequest(**changed)).input_sha256
    assert original_hash == independent_digest(original)
    assert changed_hash == independent_digest(changed)
    assert changed_hash != original_hash


@pytest.mark.parametrize("samples,mode", [
    ([900_000, 950_000, 1_000_000], "defensive"),
    ([950_000, 950_000, 949_999], "adaptive_review"),
    ([1_000_000] * 4, "adaptive_review"),
])
def test_audit_request_independently_replays_result_and_digest(
    client, auth_headers, fake_ledger, samples, mode,
):
    document = request_document(sample_scores_ppm=samples, mode=mode)
    response = client.post(ENDPOINT, json=document, headers=auth_headers)
    assert response.status_code == 202
    assert len(fake_ledger.events) == 1
    event = fake_ledger.events[0]
    payload = event["payload"]
    assert payload["request"] == document
    # This replay oracle does not call evaluate_synthetic on the recorded request.
    assert_independent_outcome(payload["request"], payload["outcome"])
    assert response.json().items() >= payload["outcome"].items()
    assert response.json()["request_id"] == str(event["request_id"])
    assert event["action"] == "synthetic-software-qa.routed"
    assert event["actor_subject"] == payload["auth"]["subject"] == "test-principal"
    assert payload["auth"]["issuer"] == "local-static"
    assert "authorization" not in payload["auth"]
    assert "token" not in payload["auth"]


@pytest.mark.parametrize("scopes", [frozenset(), frozenset({"audit:read"})])
def test_missing_evaluate_scope_rejected_without_ledger_write(client, fake_ledger, scopes):
    principal = Principal(
        subject="audit-only", scopes=scopes, token_fingerprint="a" * 12,
    )
    app.dependency_overrides[authenticate] = lambda: principal
    response = client.post(ENDPOINT, json=request_document())
    assert response.status_code == 403
    assert response.json()["detail"]["missing_scopes"] == ["evaluate"]
    assert not fake_ledger.events


def test_same_subject_from_different_issuers_preserves_audit_attribution(client, fake_ledger):
    principals = [
        Principal(
            subject="shared-subject", scopes=frozenset({"evaluate"}),
            token_fingerprint="1" * 12, issuer="https://issuer-one.example",
            principal_type="human",
        ),
        Principal(
            subject="shared-subject", scopes=frozenset({"evaluate"}),
            token_fingerprint="2" * 12, issuer="https://issuer-two.example",
            principal_type="workload",
        ),
    ]
    for principal in principals:
        app.dependency_overrides[authenticate] = authentication_dependency(principal)
        response = client.post(ENDPOINT, json=request_document())
        assert response.status_code == 202
    assert len(fake_ledger.events) == 2
    for event, principal in zip(fake_ledger.events, principals, strict=True):
        assert event["actor_subject"] == "shared-subject"
        assert event["payload"]["auth"] == {
            "issuer": principal.issuer,
            "subject": principal.subject,
            "principal_type": principal.principal_type,
            "token_fingerprint": principal.token_fingerprint,
        }
    first, second = [event["payload"] for event in fake_ledger.events]
    assert first["request"] == second["request"]
    assert first["outcome"] == second["outcome"]
    assert first["auth"] != second["auth"]
