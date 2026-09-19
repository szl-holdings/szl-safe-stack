from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
from pydantic import ValidationError

from safe_qa_service.app import app, get_ledger
from safe_qa_service.ledger import LedgerUnavailable
from safe_qa_service.synthetic_kernel import SyntheticRequest, evaluate_synthetic


def fixture(**changes):
    return {
        "kind": "synthetic_software_qa",
        "case_id": "fixture-001",
        "sample_scores_ppm": [800_000, 750_000, 650_000],
        **changes,
    }


@pytest.mark.parametrize("mode", ["defensive", "adaptive_review"])
def test_original_fail_open_regression(mode):
    result = evaluate_synthetic(SyntheticRequest(**fixture(mode=mode)))
    assert result.routing_status == "REVIEW_REQUIRED"
    assert result.score_numerator == 2_200_000
    assert result.score_denominator == 3_000_000
    assert result.release_authorized is False
    assert result.evidence_verified is False


@pytest.mark.parametrize(
    ("scores", "route"),
    [
        ([949_999], "REVIEW_REQUIRED"),
        ([950_000], "SELF_REPORTED_THRESHOLD_MET"),
        ([950_000, 950_000, 949_999], "REVIEW_REQUIRED"),
        ([1_000_000] * 4, "STEP_BUDGET_REJECTED"),
        ([0] * 4, "STEP_BUDGET_REJECTED"),
    ],
)
def test_exact_boundary_and_every_step_consumes_budget(scores, route):
    result = evaluate_synthetic(SyntheticRequest(**fixture(sample_scores_ppm=scores)))
    assert result.routing_status == route
    assert result.release_authorized is False


@pytest.mark.parametrize(
    "changes",
    [
        {"sample_scores_ppm": []}, {"sample_scores_ppm": [True]},
        {"sample_scores_ppm": ["950000"]}, {"sample_scores_ppm": [950000.0]},
        {"sample_scores_ppm": [-1]}, {"sample_scores_ppm": [1_000_001]},
        {"sample_scores_ppm": [float("nan")]},
        {"sample_scores_ppm": [float("inf")]},
        {"sample_scores_ppm": [0] * 101}, {"threshold_ppm": 0},
        {"release_authorized": True}, {"proposed_decision": "approved"},
        {"kind": "external_system"}, {"mode": "approve"},
    ],
)
def test_untrusted_inputs_rejected(changes):
    with pytest.raises(ValidationError):
        SyntheticRequest(**fixture(**changes))


def test_monotonic_mode_independent_routing_and_concurrent_isolation():
    inputs = [
        SyntheticRequest(**fixture(sample_scores_ppm=[score], mode=mode))
        for score in range(900_000, 1_000_001, 1000)
        for mode in ("defensive", "adaptive_review")
    ]
    expected = [evaluate_synthetic(item).model_dump() for item in inputs]
    with ThreadPoolExecutor(max_workers=8) as executor:
        observed = [item.model_dump() for item in executor.map(evaluate_synthetic, inputs)]
    assert observed == expected
    for index in range(0, len(expected), 2):
        left, right = expected[index:index + 2]
        assert left["routing_status"] == right["routing_status"]
        assert left["score_numerator"] == right["score_numerator"]
        assert left["release_authorized"] is right["release_authorized"] is False
    ranks = {"REVIEW_REQUIRED": 0, "SELF_REPORTED_THRESHOLD_MET": 1}
    ranking = [ranks[row["routing_status"]] for row in expected[::2]]
    assert ranking == sorted(ranking)


def test_authenticated_api_records_bound_result(client, auth_headers, fake_ledger):
    response = client.post("/api/v1/synthetic/evaluations", json=fixture(), headers=auth_headers)
    assert response.status_code == 202
    body = response.json()
    assert body["release_authorized"] is False
    assert body["routing_status"] == "REVIEW_REQUIRED"
    assert len(body["input_sha256"]) == len(body["implementation_sha256"]) == 64
    payload = fake_ledger.events[0]["payload"]
    assert payload["outcome"]["input_sha256"] == body["input_sha256"]
    replay = evaluate_synthetic(SyntheticRequest(**payload["request"]))
    assert replay.model_dump(mode="json") == payload["outcome"]
    assert payload["auth"]["subject"] == "test-principal"
    assert "issuer" in payload["auth"]
    assert client.post("/api/v1/synthetic/evaluations", json=fixture()).status_code == 401


def test_missing_ledger_returns_no_result(client, auth_headers):
    class FailedLedger:
        def append(self, **_event):
            raise LedgerUnavailable("unavailable")
    app.dependency_overrides[get_ledger] = FailedLedger
    response = client.post("/api/v1/synthetic/evaluations", json=fixture(), headers=auth_headers)
    assert response.status_code == 503
    assert "score_numerator" not in response.json()
