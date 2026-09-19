from __future__ import annotations

import pytest

from safe_qa_service.policy import evaluate
from safe_qa_service.schemas.v1 import Domain, EvaluationRequest, EvidenceItem, EvidenceStatus


@pytest.mark.parametrize("domain", list(Domain))
def test_policy_never_authorizes_or_verifies(domain: Domain) -> None:
    request = EvaluationRequest(
        trace_id="trace-1",
        domain=domain,
        proposed_decision="Release_Result",
        claims=["caller says this is valid"],
        evidence=[
            EvidenceItem(
                evidence_id="ev-1",
                kind="caller-attachment",
                sha256="b" * 64,
            )
        ],
    )

    outcome = evaluate(request)

    assert outcome.evidence_status is EvidenceStatus.UNVERIFIED_CALLER_SUPPLIED
    assert outcome.unverified_claims == ("caller says this is valid",)
    assert "was not applied" in outcome.decision_reason
    assert "service_owner" in outcome.required_approvals


def test_domain_specific_approvals_are_required() -> None:
    clinical = evaluate(EvaluationRequest(trace_id="c", domain=Domain.CLINICAL))
    biological = evaluate(EvaluationRequest(trace_id="b", domain=Domain.BIOLOGICAL))

    assert "clinical_validation_authority" in clinical.required_approvals
    assert "institutional_biosafety_authority" in biological.required_approvals


def test_absent_evidence_is_explicit() -> None:
    outcome = evaluate(EvaluationRequest(trace_id="none", domain=Domain.GENERAL))
    assert outcome.evidence_status is EvidenceStatus.MISSING
