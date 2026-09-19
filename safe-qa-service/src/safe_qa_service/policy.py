"""Non-overridable fail-closed policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass

from .schemas.v1 import Domain, EvaluationRequest, EvidenceStatus

BASE_APPROVALS = (
    "independent_evidence_reviewer",
    "security_owner",
    "safety_owner",
    "service_owner",
)

DOMAIN_APPROVALS = {
    Domain.GENERAL: (),
    Domain.CLINICAL: (
        "clinical_validation_authority",
        "regulatory_quality_authority",
    ),
    Domain.BIOLOGICAL: (
        "institutional_biosafety_authority",
        "regulatory_quality_authority",
    ),
}


@dataclass(frozen=True)
class PolicyOutcome:
    evidence_status: EvidenceStatus
    required_approvals: tuple[str, ...]
    unverified_claims: tuple[str, ...]
    decision_reason: str


def evaluate(request: EvaluationRequest) -> PolicyOutcome:
    """Classify intake only; no request can authorize a clinical or biological release."""
    evidence_status = (
        EvidenceStatus.UNVERIFIED_CALLER_SUPPLIED if request.evidence else EvidenceStatus.MISSING
    )
    required = BASE_APPROVALS + DOMAIN_APPROVALS[request.domain]
    proposed_note = (
        " A caller-proposed decision was recorded as unverified input and was not applied."
        if request.proposed_decision
        else ""
    )
    return PolicyOutcome(
        evidence_status=evidence_status,
        required_approvals=required,
        unverified_claims=tuple(request.claims),
        decision_reason=(
            "Release is withheld because this service cannot independently validate evidence or "
            "grant human approvals." + proposed_note
        ),
    )
