"""Pure, bounded routing for synthetic software QA fixtures only.

Integer millionths avoid floating point threshold ambiguity. Caller scores are
unverified metadata, not probabilities, independent evidence or safety results.
There are no tools, model calls, external actions or authorization paths here.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictInt

Sample = Annotated[StrictInt, Field(ge=0, le=1_000_000)]
THRESHOLD_PPM = 950_000
STEP_BUDGET = 3
POLICY = json.dumps(
    {
        "version": "synthetic-software-qa/1",
        "threshold_ppm": THRESHOLD_PPM,
        "step_budget": STEP_BUDGET,
        "score": "sum(samples)/len(samples)",
        "mode_effect": "review_queue_priority_only",
        "release_authorized": False,
    },
    sort_keys=True,
    separators=(",", ":"),
)
POLICY_SHA256 = hashlib.sha256(POLICY.encode()).hexdigest()
IMPLEMENTATION_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


class SyntheticRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["synthetic-software-qa/1"] = "synthetic-software-qa/1"
    kind: Literal["synthetic_software_qa"]
    case_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    sample_scores_ppm: tuple[Sample, ...] = Field(min_length=1, max_length=100)
    mode: Literal["defensive", "adaptive_review"] = "defensive"


class SyntheticOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["synthetic-software-qa/1"] = "synthetic-software-qa/1"
    case_id: str
    score_numerator: int
    score_denominator: int
    threshold_ppm: Literal[950_000] = THRESHOLD_PPM
    steps_used: int
    step_budget: Literal[3] = STEP_BUDGET
    routing_status: Literal[
        "SELF_REPORTED_THRESHOLD_MET", "REVIEW_REQUIRED", "STEP_BUDGET_REJECTED"
    ]
    review_priority: Literal["normal", "elevated"]
    metadata_provenance: Literal["unverified_caller_supplied"] = "unverified_caller_supplied"
    evidence_verified: Literal[False] = False
    release_authorized: Literal[False] = False
    simulation_only: Literal[True] = True
    input_sha256: str
    policy_sha256: str = POLICY_SHA256
    implementation_sha256: str = IMPLEMENTATION_SHA256


class SyntheticResponse(SyntheticOutcome):
    request_id: UUID
    audit_event_id: UUID
    audit_sequence_id: int = Field(ge=1)
    audit_event_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


def evaluate_synthetic(request: SyntheticRequest) -> SyntheticOutcome:
    """A mode can change queue priority, never the score, budget or disposition."""
    count = len(request.sample_scores_ppm)
    total = sum(request.sample_scores_ppm)
    if count > STEP_BUDGET:
        route = "STEP_BUDGET_REJECTED"
    elif total >= THRESHOLD_PPM * count:
        route = "SELF_REPORTED_THRESHOLD_MET"
    else:
        route = "REVIEW_REQUIRED"
    canonical_input = json.dumps(
        request.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    ).encode()
    return SyntheticOutcome(
        case_id=request.case_id,
        score_numerator=total,
        score_denominator=count * 1_000_000,
        steps_used=count,
        routing_status=route,
        review_priority=(
            "elevated" if route == "REVIEW_REQUIRED" and request.mode == "adaptive_review"
            else "normal"
        ),
        input_sha256=hashlib.sha256(canonical_input).hexdigest(),
    )
