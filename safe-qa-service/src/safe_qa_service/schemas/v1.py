"""Version 1 API contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

SCHEMA_VERSION = "1.0"
BoundedClaim = Annotated[str, Field(min_length=1, max_length=1024)]


class Domain(StrEnum):
    GENERAL = "general"
    CLINICAL = "clinical"
    BIOLOGICAL = "biological"


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    kind: str = Field(min_length=1, max_length=80)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    uri: HttpUrl | None = None
    metadata_provenance: Literal["unverified_caller_supplied"] = "unverified_caller_supplied"


class EvaluationRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "$id": "https://schemas.example.invalid/safe-qa/v1/evaluation-request.json",
            "x-truth-boundary": "Caller input is unverified and cannot authorize release.",
        },
    )

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    trace_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    domain: Domain
    proposed_decision: str | None = Field(default=None, max_length=256)
    claims: list[BoundedClaim] = Field(default_factory=list, max_length=50)
    evidence: list[EvidenceItem] = Field(default_factory=list, max_length=100)


class EvidenceStatus(StrEnum):
    MISSING = "MISSING"
    UNVERIFIED_CALLER_SUPPLIED = "UNVERIFIED_CALLER_SUPPLIED"


class ApprovalStatus(StrEnum):
    NOT_GRANTED = "NOT_GRANTED"


class Disposition(StrEnum):
    WITHHOLD_PENDING_EVIDENCE_AND_APPROVALS = "WITHHOLD_PENDING_EVIDENCE_AND_APPROVALS"


class EvaluationResponse(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "$id": "https://schemas.example.invalid/safe-qa/v1/evaluation-response.json",
            "x-release-semantics": "This schema cannot express an authorized release.",
        },
    )

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    request_id: UUID
    trace_id: str
    disposition: Literal[Disposition.WITHHOLD_PENDING_EVIDENCE_AND_APPROVALS]
    release_authorized: Literal[False] = False
    simulation_only: Literal[True] = True
    clinical_claim_verified: Literal[False] = False
    biological_claim_verified: Literal[False] = False
    evidence_status: EvidenceStatus
    approval_status: Literal[ApprovalStatus.NOT_GRANTED] = ApprovalStatus.NOT_GRANTED
    required_approvals: list[str]
    unverified_claims: list[str]
    decision_reason: str
    audit_event_id: UUID
    audit_sequence_id: int = Field(ge=1)
    audit_event_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class LedgerVerificationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    valid: bool
    event_count: int = Field(ge=0)
    first_invalid_sequence: int | None = Field(default=None, ge=1)
