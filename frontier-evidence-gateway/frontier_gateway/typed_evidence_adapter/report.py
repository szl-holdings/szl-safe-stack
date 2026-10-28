"""Evidence report for the restricted English to inert IR adapter.

`assess` never raises on untrusted text, manifest text or source bytes. Every
contract, manifest, parse and validation failure is kept in the report, and
unmapped input yields UNTRANSLATED or ABSTAIN rather than a guessed program.

The report speaks the gateway's existing vocabulary. `gateway_artifacts` are
`szl.frontier.evidence.artifact.v1` records with allowlisted kinds and
statuses, and `gateway_request` wraps them in a provider-`none` request for the
unchanged `EvidenceEvaluator`. Deployment and model promotion stay
NOT_GRANTED, text declared as model output stays UNVERIFIED_MODEL_OUTPUT, and
no declared effect is performed here.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from ..lattice_adapter import SERIALIZATION_PROFILE, EvidenceError, sha256_json
from ..schemas import ARTIFACT_VERSION, KINDS, REQUEST_VERSION, STATUSES
from .contract import ContractError, validate_contract
from .manifest import (
    ManifestAssessment,
    ManifestError,
    assess_manifest,
    invalid_assessment,
    parse_manifest,
    parse_utc,
)
from .parser import ABSTAIN, CANDIDATE, UNTRANSLATED, ParseResult, parse
from .validator import ValidationResult, validate_ir

REPORT_SCHEMA = "szl.typed-evidence-adapter.report.v1"
TRANSLATED = "TRANSLATED"
INPUT_ORIGINS = frozenset({"OPERATOR_SUPPLIED", "MODEL_OUTPUT"})
CONTRACT_ARTIFACT_ID = "typed-ir-contract"
VALIDATION_ARTIFACT_ID = "typed-ir-validation"

_CLAIMS = {
    "semantic_equivalence": "NOT_ESTABLISHED",
    "token_or_cost_savings": "NOT_MEASURED",
    "runtime_performance": "NOT_MEASURED",
    "coverage": "RESTRICTED_GRAMMAR_ONLY",
    "rights": "CALLER_DECLARED_NOT_LICENSE_REVIEWED",
}


def _input_record(text: Any, origin: str, limit: int | None) -> dict[str, Any]:
    record: dict[str, Any] = {
        "origin": origin,
        "status": "UNVERIFIED_MODEL_OUTPUT" if origin == "MODEL_OUTPUT" else "CALLER_SUPPLIED_TEXT",
        "content_stored": False,
        "utf8_bytes": None,
        "sha256": None,
    }
    bound = limit if limit is not None else 0
    if isinstance(text, str) and len(text) <= bound:
        try:
            encoded = text.encode("utf-8")
        except UnicodeEncodeError:
            return record
        if len(encoded) <= bound:
            record["utf8_bytes"] = len(encoded)
            record["sha256"] = hashlib.sha256(encoded).hexdigest()
    return record


def _artifact(artifact_id: str, kind: str, status: str, digest: str | None) -> dict[str, Any]:
    assert kind in KINDS and status in STATUSES
    return {
        "schema_version": ARTIFACT_VERSION,
        "artifact_id": artifact_id,
        "kind": kind,
        "status": status,
        "sha256": digest if status == "VERIFIED" else None,
    }


def _source_artifact(contract_digest: str | None, manifest: ManifestAssessment, contract_ok: bool) -> dict[str, Any]:
    findings = set(manifest.findings)
    if not contract_ok or findings & {
        "MANIFEST_INVALID",
        "CONTRACT_DIGEST_MISMATCH",
        "SOURCE_DIGEST_MISMATCH",
        "SOURCE_BYTES_INVALID",
        "FUTURE_TIMESTAMP",
    }:
        return _artifact(CONTRACT_ARTIFACT_ID, "source", "FAILED", None)
    if findings & {"CONTRACT_SOURCE_MISSING", "CONTRACT_RIGHTS_NOT_ADMITTED"}:
        return _artifact(CONTRACT_ARTIFACT_ID, "source", "UNAVAILABLE", None)
    if manifest.digests_fully_checked and contract_digest is not None:
        return _artifact(CONTRACT_ARTIFACT_ID, "source", "VERIFIED", contract_digest)
    return _artifact(CONTRACT_ARTIFACT_ID, "source", "UNVERIFIED", None)


def _validation_artifact(outcome: str, validation: ValidationResult | None, ir_digest: str | None,
                         contract_digest: str | None) -> dict[str, Any]:
    if validation is not None and not validation.passed:
        return _artifact(VALIDATION_ARTIFACT_ID, "evaluation", "FAILED", None)
    if outcome == TRANSLATED and ir_digest is not None and contract_digest is not None:
        record = {
            "contract_sha256": contract_digest,
            "ir_sha256": ir_digest,
            "validation": "PASSED",
            "validator": "szl.typed-evidence-adapter.validator.v1",
        }
        return _artifact(VALIDATION_ARTIFACT_ID, "evaluation", "VERIFIED", sha256_json(record))
    return _artifact(VALIDATION_ARTIFACT_ID, "evaluation", "UNAVAILABLE", None)


def assess(
    text: Any,
    *,
    contract: Any,
    manifest_text: Any,
    now: str,
    source_bytes: Mapping[str, Any] | None = None,
    input_origin: str = "OPERATOR_SUPPLIED",
) -> dict[str, Any]:
    """Translate restricted English to inert IR, or abstain, with evidence.

    `now` is the operator's UTC evaluation time (second precision, `Z`). It is
    an argument so the result is deterministic; this function reads no clock.
    """
    current = parse_utc(now, "now")
    if input_origin not in INPUT_ORIGINS:
        raise ValueError("input_origin is not allowlisted")
    reasons: set[str] = set()
    contract_record: dict[str, Any] = {"status": "INVALID", "contract_id": None, "sha256": None}
    normalized: dict[str, Any] | None = None
    contract_digest: str | None = None
    try:
        normalized = validate_contract(contract)
        contract_digest = sha256_json(normalized)
        contract_record = {"status": "VALID", "contract_id": normalized["contract_id"], "sha256": contract_digest}
    except (ContractError, EvidenceError):
        reasons.add("CONTRACT_INVALID")

    manifest = invalid_assessment()
    manifest_error = None
    try:
        parsed_manifest = parse_manifest(manifest_text)
    except ManifestError as exc:
        manifest_error = str(exc)
    else:
        if contract_digest is not None:
            manifest = assess_manifest(
                parsed_manifest, contract_digest=contract_digest, now=current, source_bytes=source_bytes
            )
        else:
            manifest = ManifestAssessment(sha256_json(parsed_manifest), (), (), (), False)
    reasons.update(manifest.blocking)

    parse_result: ParseResult | None = None
    validation: ValidationResult | None = None
    ir: dict[str, Any] | None = None
    ir_digest: str | None = None
    rejected_digest: str | None = None
    if reasons:
        outcome = ABSTAIN
    else:
        assert normalized is not None and contract_digest is not None
        parse_result = parse(text, normalized, contract_digest)
        if parse_result.status == UNTRANSLATED:
            outcome = UNTRANSLATED
            reasons.add(parse_result.reason or "UNSUPPORTED_VOCABULARY")
        elif parse_result.status != CANDIDATE or parse_result.ir is None:
            outcome = ABSTAIN
            reasons.add(parse_result.reason or "NO_DERIVATION")
        else:
            validation = validate_ir(parse_result.ir, normalized, contract_digest)
            try:
                candidate_digest: str | None = sha256_json(parse_result.ir)
            except EvidenceError:
                # Non-JSON parser output is a validation failure, not a crash.
                candidate_digest = None
            if validation.passed and candidate_digest is not None:
                outcome = TRANSLATED
                ir = parse_result.ir
                ir_digest = candidate_digest
            else:
                outcome = ABSTAIN
                reasons.add("VALIDATION_FAILED")
                rejected_digest = candidate_digest

    limit = normalized["max_input_bytes"] if normalized is not None else None
    artifacts = [
        _source_artifact(contract_digest, manifest, normalized is not None),
        _validation_artifact(outcome, validation, ir_digest, contract_digest),
    ]
    explicit_unknowns = normalized["explicit_unknowns"] if normalized is not None else []
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "serialization_profile": SERIALIZATION_PROFILE,
        "outcome": outcome,
        "reasons": sorted(reasons),
        "input": _input_record(text, input_origin, limit),
        "contract": contract_record,
        "manifest": {
            "sha256": manifest.manifest_sha256,
            "error": manifest_error,
            "findings": list(manifest.findings),
            "sources": [dict(row) for row in manifest.sources],
            "evidence_status_basis": "CALLER_DECLARED_METADATA_ONLY",
        },
        "parse": parse_result.summary() if parse_result is not None else {"status": "NOT_RUN"},
        "validation": {
            "status": "NOT_RUN" if validation is None else ("PASSED" if validation.passed else "FAILED"),
            "errors": list(validation.errors) if validation is not None else [],
            "rejected_ir_sha256": rejected_digest,
        },
        "ir": ir,
        "ir_sha256": ir_digest,
        "effects": {
            "declared": list(validation.declared_effects) if validation is not None and validation.passed else [],
            "executed": False,
            "external_effect_authority": "NOT_GRANTED",
        },
        "missing_evidence": list(manifest.missing_evidence),
        "explicit_unknowns": {key: "UNKNOWN" for key in explicit_unknowns},
        "claims": dict(_CLAIMS),
        "deployment_authorization": "NOT_GRANTED",
        "model_promotion_authorization": "NOT_GRANTED",
        "gateway_artifacts": artifacts,
    }
    report["report_sha256"] = sha256_json(report)
    return report


def gateway_artifacts(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [dict(item) for item in report["gateway_artifacts"]]


def gateway_request(report: Mapping[str, Any], request_id: str) -> dict[str, Any]:
    """A provider-`none` request for the existing EvidenceEvaluator."""
    return {
        "schema_version": REQUEST_VERSION,
        "request_id": request_id,
        "provider": "none",
        "domain": "software_infrastructure",
        "artifacts": gateway_artifacts(report),
    }
