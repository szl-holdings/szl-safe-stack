from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .ledger import ReceiptLedger
from .providers import ObservationProvider, ProviderError
from .schemas import ARTIFACT_VERSION, KINDS, RESPONSE_VERSION, EvidenceArtifact, EvidenceRequest


BUILTIN_CASES: dict[str, tuple[EvidenceArtifact, ...]] = {
    "receipt-integrity": (
        EvidenceArtifact("ledger-source", "source", "UNVERIFIED", None),
        EvidenceArtifact("ledger-tests", "evaluation", "UNVERIFIED", None),
        EvidenceArtifact("external-witness", "witness", "UNAVAILABLE", None),
    ),
    "schema-versioning": (
        EvidenceArtifact("schema-source", "source", "UNVERIFIED", None),
        EvidenceArtifact("schema-ci", "ci", "UNVERIFIED", None),
    ),
    "deployment-readiness-gap": (
        EvidenceArtifact("application-source", "source", "UNVERIFIED", None),
        EvidenceArtifact("container-build", "container", "UNVERIFIED", None),
        EvidenceArtifact("provider-deployment", "deployment", "UNAVAILABLE", None),
        EvidenceArtifact("runtime-probe", "runtime", "UNAVAILABLE", None),
    ),
}


class EvaluationProviderError(ProviderError):
    def __init__(self, message: str, receipt: dict[str, object]):
        super().__init__(message)
        self.receipt = receipt


@dataclass
class EvidenceEvaluator:
    ledger: ReceiptLedger
    providers: dict[str, ObservationProvider]

    def evaluate(self, request: EvidenceRequest) -> dict[str, object]:
        artifacts = BUILTIN_CASES[request.case_id] if request.case_id else request.artifacts
        verified_kinds = {item.kind for item in artifacts if item.status == "VERIFIED"}
        missing = sorted(KINDS - verified_kinds)
        failed = sorted({item.kind for item in artifacts if item.status == "FAILED"})
        if failed:
            classification = "FAILED_EVIDENCE_PRESENT"
        elif not verified_kinds:
            classification = "INSUFFICIENT_EVIDENCE"
        elif missing:
            classification = "PARTIAL_EVIDENCE"
        else:
            classification = "DECLARED_EVIDENCE_SET_COMPLETE_PENDING_INDEPENDENT_VERIFICATION"
        deterministic = {
            "schema_version": "szl.frontier.deterministic_evaluation.v1",
            "classification": classification,
            "evidence_status_basis": (
                "BUILTIN_STATIC_UNVERIFIED_FIXTURE"
                if request.case_id
                else "CALLER_DECLARED_METADATA_ONLY"
            ),
            "external_artifacts_fetched": False,
            "verified_kinds": sorted(verified_kinds),
            "missing_or_unverified_kinds": missing,
            "failed_kinds": failed,
            "clinical_or_biological_claim_status": "NOT_EVALUATED",
            "deployment_authorization": "NOT_GRANTED",
            "model_promotion_authorization": "NOT_GRANTED",
        }

        observation: dict[str, object] | None = None
        output_hash: str | None = None
        provider_model: str | None = None
        model_input_hash: str | None = None
        if request.provider != "none":
            provider = self.providers.get(request.provider)
            if provider is None:
                receipt = self._append_receipt(
                    request,
                    artifacts,
                    deterministic,
                    None,
                    None,
                    None,
                    "PROVIDER_NOT_CONFIGURED",
                )
                raise EvaluationProviderError("requested provider is not configured", receipt)
            provider_model = provider.model
            prompt = self._model_prompt(artifacts, deterministic)
            model_input_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
            try:
                content = provider.observe(prompt)
            except ProviderError as exc:
                receipt = self._append_receipt(
                    request,
                    artifacts,
                    deterministic,
                    None,
                    provider_model,
                    model_input_hash,
                    "PROVIDER_ERROR",
                )
                raise EvaluationProviderError(str(exc), receipt) from exc
            output_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
            observation = {
                "schema_version": "szl.frontier.model_observation.v1",
                "provider": provider.name,
                "model": provider.model,
                "status": "UNVERIFIED_MODEL_OUTPUT",
                "content": content,
                "content_sha256": output_hash,
            }

        receipt = self._append_receipt(
            request,
            artifacts,
            deterministic,
            output_hash,
            provider_model,
            model_input_hash,
            "COMPLETED",
        )
        return {
            "schema_version": RESPONSE_VERSION,
            "request_id": request.request_id,
            "deterministic_evaluation": deterministic,
            "model_observation": observation,
            "receipt": receipt,
        }

    def _append_receipt(
        self,
        request: EvidenceRequest,
        artifacts: tuple[EvidenceArtifact, ...],
        deterministic: dict[str, object],
        output_hash: str | None,
        provider_model: str | None,
        model_input_hash: str | None,
        outcome: str,
    ) -> dict[str, object]:
        artifact_payload = [item.as_dict() for item in artifacts]
        input_hash = hashlib.sha256(
            json.dumps(artifact_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return self.ledger.append(
            {
                "schema_version": "szl.frontier.receipt_event.v1",
                "request_id": request.request_id,
                "case_id": request.case_id,
                "provider": request.provider,
                "provider_model": provider_model,
                "domain": request.domain,
                "input_sha256": input_hash,
                "model_input_sha256": model_input_hash,
                "deterministic_classification": deterministic["classification"],
                "model_output_sha256": output_hash,
                "outcome": outcome,
                "content_stored": False,
            }
        )

    @staticmethod
    def _model_prompt(
        artifacts: tuple[EvidenceArtifact, ...], deterministic: dict[str, object]
    ) -> str:
        safe_artifacts = [
            {
                "schema_version": ARTIFACT_VERSION,
                "artifact_id": item.artifact_id,
                "kind": item.kind,
                "status": item.status,
                "sha256": item.sha256,
            }
            for item in artifacts
        ]
        payload = json.dumps(
            {"artifacts": safe_artifacts, "deterministic_evaluation": deterministic},
            sort_keys=True,
            separators=(",", ":"),
        )
        return (
            "Review this closed-vocabulary software evidence inventory. Explain missing proof layers in at most "
            "six sentences. Treat every model statement as unverified. Do not authorize deployment or model "
            f"promotion and do not make clinical or biological claims. Evidence JSON: {payload}"
        )
