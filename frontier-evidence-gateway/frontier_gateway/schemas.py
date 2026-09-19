from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Any


class SchemaError(ValueError):
    """Raised when a versioned request is not strictly valid."""


REQUEST_VERSION = "szl.frontier.evidence.request.v1"
ARTIFACT_VERSION = "szl.frontier.evidence.artifact.v1"
RESPONSE_VERSION = "szl.frontier.evidence.response.v1"
BUILTIN_CASE_IDS = frozenset(
    {"receipt-integrity", "schema-versioning", "deployment-readiness-gap"}
)
PROVIDERS = frozenset({"none", "ollama", "openrouter"})
KINDS = frozenset({"source", "ci", "container", "deployment", "runtime", "evaluation", "witness"})
STATUSES = frozenset({"VERIFIED", "UNVERIFIED", "UNAVAILABLE", "FAILED"})
_ARTIFACT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _exact_keys(value: dict[str, Any], allowed: set[str], required: set[str], label: str) -> None:
    unknown = set(value) - allowed
    missing = required - set(value)
    if unknown:
        raise SchemaError(f"{label} has unknown fields: {', '.join(sorted(unknown))}")
    if missing:
        raise SchemaError(f"{label} is missing fields: {', '.join(sorted(missing))}")


@dataclass(frozen=True)
class EvidenceArtifact:
    artifact_id: str
    kind: str
    status: str
    sha256: str | None

    @classmethod
    def parse(cls, value: Any) -> "EvidenceArtifact":
        if not isinstance(value, dict):
            raise SchemaError("each artifact must be an object")
        _exact_keys(
            value,
            {"schema_version", "artifact_id", "kind", "status", "sha256"},
            {"schema_version", "artifact_id", "kind", "status"},
            "artifact",
        )
        if value["schema_version"] != ARTIFACT_VERSION:
            raise SchemaError("unsupported artifact schema_version")
        artifact_id = value["artifact_id"]
        kind = value["kind"]
        status = value["status"]
        digest = value.get("sha256")
        if not isinstance(artifact_id, str) or not _ARTIFACT_ID_RE.fullmatch(artifact_id):
            raise SchemaError("artifact_id must match the safe identifier grammar")
        if not isinstance(kind, str) or kind not in KINDS:
            raise SchemaError("artifact kind is not allowlisted")
        if not isinstance(status, str) or status not in STATUSES:
            raise SchemaError("artifact status is not allowlisted")
        if digest is not None and (not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest)):
            raise SchemaError("artifact sha256 must be 64 lowercase hexadecimal characters")
        if status == "VERIFIED" and digest is None:
            raise SchemaError("VERIFIED artifacts require a sha256 digest")
        if status != "VERIFIED" and digest is not None:
            raise SchemaError("only VERIFIED artifacts may carry a sha256 digest")
        return cls(artifact_id=artifact_id, kind=kind, status=status, sha256=digest)

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": ARTIFACT_VERSION,
            "artifact_id": self.artifact_id,
            "kind": self.kind,
            "status": self.status,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class EvidenceRequest:
    request_id: str
    case_id: str | None
    provider: str
    domain: str
    artifacts: tuple[EvidenceArtifact, ...]

    @classmethod
    def parse(cls, value: Any) -> "EvidenceRequest":
        if not isinstance(value, dict):
            raise SchemaError("request must be a JSON object")
        _exact_keys(
            value,
            {"schema_version", "request_id", "case_id", "provider", "domain", "artifacts"},
            {"schema_version", "request_id", "provider", "domain"},
            "request",
        )
        if value["schema_version"] != REQUEST_VERSION:
            raise SchemaError("unsupported request schema_version")
        request_id = value["request_id"]
        try:
            if not isinstance(request_id, str) or str(uuid.UUID(request_id)) != request_id:
                raise ValueError
        except ValueError as exc:
            raise SchemaError("request_id must be a canonical UUID") from exc
        if value["domain"] != "software_infrastructure":
            raise SchemaError("only the software_infrastructure domain is supported")
        provider = value["provider"]
        if not isinstance(provider, str) or provider not in PROVIDERS:
            raise SchemaError("provider is not allowlisted")
        case_id = value.get("case_id")
        raw_artifacts = value.get("artifacts", [])
        if not isinstance(raw_artifacts, list) or len(raw_artifacts) > 32:
            raise SchemaError("artifacts must be an array of at most 32 entries")
        artifacts = tuple(EvidenceArtifact.parse(item) for item in raw_artifacts)
        if case_id is not None:
            if not isinstance(case_id, str) or case_id not in BUILTIN_CASE_IDS:
                raise SchemaError("case_id is not a built-in safe case")
            if artifacts:
                raise SchemaError("built-in cases do not accept caller artifacts")
        elif not artifacts:
            raise SchemaError("an artifact set or built-in case_id is required")
        ids = [artifact.artifact_id for artifact in artifacts]
        if len(ids) != len(set(ids)):
            raise SchemaError("artifact_id values must be unique")
        return cls(
            request_id=request_id,
            case_id=case_id,
            provider=provider,
            domain=value["domain"],
            artifacts=artifacts,
        )
