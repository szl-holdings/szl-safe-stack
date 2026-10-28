"""Rights-admitted source and evidence manifest for the typed adapter.

The manifest is caller-declared metadata. It binds the input contract by
SHA-256, records each source's rights status and observation time, and may
name bounded relative paths. This module never opens a path: digests of named
files are compared only against bytes the caller passes in memory, and an
absent byte string is recorded as missing evidence rather than assumed.

Rights statuses are declarations, not license review. ADMITTED means only
that the manifest author declared the source usable for this adapter.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ..lattice_adapter import EvidenceError, parse_json_text, sha256_json

MANIFEST_SCHEMA = "szl.typed-evidence-adapter.manifest.v1"
MAX_MANIFEST_BYTES = 64 * 1024
MAX_SOURCES = 32
MAX_SOURCE_BYTES = 1024 * 1024
MIN_EVIDENCE_AGE_SECONDS = 60
MAX_EVIDENCE_AGE_SECONDS = 366 * 24 * 60 * 60

ROLES = frozenset({"input_contract", "fixture", "reference"})
RIGHTS_STATUSES = frozenset({"ADMITTED", "NOT_ADMITTED", "UNKNOWN"})
RIGHTS_BASES = frozenset({"SZL_ORIGINAL", "LICENSED", "OWNER_PERMISSION", "UNKNOWN"})

# Findings that stop translation. Everything else is recorded and reported.
BLOCKING_FINDINGS = frozenset(
    {
        "MANIFEST_INVALID",
        "CONTRACT_SOURCE_MISSING",
        "CONTRACT_DIGEST_MISMATCH",
        "CONTRACT_RIGHTS_NOT_ADMITTED",
        "STALE_EVIDENCE",
        "FUTURE_TIMESTAMP",
        "SOURCE_DIGEST_MISMATCH",
        "SOURCE_BYTES_INVALID",
    }
)

_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_LICENSE = re.compile(r"[A-Za-z0-9.+-]{1,64}")
_OBSERVER = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._@-]{0,127}")
# One relative POSIX path segment. A leading dot is refused, which excludes
# "." and ".." and hidden names. Backslash, colon, percent and tilde are not
# in the grammar, so drive letters, URL schemes and encoded traversal fail.
_SEGMENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,63}")
_MAX_PATH_SEGMENTS = 8
_MAX_PATH_LENGTH = 255

_MANIFEST_KEYS = frozenset({"schema", "manifest_id", "generated_at", "max_evidence_age_seconds", "sources"})
_SOURCE_REQUIRED = frozenset({"source_id", "role", "sha256", "rights", "observed_at", "observer"})
_SOURCE_OPTIONAL = frozenset({"path", "note"})
_RIGHTS_REQUIRED = frozenset({"status", "basis"})
_RIGHTS_OPTIONAL = frozenset({"license"})


class ManifestError(EvidenceError):
    """The manifest is not strictly valid."""


def parse_utc(value: Any, path: str = "timestamp") -> datetime:
    if not isinstance(value, str) or not _UTC.fullmatch(value):
        raise ManifestError(f"{path}: expected second-precision UTC Z time")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ManifestError(f"{path}: invalid UTC calendar time") from exc


def _keys(value: Any, required: frozenset[str], optional: frozenset[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ManifestError(f"{path}: expected an object")
    if not required <= set(value) or not set(value) <= required | optional:
        raise ManifestError(f"{path}: unexpected or missing keys")
    return value


def validate_relative_path(value: Any, path: str = "path") -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_PATH_LENGTH:
        raise ManifestError(f"{path}: expected a bounded relative path")
    segments = value.split("/")
    if len(segments) > _MAX_PATH_SEGMENTS or not all(_SEGMENT.fullmatch(item) for item in segments):
        raise ManifestError(f"{path}: not a contained relative POSIX path")
    return value


def _source(value: Any, path: str) -> dict[str, Any]:
    item = _keys(value, _SOURCE_REQUIRED, _SOURCE_OPTIONAL, path)
    if not isinstance(item["source_id"], str) or not _ID.fullmatch(item["source_id"]):
        raise ManifestError(f"{path}.source_id: does not match the safe identifier grammar")
    if item["role"] not in ROLES:
        raise ManifestError(f"{path}.role: role is not allowlisted")
    if not isinstance(item["sha256"], str) or not _SHA256.fullmatch(item["sha256"]):
        raise ManifestError(f"{path}.sha256: expected lowercase sha256")
    rights = _keys(item["rights"], _RIGHTS_REQUIRED, _RIGHTS_OPTIONAL, f"{path}.rights")
    if rights["status"] not in RIGHTS_STATUSES:
        raise ManifestError(f"{path}.rights.status: status is not allowlisted")
    if rights["basis"] not in RIGHTS_BASES:
        raise ManifestError(f"{path}.rights.basis: basis is not allowlisted")
    if rights["status"] == "ADMITTED" and rights["basis"] == "UNKNOWN":
        raise ManifestError(f"{path}.rights: ADMITTED requires a named basis")
    if "license" in rights and (not isinstance(rights["license"], str) or not _LICENSE.fullmatch(rights["license"])):
        raise ManifestError(f"{path}.rights.license: expected an SPDX-style identifier")
    parse_utc(item["observed_at"], f"{path}.observed_at")
    if not isinstance(item["observer"], str) or not _OBSERVER.fullmatch(item["observer"]):
        raise ManifestError(f"{path}.observer: expected a bounded observer label")
    if "path" in item:
        validate_relative_path(item["path"], f"{path}.path")
    if "note" in item and (not isinstance(item["note"], str) or len(item["note"]) > 500):
        raise ManifestError(f"{path}.note: expected a bounded string")
    return item


def parse_manifest(text: Any) -> dict[str, Any]:
    """Parse and strictly validate manifest JSON text. Raises ManifestError."""
    if not isinstance(text, str):
        raise ManifestError("manifest: expected JSON text")
    if len(text) > MAX_MANIFEST_BYTES or len(text.encode("utf-8", "surrogatepass")) > MAX_MANIFEST_BYTES:
        raise ManifestError(f"manifest: exceeds {MAX_MANIFEST_BYTES} bytes")
    try:
        value = parse_json_text(text)
    except EvidenceError as exc:
        # parse_json_text refuses duplicate object keys without echoing them.
        raise ManifestError(f"manifest: {exc}") from exc
    manifest = _keys(value, _MANIFEST_KEYS, frozenset(), "manifest")
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise ManifestError("manifest.schema: unsupported schema")
    if not isinstance(manifest["manifest_id"], str) or not _ID.fullmatch(manifest["manifest_id"]):
        raise ManifestError("manifest.manifest_id: does not match the safe identifier grammar")
    generated_at = parse_utc(manifest["generated_at"], "manifest.generated_at")
    age = manifest["max_evidence_age_seconds"]
    if type(age) is not int or not MIN_EVIDENCE_AGE_SECONDS <= age <= MAX_EVIDENCE_AGE_SECONDS:
        raise ManifestError("manifest.max_evidence_age_seconds: outside the allowed range")
    sources = manifest["sources"]
    if not isinstance(sources, list) or not 1 <= len(sources) <= MAX_SOURCES:
        raise ManifestError(f"manifest.sources: expected 1 through {MAX_SOURCES} sources")
    validated = [_source(item, f"manifest.sources[{index}]") for index, item in enumerate(sources)]
    if any(parse_utc(item["observed_at"]) > generated_at for item in validated):
        raise ManifestError("manifest.sources: a source is observed after the manifest was generated")
    ids = [item["source_id"] for item in validated]
    if len(ids) != len(set(ids)):
        raise ManifestError("manifest.sources: source_id values must be unique")
    paths = [item["path"] for item in validated if "path" in item]
    if len(paths) != len(set(paths)):
        raise ManifestError("manifest.sources: paths must be unique")
    if sum(1 for item in validated if item["role"] == "input_contract") > 1:
        raise ManifestError("manifest.sources: at most one input_contract source is allowed")
    try:
        sha256_json(manifest)
    except EvidenceError as exc:
        raise ManifestError(f"manifest: {exc}") from exc
    return manifest


@dataclass(frozen=True)
class ManifestAssessment:
    manifest_sha256: str | None
    findings: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    sources: tuple[dict[str, Any], ...]
    digests_fully_checked: bool

    @property
    def blocking(self) -> tuple[str, ...]:
        return tuple(item for item in self.findings if item in BLOCKING_FINDINGS)


def invalid_assessment() -> ManifestAssessment:
    return ManifestAssessment(None, ("MANIFEST_INVALID",), (), (), False)


def assess_manifest(
    manifest: dict[str, Any],
    *,
    contract_digest: str,
    now: datetime,
    source_bytes: Mapping[str, Any] | None = None,
) -> ManifestAssessment:
    """Assess a parsed manifest. Pure: reads no file, clock or network."""
    if source_bytes is not None and not isinstance(source_bytes, Mapping):
        raise TypeError("source_bytes must be a mapping of manifest path to bytes")
    supplied = source_bytes if source_bytes is not None else {}
    findings: set[str] = set()
    missing: set[str] = set()
    rows: list[dict[str, Any]] = []
    if parse_utc(manifest["generated_at"]) > now:
        findings.add("FUTURE_TIMESTAMP")
    max_age = manifest["max_evidence_age_seconds"]
    all_checked = True
    if not any(item["role"] == "input_contract" for item in manifest["sources"]):
        findings.add("CONTRACT_SOURCE_MISSING")
    for item in manifest["sources"]:
        observed = parse_utc(item["observed_at"])
        admitted = item["rights"]["status"] == "ADMITTED"
        if observed > now:
            freshness = "FUTURE_TIMESTAMP"
            findings.add("FUTURE_TIMESTAMP")
        elif (now - observed).total_seconds() > max_age:
            freshness = "STALE"
            if admitted:
                findings.add("STALE_EVIDENCE")
        else:
            freshness = "FRESH"
        if item["role"] == "input_contract":
            # The contract digest is checked against the in-memory contract
            # object. A contract `path` is a locator only.
            if not admitted:
                findings.add("CONTRACT_RIGHTS_NOT_ADMITTED")
            if item["sha256"] == contract_digest:
                digest_check = "MATCHED_IN_MEMORY"
            else:
                digest_check = "MISMATCHED"
                findings.add("CONTRACT_DIGEST_MISMATCH")
        elif not admitted:
            digest_check = "NOT_CHECKED_RIGHTS_NOT_ADMITTED"
            findings.add("SOURCE_EXCLUDED_RIGHTS_NOT_ADMITTED")
        elif "path" not in item:
            digest_check = "NOT_CHECKABLE_NO_PATH"
            missing.add(f"source_digest_unchecked:{item['source_id']}")
            all_checked = False
        else:
            raw = supplied.get(item["path"])
            if raw is None:
                digest_check = "BYTES_NOT_SUPPLIED"
                missing.add(f"source_bytes:{item['source_id']}")
                findings.add("SOURCE_BYTES_NOT_SUPPLIED")
                all_checked = False
            elif not isinstance(raw, bytes) or len(raw) > MAX_SOURCE_BYTES:
                digest_check = "BYTES_INVALID"
                findings.add("SOURCE_BYTES_INVALID")
                all_checked = False
            elif hashlib.sha256(raw).hexdigest() != item["sha256"]:
                digest_check = "MISMATCHED"
                findings.add("SOURCE_DIGEST_MISMATCH")
                all_checked = False
            else:
                digest_check = "MATCHED"
        rows.append(
            {
                "source_id": item["source_id"],
                "role": item["role"],
                "rights_status": item["rights"]["status"],
                "rights_basis": item["rights"]["basis"],
                "use": "ADMITTED" if admitted else "EXCLUDED_RIGHTS_NOT_ADMITTED",
                "freshness": freshness,
                "digest_check": digest_check,
            }
        )
    rows.sort(key=lambda row: row["source_id"])
    return ManifestAssessment(
        manifest_sha256=sha256_json(manifest),
        findings=tuple(sorted(findings)),
        missing_evidence=tuple(sorted(missing)),
        sources=tuple(rows),
        digests_fully_checked=all_checked and not (findings & BLOCKING_FINDINGS),
    )


def build_manifest(
    *,
    manifest_id: str,
    generated_at: str,
    contract_digest: str,
    rights: dict[str, str],
    observer: str,
    max_evidence_age_seconds: int = 86_400,
    extra_sources: tuple[dict[str, Any], ...] = (),
) -> dict[str, Any]:
    """Assemble a manifest dict. The caller supplies, and owns, every rights claim."""
    return {
        "schema": MANIFEST_SCHEMA,
        "manifest_id": manifest_id,
        "generated_at": generated_at,
        "max_evidence_age_seconds": max_evidence_age_seconds,
        "sources": [
            {
                "source_id": "input-contract",
                "role": "input_contract",
                "sha256": contract_digest,
                "rights": dict(rights),
                "observed_at": generated_at,
                "observer": observer,
            },
            *extra_sources,
        ],
    }
