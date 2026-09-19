"""Environment-only configuration with fail-closed parsing."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse


class ConfigurationError(RuntimeError):
    """Raised when security-critical configuration is absent or malformed."""


@dataclass(frozen=True)
class PrincipalSpec:
    subject: str
    scopes: frozenset[str]


@dataclass(frozen=True)
class OidcIssuerSpec:
    issuer: str
    audience: str
    jwks_url: str
    algorithms: tuple[str, ...]
    required_acr: tuple[str, ...]
    required_amr: tuple[str, ...]
    principal_type_claim: str
    scopes_claim: str
    groups_claim: str
    max_token_lifetime_seconds: int


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_OIDC_ALGORITHMS = frozenset({"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"})


def production_mode() -> bool:
    value = os.getenv("SAFE_QA_PRODUCTION_MODE", "false").strip().lower()
    if value not in {"true", "false"}:
        raise ConfigurationError("SAFE_QA_PRODUCTION_MODE must be true or false")
    return value == "true"


def auth_mode() -> str:
    mode = os.getenv("SAFE_QA_AUTH_MODE", "static").strip().lower()
    if mode not in {"static", "oidc"}:
        raise ConfigurationError("SAFE_QA_AUTH_MODE must be static or oidc")
    if production_mode() and mode != "oidc":
        raise ConfigurationError("production mode requires OIDC authentication")
    return mode


def _nonempty_strings(value: object, label: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if value is None and allow_empty:
        return ()
    if (
        not isinstance(value, list)
        or (not value and not allow_empty)
        or any(not isinstance(item, str) or not item.strip() for item in value)
    ):
        raise ConfigurationError(f"{label} must be a list of non-empty strings")
    return tuple(item.strip() for item in value)


def load_oidc_issuers() -> dict[str, OidcIssuerSpec]:
    """Load exact organizational OIDC trust anchors.

    The configuration is trusted operator input. Even so, issuers and JWKS endpoints are
    constrained to HTTPS and may not contain credentials or fragments.
    """
    raw = os.getenv("SAFE_QA_OIDC_ISSUERS_JSON")
    if not raw:
        raise ConfigurationError("SAFE_QA_OIDC_ISSUERS_JSON is not configured")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigurationError("SAFE_QA_OIDC_ISSUERS_JSON is invalid JSON") from exc
    if not isinstance(parsed, dict) or not parsed:
        raise ConfigurationError("at least one OIDC issuer is required")

    issuers: dict[str, OidcIssuerSpec] = {}
    for issuer, value in parsed.items():
        if not isinstance(issuer, str) or not isinstance(value, dict):
            raise ConfigurationError("OIDC issuer entries must be objects")
        audience = value.get("audience")
        jwks_url = value.get("jwks_url")
        if not isinstance(audience, str) or not audience.strip() or len(audience) > 256:
            raise ConfigurationError("OIDC audience must be a non-empty string")
        if not isinstance(jwks_url, str):
            raise ConfigurationError("OIDC jwks_url must be a string")
        for label, candidate in (("issuer", issuer), ("jwks_url", jwks_url)):
            parsed_url = urlparse(candidate)
            if (
                parsed_url.scheme != "https"
                or not parsed_url.hostname
                or parsed_url.username
                or parsed_url.password
                or parsed_url.fragment
            ):
                raise ConfigurationError(f"OIDC {label} must be a credential-free HTTPS URL")
        algorithms = _nonempty_strings(value.get("algorithms", ["RS256"]), "OIDC algorithms")
        if not set(algorithms).issubset(_OIDC_ALGORITHMS):
            raise ConfigurationError("OIDC algorithms contain an unapproved algorithm")
        required_acr = _nonempty_strings(
            value.get("required_acr", []), "OIDC required_acr", allow_empty=True
        )
        required_amr = _nonempty_strings(
            value.get("required_amr", []), "OIDC required_amr", allow_empty=True
        )
        principal_type_claim = value.get("principal_type_claim", "safe_qa_principal_type")
        scopes_claim = value.get("scopes_claim", "scope")
        groups_claim = value.get("groups_claim", "groups")
        for label, claim in (
            ("principal_type_claim", principal_type_claim),
            ("scopes_claim", scopes_claim),
            ("groups_claim", groups_claim),
        ):
            if not isinstance(claim, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", claim):
                raise ConfigurationError(f"OIDC {label} is invalid")
        maximum = value.get("max_token_lifetime_seconds", 3600)
        if type(maximum) is not int or not 60 <= maximum <= 43_200:
            raise ConfigurationError("OIDC max token lifetime must be 60-43200 seconds")
        issuers[issuer] = OidcIssuerSpec(
            issuer=issuer,
            audience=audience.strip(),
            jwks_url=jwks_url,
            algorithms=algorithms,
            required_acr=required_acr,
            required_amr=required_amr,
            principal_type_claim=principal_type_claim,
            scopes_claim=scopes_claim,
            groups_claim=groups_claim,
            max_token_lifetime_seconds=maximum,
        )
    return issuers


def load_principals() -> dict[str, PrincipalSpec]:
    """Load token hashes mapped to subjects/scopes; plaintext tokens are never configured."""
    raw = os.getenv("SAFE_QA_AUTH_TOKEN_HASHES_JSON")
    if not raw:
        raise ConfigurationError("SAFE_QA_AUTH_TOKEN_HASHES_JSON is not configured")

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigurationError("SAFE_QA_AUTH_TOKEN_HASHES_JSON is invalid JSON") from exc

    if not isinstance(parsed, dict) or not parsed:
        raise ConfigurationError("at least one authentication principal is required")

    principals: dict[str, PrincipalSpec] = {}
    for token_hash, value in parsed.items():
        normalized_hash = str(token_hash).lower()
        if not _SHA256_RE.fullmatch(normalized_hash):
            raise ConfigurationError("authentication token keys must be lowercase SHA-256 hex")
        if not isinstance(value, dict):
            raise ConfigurationError("authentication principal entries must be objects")

        subject = value.get("subject")
        scopes = value.get("scopes")
        if not isinstance(subject, str) or not subject.strip():
            raise ConfigurationError("authentication principal subject is required")
        if (
            not isinstance(scopes, list)
            or not scopes
            or any(not isinstance(scope, str) or not scope for scope in scopes)
        ):
            raise ConfigurationError("authentication principal scopes must be non-empty strings")
        principals[normalized_hash] = PrincipalSpec(subject.strip(), frozenset(scopes))

    return principals


def database_url() -> str:
    url = os.getenv("DATABASE_URL")
    if not url:
        raise ConfigurationError("DATABASE_URL is not configured")
    if not url.startswith(("postgresql://", "postgresql+psycopg://")):
        raise ConfigurationError("DATABASE_URL must use PostgreSQL")
    normalized = url.replace("postgresql+psycopg://", "postgresql://", 1)
    if production_mode():
        parsed = urlparse(normalized)
        parameters = parse_qs(parsed.query, keep_blank_values=True)
        if parameters.get("sslmode") != ["verify-full"]:
            raise ConfigurationError("production PostgreSQL requires sslmode=verify-full")
        root_certificates = parameters.get("sslrootcert")
        if not root_certificates or len(root_certificates) != 1 or not root_certificates[0]:
            raise ConfigurationError("production PostgreSQL requires an explicit sslrootcert")
    return normalized
