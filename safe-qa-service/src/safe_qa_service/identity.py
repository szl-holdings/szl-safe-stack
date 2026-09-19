"""Strict organizational OIDC verification for human and workload identities."""

from __future__ import annotations

import hashlib
import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

from .settings import ConfigurationError, OidcIssuerSpec, load_oidc_issuers


class IdentityVerificationError(RuntimeError):
    """Raised when a bearer token cannot establish an approved identity."""


@dataclass(frozen=True)
class VerifiedIdentity:
    issuer: str
    subject: str
    principal_type: str
    scopes: frozenset[str]
    groups: frozenset[str]
    mfa_authenticated: bool
    token_id: str
    token_fingerprint: str


def _jwt_module():
    try:
        import jwt
    except ModuleNotFoundError as exc:  # pragma: no cover - production dependency guard
        raise ConfigurationError("PyJWT is required for OIDC authentication") from exc
    return jwt


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise urllib.error.HTTPError(
            req.full_url, code, "OIDC JWKS redirects are forbidden", headers, fp
        )


@lru_cache(maxsize=16)
def _jwks_client(jwks_url: str):
    jwt = _jwt_module()

    class StrictPyJWKClient(jwt.PyJWKClient):
        def fetch_data(self) -> dict[str, Any]:
            request = urllib.request.Request(
                url=self.uri,
                headers={**self.headers, "Accept": "application/json"},
                method="GET",
            )
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=ssl.create_default_context()),
                _RejectRedirects(),
            )
            try:
                with opener.open(request, timeout=min(float(self.timeout), 5.0)) as response:
                    if response.geturl() != self.uri:
                        raise IdentityVerificationError("OIDC JWKS endpoint redirected")
                    raw = response.read(512_001)
            except (OSError, TimeoutError, urllib.error.URLError) as exc:
                raise IdentityVerificationError("OIDC JWKS retrieval failed") from exc
            if len(raw) > 512_000:
                raise IdentityVerificationError("OIDC JWKS response exceeds the safety bound")
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise IdentityVerificationError("OIDC JWKS response is malformed") from exc
            keys = value.get("keys") if isinstance(value, dict) else None
            if not isinstance(keys, list) or not keys or len(keys) > 100:
                raise IdentityVerificationError("OIDC JWKS key set is empty or oversized")
            if self.jwk_set_cache is not None:
                self.jwk_set_cache.put(value)
            return value

    return StrictPyJWKClient(
        jwks_url,
        # The per-key LRU has no time-based expiry in PyJWT. Keep only the
        # bounded five-minute JWK-set cache so a removed key cannot remain
        # accepted indefinitely in a long-lived process.
        cache_keys=False,
        lifespan=300,
        timeout=5,
    )


def _string_set(value: Any, label: str) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, str):
        items = value.split()
    elif isinstance(value, list):
        items = value
    else:
        raise IdentityVerificationError(f"OIDC {label} claim has an invalid type")
    if any(not isinstance(item, str) or not item or len(item) > 256 for item in items):
        raise IdentityVerificationError(f"OIDC {label} claim contains an invalid value")
    return frozenset(items)


def _select_issuer(token: str) -> tuple[OidcIssuerSpec, dict[str, Any], dict[str, Any]]:
    jwt = _jwt_module()
    try:
        header = jwt.get_unverified_header(token)
        unverified = jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_aud": False,
                "verify_iss": False,
            },
        )
    except Exception as exc:
        raise IdentityVerificationError("bearer token is not a valid JWT") from exc
    if not isinstance(header, dict) or not isinstance(unverified, dict):
        raise IdentityVerificationError("bearer token header or claims are invalid")
    issuer = unverified.get("iss")
    if not isinstance(issuer, str):
        raise IdentityVerificationError("OIDC issuer claim is missing")
    try:
        spec = load_oidc_issuers()[issuer]
    except (ConfigurationError, KeyError) as exc:
        raise IdentityVerificationError("OIDC issuer is not trusted") from exc
    algorithm = header.get("alg")
    if algorithm not in spec.algorithms or algorithm in {"none", "HS256", "HS384", "HS512"}:
        raise IdentityVerificationError("OIDC signing algorithm is not approved")
    if not isinstance(header.get("kid"), str) or not header["kid"]:
        raise IdentityVerificationError("OIDC key identifier is missing")
    return spec, header, unverified


def verify_oidc_token(token: str) -> VerifiedIdentity:
    if not token or len(token) > 32_768:
        raise IdentityVerificationError("bearer token size is invalid")
    spec, header, _unverified = _select_issuer(token)
    jwt = _jwt_module()
    try:
        signing_key = _jwks_client(spec.jwks_url).get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=list(spec.algorithms),
            audience=spec.audience,
            issuer=spec.issuer,
            leeway=30,
            options={
                "require": ["exp", "iat", "iss", "sub", "aud", "jti"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_nbf": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )
    except Exception as exc:
        raise IdentityVerificationError("OIDC signature or registered claims are invalid") from exc
    if not isinstance(claims, dict) or header.get("alg") not in spec.algorithms:
        raise IdentityVerificationError("OIDC token verification result is invalid")
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    if type(issued_at) not in {int, float} or type(expires_at) not in {int, float}:
        raise IdentityVerificationError("OIDC token times are invalid")
    lifetime = float(expires_at) - float(issued_at)
    now = datetime.now(UTC).timestamp()
    if lifetime <= 0 or lifetime > spec.max_token_lifetime_seconds:
        raise IdentityVerificationError("OIDC token lifetime exceeds policy")
    if float(issued_at) > now + 30:
        raise IdentityVerificationError("OIDC token was issued in the future")
    subject = claims.get("sub")
    token_id = claims.get("jti")
    principal_type = claims.get(spec.principal_type_claim)
    if not isinstance(subject, str) or not 1 <= len(subject) <= 256:
        raise IdentityVerificationError("OIDC subject is invalid")
    if not isinstance(token_id, str) or not 8 <= len(token_id) <= 256:
        raise IdentityVerificationError("OIDC token identifier is invalid")
    if principal_type not in {"human", "workload"}:
        raise IdentityVerificationError("OIDC principal type must be human or workload")
    scopes = _string_set(claims.get(spec.scopes_claim), "scope")
    groups = _string_set(claims.get(spec.groups_claim), "groups")
    acr = claims.get("acr")
    amr = _string_set(claims.get("amr"), "amr")
    if spec.required_acr and acr not in spec.required_acr:
        raise IdentityVerificationError("OIDC authentication context is insufficient")
    if spec.required_amr and not set(spec.required_amr).issubset(amr):
        raise IdentityVerificationError("OIDC authentication methods are insufficient")
    mfa_authenticated = bool(
        principal_type == "human"
        and (spec.required_acr or spec.required_amr)
        and (not spec.required_acr or acr in spec.required_acr)
        and (not spec.required_amr or set(spec.required_amr).issubset(amr))
    )
    return VerifiedIdentity(
        issuer=spec.issuer,
        subject=subject,
        principal_type=principal_type,
        scopes=scopes,
        groups=groups,
        mfa_authenticated=mfa_authenticated,
        token_id=token_id,
        token_fingerprint=hashlib.sha256(token.encode("utf-8")).hexdigest()[:16],
    )
