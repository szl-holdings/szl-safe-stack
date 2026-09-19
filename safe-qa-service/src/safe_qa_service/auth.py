"""Fail-closed authentication for local static tokens or production OIDC."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status

from .identity import IdentityVerificationError, verify_oidc_token
from .settings import ConfigurationError, auth_mode, load_principals


@dataclass(frozen=True)
class Principal:
    subject: str
    scopes: frozenset[str]
    token_fingerprint: str
    issuer: str = "local-static"
    principal_type: str = "development"
    groups: frozenset[str] = frozenset()
    mfa_authenticated: bool = False
    token_id: str | None = None


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


async def authenticate(
    authorization: Annotated[str | None, Header()] = None,
) -> Principal:
    try:
        mode = auth_mode()
    except ConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="authentication boundary is not configured",
        ) from exc

    if authorization is None:
        raise _unauthorized("bearer token required")

    scheme, separator, token = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token:
        raise _unauthorized("valid bearer token required")

    if mode == "oidc":
        try:
            identity = verify_oidc_token(token)
        except (ConfigurationError, IdentityVerificationError) as exc:
            raise _unauthorized("invalid organizational identity token") from exc
        return Principal(
            subject=identity.subject,
            scopes=identity.scopes,
            token_fingerprint=identity.token_fingerprint,
            issuer=identity.issuer,
            principal_type=identity.principal_type,
            groups=identity.groups,
            mfa_authenticated=identity.mfa_authenticated,
            token_id=identity.token_id,
        )

    try:
        principals = load_principals()
    except ConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="authentication boundary is not configured",
        ) from exc

    candidate_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    matched_hash = next(
        (
            stored_hash
            for stored_hash in principals
            if hmac.compare_digest(candidate_hash, stored_hash)
        ),
        None,
    )
    if matched_hash is None:
        raise _unauthorized("invalid bearer token")

    spec = principals[matched_hash]
    return Principal(
        subject=spec.subject,
        scopes=spec.scopes,
        token_fingerprint=candidate_hash[:12],
    )


def require_scopes(*required_scopes: str) -> Callable[..., Principal]:
    async def dependency(principal: Annotated[Principal, Depends(authenticate)]) -> Principal:
        missing = sorted(set(required_scopes) - principal.scopes)
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"message": "insufficient scope", "missing_scopes": missing},
            )
        return principal

    return dependency


def require_human_scopes(*required_scopes: str) -> Callable[..., Principal]:
    async def dependency(principal: Annotated[Principal, Depends(authenticate)]) -> Principal:
        missing = sorted(set(required_scopes) - principal.scopes)
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"message": "insufficient scope", "missing_scopes": missing},
            )
        if principal.principal_type != "human" or not principal.mfa_authenticated:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="a separately authenticated human MFA session is required",
            )
        return principal

    return dependency


def require_workload_scopes(*required_scopes: str) -> Callable[..., Principal]:
    async def dependency(principal: Annotated[Principal, Depends(authenticate)]) -> Principal:
        missing = sorted(set(required_scopes) - principal.scopes)
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"message": "insufficient scope", "missing_scopes": missing},
            )
        if principal.principal_type != "workload":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="a configured workload identity is required",
            )
        return principal

    return dependency
