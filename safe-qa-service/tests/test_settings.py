from __future__ import annotations

import hashlib
import json

import pytest

from safe_qa_service.settings import (
    ConfigurationError,
    auth_mode,
    database_url,
    load_oidc_issuers,
    load_principals,
)


def test_valid_principals_are_loaded(monkeypatch: pytest.MonkeyPatch) -> None:
    digest = hashlib.sha256(b"token").hexdigest()
    monkeypatch.setenv(
        "SAFE_QA_AUTH_TOKEN_HASHES_JSON",
        json.dumps({digest: {"subject": "svc", "scopes": ["evaluate"]}}),
    )
    principals = load_principals()
    assert principals[digest].subject == "svc"
    assert principals[digest].scopes == frozenset({"evaluate"})


@pytest.mark.parametrize(
    "raw",
    [
        "not-json",
        "{}",
        json.dumps({"not-a-hash": {"subject": "svc", "scopes": ["evaluate"]}}),
        json.dumps({"a" * 64: "not-an-object"}),
        json.dumps({"a" * 64: {"subject": "", "scopes": ["evaluate"]}}),
        json.dumps({"a" * 64: {"subject": "svc", "scopes": []}}),
    ],
)
def test_invalid_principal_configuration_fails_closed(
    monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    monkeypatch.setenv("SAFE_QA_AUTH_TOKEN_HASHES_JSON", raw)
    with pytest.raises(ConfigurationError):
        load_principals()


def test_database_url_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ConfigurationError, match="not configured"):
        database_url()


def test_database_url_rejects_non_postgres(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "sqlite:///local.db")
    with pytest.raises(ConfigurationError, match="PostgreSQL"):
        database_url()


def test_database_url_normalizes_psycopg_scheme(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://db/safeqa")
    assert database_url() == "postgresql://db/safeqa"


def test_oidc_issuer_preserves_a_canonical_trailing_slash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issuer = "https://identity.example.test/"
    monkeypatch.setenv(
        "SAFE_QA_OIDC_ISSUERS_JSON",
        json.dumps(
            {
                issuer: {
                    "audience": "safe-qa",
                    "jwks_url": "https://identity.example.test/.well-known/jwks.json",
                }
            }
        ),
    )

    assert load_oidc_issuers()[issuer].issuer == issuer


def test_production_requires_oidc_and_verified_postgres_tls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SAFE_QA_PRODUCTION_MODE", "true")
    monkeypatch.setenv("SAFE_QA_AUTH_MODE", "static")
    with pytest.raises(ConfigurationError, match="requires OIDC"):
        auth_mode()

    monkeypatch.setenv("SAFE_QA_AUTH_MODE", "oidc")
    assert auth_mode() == "oidc"
    monkeypatch.setenv("DATABASE_URL", "postgresql://db.example.test/safeqa?sslmode=require")
    with pytest.raises(ConfigurationError, match="verify-full"):
        database_url()

    url = (
        "postgresql://db.example.test/safeqa?sslmode=verify-full"
        "&sslrootcert=/var/run/secrets/rds-ca.pem"
    )
    monkeypatch.setenv("DATABASE_URL", url)
    assert database_url() == url
