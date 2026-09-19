from __future__ import annotations

import asyncio
import json
import urllib.error
from datetime import UTC, datetime
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from safe_qa_service import identity
from safe_qa_service.auth import Principal, require_human_scopes, require_workload_scopes
from safe_qa_service.identity import IdentityVerificationError, verify_oidc_token

ISSUER = "https://identity.example.test"
AUDIENCE = "safe-qa-production"
JWKS_URL = "https://identity.example.test/.well-known/jwks.json"
NOW = int(datetime.now(UTC).timestamp())
ORIGINAL_JWKS_CLIENT = identity._jwks_client


@pytest.fixture
def rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


@pytest.fixture(autouse=True)
def configure_oidc(monkeypatch: pytest.MonkeyPatch, rsa_keys) -> None:
    _private_key, public_key = rsa_keys
    config = {
        ISSUER: {
            "audience": AUDIENCE,
            "jwks_url": JWKS_URL,
            "algorithms": ["RS256"],
            "required_acr": ["urn:example:mfa"],
            "required_amr": ["mfa"],
            "principal_type_claim": "safe_qa_principal_type",
            "scopes_claim": "scope",
            "groups_claim": "groups",
            "max_token_lifetime_seconds": 900,
        }
    }
    monkeypatch.setenv("SAFE_QA_OIDC_ISSUERS_JSON", json.dumps(config))
    monkeypatch.setattr(
        identity,
        "_jwks_client",
        lambda _url: SimpleNamespace(
            get_signing_key_from_jwt=lambda _token: SimpleNamespace(key=public_key)
        ),
    )


def _claims(**updates: object) -> dict[str, object]:
    claims: dict[str, object] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "identity-center-user-0001",
        "jti": "token-id-00000001",
        "iat": NOW - 10,
        "exp": NOW + 300,
        "safe_qa_principal_type": "human",
        "scope": "control:approve audit:read",
        "groups": ["security-owners"],
        "acr": "urn:example:mfa",
        "amr": ["pwd", "mfa"],
    }
    claims.update(updates)
    return claims


def _token(
    private_key, *, claims: dict[str, object] | None = None, algorithm: str = "RS256"
) -> str:
    return jwt.encode(
        claims or _claims(),
        private_key,
        algorithm=algorithm,
        headers={"kid": "test-key-1"},
    )


def test_valid_human_oidc_token_establishes_mfa_identity(rsa_keys) -> None:
    private_key, _public_key = rsa_keys

    result = verify_oidc_token(_token(private_key))

    assert result.issuer == ISSUER
    assert result.subject == "identity-center-user-0001"
    assert result.principal_type == "human"
    assert result.mfa_authenticated is True
    assert result.scopes == frozenset({"control:approve", "audit:read"})
    assert result.groups == frozenset({"security-owners"})
    assert len(result.token_fingerprint) == 16


def test_canonical_trailing_slash_issuer_verifies_exactly(
    rsa_keys, monkeypatch: pytest.MonkeyPatch
) -> None:
    private_key, _public_key = rsa_keys
    issuer = "https://identity.example.test/"
    monkeypatch.setenv(
        "SAFE_QA_OIDC_ISSUERS_JSON",
        json.dumps(
            {
                issuer: {
                    "audience": AUDIENCE,
                    "jwks_url": JWKS_URL,
                    "algorithms": ["RS256"],
                    "required_acr": ["urn:example:mfa"],
                    "required_amr": ["mfa"],
                    "principal_type_claim": "safe_qa_principal_type",
                    "scopes_claim": "scope",
                    "groups_claim": "groups",
                    "max_token_lifetime_seconds": 900,
                }
            }
        ),
    )

    result = verify_oidc_token(_token(private_key, claims=_claims(iss=issuer)))

    assert result.issuer == issuer


def test_workload_token_is_verified_but_never_marked_mfa(rsa_keys) -> None:
    private_key, _public_key = rsa_keys
    token = _token(
        private_key,
        claims=_claims(
            safe_qa_principal_type="workload",
            sub="safe-qa-controller-workload",
            scope="control:execute",
        ),
    )

    result = verify_oidc_token(token)

    assert result.principal_type == "workload"
    assert result.mfa_authenticated is False
    assert result.scopes == frozenset({"control:execute"})


@pytest.mark.parametrize(
    ("claim_update", "message"),
    [
        ({"iss": "https://attacker.example.test"}, "issuer is not trusted"),
        ({"aud": "wrong-audience"}, "signature or registered claims are invalid"),
        ({"amr": ["pwd"]}, "authentication methods are insufficient"),
        ({"acr": "urn:example:password"}, "authentication context is insufficient"),
    ],
)
def test_issuer_audience_and_mfa_claims_fail_closed(
    rsa_keys, claim_update: dict[str, object], message: str
) -> None:
    private_key, _public_key = rsa_keys

    with pytest.raises(IdentityVerificationError, match=message):
        verify_oidc_token(_token(private_key, claims=_claims(**claim_update)))


def test_unapproved_algorithm_is_rejected_before_key_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    claims = _claims()
    token = jwt.encode(
        claims,
        "local-test-secret-with-sufficient-length",
        algorithm="HS256",
        headers={"kid": "attacker-key"},
    )
    monkeypatch.setattr(
        identity,
        "_jwks_client",
        lambda _url: pytest.fail("unapproved algorithms must not reach JWKS lookup"),
    )

    with pytest.raises(IdentityVerificationError, match="signing algorithm is not approved"):
        verify_oidc_token(token)


def test_human_and_workload_dependencies_are_not_interchangeable() -> None:
    human = Principal(
        subject="human-user",
        scopes=frozenset({"control:approve", "control:execute"}),
        token_fingerprint="human-token",
        principal_type="human",
        mfa_authenticated=True,
    )
    workload = Principal(
        subject="controller-workload",
        scopes=frozenset({"control:approve", "control:execute"}),
        token_fingerprint="workload-token",
        principal_type="workload",
        mfa_authenticated=False,
    )
    human_dependency = require_human_scopes("control:approve")
    workload_dependency = require_workload_scopes("control:execute")

    assert asyncio.run(human_dependency(human)) is human
    assert asyncio.run(workload_dependency(workload)) is workload
    with pytest.raises(HTTPException, match="human MFA") as human_error:
        asyncio.run(human_dependency(workload))
    with pytest.raises(HTTPException, match="workload identity") as workload_error:
        asyncio.run(workload_dependency(human))
    assert human_error.value.status_code == 403
    assert workload_error.value.status_code == 403


@pytest.mark.parametrize(
    ("claims", "message"),
    [
        (_claims(iat=NOW - 1000, exp=NOW + 100), "lifetime exceeds policy"),
        (_claims(iat=NOW + 120, exp=NOW + 300), "registered claims are invalid"),
        (_claims(sub=""), "subject is invalid"),
        (_claims(jti="short"), "token identifier is invalid"),
        (_claims(safe_qa_principal_type="robot"), "principal type"),
        (_claims(scope={"not": "a string or list"}), "scope claim has an invalid type"),
        (_claims(groups=[""]), "groups claim contains an invalid value"),
    ],
)
def test_identity_claim_shape_and_lifetime_fail_closed(
    rsa_keys, claims: dict[str, object], message: str
) -> None:
    private_key, _public_key = rsa_keys
    with pytest.raises(IdentityVerificationError, match=message):
        verify_oidc_token(_token(private_key, claims=claims))


def test_token_size_missing_kid_and_malformed_jwt_fail_before_jwks(
    rsa_keys, monkeypatch: pytest.MonkeyPatch
) -> None:
    private_key, _public_key = rsa_keys
    with pytest.raises(IdentityVerificationError, match="size is invalid"):
        verify_oidc_token("x" * 32_769)
    with pytest.raises(IdentityVerificationError, match="not a valid JWT"):
        verify_oidc_token("not-a-jwt")

    token = jwt.encode(_claims(), private_key, algorithm="RS256", headers={"typ": "JWT"})
    monkeypatch.setattr(
        identity,
        "_jwks_client",
        lambda _url: pytest.fail("missing kid must fail before JWKS"),
    )
    with pytest.raises(IdentityVerificationError, match="key identifier is missing"):
        verify_oidc_token(token)


class _JwkCache:
    def __init__(self) -> None:
        self.value: object | None = None

    def put(self, value: object) -> None:
        self.value = value


class _PyJWKClient:
    def __init__(self, uri: str, **kwargs: object) -> None:
        self.uri = uri
        self.headers: dict[str, str] = {}
        self.timeout = kwargs["timeout"]
        self.jwk_set_cache = _JwkCache()


class _Response:
    def __init__(self, raw: bytes, *, url: str = JWKS_URL) -> None:
        self.raw = raw
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def geturl(self) -> str:
        return self.url

    def read(self, maximum: int) -> bytes:
        return self.raw


def test_strict_jwks_client_accepts_only_bounded_nonredirected_key_sets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(identity, "_jwt_module", lambda: SimpleNamespace(PyJWKClient=_PyJWKClient))
    response = _Response(json.dumps({"keys": [{"kid": "key-1"}]}).encode())
    monkeypatch.setattr(
        identity.urllib.request,
        "build_opener",
        lambda *handlers: SimpleNamespace(open=lambda request, timeout: response),
    )
    ORIGINAL_JWKS_CLIENT.cache_clear()

    client = ORIGINAL_JWKS_CLIENT(JWKS_URL)
    assert client.fetch_data() == {"keys": [{"kid": "key-1"}]}
    assert client.jwk_set_cache.value == {"keys": [{"kid": "key-1"}]}


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (_Response(b"{}", url="https://redirect.example.test/jwks"), "redirected"),
        (_Response(b"x" * 512_001), "safety bound"),
        (_Response(b"{"), "malformed"),
        (_Response(b'{"keys":[]}'), "empty or oversized"),
    ],
)
def test_strict_jwks_client_rejects_bad_responses(
    monkeypatch: pytest.MonkeyPatch, response: _Response, message: str
) -> None:
    monkeypatch.setattr(identity, "_jwt_module", lambda: SimpleNamespace(PyJWKClient=_PyJWKClient))
    monkeypatch.setattr(
        identity.urllib.request,
        "build_opener",
        lambda *handlers: SimpleNamespace(open=lambda request, timeout: response),
    )
    ORIGINAL_JWKS_CLIENT.cache_clear()

    with pytest.raises(IdentityVerificationError, match=message):
        ORIGINAL_JWKS_CLIENT(JWKS_URL).fetch_data()


def test_strict_jwks_client_closes_network_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(identity, "_jwt_module", lambda: SimpleNamespace(PyJWKClient=_PyJWKClient))

    def fail(request: object, timeout: float) -> None:
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(
        identity.urllib.request,
        "build_opener",
        lambda *handlers: SimpleNamespace(open=fail),
    )
    ORIGINAL_JWKS_CLIENT.cache_clear()
    with pytest.raises(IdentityVerificationError, match="retrieval failed"):
        ORIGINAL_JWKS_CLIENT(JWKS_URL).fetch_data()
