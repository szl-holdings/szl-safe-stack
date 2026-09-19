from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


class ConfigurationError(ValueError):
    """Raised when a security-relevant setting is missing or unsafe."""


_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$")
_BEARER_TOKEN_RE = re.compile(r"^[A-Za-z0-9._~+/=-]{32,512}$")
_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}
OPENROUTER_ORIGIN = "https://openrouter.ai"
LOOPBACK_OLLAMA_ORIGIN = "http://127.0.0.1:11434"
DOCKER_OLLAMA_ORIGIN = "http://host.docker.internal:11434"
MIN_GENERATION_TOKEN_CAP = 16
DEFAULT_GENERATION_TOKEN_CAP = 256
MAX_GENERATION_TOKEN_CAP = 512


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in _TRUE:
        return True
    if normalized in _FALSE:
        return False
    raise ConfigurationError(f"{name} must be an explicit boolean")


def _int_env(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return value


def _validate_exact_origin(value: str, *, provider: str, allow_docker_host: bool = False) -> str:
    parsed = urlsplit(value)
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ConfigurationError(f"{provider} origin must contain only scheme, host, and port")
    normalized = value[:-1] if value.endswith("/") else value
    if provider == "openrouter":
        if normalized != OPENROUTER_ORIGIN:
            raise ConfigurationError("OpenRouter origin is pinned to https://openrouter.ai")
        return normalized
    allowed = {LOOPBACK_OLLAMA_ORIGIN}
    if allow_docker_host:
        allowed.add(DOCKER_OLLAMA_ORIGIN)
    if normalized not in allowed:
        raise ConfigurationError("Ollama origin must be exact loopback, or the explicitly enabled Docker host alias")
    return normalized


def _validate_model(name: str, env_name: str) -> str:
    if not _MODEL_RE.fullmatch(name) or ".." in name:
        raise ConfigurationError(f"{env_name} is not a valid fixed model identifier")
    return name


def _validate_openrouter_key(value: str) -> str:
    if not 16 <= len(value) <= 2_048 or any(character.isspace() for character in value):
        raise ConfigurationError(
            "OPENROUTER_API_KEY must be 16 to 2048 non-whitespace characters"
        )
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in value):
        raise ConfigurationError("OPENROUTER_API_KEY must contain printable ASCII only")
    return value


@dataclass(frozen=True)
class GatewayConfig:
    bearer_token: str | None
    bind: str
    port: int
    database_path: Path
    max_request_bytes: int
    max_provider_response_bytes: int
    provider_timeout_seconds: int
    generation_token_cap: int
    ollama_enabled: bool
    ollama_origin: str
    ollama_model: str
    openrouter_enabled: bool
    openrouter_origin: str
    openrouter_model: str | None
    openrouter_api_key: str | None

    @classmethod
    def from_env(cls, *, for_serve: bool = False) -> "GatewayConfig":
        allow_docker_host = _bool_env("SZL_ALLOW_DOCKER_HOST_OLLAMA", False)
        ollama_origin = _validate_exact_origin(
            os.getenv("SZL_OLLAMA_ORIGIN", LOOPBACK_OLLAMA_ORIGIN).strip(),
            provider="ollama",
            allow_docker_host=allow_docker_host,
        )
        configured_openrouter_origin = os.getenv("SZL_OPENROUTER_ORIGIN", OPENROUTER_ORIGIN).strip()
        openrouter_origin = _validate_exact_origin(configured_openrouter_origin, provider="openrouter")
        openrouter_enabled = _bool_env("SZL_ENABLE_OPENROUTER", False)
        openrouter_model_raw = os.getenv("SZL_OPENROUTER_MODEL")
        openrouter_model = (
            _validate_model(openrouter_model_raw.strip(), "SZL_OPENROUTER_MODEL")
            if openrouter_model_raw
            else None
        )
        openrouter_key_raw = os.getenv("OPENROUTER_API_KEY")
        if openrouter_enabled and (not openrouter_key_raw or not openrouter_model):
            raise ConfigurationError(
                "OpenRouter opt-in requires OPENROUTER_API_KEY and SZL_OPENROUTER_MODEL"
            )
        openrouter_key = (
            _validate_openrouter_key(openrouter_key_raw) if openrouter_enabled else None
        )

        bearer_token = os.getenv("SZL_GATEWAY_BEARER_TOKEN")
        if for_serve and (
            not bearer_token or _BEARER_TOKEN_RE.fullmatch(bearer_token) is None
        ):
            raise ConfigurationError(
                "serve requires SZL_GATEWAY_BEARER_TOKEN with 32 to 512 bearer-safe ASCII characters"
            )

        bind = os.getenv("SZL_GATEWAY_BIND", "127.0.0.1").strip()
        try:
            is_loopback = ipaddress.ip_address(bind).is_loopback
        except ValueError as exc:
            raise ConfigurationError("SZL_GATEWAY_BIND must be a literal IP address") from exc
        if not is_loopback and not _bool_env("SZL_ALLOW_NON_LOOPBACK_BIND", False):
            raise ConfigurationError("non-loopback bind requires SZL_ALLOW_NON_LOOPBACK_BIND=true")

        return cls(
            bearer_token=bearer_token,
            bind=bind,
            port=_int_env("SZL_GATEWAY_PORT", 8787, 1, 65535),
            database_path=Path(os.getenv("SZL_GATEWAY_DB", "var/frontier-receipts.sqlite3")),
            max_request_bytes=_int_env("SZL_MAX_REQUEST_BYTES", 65_536, 1_024, 262_144),
            max_provider_response_bytes=_int_env(
                "SZL_MAX_PROVIDER_RESPONSE_BYTES", 262_144, 4_096, 1_048_576
            ),
            provider_timeout_seconds=_int_env("SZL_PROVIDER_TIMEOUT_SECONDS", 10, 1, 30),
            generation_token_cap=_int_env(
                "SZL_MAX_GENERATION_TOKENS",
                DEFAULT_GENERATION_TOKEN_CAP,
                MIN_GENERATION_TOKEN_CAP,
                MAX_GENERATION_TOKEN_CAP,
            ),
            ollama_enabled=_bool_env("SZL_ENABLE_OLLAMA", True),
            ollama_origin=ollama_origin,
            ollama_model=_validate_model(
                os.getenv("SZL_OLLAMA_MODEL", "szl-nemo:latest").strip(), "SZL_OLLAMA_MODEL"
            ),
            openrouter_enabled=openrouter_enabled,
            openrouter_origin=openrouter_origin,
            openrouter_model=openrouter_model,
            openrouter_api_key=openrouter_key,
        )

    def public_capabilities(self) -> dict[str, object]:
        return {
            "schema_version": "szl.frontier.capabilities.v1",
            "readiness_scope": "gateway_and_receipt_ledger_only",
            "generation_token_cap": self.generation_token_cap,
            "providers": {
                "ollama": {
                    "configured": self.ollama_enabled,
                    "model": self.ollama_model if self.ollama_enabled else None,
                    "live_verified": False,
                },
                "openrouter": {
                    "configured": self.openrouter_enabled,
                    "model": self.openrouter_model if self.openrouter_enabled else None,
                    "live_verified": False,
                },
            },
            "claims": {
                "clinical_or_biological": "NOT_SUPPORTED",
                "model_promotion": "NOT_SUPPORTED",
                "deployment": "NOT_PERFORMED",
            },
        }
