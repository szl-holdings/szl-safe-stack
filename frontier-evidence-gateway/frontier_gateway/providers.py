from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from .config import MAX_GENERATION_TOKEN_CAP, MIN_GENERATION_TOKEN_CAP


class ProviderError(RuntimeError):
    """A sanitized provider failure safe to return to an authenticated caller."""


class ProviderResponseTooLarge(ProviderError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise ProviderError("provider redirect refused")


def _response_header_values(headers: object, name: str) -> list[str]:
    get_all = getattr(headers, "get_all", None)
    if callable(get_all):
        values = get_all(name)
        return [str(value) for value in values] if values else []
    get = getattr(headers, "get", None)
    value = get(name) if callable(get) else None
    return [str(value)] if value is not None else []


def _request_json(
    *,
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str],
    timeout_seconds: int,
    max_response_bytes: int,
) -> dict[str, Any]:
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=encoded,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json", **headers},
    )
    # Do not inherit HTTP(S)_PROXY from the process environment. Inheriting it
    # would move a bearer credential across a network boundary the operator did
    # not select in this gateway's exact-origin policy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            content_lengths = _response_header_values(response.headers, "Content-Length")
            if len(content_lengths) > 1:
                raise ProviderError("provider returned multiple Content-Length headers")
            if content_lengths:
                try:
                    content_length = int(content_lengths[0])
                    if content_length < 0:
                        raise ValueError
                    if content_length > max_response_bytes:
                        raise ProviderResponseTooLarge("provider response exceeded configured limit")
                except ValueError:
                    raise ProviderError("provider returned an invalid Content-Length")
            content_types = _response_header_values(response.headers, "Content-Type")
            if len(content_types) > 1:
                raise ProviderError("provider returned multiple Content-Type headers")
            if content_types:
                media_type = content_types[0].split(";", 1)[0].strip().lower()
                if media_type != "application/json":
                    raise ProviderError("provider returned a non-JSON Content-Type")
            body = response.read(max_response_bytes + 1)
    except ProviderError:
        raise
    except urllib.error.HTTPError as exc:
        raise ProviderError(f"provider returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ProviderError("provider unavailable or timed out") from exc
    if len(body) > max_response_bytes:
        raise ProviderResponseTooLarge("provider response exceeded configured limit")
    try:
        decoded = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderError("provider returned invalid JSON") from exc
    if not isinstance(decoded, dict):
        raise ProviderError("provider response must be a JSON object")
    return decoded


class ObservationProvider:
    name: str
    model: str

    def observe(self, prompt: str) -> str:
        raise NotImplementedError


@dataclass(frozen=True)
class OllamaProvider(ObservationProvider):
    origin: str
    model: str
    timeout_seconds: int
    max_response_bytes: int
    generation_token_cap: int
    name: str = "ollama"

    def __post_init__(self) -> None:
        _validate_generation_token_cap(self.generation_token_cap)

    def observe(self, prompt: str) -> str:
        decoded = _request_json(
            url=f"{self.origin}/api/generate",
            payload={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0,
                    "num_predict": self.generation_token_cap,
                },
            },
            headers={},
            timeout_seconds=self.timeout_seconds,
            max_response_bytes=self.max_response_bytes,
        )
        content = decoded.get("response")
        if not isinstance(content, str) or not content.strip():
            raise ProviderError("Ollama response did not contain text")
        return content[:16_384]


@dataclass(frozen=True)
class OpenRouterProvider(ObservationProvider):
    origin: str
    model: str
    api_key: str
    timeout_seconds: int
    max_response_bytes: int
    generation_token_cap: int
    name: str = "openrouter"

    def __post_init__(self) -> None:
        _validate_generation_token_cap(self.generation_token_cap)

    def observe(self, prompt: str) -> str:
        decoded = _request_json(
            url=f"{self.origin}/api/v1/chat/completions",
            payload={
                "model": self.model,
                "temperature": 0,
                "max_tokens": self.generation_token_cap,
                "messages": [
                    {
                        "role": "system",
                        "content": "Classify only software evidence. Never approve deployment, model promotion, or clinical or biological claims.",
                    },
                    {"role": "user", "content": prompt},
                ],
            },
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout_seconds=self.timeout_seconds,
            max_response_bytes=self.max_response_bytes,
        )
        try:
            content = decoded["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError("OpenRouter response did not contain text") from exc
        if not isinstance(content, str) or not content.strip():
            raise ProviderError("OpenRouter response did not contain text")
        return content[:16_384]


def _validate_generation_token_cap(value: int) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not MIN_GENERATION_TOKEN_CAP <= value <= MAX_GENERATION_TOKEN_CAP
    ):
        raise ValueError(
            "generation_token_cap must be an integer between "
            f"{MIN_GENERATION_TOKEN_CAP} and {MAX_GENERATION_TOKEN_CAP}"
        )
