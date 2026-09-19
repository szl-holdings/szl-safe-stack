from __future__ import annotations

import hmac
import json
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Mapping

from . import __version__
from .config import GatewayConfig
from .evaluator import BUILTIN_CASES, EvaluationProviderError, EvidenceEvaluator
from .ledger import LedgerError, LedgerIntegrityError, LedgerUnavailableError, ReceiptLedger
from .schemas import EvidenceRequest, SchemaError


class _DuplicateHeader(ValueError):
    pass


def _single_header(headers: Mapping[str, str], name: str) -> str | None:
    values = [
        value
        for key, value in headers.items()
        if isinstance(key, str) and key.casefold() == name.casefold()
    ]
    if len(values) > 1:
        raise _DuplicateHeader(name)
    if not values:
        return None
    return values[0] if isinstance(values[0], str) else None


@dataclass
class GatewayService:
    config: GatewayConfig
    ledger: ReceiptLedger
    evaluator: EvidenceEvaluator

    def handle(
        self, method: str, path: str, headers: Mapping[str, str], body: bytes = b""
    ) -> tuple[int, dict[str, object]]:
        if method == "GET" and path == "/health/live":
            return 200, {"schema_version": "szl.frontier.liveness.v1", "status": "ALIVE"}
        try:
            authorization = _single_header(headers, "Authorization")
        except _DuplicateHeader:
            return 400, self._error("DUPLICATE_SECURITY_HEADER")
        if not self._authorized(authorization):
            return 401, {
                "schema_version": "szl.frontier.error.v1",
                "error": "UNAUTHORIZED",
            }
        if method == "GET" and path == "/health/ready":
            try:
                ledger = self.ledger.verify()
            except LedgerIntegrityError:
                return 503, {
                    "schema_version": "szl.frontier.readiness.v1",
                    "status": "NOT_READY",
                    "ledger": "INTEGRITY_FAILURE",
                    "provider_capability_is_readiness": False,
                }
            except LedgerUnavailableError:
                return 503, {
                    "schema_version": "szl.frontier.readiness.v1",
                    "status": "NOT_READY",
                    "ledger": "UNAVAILABLE",
                    "provider_capability_is_readiness": False,
                }
            return 200, {
                "schema_version": "szl.frontier.readiness.v1",
                "status": "READY",
                "scope": "gateway_and_receipt_ledger_only",
                "ledger": ledger,
                "provider_capability_is_readiness": False,
            }
        if method == "GET" and path == "/v1/capabilities":
            return 200, self.config.public_capabilities()
        if method == "GET" and path == "/v1/cases":
            return 200, {
                "schema_version": "szl.frontier.builtin_cases.v1",
                "case_ids": sorted(BUILTIN_CASES),
            }
        if method == "POST" and path == "/v1/evaluate":
            try:
                raw_content_type = _single_header(headers, "Content-Type") or ""
            except _DuplicateHeader:
                return 400, self._error("DUPLICATE_SECURITY_HEADER")
            content_type = raw_content_type.split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                return 415, self._error("CONTENT_TYPE_REQUIRED")
            if len(body) > self.config.max_request_bytes:
                return 413, self._error("REQUEST_TOO_LARGE")
            try:
                decoded = json.loads(body.decode("utf-8"))
                request = EvidenceRequest.parse(decoded)
                return 200, self.evaluator.evaluate(request)
            except (UnicodeDecodeError, json.JSONDecodeError):
                return 400, self._error("INVALID_JSON")
            except SchemaError as exc:
                return 422, self._error("SCHEMA_REJECTED", str(exc))
            except EvaluationProviderError as exc:
                payload = self._error("PROVIDER_FAILURE", str(exc))
                payload["receipt"] = exc.receipt
                return 502, payload
            except LedgerError:
                return 503, self._error("LEDGER_FAILURE")
        return 404, self._error("NOT_FOUND")

    def _authorized(self, header: str | None) -> bool:
        token = self.config.bearer_token
        if not token or not header:
            return False
        scheme, separator, candidate = header.partition(" ")
        if separator != " " or scheme.casefold() != "bearer":
            return False
        return bool(candidate) and hmac.compare_digest(candidate.encode("utf-8"), token.encode("utf-8"))

    @staticmethod
    def _error(code: str, detail: str | None = None) -> dict[str, object]:
        result: dict[str, object] = {"schema_version": "szl.frontier.error.v1", "error": code}
        if detail:
            result["detail"] = detail
        return result


def _handler(service: GatewayService) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = f"SZLFrontierGateway/{__version__}"
        sys_version = ""

        def do_GET(self) -> None:
            if self._has_transfer_encoding():
                self._write(400, GatewayService._error("TRANSFER_ENCODING_NOT_SUPPORTED"))
                return
            raw_lengths = self.headers.get_all("Content-Length") or []
            if len(raw_lengths) > 1:
                self._write(400, GatewayService._error("MULTIPLE_CONTENT_LENGTH"))
                return
            if raw_lengths and raw_lengths[0] != "0":
                self._write(400, GatewayService._error("GET_BODY_NOT_SUPPORTED"))
                return
            self._dispatch(b"")

        def do_POST(self) -> None:
            if self._has_transfer_encoding():
                self._write(400, GatewayService._error("TRANSFER_ENCODING_NOT_SUPPORTED"))
                return
            raw_lengths = self.headers.get_all("Content-Length") or []
            if not raw_lengths:
                self._write(411, GatewayService._error("CONTENT_LENGTH_REQUIRED"))
                return
            if len(raw_lengths) > 1:
                self._write(400, GatewayService._error("MULTIPLE_CONTENT_LENGTH"))
                return
            raw_length = raw_lengths[0]
            if not raw_length.isascii() or not raw_length.isdigit():
                self._write(400, GatewayService._error("INVALID_CONTENT_LENGTH"))
                return
            length = int(raw_length)
            if length > service.config.max_request_bytes:
                self._write(413, GatewayService._error("REQUEST_TOO_LARGE"))
                return
            body = self.rfile.read(length)
            if len(body) != length:
                self._write(400, GatewayService._error("INCOMPLETE_REQUEST_BODY"))
                return
            self._dispatch(body)

        def _has_transfer_encoding(self) -> bool:
            return bool(self.headers.get_all("Transfer-Encoding"))

        def _dispatch(self, body: bytes) -> None:
            # HTTPMessage.items() preserves duplicate fields, which lets the
            # service reject duplicate Authorization and Content-Type headers.
            status, payload = service.handle(self.command, self.path, self.headers, body)  # type: ignore[arg-type]
            self._write(status, payload)

        def _write(self, status: int, payload: dict[str, object]) -> None:
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            self.close_connection = True
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


def serve(service: GatewayService) -> None:
    service.ledger.verify()
    server = ThreadingHTTPServer((service.config.bind, service.config.port), _handler(service))
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
