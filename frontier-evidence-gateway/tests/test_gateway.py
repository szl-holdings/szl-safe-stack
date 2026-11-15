from __future__ import annotations

import json
import os
import shutil
import sqlite3
import socket
import tempfile
import threading
import unittest
import urllib.request
import uuid
from contextlib import closing
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from frontier_gateway.config import ConfigurationError, GatewayConfig
from frontier_gateway.evaluator import EvidenceEvaluator
from frontier_gateway.ledger import (
    LedgerIntegrityError,
    LedgerUnavailableError,
    ReceiptLedger,
)
from frontier_gateway.providers import (
    OllamaProvider,
    ObservationProvider,
    OpenRouterProvider,
    ProviderError,
    ProviderResponseTooLarge,
    _NoRedirect,
    _request_json,
)
from frontier_gateway.schemas import ARTIFACT_VERSION, KINDS, REQUEST_VERSION, EvidenceRequest, SchemaError
from frontier_gateway.server import GatewayService, _handler


TOKEN = "test-token-that-is-at-least-thirty-two-bytes"


class FakeProvider(ObservationProvider):
    name = "ollama"
    model = "fixed-test-model"

    def observe(self, prompt: str) -> str:
        self.last_prompt = prompt
        return "The deployment and witness layers remain unverified."


def request_payload(provider: str = "none") -> dict[str, object]:
    return {
        "schema_version": REQUEST_VERSION,
        "request_id": str(uuid.uuid4()),
        "case_id": "deployment-readiness-gap",
        "provider": provider,
        "domain": "software_infrastructure",
    }


class GatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        env = {
            "SZL_GATEWAY_BEARER_TOKEN": TOKEN,
            "SZL_GATEWAY_DB": str(Path(self.temp.name) / "receipts.sqlite3"),
        }
        self.env_patch = patch.dict(os.environ, env, clear=True)
        self.env_patch.start()
        self.config = GatewayConfig.from_env(for_serve=True)
        self.ledger = ReceiptLedger(self.config.database_path)
        self.fake = FakeProvider()
        self.service = GatewayService(
            self.config,
            self.ledger,
            EvidenceEvaluator(self.ledger, {"ollama": self.fake}),
        )

    def tearDown(self) -> None:
        self.env_patch.stop()
        self.temp.cleanup()

    def auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

    def raw_http(self, request: bytes) -> bytes:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(self.service))
        server.timeout = 2
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        chunks: list[bytes] = []
        try:
            with socket.create_connection(server.server_address, timeout=2) as client:
                client.settimeout(2)
                client.sendall(request)
                while True:
                    part = client.recv(65_536)
                    if not part:
                        break
                    chunks.append(part)
        finally:
            thread.join(timeout=2)
            server.server_close()
        self.assertFalse(thread.is_alive())
        return b"".join(chunks)

    def test_serve_fails_closed_without_bearer_token(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ConfigurationError):
                GatewayConfig.from_env(for_serve=True)

    def test_sensitive_routes_require_auth(self) -> None:
        status, payload = self.service.handle("GET", "/health/ready", {})
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "UNAUTHORIZED")
        status, _ = self.service.handle("GET", "/health/live", {})
        self.assertEqual(status, 200)

    def test_auth_header_name_and_bearer_scheme_are_case_insensitive(self) -> None:
        status, _ = self.service.handle(
            "GET", "/health/ready", {"authorization": f"bearer {TOKEN}"}
        )
        self.assertEqual(status, 200)

    def test_duplicate_case_variant_auth_header_is_rejected(self) -> None:
        status, payload = self.service.handle(
            "GET",
            "/health/ready",
            {"Authorization": f"Bearer {TOKEN}", "authorization": f"Bearer {TOKEN}"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "DUPLICATE_SECURITY_HEADER")

    def test_http_duplicate_authorization_header_is_rejected(self) -> None:
        request = (
            b"GET /health/ready HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            + f"Authorization: Bearer {TOKEN}\r\n".encode()
            + f"Authorization: Bearer {TOKEN}\r\n".encode()
            + b"Connection: close\r\n\r\n"
        )
        response = self.raw_http(request)
        self.assertIn(b" 400 ", response.split(b"\r\n", 1)[0])
        self.assertIn(b"DUPLICATE_SECURITY_HEADER", response)

    def test_http_framing_rejects_missing_duplicate_or_transfer_lengths(self) -> None:
        base = (
            b"POST /v1/evaluate HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            + f"Authorization: Bearer {TOKEN}\r\n".encode()
            + b"Content-Type: application/json\r\n"
        )
        cases = (
            base + b"Connection: close\r\n\r\n",
            base + b"Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            base
            + b"Content-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
        )
        expected = (b" 411 ", b" 400 ", b" 400 ")
        for request, marker in zip(cases, expected, strict=True):
            with self.subTest(marker=marker):
                response = self.raw_http(request)
                self.assertIn(marker, response.split(b"\r\n", 1)[0])

    def test_exact_openrouter_origin_rejects_ssrf(self) -> None:
        with patch.dict(
            os.environ,
            {"SZL_OPENROUTER_ORIGIN": "https://127.0.0.1:8443", "SZL_GATEWAY_DB": str(Path(self.temp.name) / "x.db")},
            clear=True,
        ):
            with self.assertRaises(ConfigurationError):
                GatewayConfig.from_env()

    def test_ollama_origin_rejects_arbitrary_hosts(self) -> None:
        with patch.dict(os.environ, {"SZL_OLLAMA_ORIGIN": "http://169.254.169.254"}, clear=True):
            with self.assertRaises(ConfigurationError):
                GatewayConfig.from_env()

    def test_schema_rejects_non_software_domain_and_unknown_fields(self) -> None:
        value = request_payload()
        value["domain"] = "clinical"
        with self.assertRaises(SchemaError):
            EvidenceRequest.parse(value)

    def test_schema_rejects_unhashable_enum_values_as_schema_errors(self) -> None:
        for field in ("provider", "case_id"):
            value = request_payload()
            value[field] = []
            with self.subTest(field=field), self.assertRaises(SchemaError):
                EvidenceRequest.parse(value)
        value = request_payload()
        del value["case_id"]
        value["artifacts"] = [
            {
                "schema_version": ARTIFACT_VERSION,
                "artifact_id": "bad-kind",
                "kind": [],
                "status": "UNVERIFIED",
            }
        ]
        with self.assertRaises(SchemaError):
            EvidenceRequest.parse(value)

    def test_builtin_statuses_are_explicitly_unverified_fixtures(self) -> None:
        request = EvidenceRequest.parse(request_payload())
        result = self.service.evaluator.evaluate(request)
        evaluation = result["deterministic_evaluation"]
        self.assertEqual(evaluation["classification"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(
            evaluation["evidence_status_basis"], "BUILTIN_STATIC_UNVERIFIED_FIXTURE"
        )
        self.assertFalse(evaluation["external_artifacts_fetched"])

    def test_failed_evidence_prevents_complete_classification(self) -> None:
        value = request_payload()
        del value["case_id"]
        artifacts = [
            {
                "schema_version": ARTIFACT_VERSION,
                "artifact_id": f"verified-{kind}",
                "kind": kind,
                "status": "VERIFIED",
                "sha256": "a" * 64,
            }
            for kind in sorted(KINDS)
        ]
        artifacts.append(
            {
                "schema_version": ARTIFACT_VERSION,
                "artifact_id": "failed-source",
                "kind": "source",
                "status": "FAILED",
            }
        )
        value["artifacts"] = artifacts
        request = EvidenceRequest.parse(value)
        result = self.service.evaluator.evaluate(request)
        evaluation = result["deterministic_evaluation"]
        self.assertEqual(evaluation["classification"], "FAILED_EVIDENCE_PRESENT")
        self.assertEqual(evaluation["evidence_status_basis"], "CALLER_DECLARED_METADATA_ONLY")
        value = request_payload()
        value["prompt"] = "arbitrary prompt"
        with self.assertRaises(SchemaError):
            EvidenceRequest.parse(value)

    def test_request_size_limit(self) -> None:
        body = b"x" * (self.config.max_request_bytes + 1)
        status, payload = self.service.handle("POST", "/v1/evaluate", self.auth(), body)
        self.assertEqual(status, 413)
        self.assertEqual(payload["error"], "REQUEST_TOO_LARGE")

    def test_mocked_provider_output_is_unverified_and_not_receipt_content(self) -> None:
        body = json.dumps(request_payload("ollama")).encode()
        status, payload = self.service.handle("POST", "/v1/evaluate", self.auth(), body)
        self.assertEqual(status, 200)
        observation = payload["model_observation"]
        self.assertEqual(observation["status"], "UNVERIFIED_MODEL_OUTPUT")
        self.assertEqual(payload["deterministic_evaluation"]["deployment_authorization"], "NOT_GRANTED")
        with closing(sqlite3.connect(self.config.database_path)) as connection:
            stored = connection.execute("SELECT canonical_event FROM receipts").fetchone()[0]
        self.assertNotIn(observation["content"], stored)
        self.assertIn("content_stored\":false", stored)
        stored_event = json.loads(stored)
        self.assertEqual(stored_event["provider_model"], self.fake.model)
        self.assertRegex(stored_event["model_input_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(stored_event["model_output_sha256"], observation["content_sha256"])

    def test_readiness_is_distinct_from_provider_capability(self) -> None:
        status, payload = self.service.handle("GET", "/health/ready", self.auth())
        self.assertEqual(status, 200)
        self.assertEqual(payload["scope"], "gateway_and_receipt_ledger_only")
        self.assertFalse(payload["provider_capability_is_readiness"])
        status, capabilities = self.service.handle("GET", "/v1/capabilities", self.auth())
        self.assertEqual(status, 200)
        self.assertFalse(capabilities["providers"]["ollama"]["live_verified"])

    def test_readiness_fails_closed_when_ledger_is_unavailable(self) -> None:
        with patch.object(
            self.ledger,
            "verify",
            side_effect=LedgerUnavailableError("database unavailable"),
        ):
            status, payload = self.service.handle("GET", "/health/ready", self.auth())
        self.assertEqual(status, 503)
        self.assertEqual(payload["status"], "NOT_READY")
        self.assertEqual(payload["ledger"], "UNAVAILABLE")

    def test_readiness_reuses_verified_head_without_full_reverify(self) -> None:
        status, payload = self.service.handle("GET", "/health/ready", self.auth())
        self.assertEqual(status, 200)
        receipt = self.ledger.append({"event": "warm"})
        # append() re-verified the chain and refreshed the cached head, so
        # readiness must answer from the cache without a full re-verify.
        with patch.object(
            self.ledger, "verify", side_effect=AssertionError("full verify must not run")
        ):
            status, payload = self.service.handle("GET", "/health/ready", self.auth())
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "READY")
        self.assertEqual(payload["ledger"]["receipt_count"], 1)
        self.assertEqual(payload["ledger"]["head_hash"], receipt["event_hash"])
        self.assertEqual(payload["ledger"]["status"], "VERIFIED")

    def test_readiness_detects_external_tampering(self) -> None:
        self.ledger.append({"event": 1})
        status, _ = self.service.handle("GET", "/health/ready", self.auth())
        self.assertEqual(status, 200)
        # An external writer bypasses the append-only triggers; the changed
        # row count forces a full re-verification, which the forged row fails.
        with closing(sqlite3.connect(self.config.database_path)) as connection, connection:
            connection.execute(
                """INSERT INTO receipts(
                       sequence, event_id, created_at, previous_hash, event_hash,
                       canonical_event, hash_version
                   ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    2,
                    str(uuid.uuid4()),
                    "2026-01-01T00:00:00Z",
                    "0" * 64,
                    "f" * 64,
                    '{"event":"forged"}',
                    "szl.frontier.receipt_hash.v1",
                ),
            )
        status, payload = self.service.handle("GET", "/health/ready", self.auth())
        self.assertEqual(status, 503)
        self.assertEqual(payload["status"], "NOT_READY")
        self.assertEqual(payload["ledger"], "INTEGRITY_FAILURE")

    def test_readiness_accepts_external_valid_appends_then_reuses_cache(self) -> None:
        self.ledger.append({"event": 1})
        status, _ = self.service.handle("GET", "/health/ready", self.auth())
        self.assertEqual(status, 200)
        external = ReceiptLedger(self.config.database_path)
        appended = external.append({"event": 2})
        # The cached count no longer matches, so readiness falls back to a
        # full verification of the (valid) extended chain and reports it.
        status, payload = self.service.handle("GET", "/health/ready", self.auth())
        self.assertEqual(status, 200)
        self.assertEqual(payload["ledger"]["receipt_count"], 2)
        self.assertEqual(payload["ledger"]["head_hash"], appended["event_hash"])
        # The fallback re-primed the cache, so the next probe is O(1) again.
        with patch.object(
            self.ledger, "verify", side_effect=AssertionError("full verify must not run")
        ):
            status, payload = self.service.handle("GET", "/health/ready", self.auth())
        self.assertEqual(status, 200)
        self.assertEqual(payload["ledger"]["head_hash"], appended["event_hash"])

    def test_readiness_detects_swapped_ledger_file_with_unchanged_count(self) -> None:
        self.ledger.append({"event": 1})
        status, _ = self.service.handle("GET", "/health/ready", self.auth())
        self.assertEqual(status, 200)
        other_path = Path(self.temp.name) / "other.sqlite3"
        other = ReceiptLedger(other_path)
        other.append({"event": "swapped"})
        # Checkpoint both WAL journals so the swap cannot be replayed away.
        for path in (self.config.database_path, other_path):
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        shutil.copyfile(other_path, self.config.database_path)
        # Same row count, different valid chain: only the cached head
        # comparison catches the swap, and it fails closed.
        status, payload = self.service.handle("GET", "/health/ready", self.auth())
        self.assertEqual(status, 503)
        self.assertEqual(payload["status"], "NOT_READY")
        self.assertEqual(payload["ledger"], "INTEGRITY_FAILURE")

    def test_full_verification_endpoint_and_its_auth(self) -> None:
        status, payload = self.service.handle("GET", "/health/verify", {})
        self.assertEqual(status, 401)
        receipt = self.ledger.append({"event": 1})
        status, payload = self.service.handle("GET", "/health/verify", self.auth())
        self.assertEqual(status, 200)
        self.assertEqual(payload["schema_version"], "szl.frontier.full-verification.v1")
        self.assertEqual(payload["status"], "VERIFIED")
        self.assertEqual(payload["ledger"]["receipt_count"], 1)
        self.assertEqual(payload["ledger"]["head_hash"], receipt["event_hash"])
        with closing(sqlite3.connect(self.config.database_path)) as connection, connection:
            connection.execute("DROP TRIGGER receipts_no_update")
            connection.execute(
                "UPDATE receipts SET canonical_event = ? WHERE sequence = 1",
                ('{"event":"tampered"}',),
            )
        status, payload = self.service.handle("GET", "/health/verify", self.auth())
        self.assertEqual(status, 503)
        self.assertEqual(payload["schema_version"], "szl.frontier.full-verification.v1")
        self.assertEqual(payload["status"], "NOT_VERIFIED")
        self.assertEqual(payload["ledger"], "INTEGRITY_FAILURE")

    def test_hash_chain_binds_every_immutable_envelope_field(self) -> None:
        mutations: dict[str, object] = {
            "sequence": 7,
            "event_id": str(uuid.uuid4()),
            "created_at": "2000-01-01T00:00:00Z",
            "previous_hash": "1" * 64,
            "event_hash": "f" * 64,
            "canonical_event": '{"event":9}',
            "hash_version": "szl.frontier.receipt_hash.v999",
        }
        for column, replacement in mutations.items():
            with self.subTest(column=column), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "receipts.sqlite3"
                ledger = ReceiptLedger(path)
                receipt = ledger.append({"event": 1})
                ledger.append({"event": 2})
                self.assertEqual(receipt["hash_version"], "szl.frontier.receipt_hash.v1")
                self.assertEqual(ledger.verify()["receipt_count"], 2)
                with closing(sqlite3.connect(path)) as connection, connection:
                    connection.execute("DROP TRIGGER receipts_no_update")
                    connection.execute(
                        f"UPDATE receipts SET {column} = ? WHERE sequence = 1",
                        (replacement,),
                    )
                with self.assertRaises(LedgerIntegrityError):
                    ledger.verify()

    def test_legacy_unbound_receipts_are_migrated_but_fail_closed(self) -> None:
        path = Path(self.temp.name) / "legacy.sqlite3"
        with closing(sqlite3.connect(path)) as connection, connection:
            connection.executescript(
                """
                CREATE TABLE receipts (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE,
                    canonical_event TEXT NOT NULL
                );
                """
            )
            connection.execute(
                """INSERT INTO receipts(
                       event_id, created_at, previous_hash, event_hash, canonical_event
                   ) VALUES (?, ?, ?, ?, ?)""",
                (
                    str(uuid.uuid4()),
                    "2026-09-05T00:00:00Z",
                    "0" * 64,
                    "1" * 64,
                    '{"event":"legacy"}',
                ),
            )
        ledger = ReceiptLedger(path)
        with self.assertRaisesRegex(LedgerIntegrityError, "unsupported hash version"):
            ledger.verify()

    def test_provider_body_limit(self) -> None:
        class Headers:
            def get(self, key: str):
                return None

        class Response:
            headers = Headers()
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def read(self, limit: int) -> bytes: return b"x" * limit

        class Opener:
            def open(self, request, timeout): return Response()

        with patch("frontier_gateway.providers.urllib.request.build_opener", return_value=Opener()):
            with self.assertRaises(ProviderResponseTooLarge):
                _request_json(
                    url="http://127.0.0.1:11434/api/generate",
                    payload={},
                    headers={},
                    timeout_seconds=1,
                    max_response_bytes=4096,
                )

    def test_provider_transport_disables_environment_proxies_and_redirects(self) -> None:
        class Headers:
            def get_all(self, key: str):
                if key == "Content-Length":
                    return ["2"]
                if key == "Content-Type":
                    return ["application/json"]
                return None

        class Response:
            headers = Headers()

            def __enter__(self): return self
            def __exit__(self, *args): return None
            def read(self, limit: int) -> bytes: return b"{}"

        class Opener:
            def open(self, request, timeout): return Response()

        handlers: tuple[object, ...] = ()

        def build_opener(*values):
            nonlocal handlers
            handlers = values
            return Opener()

        with patch(
            "frontier_gateway.providers.urllib.request.build_opener",
            side_effect=build_opener,
        ):
            self.assertEqual(
                _request_json(
                    url="http://127.0.0.1:11434/api/generate",
                    payload={},
                    headers={},
                    timeout_seconds=1,
                    max_response_bytes=4096,
                ),
                {},
            )
        proxy_handlers = [
            item for item in handlers if isinstance(item, urllib.request.ProxyHandler)
        ]
        self.assertEqual(len(proxy_handlers), 1)
        self.assertEqual(proxy_handlers[0].proxies, {})
        with self.assertRaises(ProviderError):
            _NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://example.com")

    def test_disabled_openrouter_does_not_retain_an_ambient_key(self) -> None:
        with patch.dict(
            os.environ,
            {
                "OPENROUTER_API_KEY": "ambient-secret-that-must-not-be-retained",
                "SZL_GATEWAY_DB": str(Path(self.temp.name) / "disabled-key.db"),
            },
            clear=True,
        ):
            config = GatewayConfig.from_env()
        self.assertFalse(config.openrouter_enabled)
        self.assertIsNone(config.openrouter_api_key)

    def test_openrouter_key_rejects_whitespace_and_control_characters(self) -> None:
        with patch.dict(
            os.environ,
            {
                "SZL_ENABLE_OPENROUTER": "true",
                "SZL_OPENROUTER_MODEL": "provider/model",
                "OPENROUTER_API_KEY": "invalid key with spaces",
            },
            clear=True,
        ):
            with self.assertRaises(ConfigurationError):
                GatewayConfig.from_env()

    def test_generation_token_cap_defaults_accepts_bounds_and_rejects_invalid_env(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(GatewayConfig.from_env().generation_token_cap, 256)
        for raw, expected in (("16", 16), ("512", 512)):
            with self.subTest(raw=raw), patch.dict(
                os.environ, {"SZL_MAX_GENERATION_TOKENS": raw}, clear=True
            ):
                self.assertEqual(GatewayConfig.from_env().generation_token_cap, expected)
        for raw in ("", "15", "513", "256.0", "not-an-integer"):
            with self.subTest(raw=raw), patch.dict(
                os.environ, {"SZL_MAX_GENERATION_TOKENS": raw}, clear=True
            ):
                with self.assertRaises(ConfigurationError):
                    GatewayConfig.from_env()

    def test_generation_token_cap_is_applied_to_both_provider_payloads(self) -> None:
        calls: list[dict[str, object]] = []

        def request_json(**kwargs):
            calls.append(kwargs)
            if str(kwargs["url"]).endswith("/api/generate"):
                return {"response": "bounded Ollama observation"}
            return {
                "choices": [
                    {"message": {"content": "bounded OpenRouter observation"}}
                ]
            }

        providers = (
            OllamaProvider(
                origin="http://127.0.0.1:11434",
                model="fixed-ollama-model",
                timeout_seconds=1,
                max_response_bytes=4096,
                generation_token_cap=321,
            ),
            OpenRouterProvider(
                origin="https://openrouter.ai",
                model="provider/fixed-model",
                api_key="test-api-key-that-is-not-sent",
                timeout_seconds=1,
                max_response_bytes=4096,
                generation_token_cap=321,
            ),
        )
        with patch("frontier_gateway.providers._request_json", side_effect=request_json):
            for provider in providers:
                provider.observe("fixed test prompt")
        self.assertEqual(calls[0]["payload"]["options"]["num_predict"], 321)
        self.assertEqual(calls[1]["payload"]["max_tokens"], 321)

    def test_provider_constructors_reject_invalid_generation_token_caps(self) -> None:
        for invalid in (True, 15, 513, "256"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    OllamaProvider(
                        origin="http://127.0.0.1:11434",
                        model="fixed-model",
                        timeout_seconds=1,
                        max_response_bytes=4096,
                        generation_token_cap=invalid,  # type: ignore[arg-type]
                    )
                with self.assertRaises(ValueError):
                    OpenRouterProvider(
                        origin="https://openrouter.ai",
                        model="provider/fixed-model",
                        api_key="test-api-key-that-is-not-sent",
                        timeout_seconds=1,
                        max_response_bytes=4096,
                        generation_token_cap=invalid,  # type: ignore[arg-type]
                    )


if __name__ == "__main__":
    unittest.main()
