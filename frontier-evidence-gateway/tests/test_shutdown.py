"""Deterministic shutdown tests: temporary ledgers and ephemeral loopback only."""
from __future__ import annotations

from dataclasses import replace
import json
import math
import os
from pathlib import Path
import queue
import signal
import socket
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid


# Support explicit `python -I -B tests/test_shutdown.py` without installation.
GATEWAY_ROOT = Path(__file__).resolve().parents[1]
if str(GATEWAY_ROOT) not in sys.path:
    sys.path.insert(0, str(GATEWAY_ROOT))

from frontier_gateway.config import GatewayConfig
from frontier_gateway.evaluator import EvidenceEvaluator
from frontier_gateway.ledger import ReceiptLedger
from frontier_gateway.providers import ObservationProvider, ProviderError
from frontier_gateway.schemas import REQUEST_VERSION
from frontier_gateway import server as server_module


TOKEN = "shutdown-test-token-at-least-thirty-two-bytes"
WAIT = 5.0


class BarrierProvider(ObservationProvider):
    name = "ollama"
    model = "synthetic-shutdown-model"

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.calls = 0
        self.failure = False

    def observe(self, prompt: str) -> str:
        self.calls += 1
        self.entered.set()
        if not self.release.wait(WAIT):
            raise AssertionError("TEST_PROVIDER_BARRIER_NOT_RELEASED")
        if self.failure:
            raise ProviderError("synthetic provider failure")
        return "Synthetic offline observation only."


def request_bytes(provider: str = "ollama") -> bytes:
    body = json.dumps({"schema_version": REQUEST_VERSION,
                       "request_id": str(uuid.uuid4()), "case_id": "receipt-integrity",
                       "provider": provider, "domain": "software_infrastructure"}).encode()
    return (b"POST /v1/evaluate HTTP/1.1\r\nHost: localhost\r\n"
            + f"Authorization: Bearer {TOKEN}\r\n".encode()
            + b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)


def receive_all(client: socket.socket) -> bytes:
    parts = []
    while True:
        part = client.recv(65_536)
        if not part:
            return b"".join(parts)
        parts.append(part)


class TransportShutdownTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="szl-shutdown-test-")
        self.addCleanup(self.temp.cleanup)
        with patch.dict(os.environ, {"SZL_GATEWAY_BEARER_TOKEN": TOKEN,
                                     "SZL_GATEWAY_DB": str(Path(self.temp.name) / "receipts.sqlite3")}, clear=True):
            self.config = replace(GatewayConfig.from_env(for_serve=True), port=0)
        self.ledger = ReceiptLedger(self.config.database_path)
        self.provider = BarrierProvider()
        self.service = server_module.GatewayService(
            self.config, self.ledger, EvidenceEvaluator(self.ledger, {"ollama": self.provider}))
        guard = patch("frontier_gateway.providers._request_json",
                      side_effect=AssertionError("LIVE_PROVIDER_FORBIDDEN"))
        guard.start()
        self.addCleanup(guard.stop)
        self.addCleanup(self.provider.release.set)
        self.servers = []

    def start(self, handler=None):
        class ObservedServer(server_module._DrainingHTTPServer):
            # Keep test transport fallback strictly inside the five-second
            # orchestration bound even when Windows SHUT_RD races recv/select.
            socket_timeout = 0.35

            def __init__(self, *args, **kwargs):
                self.worker_entered = threading.Event()
                self.worker_exited = threading.Event()
                self.worker_socket = None
                self.worker_daemon = None
                self.worker_errors = []
                super().__init__(*args, **kwargs)

            def process_request_thread(self, request, client_address):
                self.worker_socket = request
                self.worker_daemon = threading.current_thread().daemon
                self.worker_entered.set()
                try:
                    super().process_request_thread(request, client_address)
                finally:
                    self.worker_exited.set()

            def handle_error(self, request, client_address):
                self.worker_errors.append(sys.exc_info()[1])

        server = ObservedServer(("127.0.0.1", 0), handler or server_module._handler(self.service))
        server.timeout = 0.2
        accept_errors = []
        def accept_one():
            try:
                server.handle_request()
            except Exception as exc:
                accept_errors.append(exc)
        accept_thread = threading.Thread(target=accept_one, daemon=True)
        accept_thread.start()
        self.servers.append(server)
        def cleanup():
            self.provider.release.set()
            server.begin_shutdown()
            accept_thread.join(WAIT)
            closer = threading.Thread(target=server.server_close, daemon=True)
            closer.start()
            closer.join(WAIT)
            self.assertFalse(accept_thread.is_alive(), "accept loop did not return")
            self.assertFalse(closer.is_alive(), "server_close did not return")
        self.addCleanup(cleanup)
        client = socket.create_connection(server.server_address, timeout=WAIT)
        client.settimeout(WAIT)
        self.addCleanup(client.close)
        self.assertTrue(server.worker_entered.wait(WAIT), "accepted worker never started")
        return server, client, accept_thread, accept_errors

    def drain(self, server):
        done, errors = threading.Event(), []
        def close():
            try:
                server.server_close()
            except Exception as exc:
                errors.append(exc)
            finally:
                done.set()
        closer = threading.Thread(target=close, daemon=True)
        closer.start()
        return closer, done, errors

    def test_workers_are_non_daemon_and_socket_transport_timeout_is_finite(self):
        self.assertEqual(server_module._DrainingHTTPServer.socket_timeout, 5.0)
        server, _, _, _ = self.start()
        self.assertIs(server.daemon_threads, False)
        self.assertIs(server.block_on_close, True)
        self.assertIs(server.worker_daemon, False)
        timeout = server.worker_socket.gettimeout()
        self.assertIsInstance(timeout, (int, float))
        self.assertTrue(math.isfinite(timeout))
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 60)
        server.begin_shutdown()
        self.assertTrue(server.worker_exited.wait(WAIT))

    def test_admitted_provider_work_drains_to_one_receipt_after_shutdown(self):
        server, client, accept_thread, accept_errors = self.start()
        client.sendall(request_bytes())
        self.assertTrue(self.provider.entered.wait(WAIT))
        self.assertEqual(self.ledger.verify()["receipt_count"], 0)
        directions = []
        original_shutdown = socket.socket.shutdown
        def shutdown(request, direction):
            if request is server.worker_socket:
                directions.append(direction)
            return original_shutdown(request, direction)
        with patch.object(socket.socket, "shutdown", shutdown):
            server.begin_shutdown()
            server.begin_shutdown()
        self.assertNotIn(socket.SHUT_RD, directions)
        self.assertTrue(server.stop_requested)
        self.assertEqual(server.socket.fileno(), -1)
        closer, done, errors = self.drain(server)
        # Exceed the configured transport timeout: it must not become an
        # application/provider execution deadline.
        self.assertFalse(done.wait(server.socket_timeout + 0.1),
                         "server_close abandoned admitted service work")
        self.assertEqual(self.ledger.verify()["receipt_count"], 0)
        self.provider.release.set()
        response = receive_all(client)
        self.assertTrue(done.wait(WAIT))
        closer.join(WAIT)
        accept_thread.join(WAIT)
        self.assertFalse(closer.is_alive())
        self.assertEqual(errors + accept_errors + server.worker_errors, [])
        self.assertIn(b" 200 ", response.split(b"\r\n", 1)[0])
        payload = json.loads(response.split(b"\r\n\r\n", 1)[1])
        proof = self.ledger.verify()
        self.assertEqual(proof["receipt_count"], 1)
        self.assertEqual(payload["receipt"]["event_hash"], proof["head_hash"])
        self.assertEqual(self.provider.calls, 1)

    def test_admitted_provider_failure_still_finishes_one_failure_receipt(self):
        self.provider.failure = True
        server, client, _, _ = self.start()
        client.sendall(request_bytes())
        self.assertTrue(self.provider.entered.wait(WAIT))
        server.begin_shutdown()
        closer, done, errors = self.drain(server)
        self.assertFalse(done.wait(0.05))
        self.provider.release.set()
        response = receive_all(client)
        self.assertTrue(done.wait(WAIT))
        closer.join(WAIT)
        self.assertEqual(errors + server.worker_errors, [])
        self.assertIn(b" 502 ", response.split(b"\r\n", 1)[0])
        self.assertEqual(self.ledger.verify()["receipt_count"], 1)
        self.assertEqual(self.provider.calls, 1)

    def test_response_write_remains_joined_after_service_handle_finishes(self):
        writing, release_write = threading.Event(), threading.Event()
        self.addCleanup(release_write.set)
        base = server_module._handler(self.service)
        class WriteBarrierHandler(base):
            def _write(self, status, payload):
                writing.set()
                if not release_write.wait(WAIT):
                    raise AssertionError("TEST_RESPONSE_BARRIER_NOT_RELEASED")
                return super()._write(status, payload)
        server, client, _, _ = self.start(WriteBarrierHandler)
        client.sendall(request_bytes("none"))
        self.assertTrue(writing.wait(WAIT))
        self.assertEqual(self.ledger.verify()["receipt_count"], 1)
        server.begin_shutdown()
        closer, done, errors = self.drain(server)
        self.assertFalse(done.wait(0.05), "response-writing worker was abandoned")
        release_write.set()
        response = receive_all(client)
        self.assertTrue(done.wait(WAIT))
        closer.join(WAIT)
        self.assertEqual(errors + server.worker_errors, [])
        self.assertIn(b" 200 ", response.split(b"\r\n", 1)[0])
        self.assertEqual(self.ledger.verify()["receipt_count"], 1)

    def check_partial(self, raw: bytes, trickle: bool = False):
        server, client, _, _ = self.start()
        handling = Mock(wraps=self.service.handle)
        stop_trickle, trickle_started = threading.Event(), threading.Event()
        self.addCleanup(stop_trickle.set)
        def send_trickle():
            while not stop_trickle.is_set():
                try:
                    client.sendall(b"x")
                    trickle_started.set()
                except OSError:
                    break
                stop_trickle.wait(0.01)
        with patch.object(self.service, "handle", handling):
            client.sendall(raw)
            sender = None
            if trickle:
                sender = threading.Thread(target=send_trickle, daemon=True)
                sender.start()
                self.assertTrue(trickle_started.wait(WAIT))
            directions = []
            original_shutdown = socket.socket.shutdown
            def shutdown(request, direction):
                if request is server.worker_socket:
                    directions.append(direction)
                return original_shutdown(request, direction)
            with patch.object(socket.socket, "shutdown", shutdown):
                server.begin_shutdown()
            self.assertIn(socket.SHUT_RD, directions)
            closer, done, errors = self.drain(server)
            self.assertTrue(done.wait(WAIT), "partial transport held shutdown open")
            stop_trickle.set()
            if sender is not None:
                sender.join(WAIT)
                self.assertFalse(sender.is_alive())
            closer.join(WAIT)
            self.assertEqual(errors, [])
            self.assertTrue(server.worker_exited.is_set())
            handling.assert_not_called()
        self.assertEqual(self.provider.calls, 0)
        self.assertEqual(self.ledger.verify()["receipt_count"], 0)

    def test_idle_accepted_socket_is_unblocked_without_service_dispatch(self):
        self.check_partial(b"")

    def test_partial_headers_are_unblocked_without_service_dispatch(self):
        self.check_partial(b"POST /v1/evaluate HTTP/1.1\r\nHost: localhost\r\nX-Pending: ")

    def test_trickled_headers_cannot_hold_shutdown_open(self):
        self.check_partial(b"POST /v1/evaluate HTTP/1.1\r\nHost: localhost\r\nX-Pending: ", trickle=True)

    def test_partial_body_is_unblocked_without_service_dispatch(self):
        headers = request_bytes().split(b"\r\n\r\n", 1)[0]
        self.check_partial(headers + b"\r\n\r\n{")

    def test_trickled_body_cannot_hold_shutdown_open(self):
        headers = request_bytes().split(b"\r\n\r\n", 1)[0]
        self.check_partial(headers + b"\r\n\r\n{", trickle=True)

    def test_stop_request_before_admission_denies_service_dispatch(self):
        server, client, _, _ = self.start()
        with patch.object(self.service, "handle", wraps=self.service.handle) as handle:
            server.stop_requested = True
            client.sendall(request_bytes("none"))
            receive_all(client)
            self.assertTrue(server.worker_exited.wait(WAIT))
            handle.assert_not_called()
        self.assertEqual(self.ledger.verify()["receipt_count"], 0)

    def test_new_connections_are_refused_after_listener_shutdown(self):
        server, _, _, _ = self.start()
        address = server.server_address
        server.begin_shutdown()
        with self.assertRaises(OSError):
            with socket.create_connection(address, timeout=1):
                self.fail("listener accepted a new connection after shutdown")


class ServeSignalLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.previous = {signal.SIGTERM: object(), signal.SIGINT: object()}
        self.current = dict(self.previous)
        self.installed = {}
        self.fake = SimpleNamespace(stop_requested=False,
            begin_shutdown=Mock(side_effect=lambda: self.events.append("begin-shutdown")),
            server_close=Mock(side_effect=lambda: self.events.append("server-close")),
            handle_request=Mock())
        self.service = SimpleNamespace(config=SimpleNamespace(bind="127.0.0.1", port=0),
                                       ledger=SimpleNamespace(verify=Mock()))

    def signal_install(self, signum, handler):
        previous = self.current[signum]
        self.current[signum] = handler
        if callable(handler):
            self.installed[signum] = handler
        return previous

    def invoke(self):
        with patch.object(server_module, "_DrainingHTTPServer", return_value=self.fake) as factory, \
             patch.object(signal, "signal", side_effect=self.signal_install), \
             patch.object(signal, "getsignal", side_effect=lambda sig: self.current[sig]):
            server_module.serve(self.service)
        return factory

    def test_repeated_signal_callbacks_only_request_stop_and_restore_prior_handlers(self):
        def handle_request():
            self.events.append("handle-request")
            self.assertEqual(set(self.installed), {signal.SIGTERM, signal.SIGINT})
            for signum in (signal.SIGTERM, signal.SIGTERM, signal.SIGINT):
                self.installed[signum](signum, None)
                self.assertTrue(self.fake.stop_requested)
                self.fake.begin_shutdown.assert_not_called()
                self.fake.server_close.assert_not_called()
        self.fake.handle_request.side_effect = handle_request
        self.invoke()
        self.assertEqual(self.events, ["handle-request", "begin-shutdown", "server-close"])
        self.assertEqual(self.current, self.previous)
        self.fake.begin_shutdown.assert_called_once()
        self.fake.server_close.assert_called_once()
        self.assertGreater(self.fake.timeout, 0)
        self.assertLessEqual(self.fake.timeout, 0.5)

    def test_handle_request_error_still_drains_closes_and_restores_handlers(self):
        self.fake.handle_request.side_effect = RuntimeError("synthetic accept failure")
        with self.assertRaisesRegex(RuntimeError, "synthetic accept failure"):
            self.invoke()
        self.fake.begin_shutdown.assert_called_once()
        self.fake.server_close.assert_called_once()
        self.assertEqual(self.current, self.previous)

    def test_server_close_error_still_restores_handlers(self):
        self.fake.handle_request.side_effect = lambda: self.installed[signal.SIGTERM](signal.SIGTERM, None)
        self.fake.server_close.side_effect = RuntimeError("synthetic close failure")
        with self.assertRaisesRegex(RuntimeError, "synthetic close failure"):
            self.invoke()
        self.assertEqual(self.current, self.previous)

    def test_invalid_ledger_never_creates_listener_or_installs_handlers(self):
        self.service.ledger.verify.side_effect = RuntimeError("synthetic invalid ledger")
        with patch.object(server_module, "_DrainingHTTPServer") as factory, \
             patch.object(signal, "signal") as install, \
             self.assertRaisesRegex(RuntimeError, "synthetic invalid ledger"):
            server_module.serve(self.service)
        factory.assert_not_called()
        install.assert_not_called()

    def test_failed_signal_installation_restores_first_handler_and_closes_listener(self):
        installer = self.signal_install
        def fail_second(signum, handler):
            if signum == signal.SIGINT and callable(handler):
                raise ValueError("synthetic signal installation failed")
            return installer(signum, handler)
        with patch.object(server_module, "_DrainingHTTPServer", return_value=self.fake), \
             patch.object(signal, "signal", side_effect=fail_second), \
             self.assertRaisesRegex(ValueError, "synthetic signal installation failed"):
            server_module.serve(self.service)
        self.fake.handle_request.assert_not_called()
        self.fake.begin_shutdown.assert_called_once()
        self.fake.server_close.assert_called_once()
        self.assertEqual(self.current, self.previous)

    def test_begin_shutdown_failure_still_closes_listener_and_restores_handlers(self):
        self.fake.handle_request.side_effect = lambda: self.installed[signal.SIGINT](signal.SIGINT, None)
        self.fake.begin_shutdown.side_effect = RuntimeError("synthetic shutdown failure")
        with self.assertRaisesRegex(RuntimeError, "synthetic shutdown failure"):
            self.invoke()
        self.fake.server_close.assert_called_once()
        self.assertEqual(self.current, self.previous)


POSIX_CHILD = r'''
from dataclasses import replace
import json, os
from pathlib import Path
import sys
sys.path.insert(0, sys.argv[1])
from frontier_gateway.config import GatewayConfig
from frontier_gateway.evaluator import EvidenceEvaluator
from frontier_gateway.ledger import ReceiptLedger
from frontier_gateway.providers import ObservationProvider
from frontier_gateway import server as server_module

os.environ.clear()
os.environ.update(SZL_GATEWAY_BEARER_TOKEN=sys.argv[3], SZL_GATEWAY_DB=sys.argv[2])
config = replace(GatewayConfig.from_env(for_serve=True), bind="127.0.0.1", port=0)
ledger = ReceiptLedger(config.database_path)
class LocalBarrierProvider(ObservationProvider):
    name = "ollama"
    model = "synthetic-posix-shutdown"
    def observe(self, prompt):
        print(json.dumps({"event": "ADMITTED"}), flush=True)
        if sys.stdin.readline().strip() != "release":
            raise RuntimeError("TEST_RELEASE_REQUIRED")
        return "Synthetic local observation only."
service = server_module.GatewayService(config, ledger,
    EvidenceEvaluator(ledger, {"ollama": LocalBarrierProvider()}))
original = server_module._DrainingHTTPServer
class AnnouncedServer(original):
    socket_timeout = 0.35
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        print(json.dumps({"event": "LISTENING", "port": self.server_address[1]}), flush=True)
server_module._DrainingHTTPServer = AnnouncedServer
server_module.serve(service)
print(json.dumps({"event": "STOPPED", "proof": ledger.verify()}), flush=True)
'''


@unittest.skipUnless(os.name == "posix", "real SIGTERM/SIGINT subprocess semantics require POSIX")
class PosixSignalTests(unittest.TestCase):
    def test_sigterm_and_repeated_signals_drain_admitted_request_before_process_exit(self):
        with tempfile.TemporaryDirectory(prefix="szl-posix-shutdown-test-") as directory:
            path = Path(directory) / "receipts.sqlite3"
            env = {key: value for key, value in os.environ.items()
                   if key in {"PATH", "LANG", "LC_ALL", "LD_LIBRARY_PATH"}}
            env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1")
            process = subprocess.Popen(
                [sys.executable, "-I", "-B", "-c", POSIX_CHILD, str(GATEWAY_ROOT), str(path), TOKEN],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1, env=env)
            lines = queue.Queue()
            def read_lines():
                for line in process.stdout:
                    lines.put(line)
            reader = threading.Thread(target=read_lines, daemon=True)
            reader.start()
            client = None
            try:
                listening = json.loads(lines.get(timeout=WAIT))
                self.assertEqual(listening["event"], "LISTENING")
                client = socket.create_connection(("127.0.0.1", listening["port"]), timeout=WAIT)
                client.settimeout(WAIT)
                client.sendall(request_bytes())
                self.assertEqual(json.loads(lines.get(timeout=WAIT))["event"], "ADMITTED")
                process.send_signal(signal.SIGTERM)
                process.send_signal(signal.SIGINT)
                process.send_signal(signal.SIGTERM)
                with self.assertRaises(subprocess.TimeoutExpired):
                    process.wait(timeout=0.1)
                process.stdin.write("release\n")
                process.stdin.flush()
                response = receive_all(client)
                self.assertIn(b" 200 ", response.split(b"\r\n", 1)[0])
                self.assertEqual(process.wait(timeout=WAIT), 0)
                stopped = json.loads(lines.get(timeout=WAIT))
                self.assertEqual(stopped["event"], "STOPPED")
                self.assertEqual(stopped["proof"]["receipt_count"], 1)
                self.assertEqual(ReceiptLedger(path).verify(), stopped["proof"])
                self.assertEqual(process.stderr.read(), "")
            finally:
                if client is not None:
                    client.close()
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=WAIT)
                reader.join(WAIT)
                for stream in (process.stdin, process.stdout, process.stderr):
                    stream.close()


if __name__ == "__main__":
    unittest.main()
