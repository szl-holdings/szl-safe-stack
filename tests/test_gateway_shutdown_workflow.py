"""Offline contract tests for the Gateway shutdown script embedded in root CI."""

from __future__ import annotations

import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.error import HTTPError


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
STEP_MARKER = "      - name: Verify idle Gateway PID 1 shutdown and receipt retention"
SCRIPT_MARKER = "          python - <<'PY'"
SCRIPT_END = "          PY"
SCRIPT_INDENT = " " * 10
CONTAINER = "gateway-container-id"
PROOF = {
    "schema_version": "szl.frontier.ledger.verification.v2",
    "hash_version": "szl.frontier.receipt_hash.v1",
    "status": "VERIFIED",
    "receipt_count": 1,
    "head_hash": "a" * 64,
}


def workflow_script() -> str:
    """Extract only the exact indented Python heredoc from the named CI step."""
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    if lines.count(STEP_MARKER) != 1:
        raise AssertionError("Gateway shutdown CI step must occur exactly once")
    step = lines.index(STEP_MARKER)
    try:
        start = lines.index(SCRIPT_MARKER, step + 1)
        end = lines.index(SCRIPT_END, start + 1)
    except ValueError as exc:
        raise AssertionError("Gateway shutdown CI Python markers are missing") from exc
    next_step = next(
        (index for index in range(step + 1, len(lines)) if lines[index].startswith("      - name:")),
        len(lines),
    )
    if not start < end < next_step:
        raise AssertionError("Gateway shutdown CI Python markers escaped the named step")

    body: list[str] = []
    for line in lines[start + 1 : end]:
        if line and not line.startswith(SCRIPT_INDENT):
            raise AssertionError("Gateway shutdown CI Python has unexpected indentation")
        body.append(line[len(SCRIPT_INDENT) :] if line else "")
    if not body:
        raise AssertionError("Gateway shutdown CI Python is empty")
    return "\n".join(body) + "\n"


def readiness(ledger: dict[str, object]) -> dict[str, object]:
    return {"status": "READY", "ledger": ledger}


class FakeOpener:
    def __init__(self, actions: list[dict[str, object] | BaseException]) -> None:
        self.actions = list(actions)
        self.requests = []

    def open(self, request, timeout: int):
        self.requests.append((request, timeout))
        if not self.actions:
            raise AssertionError("unexpected readiness request")
        action = self.actions.pop(0)
        if isinstance(action, BaseException):
            raise action
        return io.StringIO(json.dumps(action))


class FakeDocker:
    def __init__(self, *, stopped_exit_code: int = 0) -> None:
        self.stopped_exit_code = stopped_exit_code
        self.phase = "running"
        self.calls: list[tuple[str, ...]] = []
        self.inspect_calls = 0
        self.before = {
            "Id": CONTAINER,
            "Image": "sha256:" + "b" * 64,
            "Path": "python",
            "Args": ["-m", "frontier_gateway", "serve"],
            "Config": {
                "Labels": {
                    "com.docker.compose.project": "shutdown-workflow-test",
                    "com.docker.compose.service": "gateway",
                },
                "StopSignal": "SIGTERM",
            },
            "State": {
                "Running": True,
                "Health": {"Status": "healthy"},
                "ExitCode": 0,
                "OOMKilled": False,
            },
            "Mounts": [
                {
                    "Type": "volume",
                    "Name": "gateway-receipts",
                    "Source": "/var/lib/docker/volumes/gateway-receipts/_data",
                    "Destination": "/data",
                    "RW": True,
                }
            ],
        }

    def __call__(self, command, *, text: bool, timeout: int) -> str:
        if text is not True or timeout != 30 or command[0] != "docker":
            raise AssertionError("workflow changed the bounded Docker invocation contract")
        args = tuple(command[1:])
        self.calls.append(args)
        if args == ("compose", "ps", "-q", "gateway"):
            return CONTAINER + "\n"
        if args == ("inspect", CONTAINER):
            self.inspect_calls += 1
            state = json.loads(json.dumps(self.before))
            if self.phase == "stopped":
                state["State"].update(
                    Running=False,
                    ExitCode=self.stopped_exit_code,
                    OOMKilled=False,
                )
            return json.dumps([state])
        if args == ("stop", "--timeout", "-1", CONTAINER):
            if self.phase != "running":
                raise AssertionError("container stopped from an unexpected phase")
            self.phase = "stopped"
            return CONTAINER + "\n"
        if args == ("start", CONTAINER):
            if self.phase != "stopped":
                raise AssertionError("container started from an unexpected phase")
            self.phase = "restarted"
            return CONTAINER + "\n"
        raise AssertionError(f"unexpected Docker invocation: {args!r}")


class GatewayShutdownWorkflowTests(unittest.TestCase):
    def execute(
        self,
        *,
        http_actions: list[dict[str, object] | BaseException],
        stopped_exit_code: int = 0,
        monotonic_values: list[float] | None = None,
    ) -> tuple[FakeDocker, FakeOpener, list[float], str]:
        docker = FakeDocker(stopped_exit_code=stopped_exit_code)
        opener = FakeOpener(http_actions)
        sleeps: list[float] = []
        clock = iter(monotonic_values or [0.0])
        output = io.StringIO()
        self.docker = docker
        self.opener = opener
        self.sleeps = sleeps
        environment = {
            "COMPOSE_PROJECT_NAME": "shutdown-workflow-test",
            "SZL_GATEWAY_BEARER_TOKEN": "offline-workflow-test-token",
        }
        with (
            patch.dict(os.environ, environment, clear=True),
            patch("subprocess.check_output", side_effect=docker),
            patch("urllib.request.build_opener", return_value=opener),
            patch("time.monotonic", side_effect=lambda: next(clock)),
            patch("time.sleep", side_effect=sleeps.append),
            redirect_stdout(output),
        ):
            exec(
                compile(workflow_script(), str(WORKFLOW), "exec"),
                {"__name__": "__gateway_shutdown_workflow_test__"},
            )
        return docker, opener, sleeps, output.getvalue()

    def test_transient_connection_reset_retries_then_preserves_exact_proof(self) -> None:
        docker, opener, sleeps, output = self.execute(
            http_actions=[
                readiness(PROOF),
                ConnectionResetError("synthetic restart reset"),
                readiness(PROOF),
            ],
            monotonic_values=[100.0, 101.0],
        )

        self.assertEqual(sleeps, [0.2])
        self.assertEqual(len(opener.requests), 3)
        self.assertEqual(docker.phase, "restarted")
        self.assertEqual(docker.inspect_calls, 3)
        self.assertIn("exact container and verified receipt head retained", output)
        for request, timeout in opener.requests:
            self.assertEqual(timeout, 3)
            self.assertEqual(request.full_url, "http://127.0.0.1:8787/health/ready")
            self.assertEqual(
                request.get_header("Authorization"),
                "Bearer offline-workflow-test-token",
            )

    def test_persistent_connection_reset_fails_at_deadline(self) -> None:
        with self.assertRaisesRegex(ConnectionResetError, "persistent reset"):
            self.execute(
                http_actions=[
                    readiness(PROOF),
                    ConnectionResetError("first persistent reset"),
                    ConnectionResetError("persistent reset at deadline"),
                ],
                monotonic_values=[0.0, 1.0, 30.0],
            )

        self.assertEqual(self.sleeps, [0.2])
        self.assertEqual(len(self.opener.requests), 3)
        self.assertEqual(self.docker.phase, "restarted")
        self.assertEqual(self.docker.inspect_calls, 2)

    def test_changed_ledger_fails_immediately_without_retry_success(self) -> None:
        changed = dict(PROOF, head_hash="f" * 64)
        with self.assertRaisesRegex(
            AssertionError, "Gateway receipt history changed across shutdown"
        ):
            self.execute(
                http_actions=[readiness(PROOF), readiness(changed)],
                monotonic_values=[0.0],
            )

        self.assertEqual(self.sleeps, [])
        self.assertEqual(len(self.opener.requests), 2)
        self.assertEqual(self.docker.phase, "restarted")
        self.assertEqual(self.docker.inspect_calls, 2)

    def assert_http_error_fails_immediately(self, status: int) -> None:
        failure = HTTPError(
            "http://127.0.0.1:8787/health/ready",
            status,
            "synthetic readiness failure",
            hdrs=None,
            fp=None,
        )
        with self.assertRaises(HTTPError) as raised:
            self.execute(
                http_actions=[readiness(PROOF), failure, readiness(PROOF)],
                monotonic_values=[0.0],
            )

        self.assertEqual(raised.exception.code, status)
        self.assertEqual(self.sleeps, [])
        self.assertEqual(len(self.opener.requests), 2)
        self.assertEqual(self.docker.phase, "restarted")
        self.assertEqual(self.docker.inspect_calls, 2)

    def test_post_restart_401_is_not_retried_to_success(self) -> None:
        self.assert_http_error_fails_immediately(401)

    def test_post_restart_503_is_not_retried_to_success(self) -> None:
        self.assert_http_error_fails_immediately(503)

    def test_nonzero_stop_exit_fails_before_restart_or_retry(self) -> None:
        with self.assertRaises(AssertionError):
            self.execute(
                http_actions=[readiness(PROOF)],
                stopped_exit_code=137,
            )

        self.assertEqual(self.sleeps, [])
        self.assertEqual(len(self.opener.requests), 1)
        self.assertEqual(self.docker.phase, "stopped")
        self.assertEqual(self.docker.inspect_calls, 2)
        self.assertNotIn(("start", CONTAINER), self.docker.calls)


if __name__ == "__main__":
    unittest.main()
