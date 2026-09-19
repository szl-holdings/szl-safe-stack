import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import local_stack as local


class LocalStackTests(unittest.TestCase):
    def state(self):
        return {"schema": "szl.local-runtime.v1", "source_revision": "a" * 40,
                "safeqa_token": "x" * 43, "gateway_token": "y" * 43,
                "ollama": False, "model_digest": None}

    def test_compose_pins_local_context_project_ports_and_drops_ambient_overrides(self):
        with patch.dict(local.os.environ, {"DOCKER_HOST": "tcp://remote:2375", "COMPOSE_FILE": "evil.yaml"}), patch.object(local.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            local.compose(self.state(), ["config", "--quiet"])
        args, kwargs = run.call_args
        command = args[0]
        self.assertEqual(command[:5], ["docker", "--context", "desktop-linux", "compose", "--project-name"])
        self.assertNotIn("DOCKER_HOST", kwargs["env"])
        self.assertNotIn("COMPOSE_FILE", kwargs["env"])
        self.assertEqual(kwargs["env"]["SAFE_QA_LOCAL_PORT"], "18081")
        self.assertNotIn(self.state()["safeqa_token"], json.dumps(command))
        self.assertNotIn(self.state()["safeqa_token"], kwargs["env"]["SAFE_QA_AUTH_TOKEN_HASHES_JSON"])

    def test_nonzero_compose_result_is_not_success(self):
        with patch.object(local.subprocess, "run", return_value=subprocess.CompletedProcess([], 7)):
            with self.assertRaisesRegex(local.LocalError, "COMPOSE_COMMAND_FAILED"):
                local.compose(self.state(), ["up"])

    def test_down_never_deletes_persistent_volumes(self):
        with patch.object(local.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            local.compose(self.state(), ["down"])
        self.assertNotIn("--volumes", run.call_args.args[0])

    def test_initialization_refuses_existing_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "identity.dpapi"
            path.write_bytes(b"existing-ciphertext")
            with patch.object(local, "STATE", path):
                with self.assertRaisesRegex(local.LocalError, "ALREADY_EXISTS"):
                    local.init_state(False)
            self.assertEqual(path.read_bytes(), b"existing-ciphertext")

    def test_equal_tokens_are_rejected_after_decryption(self):
        value = self.state()
        value["gateway_token"] = value["safeqa_token"]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "identity.dpapi"
            path.write_bytes(b"ciphertext")
            with patch.object(local, "STATE", path), patch.object(local, "dpapi", return_value=json.dumps(value).encode()):
                with self.assertRaisesRegex(local.LocalError, "SEPARATE_SERVICE_TOKENS"):
                    local.load_state()

    def test_ambiguous_or_missing_installed_model_is_rejected(self):
        for models in ([], [{"name": local.MODEL, "digest": "z" * 64}], [{"name": local.MODEL, "digest": "a" * 64}] * 2):
            with self.subTest(models=models), patch.object(local, "request", return_value=(200, {"models": models})):
                with self.assertRaises(local.LocalError):
                    local.model_digest()

    def test_local_requests_cannot_select_arbitrary_port(self):
        with self.assertRaisesRegex(local.LocalError, "LOCAL_ROUTE_DENIED"):
            local.request(22, "/")


if __name__ == "__main__":
    unittest.main()
