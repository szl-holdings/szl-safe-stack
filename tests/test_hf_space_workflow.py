"""Contract for the committed writer of the private Space SZLHOLDINGS/szl-safe-stack."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
WRITER = WORKFLOWS / "hf-space.yml"
LOCK = "hf-write/space/SZLHOLDINGS/szl-safe-stack"


def _text() -> str:
    return WRITER.read_text(encoding="utf-8")


class HfSpaceWriterContractTests(unittest.TestCase):
    def test_writer_is_dispatch_only_with_a_required_exact_parent(self):
        text = _text()
        on_block = re.search(r"(?ms)^on:\n(.*?)^\S", text).group(1)
        self.assertEqual(re.findall(r"(?m)^  ([a-z_]+):", on_block), ["workflow_dispatch"])
        self.assertRegex(on_block, r"expected_parent:\n(?:\s+.*\n)*?\s+required: true")
        self.assertIn("github.ref == 'refs/heads/main'", text)
        self.assertIn("^[0-9a-f]{40}$", text)

    def test_input_reaches_the_shell_only_through_the_environment(self):
        text = _text()
        self.assertIn("EXPECTED_PARENT: ${{ inputs.expected_parent }}", text)
        run_blocks = re.findall(r"(?ms)^\s+run: \|\n(.*?)(?=^\s+- |\Z)", text)
        self.assertTrue(run_blocks)
        for block in run_blocks:
            self.assertNotIn("${{", block)

    def test_writer_holds_the_per_asset_lock(self):
        self.assertRegex(
            _text(),
            rf"\n    concurrency:\n      group: {re.escape(LOCK)}\n      cancel-in-progress: false\n",
        )

    def test_writer_uses_the_hash_locked_sdk_and_the_guarded_publisher(self):
        text = _text()
        self.assertIn("--require-hashes --only-binary=:all: -r requirements-publish.lock", text)
        self.assertRegex(
            text,
            r"tools/publish_hf_source\.py \\\n\s+--output \"\$RUNNER_TEMP/safe-stack-release\" \\\n"
            r"\s+--publish \\\n\s+--expected-parent \"\$EXPECTED_PARENT\"",
        )
        self.assertIn("persist-credentials: false", text)

    def test_writer_holds_only_the_two_declared_secrets(self):
        secrets = set(re.findall(r"secrets\.([A-Z0-9_]+)", _text()))
        self.assertEqual(secrets, {"HF_TOKEN", "BRANCH_PROTECTION_READ_TOKEN"})

    def test_no_other_workflow_writes_the_space(self):
        writers = sorted(
            path.name for path in WORKFLOWS.glob("*.yml")
            if "publish_hf_source.py" in path.read_text(encoding="utf-8")
            or "HF_TOKEN" in path.read_text(encoding="utf-8")
        )
        self.assertEqual(writers, ["hf-space.yml"])


if __name__ == "__main__":
    unittest.main()
