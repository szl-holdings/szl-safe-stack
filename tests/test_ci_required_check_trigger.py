"""source-contract must come from an event branch protection evaluates.

GitHub ignores workflow_dispatch job checks when deciding a required pull
request status check. A skipped job would still count as success, so the
required job cannot be conditional.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github" / "workflows" / "ci.yml"
LOCK_SYNC = ROOT / ".github" / "workflows" / "dependabot-lock-sync.yml"


def trigger_keys(text: str) -> list[str]:
    on_block = re.search(r"(?ms)^on:\n(.*?)(?=^\S)", text)
    if on_block is None:
        raise AssertionError("workflow is missing an on: block")
    return re.findall(r"(?m)^  ([a-z_]+):", on_block.group(1))


class SourceContractTriggerTests(unittest.TestCase):
    def test_ci_triggers_are_events_branch_protection_evaluates(self):
        text = CI.read_text(encoding="utf-8")
        keys = trigger_keys(text)
        self.assertEqual(
            keys,
            ["pull_request", "push", "merge_group", "pull_request_review"],
        )
        self.assertNotIn("workflow_dispatch", keys)
        self.assertRegex(text, r"(?m)^  pull_request_review:\n    types: \[submitted\]\n")

    def test_source_contract_job_cannot_skip_past_the_required_check(self):
        text = CI.read_text(encoding="utf-8")
        job = re.search(r"(?ms)^  source-contract:\n(.*?)(?=^\S|\Z)", text)
        self.assertIsNotNone(job)
        header = []
        for line in job.group(1).splitlines():
            if line.startswith("    steps:"):
                break
            header.append(line)
        self.assertIn("    name: source-contract", header)
        self.assertFalse(any(re.match(r"    if:", line) for line in header))

    def test_lock_sync_does_not_dispatch_ci(self):
        text = LOCK_SYNC.read_text(encoding="utf-8")
        self.assertNotIn("workflow run ci.yml", text)
        self.assertNotIn("actions: write", text)
        self.assertNotIn("workflow_dispatch:", text)


if __name__ == "__main__":
    unittest.main()
