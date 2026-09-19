"""Offline publication tests: no cloud writes, account credentials, or downloads."""
import copy
import gzip
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import publish_hf_source as publisher

REVISION = "a" * 40
PARENT = "b" * 40
CANDIDATE = "c" * 40


def run_document():
    return {"total_count": 1, "workflow_runs": [{
        "id": 100, "run_number": 10, "run_attempt": 1,
        "path": publisher.WORKFLOW, "head_sha": REVISION, "head_branch": "main",
        "event": "push", "repository": {"full_name": publisher.GITHUB_REPO},
        "status": "completed", "conclusion": "success", "check_suite_id": 500,
    }]}


def archive_bytes(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, body in files.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(body)
            archive.addfile(entry, io.BytesIO(body))
    return buffer.getvalue()


class RunAdmissionTests(unittest.TestCase):
    def test_exact_source_success(self):
        self.assertEqual(publisher.select_source_run(run_document(), REVISION)["id"], 100)

    def test_newest_failed_run_cannot_fall_back_to_green(self):
        document = run_document()
        latest = copy.deepcopy(document["workflow_runs"][0])
        latest.update(id=101, run_number=11, conclusion="failure")
        document["workflow_runs"].append(latest)
        document["total_count"] = 2
        with self.assertRaisesRegex(publisher.PublicationError, "LATEST_CI_NOT_SUCCESSFUL"):
            publisher.select_source_run(document, REVISION)

    def test_repeated_successful_runs_select_latest_identity(self):
        document = run_document()
        latest = copy.deepcopy(document["workflow_runs"][0])
        latest.update(id=101, run_number=11)
        document["workflow_runs"].append(latest)
        document["total_count"] = 2
        self.assertEqual(publisher.select_source_run(document, REVISION)["id"], 101)

    def test_older_pending_rerun_cannot_be_masked_by_newer_success(self):
        for status in ("queued", "in_progress", "waiting", "requested", "pending", "unknown"):
            with self.subTest(status=status):
                document = run_document()
                older = copy.deepcopy(document["workflow_runs"][0])
                older.update(id=99, run_number=9, run_attempt=2, status=status, conclusion=None)
                document["workflow_runs"].append(older)
                document["total_count"] = 2
                with self.assertRaisesRegex(publisher.PublicationError, "CI_EXECUTION_PENDING"):
                    publisher.select_source_run(document, REVISION)

    def test_foreign_sha_workflow_repository_and_event_denied(self):
        for key, value in [("head_sha", PARENT), ("path", "evil.yml"), ("event", "pull_request"),
                           ("repository", {"full_name": "other/repo"}), ("head_branch", "feature")]:
            with self.subTest(key=key):
                document = run_document()
                document["workflow_runs"][0][key] = value
                with self.assertRaisesRegex(publisher.PublicationError, "CI_SOURCE_MISMATCH"):
                    publisher.select_source_run(document, REVISION)

    def test_ambiguous_or_truncated_run_lists_denied(self):
        document = run_document()
        document["total_count"] = 2
        with self.assertRaisesRegex(publisher.PublicationError, "CI_RUN_LIST_INCOMPLETE"):
            publisher.select_source_run(document, REVISION)
        document["workflow_runs"].append(copy.deepcopy(document["workflow_runs"][0]))
        with self.assertRaisesRegex(publisher.PublicationError, "CI_RUN_AMBIGUOUS"):
            publisher.select_source_run(document, REVISION)


class SourceBundleTests(unittest.TestCase):
    def test_private_files_and_unsafe_paths_excluded(self):
        for name in ["safe-qa-service/.env", "safe-qa-service/.env.production", "safe-qa-service/evidence/receipt.json",
                     "safe-qa-service/keys/public.pem", "docs/private/example.txt", "docs/client.pfx",
                     "../README.md", "/README.md", "tools/../secret", "tools\\secret.py", "tools/C:secret"]:
            with self.subTest(name=name):
                self.assertFalse(publisher.allowed_source_path(name))
        self.assertTrue(publisher.allowed_source_path("safe-qa-service/src/app.py"))

    def test_tracked_runtime_state_is_excluded_independently_of_gitignore(self):
        for name in ("data.sqlite3", "data.sqlite3-wal", "data.sqlite3-shm", "data.db-wal",
                     "terraform.tfstate", "terraform.tfstate.backup", "production.tfplan",
                     "production.tfvars", "production.tfvars.json", "provider.log", ".coverage"):
            with self.subTest(name=name):
                self.assertFalse(publisher.allowed_source_path("safe-qa-service/deploy/" + name))
        for folder in (".terraform", ".local-ci", "dist", "build", "wheels"):
            self.assertFalse(publisher.allowed_source_path("tools/" + folder + "/data.json"))
        self.assertTrue(publisher.allowed_source_path("safe-qa-service/deploy/aws/terraform.tfvars.example"))

    def test_root_compose_attributes_and_sdk_lock_are_preserved(self):
        files = {"README.md": b"read me", "safe-qa-service/pyproject.toml": b"[project]",
                 "frontier-evidence-gateway/pyproject.toml": b"[project]",
                 "compose.yaml": b"services: {}", "compose.ollama.yaml": b"services: {gateway: {}}", ".gitattributes": b"* text=auto eol=lf",
                 "requirements-publish.lock": b"# locked publication dependencies"}
        with patch.object(publisher, "command", return_value=archive_bytes(files)):
            compressed, inventory = publisher.source_archive(Path("."), REVISION)
        self.assertEqual({item["path"] for item in inventory}, set(files))
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(compressed))) as archive:
            self.assertEqual(archive.extractfile("compose.yaml").read(), files["compose.yaml"])

    def test_publication_sdk_mismatch_refuses_hub_initialization(self):
        with patch("importlib.metadata.version", return_value="0.0.0"):
            with self.assertRaisesRegex(publisher.PublicationError, "PINNED_PUBLICATION_SDK_REQUIRED"):
                publisher.Hub()

    def test_archive_is_deterministic_and_excludes_evidence_and_environment(self):
        files = {"README.md": b"read me", "safe-qa-service/pyproject.toml": b"[project]",
                 "frontier-evidence-gateway/pyproject.toml": b"[project]",
                 "safe-qa-service/.env": b"DO_NOT_PUBLISH",
                 "safe-qa-service/evidence/private.json": b"DO_NOT_PUBLISH"}
        with patch.object(publisher, "command", return_value=archive_bytes(files)):
            first, inventory = publisher.source_archive(Path("."), REVISION)
            second, _ = publisher.source_archive(Path("."), REVISION)
        self.assertEqual(first, second)
        self.assertEqual(len(inventory), 3)
        self.assertNotIn(b"DO_NOT_PUBLISH", gzip.decompress(first))

    def test_allowed_source_symlink_is_denied(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            entry = tarfile.TarInfo("tools/link")
            entry.type = tarfile.SYMTYPE
            entry.linkname = "../../private"
            archive.addfile(entry)
        with patch.object(publisher, "command", return_value=buffer.getvalue()):
            with self.assertRaisesRegex(publisher.PublicationError, "SOURCE_LINK_DENIED"):
                publisher.source_archive(Path("."), REVISION)

    def test_payload_extracts_source_and_refuses_existing_destination(self):
        compressed = gzip.compress(archive_bytes({"README.md": b"source only"}), mtime=0)
        markdown = publisher.python_payload(compressed, REVISION).decode()
        code = markdown.split("```python\n", 1)[1].rsplit("```", 1)[0]
        compile(code, "payload.py", "exec")
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, "-c", code], cwd=directory, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            target = Path(directory) / ("szl-safe-stack-" + REVISION[:12]) / "README.md"
            self.assertEqual(target.read_bytes(), b"source only")
            again = subprocess.run([sys.executable, "-c", code], cwd=directory, capture_output=True, text=True)
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual(target.read_bytes(), b"source only")

    def test_payload_refuses_traversal_before_creating_directory(self):
        compressed = gzip.compress(archive_bytes({"../escape": b"no"}), mtime=0)
        code = publisher.python_payload(compressed, REVISION).decode().split("```python\n", 1)[1].rsplit("```", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, "-c", code], cwd=directory, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(Path(directory).iterdir()), [])


class SourceIdentityTests(unittest.TestCase):
    def setUp(self):
        self.documents = {
            "repository": {"full_name": publisher.GITHUB_REPO, "private": True, "default_branch": "main"},
            "protection": {"required_status_checks": {"strict": True,
                "checks": [{"context": publisher.CHECK_NAME, "app_id": publisher.APP_ID}]},
                "enforce_admins": {"enabled": True}, "required_signatures": {"enabled": True},
                "required_linear_history": {"enabled": True}, "required_conversation_resolution": {"enabled": True},
                "allow_force_pushes": {"enabled": False}, "allow_deletions": {"enabled": False}},
            "commit": {"sha": REVISION, "commit": {"verification": {"verified": True, "reason": "valid"}}},
            "runs": run_document(),
            "jobs": {"total_count": 1, "jobs": [{"name": publisher.CHECK_NAME, "run_id": 100,
                     "head_sha": REVISION, "status": "completed", "conclusion": "success",
                     "check_run_url": f"https://api.github.com/repos/{publisher.GITHUB_REPO}/check-runs/600"}]},
            "check": {"id": 600, "name": publisher.CHECK_NAME, "head_sha": REVISION,
                      "app": {"id": publisher.APP_ID}, "check_suite": {"id": 500},
                      "status": "completed", "conclusion": "success"},
        }
        self.dirty = False

    def command(self, args, root):
        if args[1] == "status":
            return b"?? unreviewed.py" if self.dirty else b""
        if args[1] == "rev-parse":
            return REVISION.encode()
        if args[1] == "remote":
            return f"https://github.com/{publisher.GITHUB_REPO}.git".encode()
        raise AssertionError(args)

    def github(self, path, root):
        if path.endswith("/branches/main/protection"):
            key = "protection"
        elif path.endswith("/commits/main"):
            key = "commit"
        elif "/actions/workflows/" in path:
            key = "runs"
        elif "/jobs?" in path:
            key = "jobs"
        elif "/check-runs/" in path:
            key = "check"
        else:
            key = "repository"
        return self.documents[key]

    def snapshot(self):
        with patch.object(publisher, "command", side_effect=self.command):
            return publisher.source_snapshot(Path("."), get=self.github)

    def test_signed_source_trusted_app_and_matching_run_admit(self):
        result = self.snapshot()
        self.assertEqual(result["source_revision"], REVISION)
        self.assertEqual(result["check_id"], 600)

    def test_dirty_source_denied(self):
        self.dirty = True
        with self.assertRaisesRegex(publisher.PublicationError, "SOURCE_TREE_NOT_CLEAN"):
            self.snapshot()

    def test_relaxed_main_protection_is_denied(self):
        original = copy.deepcopy(self.documents["protection"])
        for field in ("required_signatures", "required_linear_history", "enforce_admins",
                      "required_conversation_resolution", "allow_force_pushes", "allow_deletions"):
            with self.subTest(field=field):
                self.documents["protection"] = copy.deepcopy(original)
                self.documents["protection"][field]["enabled"] = not original[field]["enabled"]
                with self.assertRaisesRegex(publisher.PublicationError, "PROTECTED_MAIN_REQUIRED"):
                    self.snapshot()
        self.documents["protection"] = copy.deepcopy(original)
        self.documents["protection"]["required_status_checks"]["strict"] = False
        with self.assertRaisesRegex(publisher.PublicationError, "PROTECTED_MAIN_REQUIRED"):
            self.snapshot()
        self.documents["protection"] = copy.deepcopy(original)
        self.documents["protection"]["required_status_checks"]["checks"][0]["app_id"] = 42
        with self.assertRaisesRegex(publisher.PublicationError, "PROTECTED_MAIN_REQUIRED"):
            self.snapshot()

    def test_unsigned_or_changed_main_denied(self):
        self.documents["commit"]["commit"]["verification"]["verified"] = False
        with self.assertRaisesRegex(publisher.PublicationError, "SIGNED_CURRENT_MAIN_REQUIRED"):
            self.snapshot()
        self.documents["commit"]["commit"]["verification"]["verified"] = True
        self.documents["commit"]["sha"] = PARENT
        with self.assertRaisesRegex(publisher.PublicationError, "SIGNED_CURRENT_MAIN_REQUIRED"):
            self.snapshot()

    def test_foreign_app_suite_or_sha_denied(self):
        original = copy.deepcopy(self.documents["check"])
        for key, value in [("app", {"id": 123}), ("check_suite", {"id": 999}), ("head_sha", PARENT)]:
            with self.subTest(key=key):
                self.documents["check"] = copy.deepcopy(original)
                self.documents["check"][key] = value
                with self.assertRaisesRegex(publisher.PublicationError, "CI_CHECK_NOT_TRUSTED"):
                    self.snapshot()

    def test_foreign_check_url_not_requested(self):
        self.documents["jobs"]["jobs"][0]["check_run_url"] = "https://attacker.invalid/check-runs/600"
        with self.assertRaisesRegex(publisher.PublicationError, "CI_CHECK_URL_INVALID"):
            self.snapshot()


class FakeHub:
    def __init__(self):
        self.head = PARENT
        self.private = True
        self.sdk = "static"
        self.files = {".gitattributes": b"attributes"}
        self.initial = self.files.copy()
        self.commits = []
        self.fail_commit = False
        self.corrupt_read = False

    def info(self, revision):
        files = self.initial if revision == PARENT else self.files
        return SimpleNamespace(id=publisher.HF_REPO, private=self.private, sdk=self.sdk,
                               sha=self.head if revision == "main" else revision,
                               siblings=[SimpleNamespace(rfilename=name, size=len(data), blob_id=publisher.digest(data))
                                         for name, data in files.items()])

    def read(self, name, revision):
        return b"corrupt" if self.corrupt_read else self.files[name]

    def commit(self, files, parent, revision):
        self.commits.append((parent, revision))
        if self.fail_commit:
            raise TimeoutError("sensitive provider detail")
        self.files.update(files)
        self.head = CANDIDATE
        return CANDIDATE


class ProviderCommitTests(unittest.TestCase):
    def setUp(self):
        self.hub = FakeHub()
        self.source = {"source_revision": REVISION}
        self.files = {name: name.encode() for name in publisher.RELEASE_FILES}
        self.receipts = []

    def publish(self, fresh=None):
        return publisher.publish(self.hub, self.files, PARENT, self.source,
                                 fresh or (lambda: self.source), self.receipts.append)

    def test_success_is_one_cas_commit_with_immutable_readback(self):
        self.assertEqual(self.publish(), CANDIDATE)
        self.assertEqual(self.hub.commits, [(PARENT, REVISION)])
        self.assertEqual(self.receipts[-1]["phase"], "SOURCE_DISTRIBUTION_VERIFIED")

    def test_changed_parent_causes_zero_writes(self):
        self.hub.head = "d" * 40
        with self.assertRaisesRegex(publisher.PublicationError, "HF_PARENT_CHANGED"):
            self.publish()
        self.assertEqual(self.hub.commits, [])

    def test_public_or_executable_target_causes_zero_writes(self):
        for field, value in [("private", False), ("sdk", "docker")]:
            with self.subTest(field=field):
                self.hub = FakeHub()
                setattr(self.hub, field, value)
                with self.assertRaisesRegex(publisher.PublicationError, "PRIVATE_STATIC_TARGET_REQUIRED"):
                    self.publish()
                self.assertEqual(self.hub.commits, [])

    def test_unknown_existing_file_is_not_overwritten(self):
        self.hub.files["user-data.txt"] = b"keep"
        with self.assertRaisesRegex(publisher.PublicationError, "HF_UNEXPECTED_FILE"):
            self.publish()
        self.assertEqual(self.hub.commits, [])

    def test_changed_github_source_causes_zero_writes(self):
        with self.assertRaisesRegex(publisher.PublicationError, "GITHUB_SOURCE_CHANGED"):
            self.publish(lambda: {"source_revision": PARENT})
        self.assertEqual(self.hub.commits, [])

    def test_commit_timeout_is_unknown_and_never_retried(self):
        self.hub.fail_commit = True
        with self.assertRaisesRegex(publisher.PublicationError, "UNKNOWN_AFTER_ATTEMPT_NO_AUTOMATIC_RETRY"):
            self.publish()
        self.assertEqual(len(self.hub.commits), 1)
        self.assertEqual(self.receipts[-1]["phase"], "UNKNOWN_AFTER_ATTEMPT")
        self.assertNotIn("sensitive", json.dumps(self.receipts))

    def test_bad_immutable_readback_is_not_success(self):
        self.hub.corrupt_read = True
        with self.assertRaisesRegex(publisher.PublicationError, "UNKNOWN_AFTER_ATTEMPT_NO_AUTOMATIC_RETRY"):
            self.publish()
        self.assertEqual(len(self.hub.commits), 1)
        self.assertEqual(self.receipts[-1]["phase"], "UNKNOWN_AFTER_ATTEMPT")


if __name__ == "__main__":
    unittest.main()
