"""Publish a verified source bundle to one private static Hugging Face Space.

Preparing files is local. Publishing requires --publish and the caller's exact
observed Hub parent commit. There are no automatic write retries.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile

GITHUB_REPO = "szl-holdings/szl-safe-stack"
HF_REPO = "SZLHOLDINGS/szl-safe-stack"
HF_ORIGIN = "https://huggingface.co"
WORKFLOW = ".github/workflows/ci.yml"
CHECK_NAME = "source-contract"
APP_ID = 15368
PUBLISH_SDK_VERSION = "0.36.2"
SHA = re.compile(r"[0-9a-f]{40}")
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_FILES = 2000
RELEASE_FILES = frozenset({"README.md", "index.html", "source-manifest.json", "source.tar.gz", "source_payload.md"})
SOURCE_ROOTS = frozenset({"safe-qa-service", "frontier-evidence-gateway", "tools", "tests", "hf-space", "docs", ".github"})
ROOT_FILES = frozenset({"README.md", "LICENSE", "LICENSE.md", "SECURITY.md", ".gitignore", ".gitattributes", "compose.yaml", "compose.ollama.yaml", "pyproject.toml", "requirements-publish.lock"})
EXCLUDED_PARTS = frozenset({".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache", ".local-ci", ".terraform", "evidence", "private", "keys", "quarantine", "outputs", "dist", "build", "wheels", "htmlcov"})


class PublicationError(RuntimeError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise PublicationError(code)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def command(args: list[str], root: Path) -> bytes:
    try:
        result = subprocess.run(args, cwd=root, check=True, capture_output=True, timeout=60)
    except (subprocess.SubprocessError, OSError):
        raise PublicationError("LOCAL_COMMAND_FAILED") from None
    return result.stdout


def github(path: str, root: Path) -> dict:
    require(path == f"repos/{GITHUB_REPO}" or path.startswith(f"repos/{GITHUB_REPO}/"), "GITHUB_PATH_DENIED")
    try:
        document = json.loads(command(["gh", "api", path], root))
    except (ValueError, UnicodeError):
        raise PublicationError("GITHUB_RESPONSE_INVALID") from None
    require(isinstance(document, dict), "GITHUB_RESPONSE_INVALID")
    return document


def select_source_run(document: dict, revision: str) -> dict:
    runs = document.get("workflow_runs")
    total = document.get("total_count")
    require(type(total) is int and 0 < total <= 100 and isinstance(runs, list)
            and len(runs) == total, "CI_RUN_LIST_INCOMPLETE")
    for run in runs:
        require(isinstance(run, dict) and type(run.get("id")) is int and run["id"] > 0
                and type(run.get("run_number")) is int and run["run_number"] > 0
                and type(run.get("run_attempt")) is int and run["run_attempt"] > 0
                and type(run.get("check_suite_id")) is int and run["check_suite_id"] > 0, "CI_RUN_INVALID")
        require(run.get("path") == WORKFLOW and run.get("head_sha") == revision
                and run.get("head_branch") == "main" and run.get("event") == "push"
                and run.get("repository", {}).get("full_name") == GITHUB_REPO,
                "CI_SOURCE_MISMATCH")
    # An older execution can be rerun while a newer execution remains green.
    # Publishing must wait until every matching source execution is terminal.
    require(all(run.get("status") == "completed" for run in runs), "CI_EXECUTION_PENDING")
    orders = [(run["run_number"], run["run_attempt"]) for run in runs]
    require(len(set(orders)) == len(orders), "CI_RUN_AMBIGUOUS")
    selected = max(runs, key=lambda run: (run["run_number"], run["run_attempt"]))
    require(selected.get("path") == WORKFLOW
            and selected.get("head_sha") == revision
            and selected.get("head_branch") == "main"
            and selected.get("event") == "push"
            and selected.get("repository", {}).get("full_name") == GITHUB_REPO,
            "CI_SOURCE_MISMATCH")
    require(selected.get("status") == "completed" and selected.get("conclusion") == "success",
            "LATEST_CI_NOT_SUCCESSFUL")
    return selected


def source_snapshot(root: Path, get=github) -> dict:
    require(not command(["git", "status", "--porcelain", "--untracked-files=all"], root).strip(),
            "SOURCE_TREE_NOT_CLEAN")
    revision = command(["git", "rev-parse", "HEAD"], root).decode().strip()
    require(SHA.fullmatch(revision) is not None, "SOURCE_SHA_INVALID")
    origin = command(["git", "remote", "get-url", "origin"], root).decode().strip()
    require(origin in {f"https://github.com/{GITHUB_REPO}.git", f"https://github.com/{GITHUB_REPO}",
                       f"git@github.com:{GITHUB_REPO}.git"}, "SOURCE_ORIGIN_DENIED")
    repository = get(f"repos/{GITHUB_REPO}", root)
    require(repository.get("full_name") == GITHUB_REPO and repository.get("private") is True
            and repository.get("default_branch") == "main", "PRIVATE_SOURCE_REPO_REQUIRED")
    protection = get(f"repos/{GITHUB_REPO}/branches/main/protection", root)
    required_checks = protection.get("required_status_checks", {})
    checks = required_checks.get("checks", [])
    require(required_checks.get("strict") is True and isinstance(checks, list)
            and sum(check.get("context") == CHECK_NAME and check.get("app_id") == APP_ID
                    for check in checks if isinstance(check, dict)) == 1
            and protection.get("enforce_admins", {}).get("enabled") is True
            and protection.get("required_signatures", {}).get("enabled") is True
            and protection.get("required_linear_history", {}).get("enabled") is True
            and protection.get("required_conversation_resolution", {}).get("enabled") is True
            and protection.get("allow_force_pushes", {}).get("enabled") is False
            and protection.get("allow_deletions", {}).get("enabled") is False,
            "PROTECTED_MAIN_REQUIRED")
    commit = get(f"repos/{GITHUB_REPO}/commits/main", root)
    verification = commit.get("commit", {}).get("verification", {})
    require(commit.get("sha") == revision and verification.get("verified") is True
            and verification.get("reason") == "valid", "SIGNED_CURRENT_MAIN_REQUIRED")
    run = select_source_run(get(f"repos/{GITHUB_REPO}/actions/workflows/ci.yml/runs"
                                f"?head_sha={revision}&event=push&per_page=100", root), revision)
    jobs = get(f"repos/{GITHUB_REPO}/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs?per_page=100", root)
    require(type(jobs.get("total_count")) is int and 0 < jobs["total_count"] <= 100
            and isinstance(jobs.get("jobs"), list) and len(jobs["jobs"]) == jobs["total_count"],
            "CI_JOB_LIST_INCOMPLETE")
    matching = [job for job in jobs["jobs"] if job.get("name") == CHECK_NAME]
    require(len(matching) == 1, "CI_CHECK_MISSING_OR_AMBIGUOUS")
    job = matching[0]
    require(job.get("run_id") == run["id"] and job.get("head_sha") == revision
            and job.get("status") == "completed" and job.get("conclusion") == "success", "CI_JOB_NOT_SUCCESSFUL")
    check_url = job.get("check_run_url", "")
    prefix = f"https://api.github.com/repos/{GITHUB_REPO}/check-runs/"
    require(isinstance(check_url, str) and check_url.startswith(prefix)
            and check_url[len(prefix):].isdigit(), "CI_CHECK_URL_INVALID")
    check = get(f"repos/{GITHUB_REPO}/check-runs/{check_url[len(prefix):]}", root)
    require(type(check.get("id")) is int and check["id"] > 0
            and check.get("name") == CHECK_NAME and check.get("head_sha") == revision
            and check.get("app", {}).get("id") == APP_ID
            and check.get("check_suite", {}).get("id") == run.get("check_suite_id")
            and check.get("status") == "completed" and check.get("conclusion") == "success",
            "CI_CHECK_NOT_TRUSTED")
    return {"github_repository": GITHUB_REPO, "source_revision": revision,
            "workflow": WORKFLOW, "run_id": run["id"], "run_attempt": run["run_attempt"],
            "check_name": CHECK_NAME, "check_id": check["id"], "check_app_id": APP_ID}


def allowed_source_path(name: str) -> bool:
    path = PurePosixPath(name)
    parts = path.parts
    if not parts or path.is_absolute() or "\\" in name or ":" in name or any(part in {".", ".."} for part in parts):
        return False
    if any(part.lower() in EXCLUDED_PARTS or part.lower().startswith(".env") for part in parts):
        return False
    if path.suffix.lower() in {".pem", ".key", ".p12", ".pfx", ".sqlite", ".sqlite3", ".db", ".pyc", ".log", ".tfplan", ".tfvars"}:
        return False
    lower = path.name.lower()
    if any(marker in lower for marker in (".sqlite-wal", ".sqlite-shm", ".sqlite3-", ".db-", ".tfstate")):
        return False
    if lower.endswith(".tfvars.json") or lower.startswith(".coverage"):
        return False
    return name in ROOT_FILES or parts[0] in SOURCE_ROOTS


def source_archive(root: Path, revision: str) -> tuple[bytes, list[dict]]:
    raw = command(["git", "archive", "--format=tar", revision], root)
    require(len(raw) <= MAX_ARCHIVE_BYTES, "SOURCE_ARCHIVE_TOO_LARGE")
    files: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for item in archive:
            if item.isdir() or not allowed_source_path(item.name):
                continue
            require(item.isfile() and not item.issym() and not item.islnk(), "SOURCE_LINK_DENIED")
            require(item.name not in files and len(files) < MAX_FILES, "SOURCE_FILE_SET_INVALID")
            reader = archive.extractfile(item)
            require(reader is not None, "SOURCE_FILE_UNREADABLE")
            files[item.name] = reader.read()
    require({"README.md", "safe-qa-service/pyproject.toml", "frontier-evidence-gateway/pyproject.toml"}
            <= files.keys(), "SOURCE_COMPONENTS_MISSING")
    packed = io.BytesIO()
    inventory = []
    with tarfile.open(fileobj=packed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(files.items()):
            item = tarfile.TarInfo(name)
            item.size = len(data)
            item.mode = 0o644
            item.mtime = 0
            archive.addfile(item, io.BytesIO(data))
            inventory.append({"path": name, "size": len(data), "sha256": digest(data)})
    return gzip.compress(packed.getvalue(), mtime=0), inventory


def python_payload(archive: bytes, revision: str) -> bytes:
    encoded = base64.b64encode(archive).decode()
    script = '''import base64, gzip, hashlib, io, pathlib, tarfile
SOURCE_REVISION = "REVISION"
EXPECTED_SHA256 = "DIGEST"
ARCHIVE = "ENCODED"
raw = base64.b64decode(ARCHIVE, validate=True)
if hashlib.sha256(raw).hexdigest() != EXPECTED_SHA256:
    raise SystemExit("Archive digest mismatch")
target = pathlib.Path("szl-safe-stack-" + SOURCE_REVISION[:12]).resolve()
if target.exists():
    raise SystemExit("Destination exists; choose a new empty destination")
with tarfile.open(fileobj=io.BytesIO(gzip.decompress(raw)), mode="r:") as bundle:
    members = bundle.getmembers()
    for item in members:
        name = pathlib.PurePosixPath(item.name)
        if not item.isfile() or name.is_absolute() or ".." in name.parts or "\\\\" in item.name or ":" in item.name:
            raise SystemExit("Unsafe archive entry")
        if not (target / item.name).resolve().is_relative_to(target):
            raise SystemExit("Unsafe destination")
    target.mkdir()
    for item in members:
        destination = target / item.name
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as output:
            output.write(bundle.extractfile(item).read())
print("Source extracted to", target)
print("Read README.md before installing or deploying. No service was started.")
'''.replace('"REVISION"', json.dumps(revision)).replace('"DIGEST"', json.dumps(digest(archive))).replace('"ENCODED"', json.dumps(encoded))
    return ("# SZL Safe Stack: source distribution\n\n"
            f"GitHub: `{GITHUB_REPO}` at `{revision}`.\n\n"
            "Copy the Python block into a file and run with Python 3.11 or later. "
            "It verifies and extracts the included source into a new directory. "
            "It does not install packages, start services, configure providers, or grant approvals. "
            "The source includes the API, policy checks, audit-ledger migrations, tests, "
            "container definitions, and deployment documentation. Read the extracted README for setup. "
            "This source-only archive has no Git history: use the README's manual Compose procedure, "
            "or use a verified canonical Git clone for the Windows launcher that requires a clean committed checkout. "
            "Cloud enforcement and model training are not claimed by this distribution.\n\n"
            "```python\n" + script + "```\n").encode()


def build_release(root: Path, source: dict) -> dict[str, bytes]:
    archive, inventory = source_archive(root, source["source_revision"])
    revision = source["source_revision"]
    release = {"source.tar.gz": archive, "source_payload.md": python_payload(archive, revision)}
    for name in ("README.md", "index.html"):
        template = command(["git", "show", f"{revision}:hf-space/{name}"], root).decode()
        release[name] = template.replace("{{SOURCE_SHA}}", revision).replace("{{ARCHIVE_SHA256}}", digest(archive)).encode()
    manifest = {"schema": "szl.source-distribution.v1", "status": "SOURCE_DISTRIBUTION",
                "hf_repository": HF_REPO, "private": True, "source": source,
                "api_deployment": "NOT_ESTABLISHED", "cloud_enforcement": "NOT_ESTABLISHED",
                "model_training": "NOT_PERFORMED", "independent_approval": "NOT_ESTABLISHED",
                "source_files": inventory,
                "release_files": [{"path": name, "sha256": digest(data), "size": len(data)}
                                  for name, data in sorted(release.items())]}
    release["source-manifest.json"] = canonical(manifest)
    return release


class Hub:
    def __init__(self):
        from importlib.metadata import version
        require(version("huggingface-hub") == PUBLISH_SDK_VERSION, "PINNED_PUBLICATION_SDK_REQUIRED")
        from huggingface_hub import HfApi
        self.api = HfApi(endpoint=HF_ORIGIN)

    def info(self, revision: str = "main"):
        return self.api.space_info(HF_REPO, revision=revision, files_metadata=True)

    def read(self, name: str, revision: str) -> bytes:
        from huggingface_hub import hf_hub_download
        path = hf_hub_download(HF_REPO, name, repo_type="space", revision=revision,
                               endpoint=HF_ORIGIN, token=self.api.token)
        return Path(path).read_bytes()

    def commit(self, files: dict[str, bytes], parent: str, revision: str) -> str:
        from huggingface_hub import CommitOperationAdd
        result = self.api.create_commit(HF_REPO, repo_type="space", revision="main",
                                       parent_commit=parent,
                                       operations=[CommitOperationAdd(path_in_repo=name, path_or_fileobj=data)
                                                   for name, data in sorted(files.items())],
                                       commit_message=f"Publish source distribution {revision}")
        return result.oid


def checked_space(hub, revision: str) -> dict:
    info = hub.info(revision)
    require(info.id == HF_REPO and info.private is True and info.sdk == "static", "PRIVATE_STATIC_TARGET_REQUIRED")
    require(isinstance(info.sha, str) and SHA.fullmatch(info.sha) is not None, "HF_HEAD_INVALID")
    siblings = info.siblings
    require(isinstance(siblings, list) and len(siblings) <= len(RELEASE_FILES) + 1, "HF_TREE_INVALID")
    files = {}
    for item in siblings:
        require(item.rfilename in RELEASE_FILES | {".gitattributes"} and item.rfilename not in files,
                "HF_UNEXPECTED_FILE")
        require(type(item.size) is int and 0 <= item.size <= MAX_ARCHIVE_BYTES * 2, "HF_FILE_SIZE_INVALID")
        files[item.rfilename] = {"size": item.size, "blob": item.blob_id}
    return {"sha": info.sha, "files": files}


def publish(hub, files: dict[str, bytes], parent: str, source: dict, fresh_source, record) -> str:
    require(SHA.fullmatch(parent) is not None and set(files) == RELEASE_FILES, "PUBLICATION_INPUT_INVALID")
    before = checked_space(hub, "main")
    require(before["sha"] == parent, "HF_PARENT_CHANGED")
    require(fresh_source() == source, "GITHUB_SOURCE_CHANGED")
    require(checked_space(hub, "main") == before, "HF_PARENT_CHANGED")
    record({"phase": "WRITE_INTENT", "expected_parent": parent, "source": source,
            "release_sha256": {name: digest(data) for name, data in sorted(files.items())}})
    try:
        commit = hub.commit(files, parent, source["source_revision"])
        require(isinstance(commit, str) and SHA.fullmatch(commit) is not None, "HF_COMMIT_INVALID")
        candidate = checked_space(hub, commit)
        require(candidate["sha"] == commit and set(candidate["files"]) == set(before["files"]) | RELEASE_FILES,
                "HF_CANDIDATE_TREE_MISMATCH")
        if ".gitattributes" in before["files"]:
            require(candidate["files"][".gitattributes"] == before["files"][".gitattributes"], "HF_BASE_FILE_CHANGED")
        for name, expected in files.items():
            require(hub.read(name, commit) == expected, "HF_IMMUTABLE_CONTENT_MISMATCH")
        require(checked_space(hub, "main")["sha"] == commit, "HF_MAIN_MOVED_AFTER_WRITE")
    except Exception:
        record({"phase": "UNKNOWN_AFTER_ATTEMPT", "expected_parent": parent})
        raise PublicationError("UNKNOWN_AFTER_ATTEMPT_NO_AUTOMATIC_RETRY") from None
    record({"phase": "SOURCE_DISTRIBUTION_VERIFIED", "hf_repository": HF_REPO,
            "hf_commit": commit, "source": source})
    return commit


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True, help="New local directory outside the source checkout")
    parser.add_argument("--publish", action="store_true")
    parser.add_argument("--expected-parent", help="Exact current private static Space commit; required for --publish")
    args = parser.parse_args()
    try:
        root, output = args.root.resolve(), args.output.resolve()
        require(not output.exists() and not output.is_relative_to(root), "NEW_EXTERNAL_OUTPUT_DIRECTORY_REQUIRED")
        require(not args.publish or (args.expected_parent is not None and SHA.fullmatch(args.expected_parent) is not None),
                "EXACT_HF_PARENT_REQUIRED")
        source = source_snapshot(root)
        require(source_snapshot(root) == source, "GITHUB_SOURCE_CHANGED")
        files = build_release(root, source)
        output.mkdir(parents=True)
        for name, data in files.items():
            with (output / name).open("xb") as stream:
                stream.write(data)
        def record(value):
            with (output / "publication-receipts.jsonl").open("ab") as stream:
                stream.write(json.dumps(value, sort_keys=True).encode() + b"\n")
                stream.flush()
                import os
                os.fsync(stream.fileno())
        record({"phase": "PREPARED", "source": source})
        if args.publish:
            commit = publish(Hub(), files, args.expected_parent, source, lambda: source_snapshot(root), record)
            print(json.dumps({"status": "SOURCE_DISTRIBUTION_VERIFIED", "hf_commit": commit, "output": str(output)}))
        else:
            print(json.dumps({"status": "PREPARED_ONLY", "output": str(output)}))
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, PublicationError) else "PUBLICATION_FAILED"
        print(json.dumps({"status": "BLOCKED", "reason": code}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
