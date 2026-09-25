"""Regenerate the hashed uv locks after a declaration-only dependency bump.

Dependabot edits safe-qa-service/pyproject.toml and
safe-qa-service/build-requirements.in but cannot regenerate the hashed
``*.lock`` files that CI installs with ``--require-hashes``. This tool:

1. copies the pinned ``[project.optional-dependencies].test`` versions from
   safe-qa-service/pyproject.toml into .github/test-requirements.in (an input
   Dependabot never edits), keeping comments and ``-c`` lines;
2. re-runs the exact ``uv pip compile`` commands recorded in each lock header,
   runtime and build first, because the test lock is constrained by both.

Existing pins stay as resolver preferences (no ``--upgrade``), so only the
packages whose declarations changed, plus transitive requirements they force,
move. requirements-publish.lock and .github/audit-requirements.lock are not
touched. tests/test_dependency_lock_alignment.py is the acceptance check.

Usage: python tools/sync_locks.py            (repository = parent of tools/)
       LOCK_SYNC_ROOT=<checkout> python tools/sync_locks.py
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

# LOCK_SYNC_ROOT lets CI run the trusted base-branch copy of this tool against a
# separate checkout of the Dependabot branch.
ROOT = Path(os.environ.get("LOCK_SYNC_ROOT") or Path(__file__).resolve().parents[1]).resolve()
PYPROJECT = ROOT / "safe-qa-service/pyproject.toml"
TEST_IN = ".github/test-requirements.in"

# Order matters: the test lock uses -c on the runtime and build locks.
COMPILES = [
    ("safe-qa-service/requirements.lock",
     ["safe-qa-service/pyproject.toml", "--universal", "--python-version", "3.12"]),
    ("safe-qa-service/build-requirements.lock",
     ["safe-qa-service/build-requirements.in", "--universal", "--python-version", "3.12"]),
    (".github/test-requirements.lock",
     [TEST_IN, "--python-version", "3.12", "--universal"]),
]
COMMON = ["--generate-hashes", "--no-emit-index-url"]


def recorded_command(lock: str) -> str:
    for line in (ROOT / lock).read_text(encoding="utf-8").splitlines()[:3]:
        text = line.lstrip("# ").strip()
        if text.startswith("uv pip compile"):
            return re.sub(r"\s+", " ", text)
    sys.exit(f"{lock}: no 'uv pip compile' header; refusing to regenerate")


def synced_test_in() -> str:
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    pins = {canonicalize_name(Requirement(r).name): r
            for r in project["project"]["optional-dependencies"]["test"]}
    lines = []
    for line in (ROOT / TEST_IN).read_text(encoding="utf-8").splitlines():
        body = line.strip()
        if body and not body.startswith(("#", "-")):
            line = pins.pop(canonicalize_name(Requirement(body).name), line)
        lines.append(line)
    if pins:
        sys.exit(f"test extras missing from {TEST_IN}: {sorted(pins)}")
    return "\n".join(lines) + "\n"


def main() -> int:
    uv = shutil.which("uv") or sys.exit("uv not on PATH")
    for lock, argv in COMPILES:
        expected = " ".join(["uv", "pip", "compile", *argv, *COMMON, "--output-file", lock])
        if recorded_command(lock) != expected:
            sys.exit(f"{lock}: header drifted from the command this tool runs:\n"
                     f"  recorded: {recorded_command(lock)}\n  expected: {expected}")

    tracked = [TEST_IN, *(lock for lock, _ in COMPILES)]
    before = {p: (ROOT / p).read_bytes() for p in tracked}
    (ROOT / TEST_IN).write_text(synced_test_in(), encoding="utf-8", newline="\n")
    for lock, argv in COMPILES:
        subprocess.run([uv, "pip", "compile", *argv, *COMMON, "--output-file", lock],
                       cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    changed = [p for p in tracked if (ROOT / p).read_bytes() != before[p]]
    print("changed:", " ".join(changed) if changed else "none")
    return 0


if __name__ == "__main__":
    sys.exit(main())
