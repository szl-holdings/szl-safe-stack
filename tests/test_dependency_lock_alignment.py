"""Check declared direct dependencies against the locks that CI installs.

This is a metadata/lock consistency guard, not a dependency resolver, a hash
verifier, or a substitute for the existing pip check/audit/container gates.
"""
from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]
HASH = re.compile(r"\s+--hash=sha256:[0-9a-f]{64}(?=\s|$)")


def exact_pins(requirements: list[str]) -> dict[str, str]:
    """Return unambiguous exact pins active in the executing Python environment."""
    pins: dict[str, str] = {}
    for text in requirements:
        requirement = Requirement(text)
        specifications = list(requirement.specifier)
        if (requirement.url is not None or len(specifications) != 1
                or specifications[0].operator != "=="
                or "*" in specifications[0].version):
            raise ValueError("An exact distribution pin is required")
        version = str(Version(specifications[0].version))
        if requirement.marker is not None and not requirement.marker.evaluate():
            continue
        name = canonicalize_name(requirement.name)
        if name in pins:
            raise ValueError(f"Ambiguous active pin: {name}")
        pins[name] = version
    return pins


def lock_pins(text: str) -> dict[str, str]:
    """Parse pip-style hashed lock entries without dropping marker expressions."""
    entries: list[str] = []
    pending: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        continued = line.endswith("\\")
        segment = line[:-1].rstrip() if continued else line
        if segment.startswith("--hash=") and not pending:
            raise ValueError("Orphan lock hash")
        pending.append(segment)
        if not continued:
            combined = " ".join(pending)
            entries.append(HASH.sub("", combined).strip())
            pending.clear()
    if pending:
        raise ValueError("Unterminated lock continuation")
    if not entries:
        raise ValueError("Empty dependency lock")
    pins = exact_pins(entries)
    if not pins:
        raise ValueError("No active dependency pins")
    return pins


def require_alignment(declarations: list[str], locked: str) -> None:
    """Require each active declared dependency to match its own installed lock."""
    expected = exact_pins(declarations)
    if not expected:
        raise ValueError("No declared dependency pins")
    actual = lock_pins(locked)
    mismatches = {
        name: {"declared": version, "locked": actual.get(name)}
        for name, version in expected.items()
        if name not in actual or Version(actual[name]) != Version(version)
    }
    if mismatches:
        raise AssertionError(f"Declared dependencies differ from installed lock: {mismatches}")


class DependencyLockAlignment(unittest.TestCase):
    """These exercise actual checked-out manifests/locks through existing root CI."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.project = tomllib.loads(
            (ROOT / "safe-qa-service/pyproject.toml").read_text(encoding="utf-8")
        )

    def assert_locked(self, declarations: list[str], path: str) -> None:
        require_alignment(declarations, (ROOT / path).read_text(encoding="utf-8"))

    def test_runtime_dependencies_match_runtime_lock(self) -> None:
        self.assert_locked(self.project["project"]["dependencies"],
                           "safe-qa-service/requirements.lock")

    def test_build_dependencies_match_no_isolation_build_lock(self) -> None:
        self.assert_locked(self.project["build-system"]["requires"],
                           "safe-qa-service/build-requirements.lock")

    def test_optional_test_dependencies_match_actual_ci_lock(self) -> None:
        self.assert_locked(self.project["project"]["optional-dependencies"]["test"],
                           ".github/test-requirements.lock")


class LockAlignmentRegressions(unittest.TestCase):
    def test_consistent_pins_allow_transitive_dependencies(self) -> None:
        require_alignment(["wheel==0.47.0"], "wheel==0.47.0\npackaging==26.3\n")

    def test_changed_build_tool_cannot_pass_with_old_lock(self) -> None:
        with self.assertRaises(AssertionError):
            require_alignment(["setuptools==84.0.0"], "setuptools==83.0.0\n")

    def test_changed_optional_test_tool_cannot_pass_with_old_lock(self) -> None:
        with self.assertRaises(AssertionError):
            require_alignment(["pytest-cov==7.1.0"], "pytest-cov==6.2.1\n")

    def test_changed_runtime_cannot_pass_with_old_lock(self) -> None:
        with self.assertRaises(AssertionError):
            require_alignment(["uvicorn[standard]==0.53.0"], "uvicorn==0.35.0\n")

    def test_missing_declared_package_is_not_a_pass(self) -> None:
        with self.assertRaises(AssertionError):
            require_alignment(["pytest-cov==7.1.0"], "pytest==9.1.1\n")

    def test_normalized_names_extras_and_equivalent_versions(self) -> None:
        require_alignment(["PyJWT[crypto]==2.13.0"], "pyjwt==2.13.0\n")
        require_alignment(["example_pkg==1.0.0"], "example-pkg==1.0\n")

    def test_multiline_hashes_crlf_and_comments(self) -> None:
        hashed = ("# Generated lock\r\nexample==1.0 \\\r\n"
                  + "    --hash=sha256:" + "a" * 64 + " \\\r\n"
                  + "    --hash=sha256:" + "b" * 64 + "\r\n    # via input\r\n")
        require_alignment(["example==1.0"], hashed)

    def test_markers_are_evaluated_not_stripped(self) -> None:
        require_alignment(["example==1.0; python_version >= '3.11'"],
                          "example==1.0; python_version >= '3.11'\n"
                          "example==2.0; python_version < '3.11'\n")
        with self.assertRaises(AssertionError):
            require_alignment(["example==1.0"],
                              "example==1.0; python_version < '3.0'\nother==1.0\n")

    def test_ambiguous_active_normalized_pins_fail(self) -> None:
        with self.assertRaises(ValueError):
            lock_pins("example_pkg==1.0\nexample-pkg==1.0\n")

    def test_invalid_or_unpinned_requirements_fail(self) -> None:
        for requirement in ("example>=1.0", "example==1.*", "example===1.0",
                            "example @ https://example.invalid/pkg.whl", "not a requirement"):
            with self.subTest(requirement=requirement), self.assertRaises(ValueError):
                exact_pins([requirement])

    def test_empty_inputs_fail(self) -> None:
        with self.assertRaises(ValueError):
            require_alignment([], "example==1.0\n")
        with self.assertRaises(ValueError):
            require_alignment(["example==1.0"], "# no pins\n")

    def test_malformed_lock_syntax_fails(self) -> None:
        for text in ("example==1.0 \\\n", "--hash=sha256:" + "a" * 64,
                     "--index-url https://example.invalid\nexample==1.0\n",
                     "example==1.0 --hash=sha256:invalid\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                lock_pins(text)


if __name__ == "__main__":
    unittest.main()
