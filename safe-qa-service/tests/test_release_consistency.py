from __future__ import annotations

import re
import tomllib
from pathlib import Path

from safe_qa_service import __version__
from safe_qa_service.app import app

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_release_version_is_consistent_across_active_artifacts() -> None:
    project = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    release_version = project["project"]["version"]

    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", release_version)
    assert __version__ == release_version
    assert app.version == release_version

    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert f'org.opencontainers.image.version="{release_version}"' in dockerfile
    assert f"safe_qa_service-{release_version}-py3-none-any.whl" in dockerfile

    compatibility_manifest = (PROJECT_ROOT / "deploy" / "kubernetes.yaml").read_text(
        encoding="utf-8"
    )
    assert f"safe-qa-service:{release_version}" in compatibility_manifest

    active_wheels = tuple((PROJECT_ROOT / "dist").glob("safe_qa_service-*.whl"))
    assert all(
        wheel.name.startswith(f"safe_qa_service-{release_version}-") for wheel in active_wheels
    )
