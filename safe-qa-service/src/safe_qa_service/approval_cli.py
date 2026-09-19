"""Offline canonical-digest helper; deliberately incapable of signing."""

from __future__ import annotations

import argparse
import json
import stat
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .approval_verification import (
    approval_signing_digest,
    deployment_plan_digest,
    witness_signing_digest,
)
from .schemas.v2 import ApprovalBundleV2, ApprovalStatementV2, DeploymentPlanV2, WitnessStatementV2

MAXIMUM_INPUT_BYTES = 512_000


def _read_json(path: Path) -> Any:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("input must be a regular non-symlink file")
    if metadata.st_size > MAXIMUM_INPUT_BYTES:
        raise ValueError("input exceeds the 512000-byte safety bound")
    with path.open("rb") as handle:
        raw = handle.read(MAXIMUM_INPUT_BYTES + 1)
    if len(raw) > MAXIMUM_INPUT_BYTES:
        raise ValueError("input grew beyond the safety bound while reading")
    return json.loads(raw.decode("utf-8"))


def _emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Create canonical SHA-256 signing inputs. This helper has no KMS Sign, HMAC, "
            "credential, approval, witness, or deployment capability."
        )
    )
    parser.add_argument(
        "operation",
        choices=("plan-digest", "approval-digest", "witness-digest", "bundle-schema-check"),
    )
    parser.add_argument("input", type=Path)
    args = parser.parse_args(argv)
    try:
        value = _read_json(args.input)
        if args.operation == "plan-digest":
            model = DeploymentPlanV2.model_validate(value)
            _emit(
                {
                    "digest_algorithm": "SHA-256",
                    "message_type": "DIGEST",
                    "plan_digest": deployment_plan_digest(model),
                    "status": "UNSIGNED_NOT_AUTHORIZED",
                }
            )
        elif args.operation == "approval-digest":
            model = ApprovalStatementV2.model_validate(value)
            _emit(
                {
                    "digest_algorithm": "SHA-256",
                    "message_type": "DIGEST",
                    "signing_digest_hex": approval_signing_digest(model).hex(),
                    "status": "UNSIGNED_NOT_APPROVED",
                }
            )
        elif args.operation == "witness-digest":
            model = WitnessStatementV2.model_validate(value)
            _emit(
                {
                    "digest_algorithm": "SHA-256",
                    "message_type": "DIGEST",
                    "signing_digest_hex": witness_signing_digest(model).hex(),
                    "status": "UNSIGNED_NOT_WITNESSED",
                }
            )
        else:
            ApprovalBundleV2.model_validate(value)
            _emit(
                {
                    "status": "SCHEMA_VALID_ONLY_NOT_AUTHORIZED",
                    "warning": "KMS signatures and CloudTrail evidence were not verified",
                }
            )
    except (OSError, UnicodeError, json.JSONDecodeError, ValidationError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
