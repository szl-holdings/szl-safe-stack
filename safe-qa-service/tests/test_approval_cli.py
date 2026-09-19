from __future__ import annotations

import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

from safe_qa_service import approval_cli
from safe_qa_service.schemas.v2 import (
    ApprovalDecision,
    ApprovalRole,
    ApprovalStatementV2,
    DeploymentPlanV2,
    EksIsolateNamespaceActionV2,
    HumanIdentityV2,
    WitnessStatementV2,
)

NOW = datetime(2026, 8, 11, 16, 0, tzinfo=UTC)
ACCOUNT = "111111111111"
IDENTITY_STORE = f"arn:aws:identitystore::{ACCOUNT}:identitystore/d-1234567890"
USER_ID = "01234567-89ab-4cde-8fab-0123456789ab"
KEY_ARN = (
    f"arn:aws:kms:us-east-1:{ACCOUNT}:key/"
    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
)


def _plan() -> DeploymentPlanV2:
    return DeploymentPlanV2(
        plan_id=UUID("11111111-1111-4111-8111-111111111111"),
        nonce="n" * 43,
        source_revision="abcdef1234567890",
        container_digest="sha256:" + "1" * 64,
        evidence_manifest_sha256="2" * 64,
        policy_bundle_sha256="3" * 64,
        provider_state_sha256="4" * 64,
        environment="aws/eks/production",
        requester_issuer="https://issuer.example.test",
        requester_subject="requester",
        created_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        provider_actions=(
            EksIsolateNamespaceActionV2(
                action_id=UUID("22222222-2222-4222-8222-222222222222"),
                cluster_name="production",
                namespace="safe-qa",
            ),
        ),
    )


def _write(path: Path, model: object) -> None:
    value = model.model_dump(mode="json") if hasattr(model, "model_dump") else model
    path.write_text(json.dumps(value), encoding="utf-8")


def test_cli_emits_unsigned_plan_approval_and_witness_digests(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plan = _plan()
    plan_path = tmp_path / "plan.json"
    _write(plan_path, plan)
    assert approval_cli.main(["plan-digest", str(plan_path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "UNSIGNED_NOT_AUTHORIZED"
    assert len(output["plan_digest"]) == 64

    human = HumanIdentityV2(
        display_name="Security Owner",
        identity_store_arn=IDENTITY_STORE,
        identity_center_user_id=USER_ID,
    )
    approval = ApprovalStatementV2(
        approval_id=UUID("33333333-3333-4333-8333-333333333333"),
        plan_id=plan.plan_id,
        plan_digest=output["plan_digest"],
        plan_nonce=plan.nonce,
        decision=ApprovalDecision.APPROVE,
        role=ApprovalRole.SECURITY_OWNER,
        approver=human,
        key_arn=KEY_ARN,
        signed_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
    )
    approval_path = tmp_path / "approval.json"
    _write(approval_path, approval)
    assert approval_cli.main(["approval-digest", str(approval_path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "UNSIGNED_NOT_APPROVED"
    assert len(output["signing_digest_hex"]) == 64

    witness = WitnessStatementV2(
        witness_id=UUID("44444444-4444-4444-8444-444444444444"),
        witness_name="Independent Witness",
        witness_account_id="333333333333",
        witness_key_arn=(
            "arn:aws:kms:us-east-1:333333333333:key/"
            "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        ),
        witness_identity=human.model_copy(
            update={"identity_center_user_id": "21234567-89ab-4cde-8fab-0123456789ab"}
        ),
        plan_id=plan.plan_id,
        plan_digest=approval.plan_digest,
        approval_ids=(approval.approval_id, UUID("55555555-5555-4555-8555-555555555555")),
        approval_record_digests=("5" * 64, "6" * 64),
        witnessed_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
    )
    witness_path = tmp_path / "witness.json"
    _write(witness_path, witness)
    assert approval_cli.main(["witness-digest", str(witness_path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "UNSIGNED_NOT_WITNESSED"
    assert len(output["signing_digest_hex"]) == 64


def test_bundle_schema_check_is_explicitly_not_authorization(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "bundle.json"
    _write(path, {"schema_version": "2.0"})
    monkeypatch.setattr(approval_cli.ApprovalBundleV2, "model_validate", lambda value: value)

    assert approval_cli.main(["bundle-schema-check", str(path)]) == 0

    output = json.loads(capsys.readouterr().out)
    assert output == {
        "status": "SCHEMA_VALID_ONLY_NOT_AUTHORIZED",
        "warning": "KMS signatures and CloudTrail evidence were not verified",
    }


def test_cli_rejects_malformed_oversized_and_non_regular_input(
    tmp_path: Path,
) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    with pytest.raises(SystemExit) as error:
        approval_cli.main(["plan-digest", str(malformed)])
    assert error.value.code == 2

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * (approval_cli.MAXIMUM_INPUT_BYTES + 1))
    with pytest.raises(ValueError, match="safety bound"):
        approval_cli._read_json(oversized)

    fake_path = SimpleNamespace(
        lstat=lambda: SimpleNamespace(st_mode=stat.S_IFLNK, st_size=2)
    )
    with pytest.raises(ValueError, match="regular non-symlink"):
        approval_cli._read_json(fake_path)
