"""Strict production approval and cross-account evidence configuration."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .approval_verification import SignerPolicy
from .schemas.v2 import ApprovalRole
from .settings import ConfigurationError


class _StrictConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class _SignerRecord(_StrictConfig):
    key_arn: str = Field(
        min_length=50,
        max_length=256,
        pattern=(
            r"^arn:(?:aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:[0-9]{12}:"
            r"key/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
        ),
    )
    identity_store_arn: str = Field(
        min_length=45,
        max_length=180,
        pattern=(
            r"^arn:(?:aws|aws-us-gov|aws-cn):identitystore::[0-9]{12}:"
            r"identitystore/d-[a-z0-9]{10,32}$"
        ),
    )
    identity_center_user_id: str = Field(
        min_length=36,
        max_length=47,
        pattern=(
            r"^(?:[0-9a-f]{10}-)?[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-"
            r"[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$"
        ),
    )
    principal_arn: str = Field(
        min_length=20,
        max_length=512,
        pattern=r"^arn:(?:aws|aws-us-gov|aws-cn):(?:iam|sts)::[0-9]{12}:.+$",
    )


class _ApprovalConfig(_StrictConfig):
    schema_version: Literal["2.0"] = "2.0"
    production_account_id: str = Field(pattern=r"^[0-9]{12}$")
    security_owner: _SignerRecord
    release_owner: _SignerRecord
    witness: _SignerRecord

    @model_validator(mode="after")
    def validate_independence(self) -> _ApprovalConfig:
        def account(arn: str) -> str:
            return arn.split(":", 5)[4]

        humans = {
            (
                signer.identity_store_arn,
                signer.identity_center_user_id,
            )
            for signer in (self.security_owner, self.release_owner, self.witness)
        }
        if len(humans) != 3:
            raise ValueError("approval authorities must be three distinct Identity Center humans")
        keys = {
            self.security_owner.key_arn,
            self.release_owner.key_arn,
            self.witness.key_arn,
        }
        if len(keys) != 3:
            raise ValueError("approval authorities must use three distinct asymmetric KMS keys")
        for signer in (self.security_owner, self.release_owner):
            if {
                account(signer.key_arn),
                account(signer.identity_store_arn),
                account(signer.principal_arn),
            } != {self.production_account_id}:
                raise ValueError(
                    "production signer key, identity store, and role must be in production"
                )
        witness_account = account(self.witness.key_arn)
        if witness_account == self.production_account_id:
            raise ValueError("witness KMS key must be in a separate AWS account")
        if {
            account(self.witness.identity_store_arn),
            account(self.witness.principal_arn),
        } != {witness_account}:
            raise ValueError(
                "witness key, identity store, and role must share the witness account"
            )
        return self


class _EvidenceRouteRecord(_StrictConfig):
    account_id: str = Field(pattern=r"^[0-9]{12}$")
    region: str = Field(min_length=3, max_length=32, pattern=r"^[a-z0-9-]+$")
    reader_role_arn: str | None = Field(
        default=None,
        min_length=20,
        max_length=512,
        pattern=r"^arn:(?:aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/.+$",
    )
    external_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=256,
        pattern=r"^[A-Za-z0-9+=,.@:/_-]+$",
    )

    @model_validator(mode="after")
    def bind_role_account(self) -> _EvidenceRouteRecord:
        if (
            self.reader_role_arn is not None
            and self.reader_role_arn.split(":", 5)[4] != self.account_id
        ):
            raise ValueError("evidence reader role must be in its declared account")
        if self.reader_role_arn is None and self.external_id is not None:
            raise ValueError("a direct evidence route cannot carry an external ID")
        return self


@dataclass(frozen=True)
class ApprovalRuntimeConfig:
    production_account_id: str
    approvers: dict[ApprovalRole, SignerPolicy]
    witness: SignerPolicy
    key_arns: tuple[str, str, str]


@dataclass(frozen=True)
class AwsEvidenceRoute:
    account_id: str
    region: str
    reader_role_arn: str | None
    external_id: str | None


def _load_json_environment(name: str, maximum_bytes: int = 128_000) -> object:
    raw = os.getenv(name)
    if not raw or len(raw.encode("utf-8")) > maximum_bytes:
        raise ConfigurationError(f"{name} is absent or oversized")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigurationError(f"{name} is invalid JSON") from exc


def load_approval_runtime_config() -> ApprovalRuntimeConfig:
    try:
        parsed = _ApprovalConfig.model_validate(
            _load_json_environment("SAFE_QA_APPROVAL_POLICY_JSON")
        )
    except ValidationError as exc:
        raise ConfigurationError("SAFE_QA_APPROVAL_POLICY_JSON failed validation") from exc

    def policy(record: _SignerRecord, role: ApprovalRole | None) -> SignerPolicy:
        return SignerPolicy(
            role=role,
            key_arn=record.key_arn,
            identity_store_arn=record.identity_store_arn,
            identity_center_user_id=record.identity_center_user_id,
            principal_arn=record.principal_arn,
        )

    security = policy(parsed.security_owner, ApprovalRole.SECURITY_OWNER)
    release = policy(parsed.release_owner, ApprovalRole.RELEASE_OWNER)
    witness = policy(parsed.witness, None)
    return ApprovalRuntimeConfig(
        production_account_id=parsed.production_account_id,
        approvers={
            ApprovalRole.SECURITY_OWNER: security,
            ApprovalRole.RELEASE_OWNER: release,
        },
        witness=witness,
        key_arns=(security.key_arn, release.key_arn, witness.key_arn),
    )


def load_aws_evidence_routes(
    required_key_arns: tuple[str, ...],
) -> dict[tuple[str, str], AwsEvidenceRoute]:
    raw = _load_json_environment("SAFE_QA_AWS_EVIDENCE_ROUTES_JSON")
    if not isinstance(raw, list) or not raw or len(raw) > 20:
        raise ConfigurationError("AWS evidence routes must be a bounded non-empty list")
    routes: dict[tuple[str, str], AwsEvidenceRoute] = {}
    try:
        records = [_EvidenceRouteRecord.model_validate(item) for item in raw]
    except ValidationError as exc:
        raise ConfigurationError("AWS evidence routes failed validation") from exc
    for record in records:
        key = (record.account_id, record.region)
        if key in routes:
            raise ConfigurationError("AWS evidence routes contain a duplicate account/region")
        routes[key] = AwsEvidenceRoute(
            account_id=record.account_id,
            region=record.region,
            reader_role_arn=record.reader_role_arn,
            external_id=record.external_id,
        )
    required = {(arn.split(":", 5)[4], arn.split(":", 5)[3]) for arn in required_key_arns}
    if required - set(routes):
        raise ConfigurationError("AWS evidence routes do not cover every configured KMS key")
    return routes
