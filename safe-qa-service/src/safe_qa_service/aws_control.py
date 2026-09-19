"""Exact-target AWS/EKS provider controls with read-before-write enforcement.

The provider never discovers mutation targets. Every account, region, cluster,
namespace, deployment, IAM user/access key, and IAM role must be present in a
locally configured allowlist before the first provider API call. Authorization
is deliberately handled by :mod:`safe_qa_service.control_plane`; this module
only implements bounded, idempotent provider reads and writes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from .approval_verification import canonical_json_bytes
from .schemas.v2 import (
    EksDeployImmutableImageActionV2,
    EksIsolateNamespaceActionV2,
    IamDisableAccessKeyActionV2,
    IamRevokeRoleSessionsActionV2,
    ProviderActionPreviewV2,
    ProviderActionReceiptV2,
    ProviderActionV2,
)
from .settings import ConfigurationError


class AwsControlError(RuntimeError):
    """A provider target, precondition, mutation, or readback was not exact."""


@dataclass(frozen=True)
class EksDeploymentTargetPolicy:
    deployment_name: str
    container_name: str
    image_repository: str
    service_account_name: str


@dataclass(frozen=True)
class AwsTargetPolicy:
    account_id: str
    region: str
    runtime_principal_arn: str
    controller_namespace: str
    controller_service_account: str
    network_policy_admin_group: str
    eks_cluster_name: str
    eks_deployments: dict[tuple[str, str], dict[str, EksDeploymentTargetPolicy]]
    eks_isolation_namespaces: frozenset[tuple[str, str]]
    iam_access_keys: dict[str, frozenset[str]]
    iam_roles: frozenset[str]


def _nonempty_string(value: object, label: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ConfigurationError(f"{label} must be a bounded non-empty string")
    return value


def load_aws_target_policy() -> AwsTargetPolicy:
    """Load a closed target set; wildcards and inferred targets are forbidden."""
    raw = os.getenv("SAFE_QA_AWS_TARGET_POLICY_JSON")
    if not raw or len(raw.encode("utf-8")) > 128_000:
        raise ConfigurationError("SAFE_QA_AWS_TARGET_POLICY_JSON is absent or oversized")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigurationError("SAFE_QA_AWS_TARGET_POLICY_JSON is invalid JSON") from exc
    if not isinstance(value, dict) or set(value) != {
        "account_id",
        "region",
        "runtime_principal_arn",
        "controller_namespace",
        "controller_service_account",
        "network_policy_admin_group",
        "eks",
        "iam_access_keys",
        "iam_roles",
    }:
        raise ConfigurationError("AWS target policy fields are incomplete or unexpected")
    account_id = _nonempty_string(value["account_id"], "AWS account ID", 12)
    region = _nonempty_string(value["region"], "AWS region", 32)
    principal = _nonempty_string(value["runtime_principal_arn"], "runtime principal ARN")
    controller_namespace = _nonempty_string(
        value["controller_namespace"], "controller namespace", 63
    )
    controller_service_account = _nonempty_string(
        value["controller_service_account"], "controller ServiceAccount", 63
    )
    network_policy_admin_group = _nonempty_string(
        value["network_policy_admin_group"], "network-policy administrator group", 256
    )
    if not re.fullmatch(r"[0-9]{12}", account_id):
        raise ConfigurationError("AWS account ID is invalid")
    if not re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-[0-9]", region):
        raise ConfigurationError("AWS region is invalid")
    arn_prefix = rf"arn:(?:aws|aws-us-gov|aws-cn):iam::{account_id}:role/.+"
    if not re.fullmatch(arn_prefix, principal):
        raise ConfigurationError("runtime principal ARN is outside the configured account")
    dns_name = r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?"
    if not re.fullmatch(dns_name, controller_namespace) or not re.fullmatch(
        dns_name, controller_service_account
    ):
        raise ConfigurationError("controller Kubernetes identity is invalid")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@/+=,-]*", network_policy_admin_group):
        raise ConfigurationError("network-policy administrator group is invalid")

    eks = value["eks"]
    if not isinstance(eks, list) or not eks or len(eks) > 100:
        raise ConfigurationError("AWS EKS allowlist must be a bounded non-empty list")
    deployments: dict[tuple[str, str], dict[str, EksDeploymentTargetPolicy]] = {}
    isolation: set[tuple[str, str]] = set()
    cluster_names: set[str] = set()
    for item in eks:
        if not isinstance(item, dict) or set(item) != {
            "cluster_name",
            "namespace",
            "deployments",
            "allow_emergency_isolation",
        }:
            raise ConfigurationError("AWS EKS allowlist entry is invalid")
        cluster = _nonempty_string(item["cluster_name"], "EKS cluster", 100)
        namespace = _nonempty_string(item["namespace"], "EKS namespace", 63)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", cluster):
            raise ConfigurationError("EKS cluster name is invalid")
        if not re.fullmatch(dns_name, namespace):
            raise ConfigurationError("EKS namespace is invalid")
        cluster_names.add(cluster)
        raw_deployments = item["deployments"]
        if not isinstance(raw_deployments, list) or len(raw_deployments) > 100:
            raise ConfigurationError("EKS deployments must be bounded exact objects")
        deployment_policies: dict[str, EksDeploymentTargetPolicy] = {}
        for deployment in raw_deployments:
            if not isinstance(deployment, dict) or set(deployment) != {
                "deployment_name",
                "container_name",
                "image_repository",
                "service_account_name",
            }:
                raise ConfigurationError("EKS deployment policy fields are invalid")
            deployment_name = _nonempty_string(
                deployment["deployment_name"], "EKS deployment name", 63
            )
            container_name = _nonempty_string(
                deployment["container_name"], "EKS container name", 63
            )
            image_repository = _nonempty_string(
                deployment["image_repository"], "EKS image repository", 512
            )
            service_account_name = _nonempty_string(
                deployment["service_account_name"], "EKS ServiceAccount name", 63
            )
            if (
                not re.fullmatch(dns_name, deployment_name)
                or not re.fullmatch(dns_name, container_name)
                or not re.fullmatch(dns_name, service_account_name)
                or not re.fullmatch(r"[A-Za-z0-9._:/-]+", image_repository)
                or "@" in image_repository
                or deployment_name in deployment_policies
            ):
                raise ConfigurationError("EKS deployment policy value is invalid")
            deployment_policies[deployment_name] = EksDeploymentTargetPolicy(
                deployment_name=deployment_name,
                container_name=container_name,
                image_repository=image_repository,
                service_account_name=service_account_name,
            )
        target = (cluster, namespace)
        if target in deployments:
            raise ConfigurationError("duplicate EKS cluster and namespace allowlist entry")
        deployments[target] = deployment_policies
        if item["allow_emergency_isolation"] is True:
            isolation.add(target)
        elif item["allow_emergency_isolation"] is not False:
            raise ConfigurationError("allow_emergency_isolation must be boolean")
    if len(cluster_names) != 1:
        raise ConfigurationError(
            "one runtime Kubernetes client must bind to exactly one EKS cluster"
        )

    keys = value["iam_access_keys"]
    if not isinstance(keys, dict) or len(keys) > 100:
        raise ConfigurationError("IAM access-key allowlist must be an object")
    access_keys: dict[str, frozenset[str]] = {}
    for user, identifiers in keys.items():
        if (
            not isinstance(user, str)
            or not user
            or not isinstance(identifiers, list)
            or not identifiers
            or len(identifiers) > 20
            or any(not isinstance(identifier, str) or not identifier for identifier in identifiers)
        ):
            raise ConfigurationError("IAM access-key allowlist entry is invalid")
        access_keys[user] = frozenset(identifiers)
    roles = value["iam_roles"]
    role_name_pattern = r"[A-Za-z0-9+=,.@_-]{1,64}"
    if (
        not isinstance(roles, list)
        or len(roles) > 100
        or any(
            not isinstance(role, str) or not re.fullmatch(role_name_pattern, role)
            for role in roles
        )
    ):
        raise ConfigurationError("IAM role allowlist must be a bounded list")
    runtime_role_name = principal.rsplit("/", 1)[-1]
    if runtime_role_name in roles:
        raise ConfigurationError("runtime role cannot be a session-revocation target")
    return AwsTargetPolicy(
        account_id=account_id,
        region=region,
        runtime_principal_arn=principal,
        controller_namespace=controller_namespace,
        controller_service_account=controller_service_account,
        network_policy_admin_group=network_policy_admin_group,
        eks_cluster_name=next(iter(cluster_names)),
        eks_deployments=deployments,
        eks_isolation_namespaces=frozenset(isolation),
        iam_access_keys=access_keys,
        iam_roles=frozenset(roles),
    )


def _field(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def _selector_matches_all(value: Any) -> bool:
    if value in ({}, None):
        return True
    return _field(value, "match_labels") in ({}, None) and _field(
        value, "match_expressions"
    ) in ([], None)


def _selector_matches_labels(value: Any, labels: dict[str, str]) -> bool:
    if _selector_matches_all(value):
        return True
    match_labels = _field(value, "match_labels", {}) or {}
    if not isinstance(match_labels, dict) or any(
        labels.get(key) != expected for key, expected in match_labels.items()
    ):
        return False
    for expression in _field(value, "match_expressions", []) or []:
        key = _field(expression, "key")
        operator = _field(expression, "operator")
        values = set(_field(expression, "values", []) or [])
        if not isinstance(key, str):
            return True
        present = key in labels
        if operator == "In" and (not present or labels[key] not in values):
            return False
        if operator == "NotIn" and (not present or labels[key] in values):
            return False
        if operator == "Exists" and not present:
            return False
        if operator == "DoesNotExist" and present:
            return False
        if operator not in {"In", "NotIn", "Exists", "DoesNotExist"}:
            return True
    return True


def _selector_shape(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    expressions = []
    for expression in _field(value, "match_expressions", []) or []:
        expressions.append(
            {
                "key": _field(expression, "key"),
                "operator": _field(expression, "operator"),
                "values": tuple(_field(expression, "values", []) or []),
            }
        )
    return {
        "match_labels": dict(_field(value, "match_labels", {}) or {}),
        "match_expressions": tuple(expressions),
    }


def _resource_rule_shape(value: Any) -> dict[str, Any]:
    return {
        "api_groups": tuple(_field(value, "api_groups", []) or []),
        "api_versions": tuple(_field(value, "api_versions", []) or []),
        "operations": tuple(_field(value, "operations", []) or []),
        "resources": tuple(_field(value, "resources", []) or []),
        "resource_names": tuple(_field(value, "resource_names", []) or []),
        "scope": _field(value, "scope"),
    }


def _match_resources_shape(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    return {
        "match_policy": _field(value, "match_policy"),
        "namespace_selector": _selector_shape(_field(value, "namespace_selector")),
        "object_selector": _selector_shape(_field(value, "object_selector")),
        "resource_rules": tuple(
            _resource_rule_shape(rule)
            for rule in (_field(value, "resource_rules", []) or [])
        ),
        "exclude_resource_rules": tuple(
            _resource_rule_shape(rule)
            for rule in (_field(value, "exclude_resource_rules", []) or [])
        ),
    }


def _validation_shape(value: Any) -> dict[str, Any]:
    return {
        "expression": _field(value, "expression"),
        "message": _field(value, "message"),
        "message_expression": _field(value, "message_expression"),
        "reason": _field(value, "reason"),
    }


def _admission_policy_shape(value: Any) -> dict[str, Any]:
    return {
        "failure_policy": _field(value, "failure_policy"),
        "match_constraints": _match_resources_shape(
            _field(value, "match_constraints")
        ),
        "match_conditions": tuple(_field(value, "match_conditions", []) or []),
        "param_kind": _field(value, "param_kind"),
        "validations": tuple(
            _validation_shape(validation)
            for validation in (_field(value, "validations", []) or [])
        ),
        "audit_annotations": tuple(_field(value, "audit_annotations", []) or []),
        "variables": tuple(_field(value, "variables", []) or []),
    }


def _admission_binding_shape(value: Any) -> dict[str, Any]:
    return {
        "policy_name": _field(value, "policy_name"),
        "param_ref": _field(value, "param_ref"),
        "validation_actions": tuple(_field(value, "validation_actions", []) or []),
        "match_resources": _match_resources_shape(_field(value, "match_resources")),
    }


def _admission_status_is_accepted(value: Any, generation: Any) -> bool:
    status = _field(value, "status")
    if type(generation) is not int or generation < 1:
        return False
    if _field(status, "observed_generation") != generation:
        return False
    warnings = _field(_field(status, "type_checking"), "expression_warnings", []) or []
    conditions = _field(status, "conditions", []) or []
    condition_types = {_field(condition, "type") for condition in conditions}
    return bool(conditions) and not warnings and "Accepted" in condition_types and all(
        _field(condition, "status") == "True" for condition in conditions
    )


def _request_id(response: Any) -> str:
    if isinstance(response, dict):
        metadata = response.get("ResponseMetadata")
        if isinstance(metadata, dict):
            request_id = metadata.get("RequestId")
            if isinstance(request_id, str) and request_id:
                return request_id
    metadata = _field(response, "metadata")
    resource_version = _field(metadata, "resource_version")
    if isinstance(resource_version, str) and resource_version:
        return f"kubernetes-resource-version:{resource_version}"
    raise AwsControlError("provider response did not contain a durable receipt identifier")


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def provider_state_digest(previews: tuple[ProviderActionPreviewV2, ...]) -> str:
    ordered = sorted(previews, key=lambda item: str(item.action_id))
    return _sha([item.model_dump(mode="json") for item in ordered])


def _role_revocation_document(action: IamRevokeRoleSessionsActionV2) -> dict[str, Any]:
    cutoff = (
        action.revoke_sessions_issued_before.astimezone(UTC)
        .isoformat()
        .replace("+00:00", "Z")
    )
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "RevokeOlderSessions",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {"DateLessThan": {"aws:TokenIssueTime": cutoff}},
            }
        ],
    }


class AwsControlProvider:
    """Real AWS/IAM and in-cluster Kubernetes controller with exact readback."""

    def __init__(
        self,
        *,
        policy: AwsTargetPolicy,
        sts_client: Any,
        eks_client: Any,
        iam_client: Any,
        core_v1: Any,
        networking_v1: Any,
        apps_v1: Any,
        admission_v1: Any | None = None,
        bound_cluster_endpoint: str | None = None,
        bound_cluster_ca_sha256: str | None = None,
        rollout_timeout_seconds: int = 120,
    ):
        self.policy = policy
        self.sts = sts_client
        self.eks = eks_client
        self.iam = iam_client
        self.core_v1 = core_v1
        self.networking_v1 = networking_v1
        self.apps_v1 = apps_v1
        self.admission_v1 = admission_v1
        self.bound_cluster_endpoint = bound_cluster_endpoint
        self.bound_cluster_ca_sha256 = bound_cluster_ca_sha256
        self.rollout_timeout_seconds = rollout_timeout_seconds

    @staticmethod
    def _cluster_connection(
        policy: AwsTargetPolicy,
        response: dict[str, Any],
    ) -> tuple[str, str, bytes]:
        cluster = response.get("cluster")
        if not isinstance(cluster, dict):
            raise AwsControlError("EKS cluster identity response is incomplete")
        partition = policy.runtime_principal_arn.split(":", 2)[1]
        expected_arn = (
            f"arn:{partition}:eks:{policy.region}:{policy.account_id}:"
            f"cluster/{policy.eks_cluster_name}"
        )
        if cluster.get("arn") != expected_arn or cluster.get("status") != "ACTIVE":
            raise AwsControlError("EKS cluster is not the exact active configured target")
        endpoint = cluster.get("endpoint")
        parsed = urlsplit(endpoint) if isinstance(endpoint, str) else None
        try:
            endpoint_port = parsed.port if parsed is not None else None
        except ValueError as exc:
            raise AwsControlError("EKS API endpoint contains an invalid port") from exc
        if (
            parsed is None
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or endpoint_port not in {None, 443}
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise AwsControlError("EKS API endpoint is not an exact HTTPS origin")
        authority = cluster.get("certificateAuthority")
        encoded_ca = authority.get("data") if isinstance(authority, dict) else None
        if not isinstance(encoded_ca, str) or len(encoded_ca) > 128_000:
            raise AwsControlError("EKS certificate authority data is missing or oversized")
        try:
            ca_bytes = base64.b64decode(encoded_ca, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise AwsControlError("EKS certificate authority data is malformed") from exc
        if not ca_bytes or len(ca_bytes) > 64_000:
            raise AwsControlError("EKS certificate authority data is empty or oversized")
        return expected_arn, endpoint.rstrip("/"), ca_bytes

    @classmethod
    def from_runtime(cls, policy: AwsTargetPolicy) -> AwsControlProvider:
        try:
            import boto3
            from botocore.config import Config
            from kubernetes import client, config
        except ModuleNotFoundError as exc:  # pragma: no cover - dependency guard
            raise AwsControlError(
                "AWS and Kubernetes production dependencies are unavailable"
            ) from exc
        api_config = Config(
            connect_timeout=3,
            read_timeout=5,
            retries={"mode": "standard", "max_attempts": 3},
            user_agent_extra="safe-qa-control-plane/0.2.0",
        )
        session = boto3.session.Session(region_name=policy.region)
        sts_client = session.client("sts", config=api_config)
        eks_client = session.client("eks", config=api_config)
        iam_client = session.client("iam", config=api_config)
        try:
            cluster_response = eks_client.describe_cluster(name=policy.eks_cluster_name)
            _, endpoint, expected_ca = cls._cluster_connection(policy, cluster_response)
            config.load_incluster_config()
            configuration = client.Configuration.get_default_copy()
            ca_path = Path(str(configuration.ssl_ca_cert))
            with ca_path.open("rb") as handle:
                observed_ca = handle.read(64_001)
            if len(observed_ca) > 64_000 or observed_ca != expected_ca:
                raise AwsControlError(
                    "in-cluster certificate authority differs from the exact EKS target"
                )
            if configuration.verify_ssl is not True:
                raise AwsControlError("Kubernetes TLS verification is not enabled")
            configuration.host = endpoint
            kubernetes_client = client.ApiClient(configuration)
        except Exception as exc:
            if isinstance(exc, AwsControlError):
                raise
            raise AwsControlError(
                "production controller could not bind its Kubernetes identity to exact EKS"
            ) from exc
        return cls(
            policy=policy,
            sts_client=sts_client,
            eks_client=eks_client,
            iam_client=iam_client,
            core_v1=client.CoreV1Api(kubernetes_client),
            networking_v1=client.NetworkingV1Api(kubernetes_client),
            apps_v1=client.AppsV1Api(kubernetes_client),
            admission_v1=client.AdmissionregistrationV1Api(kubernetes_client),
            bound_cluster_endpoint=endpoint,
            bound_cluster_ca_sha256=hashlib.sha256(expected_ca).hexdigest(),
        )

    def _verify_account(self) -> str:
        try:
            identity = self.sts.get_caller_identity()
        except Exception as exc:
            raise AwsControlError("AWS caller identity lookup failed") from exc
        if identity.get("Account") != self.policy.account_id:
            raise AwsControlError("AWS caller account differs from the exact target policy")
        caller_arn = identity.get("Arn")
        expected = self.policy.runtime_principal_arn
        exact = caller_arn == expected
        assumed_role = False
        expected_parts = expected.split(":", 5)
        observed_parts = caller_arn.split(":", 5) if isinstance(caller_arn, str) else []
        if (
            len(expected_parts) == 6
            and len(observed_parts) == 6
            and expected_parts[2] == "iam"
            and expected_parts[5].startswith("role/")
            and observed_parts[2] == "sts"
            and observed_parts[5].startswith("assumed-role/")
            and expected_parts[:2] == observed_parts[:2]
            and expected_parts[4] == observed_parts[4]
        ):
            expected_role_name = expected_parts[5].rsplit("/", 1)[-1]
            observed_role_name = observed_parts[5].split("/", 2)[1]
            assumed_role = expected_role_name == observed_role_name
        if not exact and not assumed_role:
            raise AwsControlError("AWS caller principal differs from the exact runtime identity")
        return expected

    def _verify_cluster(self, cluster_name: str) -> tuple[str, str]:
        if cluster_name != self.policy.eks_cluster_name:
            raise AwsControlError("EKS action differs from the bound runtime cluster")
        try:
            response = self.eks.describe_cluster(name=cluster_name)
        except Exception as exc:
            raise AwsControlError("EKS cluster identity lookup failed") from exc
        observed_arn, endpoint, ca_bytes = self._cluster_connection(self.policy, response)
        if self.bound_cluster_endpoint is not None and endpoint != self.bound_cluster_endpoint:
            raise AwsControlError("EKS API endpoint changed after runtime binding")
        if (
            self.bound_cluster_ca_sha256 is not None
            and hashlib.sha256(ca_bytes).hexdigest() != self.bound_cluster_ca_sha256
        ):
            raise AwsControlError("EKS certificate authority changed after runtime binding")
        return observed_arn, _request_id(response)

    def _assert_allowed(self, action: ProviderActionV2) -> None:
        if isinstance(action, EksDeployImmutableImageActionV2):
            deployment_policy = self.policy.eks_deployments.get(
                (action.cluster_name, action.namespace), {}
            ).get(action.deployment_name)
            if (
                deployment_policy is None
                or action.container_name != deployment_policy.container_name
                or action.image_repository != deployment_policy.image_repository
            ):
                raise AwsControlError("EKS deployment target is not explicitly allowlisted")
        elif isinstance(action, EksIsolateNamespaceActionV2):
            if (
                action.cluster_name,
                action.namespace,
            ) not in self.policy.eks_isolation_namespaces:
                raise AwsControlError("EKS isolation target is not explicitly allowlisted")
        elif isinstance(action, IamDisableAccessKeyActionV2):
            if action.access_key_id not in self.policy.iam_access_keys.get(
                action.user_name, frozenset()
            ):
                raise AwsControlError("IAM access key is not explicitly allowlisted")
        elif isinstance(action, IamRevokeRoleSessionsActionV2):
            if action.role_name not in self.policy.iam_roles:
                raise AwsControlError("IAM role is not explicitly allowlisted")
        else:  # pragma: no cover - discriminated schemas make this unreachable
            raise AwsControlError("provider action type is unsupported")

    def preview(self, action: ProviderActionV2) -> ProviderActionPreviewV2:
        self._assert_allowed(action)
        caller_arn = self._verify_account()
        if isinstance(action, EksDeployImmutableImageActionV2):
            state = self._preview_deployment(action, caller_arn)
        elif isinstance(action, EksIsolateNamespaceActionV2):
            state = self._preview_isolation(action, caller_arn)
        elif isinstance(action, IamDisableAccessKeyActionV2):
            state = self._preview_access_key(action, caller_arn)
        elif isinstance(action, IamRevokeRoleSessionsActionV2):
            state = self._preview_role(action, caller_arn)
        else:  # pragma: no cover
            raise AwsControlError("provider action type is unsupported")
        return ProviderActionPreviewV2(
            action_id=action.action_id,
            action_type=action.action_type,
            current_state_sha256=_sha(state),
            current_state=state,
        )

    def preview_all(
        self, actions: tuple[ProviderActionV2, ...]
    ) -> tuple[ProviderActionPreviewV2, ...]:
        return tuple(self.preview(action) for action in actions)

    def _managed_workload_security_state(
        self,
        action: EksDeployImmutableImageActionV2,
        deployment: Any,
    ) -> dict[str, str | int | bool | None]:
        target = self.policy.eks_deployments[(action.cluster_name, action.namespace)][
            action.deployment_name
        ]
        metadata = _field(deployment, "metadata")
        spec = _field(deployment, "spec")
        template = _field(spec, "template")
        template_meta = _field(template, "metadata")
        pod_spec = _field(template, "spec")
        containers = _field(pod_spec, "containers", []) or []
        labels = {
            "app.kubernetes.io/name": target.deployment_name,
            "safe-qa.io/provider-managed": "true",
        }
        selector = _selector_shape(_field(spec, "selector"))
        expected_selector = {
            "match_labels": {"app.kubernetes.io/name": target.deployment_name},
            "match_expressions": (),
        }
        annotations = dict(_field(template_meta, "annotations", {}) or {})
        if len(containers) != 1:
            raise AwsControlError("managed deployment must contain exactly one container")
        container = containers[0]
        image = _field(container, "image")
        image_prefix = f"{target.image_repository}@sha256:"
        if not isinstance(image, str) or not re.fullmatch(
            re.escape(image_prefix) + r"[0-9a-f]{64}", image
        ):
            raise AwsControlError("managed deployment image is outside the exact repository")
        digest = image.split("@", 1)[1]
        if (
            dict(_field(metadata, "labels", {}) or {}) != labels
            or selector != expected_selector
            or dict(_field(template_meta, "labels", {}) or {}) != labels
            or set(annotations) != {
                "safe-qa.io/source-revision",
                "safe-qa.io/image-digest",
            }
            or not isinstance(annotations["safe-qa.io/source-revision"], str)
            or not annotations["safe-qa.io/source-revision"]
            or annotations["safe-qa.io/image-digest"] != digest
            or _field(pod_spec, "service_account_name") != target.service_account_name
            or _field(pod_spec, "automount_service_account_token") is not False
            or _field(pod_spec, "enable_service_links") is not False
            or _field(pod_spec, "host_network") is not False
            or _field(pod_spec, "host_pid") is not False
            or _field(pod_spec, "host_ipc") is not False
            or _field(pod_spec, "restart_policy") != "Always"
            or _field(pod_spec, "node_name") is not None
            or (_field(pod_spec, "init_containers", []) or [])
            or (_field(pod_spec, "ephemeral_containers", []) or [])
            or (_field(pod_spec, "volumes", []) or [])
        ):
            raise AwsControlError("managed deployment pod identity or isolation profile drifted")
        if (
            _field(container, "name") != target.container_name
            or _field(container, "image_pull_policy") != "IfNotPresent"
            or (_field(container, "command", []) or [])
            or (_field(container, "args", []) or [])
            or (_field(container, "env", []) or [])
            or (_field(container, "env_from", []) or [])
            or (_field(container, "volume_mounts", []) or [])
            or (_field(container, "ports", []) or [])
        ):
            raise AwsControlError("managed deployment container profile drifted")
        pod_security = _field(pod_spec, "security_context")
        pod_seccomp = _field(pod_security, "seccomp_profile")
        container_security = _field(container, "security_context")
        capabilities = _field(container_security, "capabilities")
        if (
            _field(pod_security, "run_as_non_root") is not True
            or _field(pod_seccomp, "type") != "RuntimeDefault"
            or _field(container_security, "allow_privilege_escalation") is not False
            or _field(container_security, "privileged") is not False
            or _field(container_security, "read_only_root_filesystem") is not True
            or _field(container_security, "run_as_non_root") is not True
            or _field(container_security, "run_as_user") != 65532
            or _field(container_security, "run_as_group") != 65532
            or tuple(_field(capabilities, "drop", []) or []) != ("ALL",)
            or (_field(capabilities, "add", []) or [])
        ):
            raise AwsControlError("managed deployment security context drifted")

        try:
            inventory = self.networking_v1.list_namespaced_network_policy(
                namespace=action.namespace,
                limit=500,
            )
        except Exception as exc:
            raise AwsControlError("managed deployment NetworkPolicy inventory failed") from exc
        policies = _field(inventory, "items", []) or []
        continuation = _field(_field(inventory, "metadata"), "_continue") or _field(
            _field(inventory, "metadata"), "continue"
        )
        if not isinstance(policies, list) or len(policies) > 500 or continuation:
            raise AwsControlError("managed deployment NetworkPolicy inventory is incomplete")
        by_name = {_field(_field(item, "metadata"), "name"): item for item in policies}
        default_deny = by_name.get("safe-qa-default-deny")
        workload_isolation = by_name.get("safe-qa-managed-workload-isolation")
        default_spec = _field(default_deny, "spec")
        isolation_spec = _field(workload_isolation, "spec")
        if (
            default_deny is None
            or workload_isolation is None
            or not _selector_matches_all(_field(default_spec, "pod_selector"))
            or set(_field(default_spec, "policy_types", []) or [])
            != {"Ingress", "Egress"}
            or (_field(default_spec, "ingress", []) or [])
            or (_field(default_spec, "egress", []) or [])
            or _selector_shape(_field(isolation_spec, "pod_selector"))
            != {"match_labels": labels, "match_expressions": ()}
            or set(_field(isolation_spec, "policy_types", []) or [])
            != {"Ingress", "Egress"}
            or _field(isolation_spec, "ingress") != []
            or _field(isolation_spec, "egress") != []
        ):
            raise AwsControlError("managed deployment baseline NetworkPolicies drifted")
        for network_policy in policies:
            network_spec = _field(network_policy, "spec")
            if not _selector_matches_labels(_field(network_spec, "pod_selector"), labels):
                continue
            if (_field(network_spec, "ingress", []) or []) or (
                _field(network_spec, "egress", []) or []
            ):
                raise AwsControlError("an additive NetworkPolicy grants managed workload access")
        policy_meta = _field(workload_isolation, "metadata")
        policy_uid = _field(policy_meta, "uid")
        policy_resource_version = _field(policy_meta, "resource_version")
        if not all(
            isinstance(value, str) and value for value in (policy_uid, policy_resource_version)
        ):
            raise AwsControlError("managed deployment NetworkPolicy receipt is incomplete")
        return {
            "managed_security_profile": "SAFE_QA_MANAGED_WORKLOAD_V1",
            "managed_service_account": target.service_account_name,
            "managed_image_repository": target.image_repository,
            "managed_network_policy_uid": policy_uid,
            "managed_network_policy_resource_version": policy_resource_version,
        }

    def _preview_deployment(
        self, action: EksDeployImmutableImageActionV2, caller_arn: str
    ) -> dict[str, str | int | bool | None]:
        cluster_arn, _ = self._verify_cluster(action.cluster_name)
        try:
            deployment = self.apps_v1.read_namespaced_deployment(
                name=action.deployment_name,
                namespace=action.namespace,
            )
        except Exception as exc:
            raise AwsControlError("Kubernetes deployment read failed") from exc
        metadata = _field(deployment, "metadata")
        spec = _field(deployment, "spec")
        status = _field(deployment, "status")
        template = _field(spec, "template")
        pod_spec = _field(template, "spec")
        containers = _field(pod_spec, "containers", [])
        security_state = self._managed_workload_security_state(action, deployment)
        enforcement_state = self._verify_network_policy_enforcement(action.cluster_name)
        matching = [item for item in containers if _field(item, "name") == action.container_name]
        if len(matching) != 1:
            raise AwsControlError("exact Kubernetes container target was not found")
        deployment_uid = _field(metadata, "uid")
        resource_version = _field(metadata, "resource_version")
        generation = _field(metadata, "generation")
        if (
            not isinstance(deployment_uid, str)
            or not deployment_uid
            or not isinstance(resource_version, str)
            or not resource_version
            or type(generation) is not int
            or generation < 1
        ):
            raise AwsControlError("Kubernetes deployment identity receipt is incomplete")
        return {
            "caller_arn": caller_arn,
            "cluster_arn": cluster_arn,
            "deployment_uid": deployment_uid,
            "resource_version": resource_version,
            "generation": generation,
            "observed_generation": int(_field(status, "observed_generation", 0) or 0),
            "replicas": int(_field(spec, "replicas", 0) or 0),
            "updated_replicas": int(_field(status, "updated_replicas", 0) or 0),
            "available_replicas": int(_field(status, "available_replicas", 0) or 0),
            "image": str(_field(matching[0], "image", "")),
            **security_state,
            **enforcement_state,
        }

    @staticmethod
    def _not_found(exc: Exception) -> bool:
        return getattr(exc, "status", None) == 404

    def _preview_isolation(
        self, action: EksIsolateNamespaceActionV2, caller_arn: str
    ) -> dict[str, str | int | bool | None]:
        cluster_arn, _ = self._verify_cluster(action.cluster_name)
        enforcement = self._verify_network_policy_enforcement(action.cluster_name)
        try:
            namespace = self.core_v1.read_namespace(name=action.namespace)
        except Exception as exc:
            raise AwsControlError("Kubernetes namespace read failed") from exc
        try:
            inventory = self.networking_v1.list_namespaced_network_policy(
                namespace=action.namespace
            )
            policy = self.networking_v1.read_namespaced_network_policy(
                name=action.policy_name,
                namespace=action.namespace,
            )
        except Exception as exc:
            raise AwsControlError(
                "required Kubernetes isolation-policy inventory is unavailable"
            ) from exc
        inventory_items = _field(inventory, "items")
        if not isinstance(inventory_items, list):
            raise AwsControlError("Kubernetes NetworkPolicy inventory is malformed")
        inventory_by_name: dict[str, Any] = {}
        for item in inventory_items:
            name = _field(_field(item, "metadata"), "name")
            if not isinstance(name, str) or name in inventory_by_name:
                raise AwsControlError("Kubernetes NetworkPolicy inventory is ambiguous")
            inventory_by_name[name] = item
        expected_policy_names = {
            "safe-qa-agent-default-deny",
            "safe-qa-approved-egress",
        }
        if set(inventory_by_name) != expected_policy_names:
            raise AwsControlError(
                "sandbox namespace NetworkPolicy inventory differs from the closed baseline"
            )
        default_spec = _field(inventory_by_name["safe-qa-agent-default-deny"], "spec")
        default_types = set(_field(default_spec, "policy_types", []) or [])
        if (
            not _selector_matches_all(_field(default_spec, "pod_selector"))
            or default_types != {"Ingress", "Egress"}
            or _field(default_spec, "ingress") not in (None, [])
            or _field(default_spec, "egress") not in (None, [])
        ):
            raise AwsControlError("sandbox default-deny NetworkPolicy is not exact")
        metadata = _field(namespace, "metadata")
        namespace_labels = _field(metadata, "labels", {}) or {}
        expected_namespace_labels = {
            "safe-qa.io/dedicated-agent-namespace": "true",
            "safe-qa.io/firewall-enforced": "true",
            "safe-qa.io/runtime": "ec2-network-policy-sandbox",
            "pod-security.kubernetes.io/enforce": "restricted",
            "pod-security.kubernetes.io/enforce-version": "latest",
            "pod-security.kubernetes.io/audit": "restricted",
            "pod-security.kubernetes.io/audit-version": "latest",
            "pod-security.kubernetes.io/warn": "restricted",
            "pod-security.kubernetes.io/warn-version": "latest",
        }
        if not isinstance(namespace_labels, dict) or any(
            namespace_labels.get(key) != value
            for key, value in expected_namespace_labels.items()
        ):
            raise AwsControlError("sandbox namespace security labels are absent or changed")
        policy_meta = _field(policy, "metadata")
        policy_spec = _field(policy, "spec")
        types = set(_field(policy_spec, "policy_types", []) or [])
        pod_selector = _field(policy_spec, "pod_selector")
        egress = _field(policy_spec, "egress")
        labels = _field(policy_meta, "labels", {}) or {}
        enforced = bool(
            _selector_matches_all(pod_selector)
            and types == {"Egress"}
            and egress == []
            and isinstance(labels, dict)
            and labels.get("safe-qa.io/controller-owned") == "true"
        )
        namespace_uid = _field(metadata, "uid")
        if not isinstance(namespace_uid, str) or not namespace_uid:
            raise AwsControlError("Kubernetes namespace identity receipt is incomplete")
        policy_resource_version = str(_field(policy_meta, "resource_version", ""))
        if not policy_resource_version:
            raise AwsControlError("Kubernetes NetworkPolicy identity receipt is incomplete")
        admission = self._verify_isolation_admission()
        return {
            "caller_arn": caller_arn,
            "cluster_arn": cluster_arn,
            "namespace_uid": namespace_uid,
            "policy_present": True,
            "policy_enforced": enforced,
            "policy_resource_version": policy_resource_version,
            **admission,
            **enforcement,
        }

    def _verify_isolation_admission(self) -> dict[str, str | int | bool | None]:
        if self.admission_v1 is None:
            raise AwsControlError("Kubernetes admission-policy client is unavailable")
        name = "safe-qa-agent-network-policy-boundary"
        namespace_guard_name = "safe-qa-agent-namespace-boundary"
        pod_guard_name = "safe-qa-agent-pod-boundary"
        immutable_images_name = "safe-qa-immutable-images"
        try:
            policy = self.admission_v1.read_validating_admission_policy(name=name)
            binding = self.admission_v1.read_validating_admission_policy_binding(name=name)
            namespace_policy = self.admission_v1.read_validating_admission_policy(
                name=namespace_guard_name
            )
            namespace_binding = self.admission_v1.read_validating_admission_policy_binding(
                name=namespace_guard_name
            )
            pod_policy = self.admission_v1.read_validating_admission_policy(
                name=pod_guard_name
            )
            pod_binding = self.admission_v1.read_validating_admission_policy_binding(
                name=pod_guard_name
            )
            immutable_policy = self.admission_v1.read_validating_admission_policy(
                name=immutable_images_name
            )
            immutable_binding = self.admission_v1.read_validating_admission_policy_binding(
                name=immutable_images_name
            )
        except Exception as exc:
            raise AwsControlError("Kubernetes isolation admission guard is unavailable") from exc
        policy_meta = _field(policy, "metadata")
        binding_meta = _field(binding, "metadata")
        policy_spec = _field(policy, "spec")
        binding_spec = _field(binding, "spec")
        namespace_selector = {
            "match_labels": {"safe-qa.io/dedicated-agent-namespace": "true"},
            "match_expressions": (),
        }
        network_rule = {
            "api_groups": ("networking.k8s.io",),
            "api_versions": ("v1",),
            "operations": ("CREATE", "UPDATE", "DELETE"),
            "resources": ("networkpolicies",),
            "resource_names": (),
            "scope": None,
        }
        expected_policy = {
            "failure_policy": "Fail",
            "match_constraints": {
                "match_policy": "Exact",
                "namespace_selector": namespace_selector,
                "object_selector": None,
                "resource_rules": (network_rule,),
                "exclude_resource_rules": (),
            },
            "match_conditions": (),
            "param_kind": None,
            "validations": (
                {
                    "expression": "request.operation != 'DELETE'",
                    "message": "The two baseline sandbox NetworkPolicies may not be deleted.",
                    "message_expression": None,
                    "reason": None,
                },
                {
                    "expression": (
                        "object.metadata.name in ['safe-qa-agent-default-deny', "
                        "'safe-qa-approved-egress']"
                    ),
                    "message": (
                        "Only the default-deny and controller-owned approved-egress "
                        "policies are permitted."
                    ),
                    "message_expression": None,
                    "reason": None,
                },
                {
                    "expression": (
                        "object.metadata.name != 'safe-qa-agent-default-deny' || "
                        "oldObject == null || object.spec == oldObject.spec"
                    ),
                    "message": "The agent namespace default-deny policy is immutable.",
                    "message_expression": None,
                    "reason": None,
                },
                {
                    "expression": (
                        "object.metadata.name != 'safe-qa-approved-egress' || "
                        "request.userInfo.username == 'system:serviceaccount:"
                        f"{self.policy.controller_namespace}:"
                        f"{self.policy.controller_service_account}' || "
                        "request.userInfo.groups.exists(group, group == "
                        f"'{self.policy.network_policy_admin_group}')"
                    ),
                    "message": (
                        "Only the controller ServiceAccount or named break-glass group "
                        "may change approved egress."
                    ),
                    "message_expression": None,
                    "reason": None,
                },
            ),
            "audit_annotations": (),
            "variables": (),
        }
        expected_binding = {
            "policy_name": name,
            "param_ref": None,
            "validation_actions": ("Deny", "Audit"),
            "match_resources": {
                "match_policy": "Exact",
                "namespace_selector": namespace_selector,
                "object_selector": None,
                "resource_rules": (),
                "exclude_resource_rules": (),
            },
        }
        policy_uid = _field(policy_meta, "uid")
        binding_uid = _field(binding_meta, "uid")
        policy_generation = _field(policy_meta, "generation")
        if (
            _admission_policy_shape(policy_spec) != expected_policy
            or _admission_binding_shape(binding_spec) != expected_binding
            or not all(isinstance(value, str) and value for value in (policy_uid, binding_uid))
            or not _admission_status_is_accepted(policy, policy_generation)
        ):
            raise AwsControlError("Kubernetes isolation admission guard differs from policy")

        namespace_meta = _field(namespace_policy, "metadata")
        namespace_spec = _field(namespace_policy, "spec")
        namespace_binding_meta = _field(namespace_binding, "metadata")
        namespace_binding_spec = _field(namespace_binding, "spec")
        namespace_rule = {
            "api_groups": ("",),
            "api_versions": ("v1",),
            "operations": ("UPDATE", "DELETE"),
            "resources": ("namespaces",),
            "resource_names": (),
            "scope": None,
        }
        namespace_label_guards = (
            (
                "safe-qa.io/dedicated-agent-namespace",
                "true",
                "The sandbox dedicated-agent label must remain exactly true.",
            ),
            (
                "safe-qa.io/firewall-enforced",
                "true",
                "The sandbox firewall-enforced label must remain exactly true.",
            ),
            (
                "safe-qa.io/runtime",
                "ec2-network-policy-sandbox",
                "The sandbox runtime label must remain exactly ec2-network-policy-sandbox.",
            ),
            (
                "pod-security.kubernetes.io/enforce",
                "restricted",
                "The sandbox Pod Security enforce level must remain exactly restricted.",
            ),
            (
                "pod-security.kubernetes.io/enforce-version",
                "latest",
                "The sandbox Pod Security enforce version must remain exactly latest.",
            ),
            (
                "pod-security.kubernetes.io/audit",
                "restricted",
                "The sandbox Pod Security audit level must remain exactly restricted.",
            ),
            (
                "pod-security.kubernetes.io/audit-version",
                "latest",
                "The sandbox Pod Security audit version must remain exactly latest.",
            ),
            (
                "pod-security.kubernetes.io/warn",
                "restricted",
                "The sandbox Pod Security warn level must remain exactly restricted.",
            ),
            (
                "pod-security.kubernetes.io/warn-version",
                "latest",
                "The sandbox Pod Security warn version must remain exactly latest.",
            ),
        )
        namespace_validations = (
            {
                "expression": (
                    "request.name != 'safe-qa-agent-sandbox' || "
                    "request.operation != 'DELETE'"
                ),
                "message": "The dedicated sandbox namespace may not be deleted.",
                "message_expression": None,
                "reason": None,
            },
            *(
                {
                    "expression": (
                        "request.name != 'safe-qa-agent-sandbox' || "
                        "request.operation == 'DELETE' || "
                        "(has(object.metadata.labels) && object.metadata.labels"
                        f"['{label}'] == '{expected_value}')"
                    ),
                    "message": message,
                    "message_expression": None,
                    "reason": None,
                }
                for label, expected_value, message in namespace_label_guards
            ),
        )
        expected_namespace_policy = {
            "failure_policy": "Fail",
            "match_constraints": {
                "match_policy": "Exact",
                "namespace_selector": None,
                "object_selector": None,
                "resource_rules": (namespace_rule,),
                "exclude_resource_rules": (),
            },
            "match_conditions": (),
            "param_kind": None,
            "validations": namespace_validations,
            "audit_annotations": (),
            "variables": (),
        }
        expected_namespace_binding = {
            "policy_name": namespace_guard_name,
            "param_ref": None,
            "validation_actions": ("Deny", "Audit"),
            "match_resources": None,
        }
        namespace_generation = _field(namespace_meta, "generation")
        if (
            _admission_policy_shape(namespace_spec) != expected_namespace_policy
            or _admission_binding_shape(namespace_binding_spec)
            != expected_namespace_binding
            or not all(
                isinstance(value, str) and value
                for value in (
                    _field(namespace_meta, "uid"),
                    _field(namespace_binding_meta, "uid"),
                )
            )
            or not _admission_status_is_accepted(namespace_policy, namespace_generation)
        ):
            raise AwsControlError("Kubernetes sandbox-namespace guard differs from policy")

        pod_rule = {
            "api_groups": ("",),
            "api_versions": ("v1",),
            "operations": ("CREATE", "UPDATE"),
            "resources": ("pods", "pods/ephemeralcontainers"),
            "resource_names": (),
            "scope": None,
        }
        expected_pod_policy = {
            "failure_policy": "Fail",
            "match_constraints": {
                "match_policy": "Exact",
                "namespace_selector": namespace_selector,
                "object_selector": None,
                "resource_rules": (pod_rule,),
                "exclude_resource_rules": (),
            },
            "match_conditions": (),
            "param_kind": None,
            "validations": tuple(
                {
                    "expression": expression,
                    "message": message,
                    "message_expression": None,
                    "reason": None,
                }
                for expression, message in (
                    (
                        "object.metadata.labels['safe-qa.io/runtime'] == "
                        "'ec2-network-policy-sandbox' && object.spec.nodeSelector"
                        "['safe-qa.io/runtime'] == 'ec2-network-policy-sandbox' && "
                        "object.spec.nodeSelector['safe-qa.io/exclusive-node-group'] == "
                        "'true' && object.spec.serviceAccountName == "
                        "'safe-qa-agent-sandbox'",
                        "Sandbox pods must select the exclusive EC2 NetworkPolicy node "
                        "group and tokenless sandbox ServiceAccount.",
                    ),
                    (
                        "!has(object.spec.nodeName)",
                        "Sandbox pods may not bypass scheduling policy with spec.nodeName.",
                    ),
                    (
                        "has(object.spec.tolerations) && object.spec.tolerations.size() == "
                        "1 && object.spec.tolerations.exists(toleration, toleration.key == "
                        "'safe-qa.io/agent-sandbox' && toleration.operator == 'Equal' && "
                        "toleration.value == 'true' && toleration.effect == 'NoSchedule')",
                        "Sandbox pods must carry exactly the dedicated node-group toleration.",
                    ),
                    (
                        "object.spec.automountServiceAccountToken == false && "
                        "object.spec.hostNetwork == false && object.spec.hostPID == false "
                        "&& object.spec.hostIPC == false",
                        "Sandbox pods may not receive a Kubernetes token or join host "
                        "namespaces.",
                    ),
                    (
                        "has(object.spec.activeDeadlineSeconds) && "
                        "object.spec.activeDeadlineSeconds <= 300 && "
                        "object.spec.restartPolicy == 'Never'",
                        "Sandbox pods must terminate within 300 seconds and may not restart.",
                    ),
                    (
                        "!has(object.spec.initContainers) && "
                        "(!has(object.spec.ephemeralContainers) || "
                        "object.spec.ephemeralContainers.size() == 0) && "
                        "object.spec.containers.size() == 1",
                        "Sandbox pods permit exactly one container and no init or "
                        "ephemeral containers.",
                    ),
                    (
                        "object.spec.containers.all(container, !has(container.env) && "
                        "!has(container.envFrom) && "
                        "container.securityContext.readOnlyRootFilesystem == true && "
                        "container.securityContext.allowPrivilegeEscalation == false && "
                        "container.securityContext.privileged == false)",
                        "Sandbox containers may not receive injected configuration and "
                        "must use the restricted security context.",
                    ),
                    (
                        "!has(object.spec.volumes) || object.spec.volumes.size() == 0",
                        "Sandbox pods may not declare any volumes.",
                    ),
                )
            ),
            "audit_annotations": (),
            "variables": (),
        }
        expected_pod_binding = {
            "policy_name": pod_guard_name,
            "param_ref": None,
            "validation_actions": ("Deny", "Audit"),
            "match_resources": {
                "match_policy": "Exact",
                "namespace_selector": namespace_selector,
                "object_selector": None,
                "resource_rules": (),
                "exclude_resource_rules": (),
            },
        }
        pod_meta = _field(pod_policy, "metadata")
        pod_binding_meta = _field(pod_binding, "metadata")
        if (
            _admission_policy_shape(_field(pod_policy, "spec")) != expected_pod_policy
            or _admission_binding_shape(_field(pod_binding, "spec"))
            != expected_pod_binding
            or not all(
                isinstance(value, str) and value
                for value in (_field(pod_meta, "uid"), _field(pod_binding_meta, "uid"))
            )
            or not _admission_status_is_accepted(
                pod_policy, _field(pod_meta, "generation")
            )
        ):
            raise AwsControlError("Kubernetes sandbox-pod guard differs from policy")

        firewall_selector = {
            "match_labels": {"safe-qa.io/firewall-enforced": "true"},
            "match_expressions": (),
        }
        immutable_rule = {
            "api_groups": ("",),
            "api_versions": ("v1",),
            "operations": ("CREATE", "UPDATE"),
            "resources": ("pods",),
            "resource_names": (),
            "scope": None,
        }
        image_pattern = "^[^@]+@sha256:[a-f0-9]{64}$"
        expected_immutable_policy = {
            "failure_policy": "Fail",
            "match_constraints": {
                "match_policy": "Exact",
                "namespace_selector": firewall_selector,
                "object_selector": None,
                "resource_rules": (immutable_rule,),
                "exclude_resource_rules": (),
            },
            "match_conditions": (),
            "param_kind": None,
            "validations": (
                {
                    "expression": (
                        "object.spec.containers.all(container, container.image.matches("
                        f"'{image_pattern}'))"
                    ),
                    "message": (
                        "Every container image must use repository@sha256:<64 lowercase hex>."
                    ),
                    "message_expression": None,
                    "reason": None,
                },
                {
                    "expression": (
                        "!has(object.spec.initContainers) || "
                        "object.spec.initContainers.all(container, container.image.matches("
                        f"'{image_pattern}'))"
                    ),
                    "message": (
                        "Every init-container image must use repository@sha256:<64 "
                        "lowercase hex>."
                    ),
                    "message_expression": None,
                    "reason": None,
                },
            ),
            "audit_annotations": (),
            "variables": (),
        }
        expected_immutable_binding = {
            "policy_name": immutable_images_name,
            "param_ref": None,
            "validation_actions": ("Deny", "Audit"),
            "match_resources": {
                "match_policy": "Exact",
                "namespace_selector": firewall_selector,
                "object_selector": None,
                "resource_rules": (),
                "exclude_resource_rules": (),
            },
        }
        immutable_meta = _field(immutable_policy, "metadata")
        immutable_binding_meta = _field(immutable_binding, "metadata")
        if (
            _admission_policy_shape(_field(immutable_policy, "spec"))
            != expected_immutable_policy
            or _admission_binding_shape(_field(immutable_binding, "spec"))
            != expected_immutable_binding
            or not all(
                isinstance(value, str) and value
                for value in (
                    _field(immutable_meta, "uid"),
                    _field(immutable_binding_meta, "uid"),
                )
            )
            or not _admission_status_is_accepted(
                immutable_policy, _field(immutable_meta, "generation")
            )
        ):
            raise AwsControlError("Kubernetes immutable-image guard differs from policy")
        return {
            "admission_guard_verified": True,
            "admission_policy_uid": policy_uid,
            "admission_binding_uid": binding_uid,
            "namespace_admission_policy_uid": _field(namespace_meta, "uid"),
            "pod_admission_policy_uid": _field(pod_meta, "uid"),
            "immutable_image_policy_uid": _field(immutable_meta, "uid"),
        }

    def _verify_network_policy_enforcement(
        self, cluster_name: str
    ) -> dict[str, str | int | bool | None]:
        try:
            addon_response = self.eks.describe_addon(
                clusterName=cluster_name,
                addonName="vpc-cni",
            )
            daemonset = self.apps_v1.read_namespaced_daemon_set(
                name="aws-node",
                namespace="kube-system",
            )
        except Exception as exc:
            raise AwsControlError("EKS network-policy enforcement lookup failed") from exc
        addon = addon_response.get("addon")
        if not isinstance(addon, dict) or addon.get("status") != "ACTIVE":
            raise AwsControlError("EKS VPC CNI add-on is not active")
        version = addon.get("addonVersion")
        if not isinstance(version, str):
            raise AwsControlError("EKS VPC CNI version receipt is missing")
        match = re.match(r"^v?([0-9]+)\.([0-9]+)\.", version)
        if not match or (int(match.group(1)), int(match.group(2))) < (1, 21):
            raise AwsControlError("EKS VPC CNI version does not meet the enforced minimum")
        raw_configuration = addon.get("configurationValues", "{}")
        try:
            configuration = (
                json.loads(raw_configuration)
                if isinstance(raw_configuration, str)
                else raw_configuration
            )
        except json.JSONDecodeError as exc:
            raise AwsControlError("EKS VPC CNI configuration receipt is malformed") from exc
        if not isinstance(configuration, dict) or configuration.get("enableNetworkPolicy") not in {
            True,
            "true",
        }:
            raise AwsControlError("EKS VPC CNI network policy support is not enabled")
        metadata = _field(daemonset, "metadata")
        spec = _field(daemonset, "spec")
        template = _field(spec, "template")
        pod_spec = _field(template, "spec")
        containers = _field(pod_spec, "containers", []) or []
        names = {_field(container, "name") for container in containers}
        strict = False
        for container in containers:
            # AWS documents startup strict mode on the exact aws-node
            # container; agent presence is checked independently above.
            if _field(container, "name") != "aws-node":
                continue
            environment = _field(container, "env", []) or []
            for variable in environment:
                if (
                    _field(variable, "name") == "NETWORK_POLICY_ENFORCING_MODE"
                    and _field(variable, "value") == "strict"
                ):
                    strict = True
        status = _field(daemonset, "status")
        generation = _field(metadata, "generation")
        observed_generation = _field(status, "observed_generation")
        desired = int(_field(status, "desired_number_scheduled", 0) or 0)
        updated = int(_field(status, "updated_number_scheduled", 0) or 0)
        available = int(_field(status, "number_available", 0) or 0)
        ready = int(_field(status, "number_ready", 0) or 0)
        resource_version = _field(metadata, "resource_version")
        if (
            "aws-network-policy-agent" not in names
            or not strict
            or type(generation) is not int
            or generation < 1
            or observed_generation != generation
            or desired < 1
            or updated != desired
            or available != desired
            or ready != desired
            or not isinstance(resource_version, str)
            or not resource_version
        ):
            raise AwsControlError("EKS network policy agent is not healthy in strict mode")
        return {
            "network_policy_enforcement_verified": True,
            "vpc_cni_addon_version": version,
            "aws_node_resource_version": resource_version,
            "aws_node_generation": generation,
            "aws_node_desired": desired,
            "aws_node_updated": updated,
            "aws_node_available": available,
            "aws_node_ready": ready,
        }

    def _list_access_keys(self, user_name: str) -> tuple[list[dict[str, Any]], list[str]]:
        items: list[dict[str, Any]] = []
        request_ids: list[str] = []
        marker: str | None = None
        for _ in range(10):
            arguments: dict[str, Any] = {"UserName": user_name, "MaxItems": 100}
            if marker:
                arguments["Marker"] = marker
            try:
                response = self.iam.list_access_keys(**arguments)
            except Exception as exc:
                raise AwsControlError("IAM access-key lookup failed") from exc
            request_ids.append(_request_id(response))
            page = response.get("AccessKeyMetadata")
            if not isinstance(page, list):
                raise AwsControlError("IAM access-key lookup returned invalid data")
            items.extend(item for item in page if isinstance(item, dict))
            if response.get("IsTruncated") is not True:
                return items, request_ids
            marker = response.get("Marker")
            if not isinstance(marker, str) or not marker:
                raise AwsControlError("IAM access-key pagination receipt is incomplete")
        raise AwsControlError("IAM access-key lookup exceeded the pagination bound")

    def _preview_access_key(
        self, action: IamDisableAccessKeyActionV2, caller_arn: str
    ) -> dict[str, str | int | bool | None]:
        items, _ = self._list_access_keys(action.user_name)
        matches = [item for item in items if item.get("AccessKeyId") == action.access_key_id]
        if len(matches) != 1:
            raise AwsControlError("exact IAM access key was missing or ambiguous")
        item = matches[0]
        if item.get("UserName") != action.user_name:
            raise AwsControlError("IAM access-key owner differs from the exact target")
        created = item.get("CreateDate")
        return {
            "caller_arn": caller_arn,
            "user_name": action.user_name,
            "access_key_id": action.access_key_id,
            "status": str(item.get("Status", "")),
            "created_at": (
                created.astimezone(UTC).isoformat() if isinstance(created, datetime) else ""
            ),
        }

    def _preview_role(
        self, action: IamRevokeRoleSessionsActionV2, caller_arn: str
    ) -> dict[str, str | int | bool | None]:
        try:
            response = self.iam.get_role(RoleName=action.role_name)
        except Exception as exc:
            raise AwsControlError("IAM role lookup failed") from exc
        role = response.get("Role")
        if not isinstance(role, dict):
            raise AwsControlError("IAM role lookup returned invalid data")
        path = role.get("Path")
        if not isinstance(path, str) or path.startswith("/aws-service-role/"):
            raise AwsControlError("service-linked or malformed IAM roles cannot be revoked")
        partition = self.policy.runtime_principal_arn.split(":", 2)[1]
        expected_role_arn = (
            f"arn:{partition}:iam::{self.policy.account_id}:role{path}{action.role_name}"
        )
        if role.get("Arn") != expected_role_arn:
            raise AwsControlError("IAM role ARN differs from the exact target")
        policy_document: dict[str, Any] | None = None
        try:
            current = self.iam.get_role_policy(
                RoleName=action.role_name,
                PolicyName=action.policy_name,
            )
            raw_document = current.get("PolicyDocument")
            if isinstance(raw_document, str):
                raw_document = json.loads(unquote(raw_document))
            if not isinstance(raw_document, dict):
                raise AwsControlError("existing role revocation policy is malformed")
            policy_document = raw_document
        except AwsControlError:
            raise
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code not in {"NoSuchEntity", "NoSuchEntityException"}:
                raise AwsControlError("IAM role revocation-policy lookup failed") from exc
        expected_policy = _role_revocation_document(action)
        valid_policy = policy_document == expected_policy
        cutoff = expected_policy["Statement"][0]["Condition"]["DateLessThan"][
            "aws:TokenIssueTime"
        ]
        return {
            "caller_arn": caller_arn,
            "role_arn": str(role.get("Arn", "")),
            "role_path": path,
            "revocation_policy_present": policy_document is not None,
            "revocation_policy_valid": valid_policy,
            "revocation_cutoff": cutoff if valid_policy else None,
            "expected_revocation_policy_sha256": _sha(expected_policy),
            "revocation_policy_sha256": _sha(policy_document) if policy_document else None,
        }

    def apply(
        self,
        action: ProviderActionV2,
        *,
        expected_before_sha256: str,
    ) -> ProviderActionReceiptV2:
        before = self.preview(action)
        if before.current_state_sha256 != expected_before_sha256:
            raise AwsControlError(
                "provider state changed after approval; no mutation was attempted"
            )
        if isinstance(action, EksDeployImmutableImageActionV2):
            response, status = self._apply_deployment(action, before)
        elif isinstance(action, EksIsolateNamespaceActionV2):
            response, status = self._apply_isolation(action, before)
        elif isinstance(action, IamDisableAccessKeyActionV2):
            response, status = self._apply_access_key(action)
        elif isinstance(action, IamRevokeRoleSessionsActionV2):
            response, status = self._apply_role_revocation(action)
        else:  # pragma: no cover
            raise AwsControlError("provider action type is unsupported")
        after = self.preview(action)
        self._assert_enforced(action, after)
        return ProviderActionReceiptV2(
            action_id=action.action_id,
            action_type=action.action_type,
            status=status,
            before_state_sha256=before.current_state_sha256,
            after_state_sha256=after.current_state_sha256,
            provider_receipt_ids=(_request_id(response),),
            enforced_at=datetime.now(UTC),
        )

    def _apply_deployment(
        self,
        action: EksDeployImmutableImageActionV2,
        before: ProviderActionPreviewV2,
    ) -> tuple[Any, str]:
        exact_image = f"{action.image_repository}@{action.image_digest}"
        patch = {
            "metadata": {"resourceVersion": before.current_state["resource_version"]},
            "spec": {
                "replicas": action.replicas,
                "template": {
                    "metadata": {
                        "annotations": {
                            "safe-qa.io/source-revision": action.source_revision,
                            "safe-qa.io/image-digest": action.image_digest,
                        }
                    },
                    "spec": {"containers": [{"name": action.container_name, "image": exact_image}]}
                },
            },
        }
        try:
            response = self.apps_v1.patch_namespaced_deployment(
                name=action.deployment_name,
                namespace=action.namespace,
                body=patch,
            )
        except Exception as exc:
            raise AwsControlError("Kubernetes immutable deployment mutation failed") from exc
        deadline = time.monotonic() + self.rollout_timeout_seconds
        while True:
            observed = self._preview_deployment(action, self.policy.runtime_principal_arn)
            if (
                observed["image"] == exact_image
                and observed["replicas"] == action.replicas
                and observed["updated_replicas"] == action.replicas
                and observed["available_replicas"] == action.replicas
                and int(observed["observed_generation"] or 0) >= int(observed["generation"] or 0)
            ):
                return response, "DEPLOYED"
            if time.monotonic() >= deadline:
                raise AwsControlError(
                    "Kubernetes deployment did not become available before timeout"
                )
            time.sleep(2)

    def _apply_isolation(
        self,
        action: EksIsolateNamespaceActionV2,
        before: ProviderActionPreviewV2,
    ) -> tuple[Any, str]:
        metadata: dict[str, Any] = {
            "name": action.policy_name,
            "namespace": action.namespace,
            "labels": {
                "app.kubernetes.io/managed-by": "safe-qa-control-plane",
                "safe-qa.io/controller-owned": "true",
            },
            "resourceVersion": before.current_state["policy_resource_version"],
        }
        body = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": metadata,
            "spec": {
                "podSelector": {},
                "policyTypes": ["Egress"],
                "egress": [],
            },
        }
        try:
            response = self.networking_v1.replace_namespaced_network_policy(
                name=action.policy_name,
                namespace=action.namespace,
                body=body,
            )
        except Exception as exc:
            raise AwsControlError("Kubernetes emergency isolation mutation failed") from exc
        return response, "ISOLATION_POLICY_OBJECT_APPLIED"

    def _apply_access_key(self, action: IamDisableAccessKeyActionV2) -> tuple[Any, str]:
        try:
            response = self.iam.update_access_key(
                UserName=action.user_name,
                AccessKeyId=action.access_key_id,
                Status="Inactive",
            )
        except Exception as exc:
            raise AwsControlError("IAM access-key disable operation failed") from exc
        return response, "CREDENTIAL_DISABLED"

    def _apply_role_revocation(self, action: IamRevokeRoleSessionsActionV2) -> tuple[Any, str]:
        policy_document = _role_revocation_document(action)
        try:
            response = self.iam.put_role_policy(
                RoleName=action.role_name,
                PolicyName=action.policy_name,
                PolicyDocument=json.dumps(policy_document, separators=(",", ":")),
            )
        except Exception as exc:
            raise AwsControlError("IAM role-session revocation failed") from exc
        return response, "SESSIONS_REVOKED"

    @staticmethod
    def _assert_enforced(
        action: ProviderActionV2,
        after: ProviderActionPreviewV2,
    ) -> None:
        state = after.current_state
        if isinstance(action, EksDeployImmutableImageActionV2):
            expected_image = f"{action.image_repository}@{action.image_digest}"
            valid = (
                state["image"] == expected_image
                and state["replicas"] == action.replicas
                and state["updated_replicas"] == action.replicas
                and state["available_replicas"] == action.replicas
            )
        elif isinstance(action, EksIsolateNamespaceActionV2):
            valid = (
                state["policy_enforced"] is True
                and state["network_policy_enforcement_verified"] is True
                and state["admission_guard_verified"] is True
            )
        elif isinstance(action, IamDisableAccessKeyActionV2):
            valid = state["status"] == "Inactive"
        elif isinstance(action, IamRevokeRoleSessionsActionV2):
            expected_cutoff = (
                action.revoke_sessions_issued_before.astimezone(UTC)
                .isoformat()
                .replace("+00:00", "Z")
            )
            valid = (
                state["revocation_policy_present"] is True
                and state["revocation_policy_valid"] is True
                and state["revocation_cutoff"] == expected_cutoff
                and state["revocation_policy_sha256"]
                == state["expected_revocation_policy_sha256"]
            )
        else:  # pragma: no cover
            valid = False
        if not valid:
            raise AwsControlError("provider readback did not prove the requested enforcement")
