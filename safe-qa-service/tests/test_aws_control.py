from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID

import pytest

from safe_qa_service.aws_control import (
    AwsControlError,
    AwsControlProvider,
    AwsTargetPolicy,
    EksDeploymentTargetPolicy,
    load_aws_target_policy,
)
from safe_qa_service.schemas.v2 import (
    EksDeployImmutableImageActionV2,
    EksIsolateNamespaceActionV2,
    IamDisableAccessKeyActionV2,
    IamRevokeRoleSessionsActionV2,
)
from safe_qa_service.settings import ConfigurationError

ACCOUNT = "999999999999"
REGION = "us-east-1"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/safe-qa-controller"
CLUSTER = "production"
NAMESPACE = "safe-qa"
SANDBOX_NAMESPACE = "safe-qa-agent-sandbox"
ACCESS_KEY = "AKIAEXAMPLE00001"


def _uuid(value: int) -> UUID:
    return UUID(int=value, version=4)


def _metadata(request_id: str) -> dict[str, dict[str, str]]:
    return {"ResponseMetadata": {"RequestId": request_id}}


class FakeSts:
    def __init__(self, *, account: str = ACCOUNT, arn: str = ROLE_ARN) -> None:
        self.account = account
        self.arn = arn
        self.calls = 0

    def get_caller_identity(self) -> dict[str, str]:
        self.calls += 1
        return {"Account": self.account, "Arn": self.arn}


class FakeEks:
    def __init__(self, *, endpoint: str = "https://cluster.example.test") -> None:
        self.calls = 0
        self.endpoint = endpoint

    def describe_cluster(self, *, name: str) -> dict[str, object]:
        self.calls += 1
        return {
            "cluster": {
                "arn": f"arn:aws:eks:{REGION}:{ACCOUNT}:cluster/{name}",
                "status": "ACTIVE",
                "endpoint": self.endpoint,
                "certificateAuthority": {
                    "data": base64.b64encode(b"test-cluster-ca").decode()
                },
            },
            **_metadata("eks-read"),
        }

    def describe_addon(self, **kwargs: object) -> dict[str, object]:
        self.calls += 1
        return {
            "addon": {
                "status": "ACTIVE",
                "addonVersion": "v1.21.1-eksbuild.1",
                "configurationValues": json.dumps({"enableNetworkPolicy": "true"}),
            },
            **_metadata("eks-addon-read"),
        }


class NoSuchEntity(Exception):
    def __init__(self) -> None:
        self.response = {"Error": {"Code": "NoSuchEntity"}}


class FakeIam:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.key_status = "Active"
        self.role_policy: dict[str, object] | None = None

    def list_access_keys(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("list_access_keys")
        return {
            "AccessKeyMetadata": [
                {
                    "UserName": "operator",
                    "AccessKeyId": ACCESS_KEY,
                    "Status": self.key_status,
                    "CreateDate": datetime(2026, 1, 1, tzinfo=UTC),
                }
            ],
            "IsTruncated": False,
            **_metadata("iam-list"),
        }

    def update_access_key(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("update_access_key")
        assert kwargs == {
            "UserName": "operator",
            "AccessKeyId": ACCESS_KEY,
            "Status": "Inactive",
        }
        self.key_status = "Inactive"
        return _metadata("iam-disable")

    def get_role(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("get_role")
        return {
            "Role": {
                "Arn": f"arn:aws:iam::{ACCOUNT}:role/incident-role",
                "Path": "/",
            },
            **_metadata("iam-role"),
        }

    def get_role_policy(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("get_role_policy")
        if self.role_policy is None:
            raise NoSuchEntity
        return {"PolicyDocument": self.role_policy, **_metadata("iam-policy-read")}

    def put_role_policy(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("put_role_policy")
        self.role_policy = json.loads(str(kwargs["PolicyDocument"]))
        return _metadata("iam-revoke")


class NotFound(Exception):
    status = 404


def _object_metadata(**values: object) -> SimpleNamespace:
    return SimpleNamespace(**values)


class FakeCoreV1:
    def __init__(self) -> None:
        self.calls = 0

    def read_namespace(self, *, name: str) -> SimpleNamespace:
        self.calls += 1
        labels = {
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
        return SimpleNamespace(
            metadata=_object_metadata(
                uid=f"uid-{name}",
                labels=labels,
            )
        )


class FakeNetworkingV1:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.policy = SimpleNamespace(
            metadata=_object_metadata(
                name="safe-qa-approved-egress",
                resource_version="network-policy-v0",
                labels={"safe-qa.io/controller-owned": "true"},
            ),
            spec=SimpleNamespace(
                pod_selector={},
                policy_types=["Egress"],
                ingress=None,
                egress=[{"to": [{"ipBlock": {"cidr": "10.0.0.0/24"}}]}],
            ),
        )
        self.default_deny = SimpleNamespace(
            metadata=_object_metadata(name="safe-qa-agent-default-deny"),
            spec=SimpleNamespace(
                pod_selector={},
                policy_types=["Ingress", "Egress"],
                ingress=None,
                egress=None,
            ),
        )
        managed_labels = {
            "app.kubernetes.io/name": "api",
            "safe-qa.io/provider-managed": "true",
        }
        self.managed_default_deny = SimpleNamespace(
            metadata=_object_metadata(
                name="safe-qa-default-deny",
                uid="uid-managed-default-deny",
                resource_version="managed-default-deny-v1",
            ),
            spec=SimpleNamespace(
                pod_selector={},
                policy_types=["Ingress", "Egress"],
                ingress=None,
                egress=None,
            ),
        )
        self.managed_isolation = SimpleNamespace(
            metadata=_object_metadata(
                name="safe-qa-managed-workload-isolation",
                uid="uid-managed-workload-isolation",
                resource_version="managed-workload-isolation-v1",
            ),
            spec=SimpleNamespace(
                pod_selector=SimpleNamespace(
                    match_labels=managed_labels,
                    match_expressions=None,
                ),
                policy_types=["Ingress", "Egress"],
                ingress=[],
                egress=[],
            ),
        )

    def list_namespaced_network_policy(self, **kwargs: object) -> SimpleNamespace:
        self.calls.append("list")
        if kwargs.get("namespace") == SANDBOX_NAMESPACE:
            items = [self.default_deny, self.policy]
        else:
            items = [self.managed_default_deny, self.managed_isolation]
        return SimpleNamespace(items=items, metadata=SimpleNamespace(_continue=None))

    def read_namespaced_network_policy(self, **kwargs: object) -> SimpleNamespace:
        self.calls.append("read")
        return self.policy

    def replace_namespaced_network_policy(self, **kwargs: object) -> SimpleNamespace:
        self.calls.append("replace")
        body = kwargs["body"]
        self.policy = SimpleNamespace(
            metadata=_object_metadata(
                name="safe-qa-approved-egress",
                resource_version="network-policy-v1",
                labels=body["metadata"]["labels"],
            ),
            spec=SimpleNamespace(
                pod_selector=body["spec"]["podSelector"],
                policy_types=body["spec"]["policyTypes"],
                ingress=None,
                egress=body["spec"]["egress"],
            ),
        )
        return self.policy


class FakeAdmissionV1:
    @staticmethod
    def _metadata(name: str) -> SimpleNamespace:
        return SimpleNamespace(uid=f"uid-{name}", generation=1)

    @staticmethod
    def _status() -> SimpleNamespace:
        return SimpleNamespace(
            observed_generation=1,
            type_checking=SimpleNamespace(expression_warnings=[]),
            conditions=[SimpleNamespace(type="Accepted", status="True")],
        )

    def read_validating_admission_policy(self, *, name: str) -> SimpleNamespace:
        if name == "safe-qa-agent-network-policy-boundary":
            rule = ("networking.k8s.io", ["CREATE", "UPDATE", "DELETE"], ["networkpolicies"])
            validations = [
                (
                    "request.operation != 'DELETE'",
                    "The two baseline sandbox NetworkPolicies may not be deleted.",
                ),
                (
                    "object.metadata.name in ['safe-qa-agent-default-deny', "
                    "'safe-qa-approved-egress']",
                    "Only the default-deny and controller-owned approved-egress "
                    "policies are permitted.",
                ),
                (
                    "object.metadata.name != 'safe-qa-agent-default-deny' || "
                    "oldObject == null || object.spec == oldObject.spec",
                    "The agent namespace default-deny policy is immutable.",
                ),
                (
                    "object.metadata.name != 'safe-qa-approved-egress' || "
                    "request.userInfo.username == 'system:serviceaccount:"
                    "safe-qa-control:safe-qa-controller' || "
                    "request.userInfo.groups.exists(group, group == "
                    "'safe-qa-network-policy-admins')",
                    "Only the controller ServiceAccount or named break-glass group "
                    "may change approved egress.",
                ),
            ]
            selector = SimpleNamespace(
                match_labels={"safe-qa.io/dedicated-agent-namespace": "true"},
                match_expressions=None,
            )
        elif name == "safe-qa-agent-namespace-boundary":
            rule = ("", ["UPDATE", "DELETE"], ["namespaces"])
            validations = [
                (
                    "request.name != 'safe-qa-agent-sandbox' || "
                    "request.operation != 'DELETE'",
                    "The dedicated sandbox namespace may not be deleted.",
                ),
                (
                    "request.name != 'safe-qa-agent-sandbox' || request.operation == "
                    "'DELETE' || (has(object.metadata.labels) && "
                    "object.metadata.labels['safe-qa.io/dedicated-agent-namespace'] == "
                    "'true')",
                    "The sandbox dedicated-agent label must remain exactly true.",
                ),
            ]
            for label, expected, message in (
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
            ):
                validations.append(
                    (
                        "request.name != 'safe-qa-agent-sandbox' || request.operation == "
                        "'DELETE' || (has(object.metadata.labels) && "
                        f"object.metadata.labels['{label}'] == '{expected}')",
                        message,
                    )
                )
            selector = None
        elif name == "safe-qa-agent-pod-boundary":
            rule = ("", ["CREATE", "UPDATE"], ["pods", "pods/ephemeralcontainers"])
            validations = [
                (
                    "object.metadata.labels['safe-qa.io/runtime'] == "
                    "'ec2-network-policy-sandbox' && object.spec.nodeSelector"
                    "['safe-qa.io/runtime'] == 'ec2-network-policy-sandbox' && "
                    "object.spec.nodeSelector['safe-qa.io/exclusive-node-group'] == "
                    "'true' && object.spec.serviceAccountName == 'safe-qa-agent-sandbox'",
                    "Sandbox pods must select the exclusive EC2 NetworkPolicy node group "
                    "and tokenless sandbox ServiceAccount.",
                ),
                (
                    "!has(object.spec.nodeName)",
                    "Sandbox pods may not bypass scheduling policy with spec.nodeName.",
                ),
                (
                    "has(object.spec.tolerations) && object.spec.tolerations.size() == 1 "
                    "&& object.spec.tolerations.exists(toleration, toleration.key == "
                    "'safe-qa.io/agent-sandbox' && toleration.operator == 'Equal' && "
                    "toleration.value == 'true' && toleration.effect == 'NoSchedule')",
                    "Sandbox pods must carry exactly the dedicated node-group toleration.",
                ),
                (
                    "object.spec.automountServiceAccountToken == false && "
                    "object.spec.hostNetwork == false && object.spec.hostPID == false && "
                    "object.spec.hostIPC == false",
                    "Sandbox pods may not receive a Kubernetes token or join host namespaces.",
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
                    "Sandbox pods permit exactly one container and no init or ephemeral "
                    "containers.",
                ),
                (
                    "object.spec.containers.all(container, !has(container.env) && "
                    "!has(container.envFrom) && "
                    "container.securityContext.readOnlyRootFilesystem == true && "
                    "container.securityContext.allowPrivilegeEscalation == false && "
                    "container.securityContext.privileged == false)",
                    "Sandbox containers may not receive injected configuration and must "
                    "use the restricted security context.",
                ),
                (
                    "!has(object.spec.volumes) || object.spec.volumes.size() == 0",
                    "Sandbox pods may not declare any volumes.",
                ),
            ]
            selector = SimpleNamespace(
                match_labels={"safe-qa.io/dedicated-agent-namespace": "true"},
                match_expressions=None,
            )
        else:
            rule = ("", ["CREATE", "UPDATE"], ["pods"])
            pattern = "^[^@]+@sha256:[a-f0-9]{64}$"
            validations = [
                (
                    "object.spec.containers.all(container, container.image.matches("
                    f"'{pattern}'))",
                    "Every container image must use repository@sha256:<64 lowercase hex>.",
                ),
                (
                    "!has(object.spec.initContainers) || "
                    "object.spec.initContainers.all(container, container.image.matches("
                    f"'{pattern}'))",
                    "Every init-container image must use repository@sha256:<64 lowercase "
                    "hex>.",
                ),
            ]
            selector = SimpleNamespace(
                match_labels={"safe-qa.io/firewall-enforced": "true"},
                match_expressions=None,
            )
        rules = [
            SimpleNamespace(
                api_groups=[rule[0]],
                api_versions=["v1"],
                operations=rule[1],
                resources=rule[2],
            )
        ]
        return SimpleNamespace(
            metadata=self._metadata(name),
            status=self._status(),
            spec=SimpleNamespace(
                failure_policy="Fail",
                match_constraints=SimpleNamespace(
                    match_policy="Exact",
                    resource_rules=rules,
                    namespace_selector=selector,
                    object_selector=None,
                    exclude_resource_rules=None,
                ),
                validations=[
                    SimpleNamespace(
                        expression=expression,
                        message=message,
                        message_expression=None,
                        reason=None,
                    )
                    for expression, message in validations
                ],
                match_conditions=None,
                param_kind=None,
                audit_annotations=None,
                variables=None,
            ),
        )

    def read_validating_admission_policy_binding(self, *, name: str) -> SimpleNamespace:
        if name in {
            "safe-qa-agent-network-policy-boundary",
            "safe-qa-agent-pod-boundary",
        }:
            labels = {"safe-qa.io/dedicated-agent-namespace": "true"}
        elif name == "safe-qa-immutable-images":
            labels = {"safe-qa.io/firewall-enforced": "true"}
        else:
            labels = None
        selector = (
            SimpleNamespace(match_labels=labels, match_expressions=None)
            if labels is not None
            else None
        )
        match_resources = (
            SimpleNamespace(
                match_policy="Exact",
                namespace_selector=selector,
                object_selector=None,
                resource_rules=None,
                exclude_resource_rules=None,
            )
            if selector is not None
            else None
        )
        return SimpleNamespace(
            metadata=self._metadata(name),
            spec=SimpleNamespace(
                policy_name=name,
                validation_actions=["Deny", "Audit"],
                match_resources=match_resources,
                param_ref=None,
            ),
        )


class FakeAppsV1:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.image = "registry.example.test/safe-qa@sha256:" + "0" * 64
        self.source_revision = "abcdef1234567890"
        self.replicas = 1
        self.generation = 1

    def read_namespaced_deployment(self, **kwargs: object) -> SimpleNamespace:
        self.calls.append("read")
        container = SimpleNamespace(
            name="api",
            image=self.image,
            image_pull_policy="IfNotPresent",
            command=None,
            args=None,
            env=None,
            env_from=None,
            volume_mounts=None,
            ports=None,
            security_context=SimpleNamespace(
                allow_privilege_escalation=False,
                privileged=False,
                read_only_root_filesystem=True,
                run_as_non_root=True,
                run_as_user=65532,
                run_as_group=65532,
                capabilities=SimpleNamespace(drop=["ALL"], add=None),
            ),
        )
        labels = {
            "app.kubernetes.io/name": "api",
            "safe-qa.io/provider-managed": "true",
        }
        return SimpleNamespace(
            metadata=_object_metadata(
                uid="deployment-uid",
                resource_version=f"deployment-v{self.generation}",
                generation=self.generation,
                labels=labels,
            ),
            spec=SimpleNamespace(
                replicas=self.replicas,
                selector=SimpleNamespace(
                    match_labels={"app.kubernetes.io/name": "api"},
                    match_expressions=None,
                ),
                template=SimpleNamespace(
                    metadata=SimpleNamespace(
                        labels=labels,
                        annotations={
                            "safe-qa.io/source-revision": self.source_revision,
                            "safe-qa.io/image-digest": self.image.split("@", 1)[1],
                        },
                    ),
                    spec=SimpleNamespace(
                        containers=[container],
                        service_account_name="safe-qa-managed-workload",
                        automount_service_account_token=False,
                        enable_service_links=False,
                        host_network=False,
                        host_pid=False,
                        host_ipc=False,
                        restart_policy="Always",
                        node_name=None,
                        init_containers=None,
                        ephemeral_containers=None,
                        volumes=None,
                        security_context=SimpleNamespace(
                            run_as_non_root=True,
                            seccomp_profile=SimpleNamespace(type="RuntimeDefault"),
                        ),
                    ),
                ),
            ),
            status=SimpleNamespace(
                observed_generation=self.generation,
                updated_replicas=self.replicas,
                available_replicas=self.replicas,
            ),
        )

    def patch_namespaced_deployment(self, **kwargs: object) -> SimpleNamespace:
        self.calls.append("patch")
        body = kwargs["body"]
        self.image = body["spec"]["template"]["spec"]["containers"][0]["image"]
        self.source_revision = body["spec"]["template"]["metadata"]["annotations"][
            "safe-qa.io/source-revision"
        ]
        self.replicas = body["spec"]["replicas"]
        self.generation += 1
        return SimpleNamespace(metadata=_object_metadata(resource_version="deployment-v2"))

    def read_namespaced_daemon_set(self, **kwargs: object) -> SimpleNamespace:
        policy_agent = SimpleNamespace(name="aws-network-policy-agent", env=[])
        aws_node = SimpleNamespace(
            name="aws-node",
            env=[SimpleNamespace(name="NETWORK_POLICY_ENFORCING_MODE", value="strict")],
        )
        return SimpleNamespace(
            metadata=_object_metadata(resource_version="aws-node-v1", generation=2),
            spec=SimpleNamespace(
                template=SimpleNamespace(spec=SimpleNamespace(containers=[aws_node, policy_agent]))
            ),
            status=SimpleNamespace(
                observed_generation=2,
                desired_number_scheduled=3,
                updated_number_scheduled=3,
                number_available=3,
                number_ready=3,
            ),
        )


def _policy() -> AwsTargetPolicy:
    return AwsTargetPolicy(
        account_id=ACCOUNT,
        region=REGION,
        runtime_principal_arn=ROLE_ARN,
        controller_namespace="safe-qa-control",
        controller_service_account="safe-qa-controller",
        network_policy_admin_group="safe-qa-network-policy-admins",
        eks_cluster_name=CLUSTER,
        eks_deployments={
            (CLUSTER, NAMESPACE): {
                "api": EksDeploymentTargetPolicy(
                    deployment_name="api",
                    container_name="api",
                    image_repository="registry.example.test/safe-qa",
                    service_account_name="safe-qa-managed-workload",
                )
            }
        },
        eks_isolation_namespaces=frozenset({(CLUSTER, SANDBOX_NAMESPACE)}),
        iam_access_keys={"operator": frozenset({ACCESS_KEY})},
        iam_roles=frozenset({"incident-role"}),
    )


def _provider(
    *,
    sts: FakeSts | None = None,
    iam: FakeIam | None = None,
    networking: FakeNetworkingV1 | None = None,
    apps: FakeAppsV1 | None = None,
    eks: FakeEks | None = None,
    admission: FakeAdmissionV1 | None = None,
) -> AwsControlProvider:
    return AwsControlProvider(
        policy=_policy(),
        sts_client=sts or FakeSts(),
        eks_client=eks or FakeEks(),
        iam_client=iam or FakeIam(),
        core_v1=FakeCoreV1(),
        networking_v1=networking or FakeNetworkingV1(),
        apps_v1=apps or FakeAppsV1(),
        admission_v1=admission or FakeAdmissionV1(),
        rollout_timeout_seconds=0,
    )


def _key_action(*, key: str = ACCESS_KEY) -> IamDisableAccessKeyActionV2:
    return IamDisableAccessKeyActionV2(action_id=_uuid(1), user_name="operator", access_key_id=key)


def test_target_policy_rejects_runtime_role_as_a_revocation_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = {
        "account_id": ACCOUNT,
        "region": REGION,
        "runtime_principal_arn": ROLE_ARN,
        "controller_namespace": NAMESPACE,
        "controller_service_account": "safe-qa-controller",
        "network_policy_admin_group": "safe-qa-network-policy-admins",
        "eks": [
            {
                "cluster_name": CLUSTER,
                "namespace": NAMESPACE,
                "deployments": [
                    {
                        "deployment_name": "api",
                        "container_name": "api",
                        "image_repository": "registry.example.test/safe-qa",
                        "service_account_name": "safe-qa-managed-workload",
                    }
                ],
                "allow_emergency_isolation": False,
            }
        ],
        "iam_access_keys": {},
        "iam_roles": ["safe-qa-controller"],
    }
    monkeypatch.setenv("SAFE_QA_AWS_TARGET_POLICY_JSON", json.dumps(raw))

    with pytest.raises(ConfigurationError, match="runtime role"):
        load_aws_target_policy()


def test_exact_target_rejection_happens_before_any_provider_call() -> None:
    sts = FakeSts()
    iam = FakeIam()
    provider = _provider(sts=sts, iam=iam)
    action = _key_action(key="AKIAEXAMPLE99999")

    with pytest.raises(AwsControlError, match="not explicitly allowlisted"):
        provider.preview(action)

    assert sts.calls == 0
    assert iam.calls == []


@pytest.mark.parametrize(
    ("account", "arn", "message"),
    [
        ("111111111111", ROLE_ARN, "account differs"),
        (ACCOUNT, f"arn:aws:iam::{ACCOUNT}:role/other", "principal differs"),
    ],
)
def test_account_and_principal_mismatch_fail_closed(account: str, arn: str, message: str) -> None:
    iam = FakeIam()
    provider = _provider(sts=FakeSts(account=account, arn=arn), iam=iam)

    with pytest.raises(AwsControlError, match=message):
        provider.preview(_key_action())

    assert iam.calls == []


def test_provider_state_drift_prevents_access_key_mutation() -> None:
    iam = FakeIam()
    provider = _provider(iam=iam)
    before = provider.preview(_key_action())
    iam.key_status = "Inactive"

    with pytest.raises(AwsControlError, match="state changed after approval"):
        provider.apply(_key_action(), expected_before_sha256=before.current_state_sha256)

    assert "update_access_key" not in iam.calls


def test_access_key_disable_has_provider_receipt_and_inactive_readback() -> None:
    iam = FakeIam()
    provider = _provider(iam=iam)
    action = _key_action()
    before = provider.preview(action)

    receipt = provider.apply(action, expected_before_sha256=before.current_state_sha256)

    assert receipt.status == "CREDENTIAL_DISABLED"
    assert receipt.provider_receipt_ids == ("iam-disable",)
    assert receipt.before_state_sha256 != receipt.after_state_sha256
    assert iam.key_status == "Inactive"
    assert iam.calls.count("update_access_key") == 1


def test_role_session_revocation_has_policy_readback() -> None:
    iam = FakeIam()
    provider = _provider(iam=iam)
    cutoff = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
    action = IamRevokeRoleSessionsActionV2(
        action_id=_uuid(2),
        role_name="incident-role",
        revoke_sessions_issued_before=cutoff,
    )
    before = provider.preview(action)

    receipt = provider.apply(action, expected_before_sha256=before.current_state_sha256)

    assert receipt.status == "SESSIONS_REVOKED"
    assert receipt.provider_receipt_ids == ("iam-revoke",)
    assert iam.role_policy is not None
    statement = iam.role_policy["Statement"][0]
    assert statement["Effect"] == "Deny"
    assert statement["Condition"]["DateLessThan"]["aws:TokenIssueTime"].endswith("Z")


def test_namespace_isolation_closes_preprovisioned_egress_and_reads_it_back() -> None:
    networking = FakeNetworkingV1()
    provider = _provider(networking=networking)
    action = EksIsolateNamespaceActionV2(
        action_id=_uuid(3), cluster_name=CLUSTER, namespace=SANDBOX_NAMESPACE
    )
    before = provider.preview(action)

    receipt = provider.apply(action, expected_before_sha256=before.current_state_sha256)

    assert receipt.status == "ISOLATION_POLICY_OBJECT_APPLIED"
    assert receipt.provider_receipt_ids == ("kubernetes-resource-version:network-policy-v1",)
    assert "replace" in networking.calls
    assert provider.preview(action).current_state["policy_enforced"] is True


def test_isolation_rejects_narrowed_or_unaccepted_admission_policy() -> None:
    class DriftedAdmission(FakeAdmissionV1):
        def read_validating_admission_policy(self, *, name: str) -> SimpleNamespace:
            policy = super().read_validating_admission_policy(name=name)
            if name == "safe-qa-agent-network-policy-boundary":
                policy.spec.match_constraints.exclude_resource_rules = [
                    SimpleNamespace(
                        api_groups=["networking.k8s.io"],
                        api_versions=["v1"],
                        operations=["UPDATE"],
                        resources=["networkpolicies"],
                    )
                ]
            return policy

    action = EksIsolateNamespaceActionV2(
        action_id=_uuid(30), cluster_name=CLUSTER, namespace=SANDBOX_NAMESPACE
    )
    with pytest.raises(AwsControlError, match="admission guard differs"):
        _provider(admission=DriftedAdmission()).preview(action)

    class EmptyStatusAdmission(FakeAdmissionV1):
        @staticmethod
        def _status() -> SimpleNamespace:
            return SimpleNamespace(
                observed_generation=1,
                type_checking=SimpleNamespace(expression_warnings=[]),
                conditions=[],
            )

    with pytest.raises(AwsControlError, match="admission guard differs"):
        _provider(admission=EmptyStatusAdmission()).preview(action)


def test_immutable_image_deployment_uses_digest_and_proves_rollout() -> None:
    apps = FakeAppsV1()
    provider = _provider(apps=apps)
    digest = "sha256:" + "a" * 64
    action = EksDeployImmutableImageActionV2(
        action_id=_uuid(4),
        cluster_name=CLUSTER,
        namespace=NAMESPACE,
        deployment_name="api",
        container_name="api",
        image_repository="registry.example.test/safe-qa",
        image_digest=digest,
        source_revision="abcdef1234567890",
        replicas=3,
    )
    before = provider.preview(action)

    receipt = provider.apply(action, expected_before_sha256=before.current_state_sha256)

    assert receipt.status == "DEPLOYED"
    assert receipt.provider_receipt_ids == ("kubernetes-resource-version:deployment-v2",)
    assert apps.image == f"registry.example.test/safe-qa@{digest}"
    assert apps.replicas == 3
    assert apps.calls.count("patch") == 1


def test_deployment_repository_and_security_profile_are_fail_closed() -> None:
    sts = FakeSts()
    provider = _provider(sts=sts)
    digest = "sha256:" + "a" * 64
    wrong_repository = EksDeployImmutableImageActionV2(
        action_id=_uuid(40),
        cluster_name=CLUSTER,
        namespace=NAMESPACE,
        deployment_name="api",
        container_name="api",
        image_repository="registry.example.test/other",
        image_digest=digest,
        source_revision="abcdef1234567890",
        replicas=2,
    )
    with pytest.raises(AwsControlError, match="not explicitly allowlisted"):
        provider.preview(wrong_repository)
    assert sts.calls == 0

    class DriftedApps(FakeAppsV1):
        def read_namespaced_deployment(self, **kwargs: object) -> SimpleNamespace:
            deployment = super().read_namespaced_deployment(**kwargs)
            deployment.spec.template.spec.service_account_name = "safe-qa-controller"
            return deployment

    exact_action = wrong_repository.model_copy(
        update={"image_repository": "registry.example.test/safe-qa"}
    )
    with pytest.raises(AwsControlError, match="identity or isolation profile drifted"):
        _provider(apps=DriftedApps()).preview(exact_action)
