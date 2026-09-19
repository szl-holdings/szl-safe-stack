"""Fail-closed AWS Systems Manager Automation provider mutation handler.

This file is embedded verbatim in a numerically versioned SSM Automation
document by ``provider-gate.tf``.  It deliberately supports one provider action
per Change Manager request so a failed later action can never hide an earlier,
partially applied mutation.

The handler is not a standalone authorization mechanism.  Its caller must be
the narrowly trusted SSM Automation role, and the enclosing Change Manager
template must have completed all three fixed approval levels.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from typing import Any

MAX_ENVELOPE_BYTES = 131_072
MAX_KUBERNETES_RESPONSE_BYTES = 4 * 1024 * 1024
ROLLOUT_TIMEOUT_SECONDS = 300
PROVIDER_GATE_GROUP = "safe-qa-provider-gate"

SUPPORTED_ACTIONS = {
    "EKS_DEPLOY_IMMUTABLE_IMAGE",
    "EKS_ISOLATE_NAMESPACE",
    "IAM_DISABLE_ACCESS_KEY",
    "IAM_REVOKE_ROLE_SESSIONS",
}


class GateError(RuntimeError):
    """A checked precondition failed; no later operation may run."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def _exact_keys(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{name} must be an object")
    _require(set(value) == keys, f"{name} has an unexpected shape")
    return value


def _parse_aware(value: Any, name: str) -> datetime:
    _require(isinstance(value, str), f"{name} must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GateError(f"{name} is not an ISO-8601 timestamp") from exc
    _require(parsed.tzinfo is not None, f"{name} must include a timezone")
    return parsed.astimezone(UTC)


def _request_id(response: dict[str, Any]) -> str:
    metadata = response.get("ResponseMetadata", {})
    request_id = metadata.get("RequestId") if isinstance(metadata, dict) else None
    _require(isinstance(request_id, str) and request_id, "AWS response omitted RequestId")
    return request_id


def _config(events: dict[str, Any]) -> dict[str, Any]:
    required = {
        "change_envelope_json",
        "change_envelope_sha256",
        "account_id",
        "region",
        "partition",
        "controller_principal_arn",
        "automation_role_arn",
        "cluster_name",
        "allowed_eks_deployments",
        "allowed_isolation_namespaces",
        "allowed_user_arns",
        "allowed_role_arns",
    }
    cfg = _exact_keys(events, required, "Automation input")
    _require(
        isinstance(cfg["change_envelope_json"], str)
        and 0 < len(cfg["change_envelope_json"].encode("utf-8")) <= MAX_ENVELOPE_BYTES,
        "change envelope length is outside the closed bound",
    )
    _require(
        isinstance(cfg["change_envelope_sha256"], str)
        and re.fullmatch(r"[0-9a-f]{64}", cfg["change_envelope_sha256"]) is not None,
        "change envelope digest is invalid",
    )
    _require(
        isinstance(cfg["account_id"], str)
        and re.fullmatch(r"[0-9]{12}", cfg["account_id"]) is not None,
        "account ID is invalid",
    )
    _require(
        isinstance(cfg["region"], str)
        and re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-[0-9]", cfg["region"]) is not None,
        "AWS Region is invalid",
    )
    _require(cfg["partition"] in {"aws", "aws-us-gov", "aws-cn"}, "partition is invalid")
    _require(isinstance(cfg["allowed_eks_deployments"], dict), "EKS target map is invalid")
    _require(
        isinstance(cfg["allowed_isolation_namespaces"], list), "isolation target list is invalid"
    )
    _require(isinstance(cfg["allowed_user_arns"], list), "IAM user allowlist is invalid")
    _require(isinstance(cfg["allowed_role_arns"], list), "IAM role allowlist is invalid")
    return cfg


def _validate_envelope(cfg: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        envelope = json.loads(cfg["change_envelope_json"])
    except json.JSONDecodeError as exc:
        raise GateError("change envelope is not JSON") from exc
    envelope = _exact_keys(
        envelope,
        {"schema_version", "plan", "plan_digest", "expected_preview"},
        "change envelope",
    )
    _require(
        envelope["schema_version"] == "safe-qa-provider-change/v1",
        "change envelope schema is unsupported",
    )
    _require(
        _sha(envelope) == cfg["change_envelope_sha256"],
        "change envelope digest mismatch",
    )
    plan = envelope["plan"]
    _require(isinstance(plan, dict), "plan must be an object")
    _require(plan.get("schema_version") == "2.0", "plan schema is unsupported")
    _require(
        plan.get("statement_type") == "safe-qa-deployment-plan/v2"
        and plan.get("operation") == "EXECUTE_EXACT_PROVIDER_ACTIONS",
        "plan operation is unsupported",
    )
    _require(
        isinstance(envelope["plan_digest"], str)
        and re.fullmatch(r"[0-9a-f]{64}", envelope["plan_digest"]) is not None
        and _sha(plan) == envelope["plan_digest"],
        "plan digest mismatch",
    )
    _require(
        _parse_aware(plan.get("expires_at"), "plan.expires_at") > datetime.now(UTC),
        "plan expired before execution",
    )
    actions = plan.get("provider_actions")
    _require(isinstance(actions, list) and len(actions) == 1, "exactly one action is required")
    action = actions[0]
    _require(isinstance(action, dict), "provider action must be an object")
    _require(action.get("action_type") in SUPPORTED_ACTIONS, "provider action is unsupported")
    preview = envelope["expected_preview"]
    preview = _exact_keys(
        preview,
        {"action_id", "action_type", "current_state_sha256", "current_state"},
        "expected preview",
    )
    _require(
        preview["action_id"] == action.get("action_id")
        and preview["action_type"] == action.get("action_type"),
        "preview is not bound to the action",
    )
    _require(
        isinstance(preview["current_state_sha256"], str)
        and re.fullmatch(r"[0-9a-f]{64}", preview["current_state_sha256"]) is not None
        and _sha(preview["current_state"]) == preview["current_state_sha256"],
        "preview state digest mismatch",
    )
    _require(
        _sha([preview]) == plan.get("provider_state_sha256"),
        "plan provider-state digest mismatch",
    )
    if action["action_type"] == "EKS_DEPLOY_IMMUTABLE_IMAGE":
        _require(
            action.get("image_digest") == plan.get("container_digest"),
            "deployment image digest is not the plan digest",
        )
    return action, preview


def _validate_execution_identity(cfg: dict[str, Any]) -> None:
    import boto3

    identity = boto3.client("sts", region_name=cfg["region"]).get_caller_identity()
    _require(identity.get("Account") == cfg["account_id"], "execution account mismatch")
    expected_role = cfg["automation_role_arn"].split(":role/", 1)[-1]
    arn = identity.get("Arn")
    _require(
        isinstance(arn, str)
        and arn.startswith(
            f"arn:{cfg['partition']}:sts::{cfg['account_id']}:assumed-role/{expected_role}/"
        ),
        "execution did not use the pinned Automation role",
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        raise GateError("Kubernetes API redirect was refused")


class KubernetesApi:
    def __init__(self, cfg: dict[str, Any]) -> None:
        import boto3

        self.cfg = cfg
        self.session = boto3.session.Session(region_name=cfg["region"])
        self.eks = self.session.client("eks", region_name=cfg["region"])
        response = self.eks.describe_cluster(name=cfg["cluster_name"])
        cluster = response.get("cluster")
        _require(isinstance(cluster, dict), "EKS DescribeCluster returned no cluster")
        expected_arn = (
            f"arn:{cfg['partition']}:eks:{cfg['region']}:{cfg['account_id']}:"
            f"cluster/{cfg['cluster_name']}"
        )
        _require(
            cluster.get("arn") == expected_arn and cluster.get("status") == "ACTIVE",
            "EKS cluster identity or status mismatch",
        )
        endpoint = cluster.get("endpoint")
        _require(
            isinstance(endpoint, str)
            and endpoint.startswith("https://")
            and urllib.parse.urlsplit(endpoint).path in {"", "/"},
            "EKS endpoint is invalid",
        )
        authority = cluster.get("certificateAuthority")
        _require(isinstance(authority, dict), "EKS certificate authority is absent")
        encoded_ca = authority.get("data")
        _require(isinstance(encoded_ca, str) and encoded_ca, "EKS CA data is absent")
        try:
            ca_pem = base64.b64decode(encoded_ca, validate=True).decode("ascii")
        except (ValueError, UnicodeDecodeError) as exc:
            raise GateError("EKS CA data is invalid") from exc
        self.cluster_arn = expected_arn
        self.endpoint = endpoint.rstrip("/")
        self.ssl_context = ssl.create_default_context(cadata=ca_pem)

    def _token(self) -> str:
        from botocore.signers import RequestSigner

        credentials = self.session.get_credentials()
        _require(credentials is not None, "Automation role credentials are unavailable")
        sts = self.session.client("sts", region_name=self.cfg["region"])
        signer = RequestSigner(
            sts.meta.service_model.service_id,
            self.cfg["region"],
            "sts",
            "v4",
            credentials,
            self.session.events,
        )
        url = signer.generate_presigned_url(
            {
                "method": "GET",
                "url": (
                    f"https://sts.{self.cfg['region']}.amazonaws.com/"
                    "?Action=GetCallerIdentity&Version=2011-06-15"
                ),
                "body": {},
                "headers": {"x-k8s-aws-id": self.cfg["cluster_name"]},
                "context": {},
            },
            region_name=self.cfg["region"],
            expires_in=60,
            operation_name="",
        )
        return "k8s-aws-v1." + base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        content_type: str = "application/json",
    ) -> tuple[dict[str, Any], str]:
        _require(path.startswith("/") and ".." not in path, "Kubernetes path is invalid")
        encoded = None if body is None else _canonical(body)
        request = urllib.request.Request(
            self.endpoint + path,
            data=encoded,
            method=method,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._token()}",
                "Content-Type": content_type,
            },
        )
        opener = urllib.request.build_opener(
            _NoRedirect(), urllib.request.HTTPSHandler(context=self.ssl_context)
        )
        try:
            with opener.open(request, timeout=15) as response:
                raw = response.read(MAX_KUBERNETES_RESPONSE_BYTES + 1)
                _require(
                    len(raw) <= MAX_KUBERNETES_RESPONSE_BYTES,
                    "Kubernetes response exceeded the closed size bound",
                )
                payload = json.loads(raw) if raw else {}
                audit_id = response.headers.get("Audit-Id") or response.headers.get(
                    "X-Kubernetes-Audit-Id"
                )
        except (urllib.error.URLError, json.JSONDecodeError) as exc:
            raise GateError("Kubernetes API operation failed") from exc
        _require(isinstance(payload, dict), "Kubernetes response must be an object")
        _require(isinstance(audit_id, str) and audit_id, "Kubernetes audit ID is absent")
        return payload, audit_id

    @staticmethod
    def segment(value: Any, name: str) -> str:
        _require(
            isinstance(value, str)
            and re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", value) is not None,
            f"{name} is not a DNS label",
        )
        return urllib.parse.quote(value, safe="")


def _cluster(cfg: dict[str, Any], action: dict[str, Any]) -> KubernetesApi:
    _require(
        action.get("cluster_name") == cfg["cluster_name"],
        "EKS action does not target the pinned cluster",
    )
    return KubernetesApi(cfg)


def _deployment_state(
    cfg: dict[str, Any], action: dict[str, Any], api: KubernetesApi
) -> dict[str, Any]:
    key = "/".join(
        [
            str(action.get("namespace", "")),
            str(action.get("deployment_name", "")),
            str(action.get("container_name", "")),
        ]
    )
    repository_prefix = cfg["allowed_eks_deployments"].get(key)
    _require(
        isinstance(repository_prefix, str)
        and repository_prefix
        and isinstance(action.get("image_repository"), str)
        and action["image_repository"].startswith(repository_prefix),
        "deployment or image repository is not allowlisted",
    )
    namespace = api.segment(action.get("namespace"), "namespace")
    deployment = api.segment(action.get("deployment_name"), "deployment name")
    obj, _ = api.request("GET", f"/apis/apps/v1/namespaces/{namespace}/deployments/{deployment}")
    metadata = obj.get("metadata", {})
    spec = obj.get("spec", {})
    status = obj.get("status", {})
    containers = spec.get("template", {}).get("spec", {}).get("containers", [])
    matches = [item for item in containers if item.get("name") == action.get("container_name")]
    _require(len(matches) == 1, "exact deployment container is absent or ambiguous")
    uid = metadata.get("uid")
    resource_version = metadata.get("resourceVersion")
    generation = metadata.get("generation")
    _require(
        isinstance(uid, str)
        and uid
        and isinstance(resource_version, str)
        and resource_version
        and type(generation) is int
        and generation >= 1,
        "deployment identity receipt is incomplete",
    )
    return {
        "caller_arn": cfg["controller_principal_arn"],
        "cluster_arn": api.cluster_arn,
        "deployment_uid": uid,
        "resource_version": resource_version,
        "generation": generation,
        "observed_generation": int(status.get("observedGeneration") or 0),
        "replicas": int(spec.get("replicas") or 0),
        "updated_replicas": int(status.get("updatedReplicas") or 0),
        "available_replicas": int(status.get("availableReplicas") or 0),
        "image": str(matches[0].get("image") or ""),
    }


def _admission_accepted(obj: dict[str, Any]) -> bool:
    metadata = obj.get("metadata", {})
    generation = metadata.get("generation")
    conditions = obj.get("status", {}).get("conditions", [])
    return bool(
        isinstance(generation, int)
        and any(
            item.get("type") == "Accepted"
            and item.get("status") == "True"
            and item.get("observedGeneration") == generation
            for item in conditions
            if isinstance(item, dict)
        )
    )


def _admission_state(api: KubernetesApi) -> dict[str, Any]:
    names = {
        "network": "safe-qa-agent-network-policy-boundary",
        "namespace": "safe-qa-agent-namespace-boundary",
        "pod": "safe-qa-agent-pod-boundary",
        "image": "safe-qa-immutable-images",
    }
    policies: dict[str, dict[str, Any]] = {}
    bindings: dict[str, dict[str, Any]] = {}
    for key, name in names.items():
        policies[key], _ = api.request(
            "GET", f"/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/{name}"
        )
        bindings[key], _ = api.request(
            "GET",
            f"/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/{name}",
        )
        _require(_admission_accepted(policies[key]), f"{name} is not accepted")
        _require(
            policies[key].get("spec", {}).get("failurePolicy") == "Fail", f"{name} is fail-open"
        )
        _require(
            set(bindings[key].get("spec", {}).get("validationActions", [])) == {"Deny", "Audit"},
            f"{name} binding does not deny",
        )
    network_expressions = "\n".join(
        str(item.get("expression", ""))
        for item in policies["network"].get("spec", {}).get("validations", [])
        if isinstance(item, dict)
    )
    _require("request.operation != 'DELETE'" in network_expressions, "delete guard is absent")
    _require(PROVIDER_GATE_GROUP in network_expressions, "provider-gate group is absent")
    return {
        "admission_guard_verified": True,
        "admission_policy_uid": policies["network"].get("metadata", {}).get("uid"),
        "admission_binding_uid": bindings["network"].get("metadata", {}).get("uid"),
        "namespace_admission_policy_uid": policies["namespace"].get("metadata", {}).get("uid"),
        "pod_admission_policy_uid": policies["pod"].get("metadata", {}).get("uid"),
        "immutable_image_policy_uid": policies["image"].get("metadata", {}).get("uid"),
    }


def _network_enforcement(cfg: dict[str, Any], api: KubernetesApi) -> dict[str, Any]:
    addon_response = api.eks.describe_addon(clusterName=cfg["cluster_name"], addonName="vpc-cni")
    addon = addon_response.get("addon", {})
    _require(addon.get("status") == "ACTIVE", "VPC CNI add-on is not active")
    version = addon.get("addonVersion")
    match = re.fullmatch(r"v?([0-9]+)\.([0-9]+)\..+", str(version))
    _require(match is not None and (int(match[1]), int(match[2])) >= (1, 21), "VPC CNI is too old")
    raw_config = addon.get("configurationValues") or "{}"
    config = json.loads(raw_config) if isinstance(raw_config, str) else raw_config
    _require(
        isinstance(config, dict) and config.get("enableNetworkPolicy") in {True, "true"},
        "VPC CNI network policy is disabled",
    )
    daemonset, _ = api.request("GET", "/apis/apps/v1/namespaces/kube-system/daemonsets/aws-node")
    containers = daemonset.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
    names = {item.get("name") for item in containers if isinstance(item, dict)}
    aws_node = next((item for item in containers if item.get("name") == "aws-node"), {})
    env = {item.get("name"): item.get("value") for item in aws_node.get("env", [])}
    status = daemonset.get("status", {})
    desired = int(status.get("desiredNumberScheduled") or 0)
    ready = int(status.get("numberReady") or 0)
    rv = daemonset.get("metadata", {}).get("resourceVersion")
    _require(
        "aws-network-policy-agent" in names
        and env.get("NETWORK_POLICY_ENFORCING_MODE") == "strict"
        and desired >= 1
        and ready == desired
        and isinstance(rv, str)
        and rv,
        "VPC CNI policy agent is not healthy in strict mode",
    )
    return {
        "network_policy_enforcement_verified": True,
        "vpc_cni_addon_version": version,
        "aws_node_resource_version": rv,
        "aws_node_desired": desired,
        "aws_node_ready": ready,
    }


def _isolation_state(
    cfg: dict[str, Any], action: dict[str, Any], api: KubernetesApi
) -> dict[str, Any]:
    namespace_name = action.get("namespace")
    _require(
        namespace_name in cfg["allowed_isolation_namespaces"]
        and action.get("policy_name") == "safe-qa-approved-egress",
        "isolation target is not allowlisted",
    )
    namespace = api.segment(namespace_name, "namespace")
    ns_obj, _ = api.request("GET", f"/api/v1/namespaces/{namespace}")
    labels = ns_obj.get("metadata", {}).get("labels", {})
    required_labels = {
        "safe-qa.io/dedicated-agent-namespace": "true",
        "safe-qa.io/firewall-enforced": "true",
        "safe-qa.io/runtime": "ec2-network-policy-sandbox",
        "pod-security.kubernetes.io/enforce": "restricted",
    }
    _require(
        all(labels.get(k) == v for k, v in required_labels.items()), "namespace labels drifted"
    )
    listing, _ = api.request(
        "GET", f"/apis/networking.k8s.io/v1/namespaces/{namespace}/networkpolicies"
    )
    by_name = {
        item.get("metadata", {}).get("name"): item
        for item in listing.get("items", [])
        if isinstance(item, dict)
    }
    _require(
        set(by_name) == {"safe-qa-agent-default-deny", "safe-qa-approved-egress"},
        "NetworkPolicy inventory differs from the closed baseline",
    )
    default_spec = by_name["safe-qa-agent-default-deny"].get("spec", {})
    _require(
        default_spec.get("podSelector") == {}
        and set(default_spec.get("policyTypes", [])) == {"Ingress", "Egress"}
        and default_spec.get("ingress") in (None, [])
        and default_spec.get("egress") in (None, []),
        "default-deny policy drifted",
    )
    policy = by_name["safe-qa-approved-egress"]
    metadata = policy.get("metadata", {})
    spec = policy.get("spec", {})
    enforced = bool(
        spec.get("podSelector") == {}
        and set(spec.get("policyTypes", [])) == {"Egress"}
        and spec.get("egress") == []
        and metadata.get("labels", {}).get("safe-qa.io/controller-owned") == "true"
    )
    rv = metadata.get("resourceVersion")
    ns_uid = ns_obj.get("metadata", {}).get("uid")
    _require(
        isinstance(rv, str) and rv and isinstance(ns_uid, str) and ns_uid,
        "isolation identity is incomplete",
    )
    return {
        "caller_arn": cfg["controller_principal_arn"],
        "cluster_arn": api.cluster_arn,
        "namespace_uid": ns_uid,
        "policy_present": True,
        "policy_enforced": enforced,
        "policy_resource_version": rv,
        **_admission_state(api),
        **_network_enforcement(cfg, api),
    }


def _iam_user_arn(cfg: dict[str, Any], user_name: Any) -> str:
    _require(
        isinstance(user_name, str)
        and re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,64}", user_name) is not None,
        "IAM user name is invalid",
    )
    matches = [
        arn
        for arn in cfg["allowed_user_arns"]
        if isinstance(arn, str) and ":user/" in arn and arn.rsplit("/", 1)[-1] == user_name
    ]
    _require(len(matches) == 1, "IAM user is not exactly allowlisted")
    return matches[0]


def _access_key_state(cfg: dict[str, Any], action: dict[str, Any]) -> dict[str, Any]:
    import boto3

    allowed_arn = _iam_user_arn(cfg, action.get("user_name"))
    key_id = action.get("access_key_id")
    _require(
        isinstance(key_id, str) and re.fullmatch(r"[A-Z0-9]{16,128}", key_id) is not None,
        "access key ID is invalid",
    )
    iam = boto3.client("iam", region_name=cfg["region"])
    user = iam.get_user(UserName=action["user_name"]).get("User", {})
    _require(
        user.get("Arn") == allowed_arn and user.get("UserName") == action["user_name"],
        "IAM user identity differs from the exact allowlist",
    )
    items: list[dict[str, Any]] = []
    marker: str | None = None
    for _ in range(10):
        args: dict[str, Any] = {"UserName": action["user_name"], "MaxItems": 100}
        if marker:
            args["Marker"] = marker
        response = iam.list_access_keys(**args)
        page = response.get("AccessKeyMetadata")
        _require(isinstance(page, list), "IAM access-key response is malformed")
        items.extend(item for item in page if isinstance(item, dict))
        if response.get("IsTruncated") is not True:
            break
        marker = response.get("Marker")
        _require(isinstance(marker, str) and marker, "IAM access-key pagination is incomplete")
    else:
        raise GateError("IAM access-key pagination exceeded the closed bound")
    matches = [item for item in items if item.get("AccessKeyId") == key_id]
    _require(
        len(matches) == 1 and matches[0].get("UserName") == action["user_name"],
        "access key target is absent or ambiguous",
    )
    created = matches[0].get("CreateDate")
    return {
        "caller_arn": cfg["controller_principal_arn"],
        "user_name": action["user_name"],
        "access_key_id": key_id,
        "status": str(matches[0].get("Status") or ""),
        "created_at": created.astimezone(UTC).isoformat() if isinstance(created, datetime) else "",
    }


def _revocation_document(action: dict[str, Any]) -> dict[str, Any]:
    cutoff = (
        _parse_aware(action.get("revoke_sessions_issued_before"), "revoke_sessions_issued_before")
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


def _role_state(cfg: dict[str, Any], action: dict[str, Any]) -> dict[str, Any]:
    import boto3

    role_name = action.get("role_name")
    _require(
        isinstance(role_name, str)
        and re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,64}", role_name) is not None
        and action.get("policy_name") == "AWSRevokeOlderSessions",
        "IAM role action is invalid",
    )
    iam = boto3.client("iam", region_name=cfg["region"])
    role = iam.get_role(RoleName=role_name).get("Role", {})
    arn = role.get("Arn")
    _require(arn in cfg["allowed_role_arns"], "IAM role is not exactly allowlisted")
    path = role.get("Path")
    _require(
        isinstance(path, str) and not path.startswith("/aws-service-role/"),
        "service-linked role cannot be revoked",
    )
    policy_document = None
    try:
        policy_document = iam.get_role_policy(
            RoleName=role_name, PolicyName="AWSRevokeOlderSessions"
        ).get("PolicyDocument")
        if isinstance(policy_document, str):
            policy_document = json.loads(urllib.parse.unquote(policy_document))
    except iam.exceptions.NoSuchEntityException:
        policy_document = None
    _require(
        policy_document is None or isinstance(policy_document, dict), "role policy is malformed"
    )
    expected = _revocation_document(action)
    valid = policy_document == expected
    cutoff = expected["Statement"][0]["Condition"]["DateLessThan"]["aws:TokenIssueTime"]
    return {
        "caller_arn": cfg["controller_principal_arn"],
        "role_arn": arn,
        "role_path": path,
        "revocation_policy_present": policy_document is not None,
        "revocation_policy_valid": valid,
        "revocation_cutoff": cutoff if valid else None,
        "expected_revocation_policy_sha256": _sha(expected),
        "revocation_policy_sha256": _sha(policy_document) if policy_document else None,
    }


def _state(cfg: dict[str, Any], action: dict[str, Any]) -> dict[str, Any]:
    action_type = action["action_type"]
    if action_type == "IAM_DISABLE_ACCESS_KEY":
        return _access_key_state(cfg, action)
    if action_type == "IAM_REVOKE_ROLE_SESSIONS":
        return _role_state(cfg, action)
    api = _cluster(cfg, action)
    if action_type == "EKS_DEPLOY_IMMUTABLE_IMAGE":
        return _deployment_state(cfg, action, api)
    return _isolation_state(cfg, action, api)


def _apply(cfg: dict[str, Any], action: dict[str, Any], before: dict[str, Any]) -> tuple[str, str]:
    import boto3

    action_type = action["action_type"]
    if action_type == "IAM_DISABLE_ACCESS_KEY":
        response = boto3.client("iam", region_name=cfg["region"]).update_access_key(
            UserName=action["user_name"], AccessKeyId=action["access_key_id"], Status="Inactive"
        )
        return "CREDENTIAL_DISABLED", _request_id(response)
    if action_type == "IAM_REVOKE_ROLE_SESSIONS":
        response = boto3.client("iam", region_name=cfg["region"]).put_role_policy(
            RoleName=action["role_name"],
            PolicyName="AWSRevokeOlderSessions",
            PolicyDocument=_canonical(_revocation_document(action)).decode("ascii"),
        )
        return "SESSIONS_REVOKED", _request_id(response)
    api = _cluster(cfg, action)
    namespace = api.segment(action["namespace"], "namespace")
    if action_type == "EKS_ISOLATE_NAMESPACE":
        policy = api.segment(action["policy_name"], "policy name")
        _, audit_id = api.request(
            "PUT",
            f"/apis/networking.k8s.io/v1/namespaces/{namespace}/networkpolicies/{policy}",
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {
                    "name": action["policy_name"],
                    "namespace": action["namespace"],
                    "resourceVersion": before["policy_resource_version"],
                    "labels": {
                        "app.kubernetes.io/managed-by": "safe-qa-provider-gate",
                        "safe-qa.io/controller-owned": "true",
                    },
                },
                "spec": {"podSelector": {}, "policyTypes": ["Egress"], "egress": []},
            },
        )
        return "ISOLATION_POLICY_OBJECT_APPLIED", audit_id
    deployment = api.segment(action["deployment_name"], "deployment name")
    exact_image = f"{action['image_repository']}@{action['image_digest']}"
    _, audit_id = api.request(
        "PATCH",
        f"/apis/apps/v1/namespaces/{namespace}/deployments/{deployment}",
        {
            "metadata": {"resourceVersion": before["resource_version"]},
            "spec": {
                "replicas": action["replicas"],
                "template": {
                    "spec": {
                        "containers": [{"name": action["container_name"], "image": exact_image}]
                    }
                },
            },
        },
        "application/strategic-merge-patch+json",
    )
    deadline = time.monotonic() + ROLLOUT_TIMEOUT_SECONDS
    while True:
        observed = _deployment_state(cfg, action, api)
        if (
            observed["image"] == exact_image
            and observed["replicas"] == action["replicas"]
            and observed["updated_replicas"] == action["replicas"]
            and observed["available_replicas"] == action["replicas"]
            and observed["observed_generation"] >= observed["generation"]
        ):
            return "DEPLOYED", audit_id
        if time.monotonic() >= deadline:
            raise GateError("deployment did not become available before the closed timeout")
        time.sleep(2)


def _assert_after(action: dict[str, Any], after: dict[str, Any]) -> None:
    action_type = action["action_type"]
    if action_type == "IAM_DISABLE_ACCESS_KEY":
        valid = after["status"] == "Inactive"
    elif action_type == "IAM_REVOKE_ROLE_SESSIONS":
        valid = bool(
            after["revocation_policy_present"]
            and after["revocation_policy_valid"]
            and after["revocation_policy_sha256"] == after["expected_revocation_policy_sha256"]
        )
    elif action_type == "EKS_ISOLATE_NAMESPACE":
        valid = bool(
            after["policy_enforced"]
            and after["admission_guard_verified"]
            and after["network_policy_enforcement_verified"]
        )
    else:
        exact_image = f"{action['image_repository']}@{action['image_digest']}"
        valid = bool(
            after["image"] == exact_image
            and after["replicas"] == action["replicas"]
            and after["updated_replicas"] == action["replicas"]
            and after["available_replicas"] == action["replicas"]
        )
    _require(valid, "provider readback did not prove the requested enforcement")


def execute(events: dict[str, Any], context: Any) -> dict[str, Any]:
    """Validate, mutate once, and return a provider receipt."""

    del context
    cfg = _config(events)
    action, expected_preview = _validate_envelope(cfg)
    _validate_execution_identity(cfg)
    before = _state(cfg, action)
    _require(
        before == expected_preview["current_state"]
        and _sha(before) == expected_preview["current_state_sha256"],
        "provider state changed after approval; no mutation was attempted",
    )
    status, provider_request_id = _apply(cfg, action, before)
    after = _state(cfg, action)
    _assert_after(action, after)
    receipt = {
        "schema_version": "safe-qa-provider-receipt/v1",
        "action_id": action["action_id"],
        "action_type": action["action_type"],
        "status": status,
        "before_state_sha256": _sha(before),
        "after_state_sha256": _sha(after),
        "provider_receipt_ids": [provider_request_id],
        "enforced_at": datetime.now(UTC).isoformat(),
    }
    return {"receipt_json": _canonical(receipt).decode("ascii")}
