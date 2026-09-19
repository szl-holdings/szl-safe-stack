# AWS production deployment and readiness runbook

## Evidence status

This package is a production-capable reference, not production evidence. Its
Terraform has not been applied to an AWS account, its Kubernetes template has
not been admitted to an EKS cluster, no firewall route has been changed, no
credential has been disabled, no role session has been revoked, no human has
signed an approval, and no third party has witnessed a deployment merely
because these files exist.

Use these exact status labels in release records:

| Status | Required evidence |
| --- | --- |
| `LOCALLY_VALIDATED` | Exact file digests plus successful local static checks |
| `PLANNED` | Saved Terraform plan digest and independently reviewed JSON plan |
| `HUMAN_APPROVED` | Two valid KMS signatures from the pinned security and release roles, with distinct Identity Center users and matching CloudTrail Sign events |
| `THIRD_PARTY_WITNESSED` | A valid witness-account KMS signature, witness CloudTrail event, and detached auditor receipt |
| `PROVIDER_ENFORCED` | Exact AWS and Kubernetes readback proving policies, routes, role permissions, and admission controls |
| `DEPLOYED` | Immutable source/image identity, successful rollout, ready replicas, API/database checks, and provider readback at the same revision |
| `CREDENTIALS_REVOKED` | Exact target identifier, provider request ID, before/after state, timestamp, approval bundle digest, and post-action readback |

Never infer a later state from an earlier one. A successful Terraform apply is
not by itself `PROVIDER_ENFORCED`, and `PROVIDER_ENFORCED` is not by itself a
successful application deployment.

## Architecture and trust boundaries

The workload account contains EKS, Network Firewall, the runtime role, the
security-approver key, the release-approver key, and a validated CloudTrail.
The witness account is authenticated through a second Terraform provider and
contains its own witness key, validated trail, durable log bucket, and evidence
reader role. The Terraform invariant requires the two account IDs to differ.

The service never receives `kms:Sign`. Its IAM role has an explicit deny for
that action. Each production approval key grants Sign to one existing human
federated role and one exact `identitystore:UserId` plus
`identitystore:IdentityStoreArn` context only. The witness key applies the same
two-part binding in the witness account. This removes the prior
convenience-command failure mode where one process could access two HMAC
secrets.

The approval-key account-principal statement is restricted to named key
management actions and excludes Sign, Verify, cryptographic data operations,
and `CreateGrant`; it therefore does not generally delegate Sign through IAM.
`PutKeyPolicy` remains an unavoidable key-administration recovery capability,
so any key-policy change is a witnessed high-severity event and invalidates
approval readiness until independently reviewed and read back.

The ordinary Identity Center permission-set session is insufficient when it
does not carry identity-enhanced role-session context. If KMS does not evaluate
the two `identitystore` condition keys for the exact session, or CloudTrail does
not emit matching `userIdentity.onBehalfOf` evidence, Sign must fail or the
result must be rejected. AWS service support and event shape are live-tested in
the selected accounts and Regions during bootstrap and again after provider or
Identity Center changes. Infrastructure source alone never supports
`HUMAN_APPROVED`.

Key separation does not prove human separation by itself. Admission must also
verify all of the following:

- each CloudTrail event is a successful KMS `Sign` event for the exact key and
  provider request ID;
- CloudTrail `userIdentity.onBehalfOf` identifies an AWS IAM Identity Center
  user and identity store matching the exact key-policy condition values;
- the security user, release user, and witness user IDs are all distinct;
- the two production roles match their configured key/role mapping;
- the witness event and signer belong to the independently administered
  witness account;
- all three signatures cover the same canonical plan digest, nonce, immutable
  source revision, image digest, policy bundle digest, and expiration; and
- the runtime performs KMS `Verify` over the digest and independently looks up
  the CloudTrail event. Submitted event JSON is never trusted as evidence.

AWS documents asymmetric `SIGN_VERIFY` keys and the distinction between Sign
and Verify in the [KMS Sign API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html)
and [KMS Verify API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Verify.html).
Identity Center user attribution is described in [IAM Identity Center
CloudTrail logging](https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-info-in-cloudtrail.html)
and the [user-attribution use cases](https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-cloudtrail-use-cases.html).

## Prerequisites that must already exist

Do not invent or auto-discover any production target. Record and independently
review:

1. Exact workload and witness AWS account IDs and the named owners of each.
2. Existing deployment roles in each account. The witness role must be governed
   by a different administrative boundary.
3. Three existing Identity Center permission-set role ARNs, MFA policy, user
   IDs, identity-store IDs, and named human owners. Shared accounts and generic
   automation roles are unacceptable. Confirm the selected sign-in path creates
   an identity-enhanced IAM role session, not an ordinary permission-set session
   lacking identity context.
4. Exact EKS cluster, Kubernetes version, VPC, OIDC provider, issuer,
   control-plane namespace/ServiceAccount, the literal
   `safe-qa-agent-sandbox` namespace, and cluster access entry. The privileged
   control-plane ServiceAccount is never reused by an agent Job.
5. An EKS-compatible VPC CNI add-on version that supports network policy and
   `strict` startup enforcement. AWS notes that strict mode starts new pods in a
   default-deny posture; confirm current compatibility in the [EKS network
   policy configuration guide](https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy-configure.html).
6. At least two dedicated firewall subnets and an Availability Zone diagram
   proving symmetric routing for every ingress and egress path. AWS Network
   Firewall requires explicit route-table steering; follow the [route-table
   integration guidance](https://docs.aws.amazon.com/network-firewall/latest/developerguide/route-tables.html).
7. Reviewed strict-order Suricata rules with explicit destination allow rules
   and a final drop/reject. Do not use `0.0.0.0/0` as an allow shortcut.
8. Private KMS, STS, CloudTrail, and container-registry connectivity, preferably
   interface VPC endpoints with exact endpoint subnet CIDRs. Record the exact
   OIDC JWKS HTTPS destination CIDR for an internal mirror, egress proxy, or
   reviewed issuer endpoint; token verification fails closed without this path.
9. A private, encrypted Terraform backend with state locking, versioning,
   break-glass recovery, and access logs. State must not be stored in this
   source directory.
10. Exact immutable container digest, exact source revision, SBOM digest,
    provenance/signature verification, vulnerability disposition, PostgreSQL
    TLS endpoint, and OIDC issuer configuration.
11. A Kubernetes version exposing stable
    `admissionregistration.k8s.io/v1` `ValidatingAdmissionPolicy`. The deployment
    must fail preflight if that API is unavailable.
12. Two or more exact private subnets across Availability Zones for the sandbox
    EC2 Linux managed node group. Each declared route table must appear in
    `protected_routes` and steer the reviewed paths through Network Firewall.
    Public-IP assignment is disabled at both subnet and launch-template layers.
    The minimal node role has only worker-node and ECR-pull managed policies;
    VPC CNI permissions use a separate IRSA role. The sandbox ServiceAccount has
    no IRSA annotation, token, RBAC, Secret, or ConfigMap.

## Phase 0: inspect without mutation

Use read-only provider calls from the named deployment session and preserve the
JSON outputs in the review record. At minimum inspect:

```bash
aws sts get-caller-identity
aws eks describe-cluster --name "$EKS_CLUSTER" --region "$AWS_REGION"
aws eks describe-addon --cluster-name "$EKS_CLUSTER" --addon-name vpc-cni --region "$AWS_REGION"
aws eks list-nodegroups --cluster-name "$EKS_CLUSTER" --region "$AWS_REGION"
aws ec2 describe-route-tables --route-table-ids $EXACT_ROUTE_TABLE_IDS --region "$AWS_REGION"
aws ec2 describe-subnets --subnet-ids $EXACT_SANDBOX_SUBNET_IDS --region "$AWS_REGION"
aws network-firewall list-firewalls --region "$AWS_REGION"
aws cloudtrail describe-trails --include-shadow-trails --region "$AWS_REGION"
kubectl api-resources --api-group=admissionregistration.k8s.io
kubectl get ns "$SAFE_QA_NAMESPACE" safe-qa-agent-sandbox -o yaml
```

Confirm that each CLI is authenticated to the intended account/cluster. Stop
on any mismatch, unresolved resource, unmanaged conflicting route, existing
unhealthy add-on, or unknown NetworkPolicy.

## Phase 1: bootstrap the approval infrastructure

The initial KMS keys and trails cannot approve their own creation. Treat first
installation as a separately governed bootstrap:

1. Populate `deploy/aws/terraform.tfvars.example` into a protected file outside
   the repository. Replace every `REPLACE_*` token. Empty revocation allowlists
   are the safe bootstrap default.
2. Initialize the reviewed backend, run formatting and validation, refresh
   state, and save a binary plan plus JSON rendering.
3. Hash the Terraform sources, provider lock file, input file, binary plan, and
   JSON plan. Independent security, release, network, identity, and witness
   owners review those exact hashes.
4. Obtain bootstrap approval through the organization's existing change system,
   not through either not-yet-created KMS key.
5. Apply only the saved binary plan. Never run an unsaved interactive apply.
6. Perform every provider readback below. Record bootstrap status separately.
7. Have the external auditor retrieve and validate both CloudTrail digest
   chains from S3. Only then activate KMS-based approvals for later changes.

After bootstrap, every plan and action must use detached KMS approval. Do not
add any command to the service that signs on behalf of a human.

## Terraform plan and apply after bootstrap

From `deploy/aws`:

```bash
terraform init -upgrade=false
terraform fmt -check -recursive
terraform validate
terraform plan -refresh=true -input=false -var-file=/secure/path/production.tfvars -out=/secure/path/safe-qa.tfplan
terraform show -json /secure/path/safe-qa.tfplan > /secure/path/safe-qa.tfplan.json
sha256sum /secure/path/safe-qa.tfplan /secure/path/safe-qa.tfplan.json
```

Reject the plan if it replaces a KMS key, trail, log bucket, firewall, route,
OIDC trust policy, or role unexpectedly; widens an IAM resource; removes an
explicit deny; contains an unreviewed destination; or changes witness-account
ownership.

The two human approvers independently use AWS KMS Sign from their own
identity-enhanced Identity Center sessions. Each signs the canonical
application plan digest, not a prose summary. The independent witness signs a
witness statement containing both verified approval-record digests. Capture
provider request IDs, then wait for and independently look up their CloudTrail
events. An ordinary session without the exact user/store context must fail the
KMS key policy. If any evidence is missing, ambiguous, expired, repeated, or
identity attribution differs, fail closed.

After admission succeeds:

```bash
terraform apply -input=false /secure/path/safe-qa.tfplan
```

An apply exit code is only mutation evidence. Continue to live readback.

## Provider enforcement readback

Preserve raw JSON and hashes for all commands. Do not summarize away IDs.

### EKS and VPC CNI

```bash
aws eks describe-addon --cluster-name "$EKS_CLUSTER" --addon-name vpc-cni --region "$AWS_REGION"
aws eks describe-nodegroup --cluster-name "$EKS_CLUSTER" --nodegroup-name "$SANDBOX_NODE_GROUP" --region "$AWS_REGION"
kubectl -n kube-system get daemonset aws-node -o yaml
kubectl -n kube-system get pods -l k8s-app=aws-node -o wide
kubectl get nodes -l safe-qa.io/runtime=ec2-network-policy-sandbox -o yaml
kubectl get networkpolicy -A -o yaml
kubectl get validatingadmissionpolicy,validatingadmissionpolicybinding -o yaml
```

Require the exact add-on version, `ACTIVE` health, network-policy enablement,
strict enforcement mode, ready policy agents on every eligible node, and no
unreviewed policy. AWS describes network-policy behavior and limitations in
the [EKS network-policy guide](https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy.html).

### OIDC JWKS egress

Resolve the configured issuer and `jwks_uri` before deployment. Require HTTPS,
the exact configured host/path, a valid certificate chain, and address results
contained by `${OIDC_JWKS_ENDPOINTS_CIDR}`. Prefer a stable internal JWKS mirror
or egress proxy CIDR; direct public DNS address drift fails closed rather than
widening the policy. Read back the installed policy:

```bash
kubectl get networkpolicy safe-qa-oidc-jwks-egress -n "$SAFE_QA_NAMESPACE" -o yaml
```

Using an approved immutable, tokenless diagnostic pod with the same
`app.kubernetes.io/name: safe-qa-service` selector, prove HTTPS retrieval of the
exact JWKS succeeds while a different HTTPS destination fails. Then send a
valid short-lived OIDC token through the real ingress and confirm signature,
issuer, audience, lifetime, ACR/AMR, and scope checks succeed. Block the JWKS
path and confirm an uncached/rotated key fails authentication rather than
bypassing verification. Preserve DNS answers, certificate details, policy
readback, HTTP result, and provider flow logs.

### EC2 Linux agent sandbox

The privileged `safe-qa-service` control-plane pods use IRSA and Kubernetes
patch RBAC. Sandbox agent Jobs do not. They run in the literal
`safe-qa-agent-sandbox` namespace and select only the dedicated tainted and
labeled EC2 Linux managed node group. They use one pod per Job, have a
five-minute hard deadline, no retries, bounded quota and limits, a read-only
restricted container, and a ServiceAccount with
`automountServiceAccountToken: false`, no IRSA annotation, and no RoleBinding.
The supplied example Job is suspended.

The managed node group uses private subnets, no public IP, encrypted gp3 root
volumes, IMDSv2-required metadata with
hop limit 1, a minimal node role, bounded `1 <= min <= desired <= max <= 3`, and
an exclusive `NoSchedule` taint. Standard Linux EC2 pods, including pods owned
by Jobs, remain subject to the VPC CNI NetworkPolicy eligibility and owner
reference behavior documented in the [EKS network-policy
considerations](https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy.html).

Node-group creation still does not prove isolation. Keep Jobs suspended until
the exact VPC CNI policy agent is Ready on every eligible node and live tests
prove that zero egress blocks DNS, VPC targets, internet targets, IMDS
`169.254.169.254`, and task metadata `169.254.170.2`. Both hop-limit enforcement
and NetworkPolicy enforcement must pass; Network Firewall route tables must
also read back the endpoint in the same Availability Zone.

Read back and test:

```bash
aws eks describe-nodegroup --cluster-name "$EKS_CLUSTER" --nodegroup-name "$SANDBOX_NODE_GROUP" --region "$AWS_REGION"
aws ec2 describe-launch-template-versions --launch-template-id "$SANDBOX_LAUNCH_TEMPLATE_ID" --versions '$Latest' --region "$AWS_REGION"
aws ec2 describe-subnets --subnet-ids $EXACT_SANDBOX_SUBNET_IDS --region "$AWS_REGION"
aws ec2 describe-route-tables --filters Name=association.subnet-id,Values=$EXACT_SANDBOX_SUBNET_IDS --region "$AWS_REGION"
aws ec2 describe-security-groups --group-ids "$SANDBOX_NODE_SECURITY_GROUP_ID" --region "$AWS_REGION"
aws ec2 describe-security-group-rules --filters Name=group-id,Values="$SANDBOX_NODE_SECURITY_GROUP_ID" --region "$AWS_REGION"
aws ec2 describe-flow-logs --filter Name=resource-id,Values=$EXACT_SANDBOX_SUBNET_IDS --region "$AWS_REGION"
kubectl get serviceaccount,resourcequota,limitrange,networkpolicy,job -n safe-qa-agent-sandbox -o yaml
kubectl auth can-i --list --as=system:serviceaccount:safe-qa-agent-sandbox:safe-qa-agent-sandbox -n safe-qa-agent-sandbox
kubectl get nodes -l safe-qa.io/runtime=ec2-network-policy-sandbox -o yaml
kubectl -n kube-system get pods -l k8s-app=aws-node -o json
kubectl get pod -n safe-qa-agent-sandbox -l safe-qa.io/runtime=ec2-network-policy-sandbox -o wide
```

The node group must be `ACTIVE` with the exact launch-template version,
AL2023 x86-64 AMI type, on-demand capacity, exact private subnets, exact instance
types, expected taint/labels, encrypted root, IMDSv2 required, hop limit 1, and
no public IP. Every eligible node must have a Ready `aws-node` pod and Ready
`aws-network-policy-agent` container before a sandbox pod is admitted. The test
pod must schedule only on that node group. The authorization list must contain
no provider mutation or Kubernetes workload/policy permissions. Inspect the pod
spec and environment from a purpose-built, immutable negative-test image and
prove there is no Kubernetes token mount, IRSA role, AWS web-identity token,
Secret, ConfigMap, host namespace, or host path. Preserve all failed connection
output and flow/firewall logs.

Admission must match both `pods` and `pods/ephemeralcontainers`. Server-side
dry-run negative tests must reject a sandbox pod with pre-bound `spec.nodeName`,
any declared volume source, an init container, a second regular container, or
an ephemeral-container update. This prevents scheduler, credential-volume, and
debug-subresource bypasses while preserving the one-container bounded Job.
The namespace guard must also reject deletion of the sandbox namespace and any
update that removes or changes its exact dedicated-agent, firewall-enforced,
EC2 runtime, or Pod Security enforce/audit/warn level and version labels. Read
back every label and the active guard before relying on selector-based policy.

Require provider readback to show each exact sandbox subnet actually associated
with its declared firewall-steered route table; configuration input membership
is not evidence. The dedicated node security group has no implicit egress,
only the cluster security-group reference and reviewed exact private CIDRs, and
no `0.0.0.0/0`. Each sandbox subnet must have an `ALL` VPC Flow Log with
60-second aggregation delivering current records to the dedicated retained log
group. Missing associations, flow logs, or delivery records fail closed.

As the privileged control ServiceAccount, patching only
`safe-qa-approved-egress` must be permitted while creating a new policy is
denied:

```bash
kubectl auth can-i patch networkpolicy/safe-qa-approved-egress --as="system:serviceaccount:$SAFE_QA_NAMESPACE:$SAFE_QA_SERVICE_ACCOUNT" -n safe-qa-agent-sandbox
kubectl auth can-i create networkpolicies --as="system:serviceaccount:$SAFE_QA_NAMESPACE:$SAFE_QA_SERVICE_ACCOUNT" -n safe-qa-agent-sandbox
```

The first result must be `yes`; the second must be `no`. The installed
`safe-qa-approved-egress.spec.egress` is empty. Any future egress grant is a new
approved action and must exclude both link-local metadata addresses. Creating
or patching an additive policy outside the two admitted names must be denied.

The provider receipt `ISOLATION_POLICY_OBJECT_APPLIED` proves only that the
exact NetworkPolicy object was replaced and read back. It must never be labeled
network enforcement. `PROVIDER_ENFORCED` additionally requires an active VPC
CNI `PolicyEndpoint` selecting the intended pods at the observed generation,
Ready policy-agent state on their node, and live negative packets to DNS, VPC,
internet, IMDS, and task-metadata destinations. Missing or stale PolicyEndpoint
state fails closed.

Read and negative-test the exact RBAC and admission boundaries:

```bash
kubectl auth can-i list networkpolicies --as="system:serviceaccount:$SAFE_QA_NAMESPACE:$SAFE_QA_SERVICE_ACCOUNT" -n safe-qa-agent-sandbox
kubectl auth can-i delete networkpolicy/safe-qa-approved-egress --as="system:serviceaccount:$SAFE_QA_NAMESPACE:$SAFE_QA_SERVICE_ACCOUNT" -n safe-qa-agent-sandbox
kubectl auth can-i patch deployment/safe-qa-managed-workload --as="system:serviceaccount:$SAFE_QA_NAMESPACE:$SAFE_QA_SERVICE_ACCOUNT" -n "$SAFE_QA_NAMESPACE"
kubectl auth can-i patch deployment/safe-qa-service --as="system:serviceaccount:$SAFE_QA_NAMESPACE:$SAFE_QA_SERVICE_ACCOUNT" -n "$SAFE_QA_NAMESPACE"
kubectl get validatingadmissionpolicy safe-qa-agent-network-policy-boundary safe-qa-agent-namespace-boundary safe-qa-agent-pod-boundary safe-qa-immutable-images safe-qa-managed-workload-boundary -o yaml
kubectl get validatingadmissionpolicybinding safe-qa-agent-network-policy-boundary safe-qa-agent-namespace-boundary safe-qa-agent-pod-boundary safe-qa-immutable-images safe-qa-managed-workload-boundary -o yaml
```

List and the exact managed-workload patch must be `yes`; NetworkPolicy delete
and the control-plane self-patch must be `no`. All five admission policies and
bindings must have live UIDs and status `observedGeneration` equal to metadata
`generation`. The NetworkPolicy guard must match CREATE, UPDATE, and DELETE;
the Namespace guard must match UPDATE and DELETE. Those two sandbox guards may
not use `matchConditions`, `paramKind`, or binding `paramRef`. The managed
workload guard intentionally uses canonical match conditions to bind the exact
control namespace and resource set; compare them deeply rather than accepting
an equivalent selector. Prove deletion of either sandbox baseline policy,
deletion or security-label removal from `safe-qa-agent-sandbox`, mutation of the
managed isolation policy, and a managed Pod ephemeral-container update are all
denied by server-side dry-run.

### Network Firewall and routes

```bash
aws network-firewall describe-firewall --firewall-name "$FIREWALL_NAME" --region "$AWS_REGION"
aws network-firewall describe-firewall-policy --firewall-policy-arn "$FIREWALL_POLICY_ARN" --region "$AWS_REGION"
aws network-firewall describe-rule-group --rule-group-arn "$RULE_GROUP_ARN" --type STATEFUL --region "$AWS_REGION"
aws network-firewall describe-logging-configuration --firewall-arn "$FIREWALL_ARN" --region "$AWS_REGION"
aws ec2 describe-route-tables --route-table-ids $EXACT_ROUTE_TABLE_IDS --region "$AWS_REGION"
```

Require every firewall sync state to be `READY`, one endpoint per intended
Availability Zone, exact strict-order rules and capacity, alert and flow log
destinations, `aws:drop_strict` as the unmatched stateful default action, a
final effective Suricata `drop|reject ip any any -> any any (...)` catch-all,
and exact route endpoint IDs. Validate both directions of every flow. A single
default route through a firewall is insufficient if return paths bypass the
same endpoint.

### KMS, IAM, and CloudTrail

```bash
aws kms describe-key --key-id "$SECURITY_KEY_ARN" --region "$AWS_REGION"
aws kms get-key-policy --key-id "$SECURITY_KEY_ARN" --policy-name default --region "$AWS_REGION"
aws kms describe-key --key-id "$RELEASE_KEY_ARN" --region "$AWS_REGION"
aws kms get-key-policy --key-id "$RELEASE_KEY_ARN" --policy-name default --region "$AWS_REGION"
aws iam get-role --role-name "$RUNTIME_ROLE_NAME"
aws iam get-role-policy --role-name "$RUNTIME_ROLE_NAME" --policy-name "$RUNTIME_POLICY_NAME"
aws cloudtrail get-trail-status --name "$PRODUCTION_TRAIL_ARN" --region "$AWS_REGION"
```

Repeat KMS and CloudTrail readback from the witness account. Require enabled
asymmetric P-256 `SIGN_VERIFY` keys; one signer principal per key; runtime
Verify but explicit Sign denial; exact IRSA subject/audience; enabled,
multi-region, log-file-validation trails; recent delivery times; encrypted,
versioned, non-public S3 buckets; and no delivery errors.

Use IAM policy simulation and a dedicated non-production digest to prove the
runtime role receives an explicit deny for `kms:Sign` and an allow for
`kms:Verify`. Do not attempt unauthorized production signing merely to test a
deny. The witness reader session name must be exactly
`safe-qa-evidence-reader`; confirm it can look up witness events and cannot sign.

An independent auditor downloads the CloudTrail log and digest files from the
witness bucket, validates the digest chain using AWS's CloudTrail validation
procedure, checks the relevant Sign event, and returns a detached receipt with
object version IDs and SHA-256 hashes. A receipt generated by the workload
account is not third-party evidence.

## Render and deploy Kubernetes

`deploy/kubernetes-v2.yaml` is a template. Populate every placeholder from the
approved release record. `IMAGE_DIGEST` is exactly 64 lowercase hexadecimal
characters without the `sha256:` prefix. `IMAGE_REPOSITORY` has no tag. Endpoint
CIDRs are exact private interface-endpoint or API-server ranges, never broad
internet ranges.

The immutable target-policy ConfigMap binds the exact rendered
`controller_namespace`, `controller_service_account`, and
`network_policy_admin_group` used by the admission policy, in addition to the
exact account, region, and runtime principal. It contains exactly two `eks`
entries for the one exact EKS cluster: `${SAFE_QA_NAMESPACE}` permits deployment
mutation only through a structured binding containing deployment name
`safe-qa-managed-workload`, container name `workload`, exact
`${MANAGED_IMAGE_REPOSITORY}`, and ServiceAccount `safe-qa-managed-workload`, and
does not permit isolation; the literal `safe-qa-agent-sandbox` permits
isolation, has an empty deployment list, and does not grant the sandbox
ServiceAccount any token, RBAC, or IRSA.
Runtime must compare all three controller/admission identity fields to the live
ValidatingAdmissionPolicy and Binding before claiming the admission guard is
verified. Every policy `matchConstraints` and each nonempty binding
`matchResources` must read back with `matchPolicy: Exact`; equivalent-resource
matching is not accepted. The control Deployment `safe-qa-service` is not a
rollout target and its ServiceAccount has no RBAC to patch it. The distinct
managed workload uses a tokenless, RBAC-free ServiceAccount, immutable rendered
image digest, bounded resources, and explicit empty ingress/egress policy. It
has no manifest `command` or `args`; the approved image digest determines its
entrypoint. The managed-workload admission policy pins the exact Deployment and
Pod identity, selectors, ServiceAccount, token setting, host-namespace flags,
single `workload` container, absence of env/envFrom/volumes/entrypoint override,
restricted contexts, exact repository, digest shape, and digest/source
annotation consistency. Only the exact control ServiceAccount may change its
replica count, image, source-revision annotation, or digest annotation. The
approved plan and terminal readback—not the admission policy—bind the specific
new digest and source revision. This separation keeps the request pod alive to
persist the rollout's terminal receipt.

Only `safe-qa-managed-workload-isolation` may select the provider-managed Pods.
Its exact selector, both policy types, and empty ingress and egress lists are
admission protected and deletion is denied. The two complementary control
namespace default-deny policies cover non-managed and provider-label-absent
Pods without selecting the managed target. Every remaining admitted control
policy is pinned to the `safe-qa-service` selector; unknown policy names fail
closed.

Render `IAM_ROLE_TARGETS_JSON` from the exact reviewed Terraform
`revocable_iam_role_arns` value. The Terraform invariant rejects the generated
`<name_prefix>-runtime` role ARN, and runtime policy loading must independently
reject that same self-target. A hand-edited ConfigMap list is not aligned
provider authorization evidence.

Before server-side dry-run, scan the rendered file for `${`, `REPLACE_`, image
tags, `latest`, `0.0.0.0/0`, wildcard RBAC resources, and unexpected namespaces.
Any match fails the gate. Then run:

```bash
kubectl apply --server-side --dry-run=server -f /secure/path/kubernetes-v2.rendered.yaml
kubectl auth can-i patch networkpolicy/safe-qa-approved-egress --as="system:serviceaccount:$SAFE_QA_NAMESPACE:$SAFE_QA_SERVICE_ACCOUNT" -n safe-qa-agent-sandbox
kubectl auth can-i create networkpolicies --as="system:serviceaccount:$SAFE_QA_NAMESPACE:$SAFE_QA_SERVICE_ACCOUNT" -n safe-qa-agent-sandbox
kubectl diff -f /secure/path/kubernetes-v2.rendered.yaml
```

The first authorization check must be `yes`; the second must be `no`. Obtain
detached approval over the rendered-manifest digest and diff. Apply the exact
same bytes, then read back:

```bash
kubectl apply --server-side -f /secure/path/kubernetes-v2.rendered.yaml
kubectl rollout status deployment/safe-qa-service -n "$SAFE_QA_NAMESPACE" --timeout=10m
kubectl rollout status deployment/safe-qa-managed-workload -n "$SAFE_QA_NAMESPACE" --timeout=10m
kubectl get deployment,pod,pdb,serviceaccount,networkpolicy -n "$SAFE_QA_NAMESPACE" -o yaml
kubectl get namespace,serviceaccount,resourcequota,limitrange,role,rolebinding,networkpolicy,job -n safe-qa-agent-sandbox -o yaml
kubectl get pods -n "$SAFE_QA_NAMESPACE" -l app.kubernetes.io/name=safe-qa-service -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.containers[*].image}{"\n"}{end}'
```

Require three ready replicas across the intended topology, the exact
`repository@sha256:digest`, the IRSA role annotation, restricted Pod Security,
read-only root filesystems, dropped capabilities, the PDB, default-deny
policies, admission bindings, and only the named NetworkPolicy patch RBAC.
Separately require two ready managed-workload replicas at the exact managed
digest, no token mount, no IRSA annotation, no RoleBinding naming its
ServiceAccount, no command/args override, and zero effective ingress/egress.
Read back the exact managed boundary policy/binding and prove no other
NetworkPolicy selects either managed-workload label.

Run authenticated API tests through the actual ingress, verify the PostgreSQL
audit chain using its read-only verifier identity, then repeat the route,
firewall, KMS, CloudTrail, and image readbacks. Only the joint evidence supports
`DEPLOYED` and `PROVIDER_ENFORCED`.

## Credential and session revocation actions

Terraform only grants narrowly scoped capability; it does not revoke anything.
Both allowlists are empty unless exact IAM ARNs are supplied. The application
must plan, approve, witness, execute, and read back one target at a time.

### Disable an IAM access key

The plan binds the exact AWS account, IAM user ARN, user name, access-key ID,
current `Active` status, plan expiration, and provider-state digest. After the
full approval bundle is verified, call `UpdateAccessKey` with `Inactive`, then
read the same key back as `Inactive`. Record the AWS request ID and audit-ledger
event. Never print or store secret access-key material. AWS's supported rotation
and disable sequence is documented in [IAM access-key updates](https://docs.aws.amazon.com/IAM/latest/UserGuide/id-credentials-access-keys-update.html).

### Revoke existing IAM role sessions

The plan binds the exact role ARN and revocation cutoff. For an allowlisted
role, install the AWS-documented `AWSRevokeOlderSessions` inline deny using
`aws:TokenIssueTime`, then read back and hash the exact policy. This invalidates
sessions issued before the cutoff; it does not alter sessions issued afterward.
Service-linked roles and unallowlisted roles must fail closed. AWS documents
the behavior and policy shape in [Revoke IAM role temporary security
credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html).

Restoring an access key to `Active` or deleting/changing a revocation policy is
a separate, newly approved action. No automatic rollback is permitted for an
identity containment event.

## Rollback and break glass

- Application rollback selects a previously approved immutable image digest;
  never retag or use a mutable tag.
- Network isolation remains fail closed during rollback. Reopening egress needs
  a new plan, two human approvals, witness, and readback.
- Firewall route changes use a separately saved Terraform plan and must preserve
  symmetric inspection. Do not bypass Network Firewall to recover application
  availability.
- KMS keys, trails, evidence buckets, firewall resources, and the runtime role
  have `prevent_destroy`; firewall protection flags are also enabled. Removing
  protection is a separate break-glass change reviewed outside this state.
- Lost access to the witness account is a witness failure, not permission to
  self-witness. Production mutations remain denied.
- If approval verification, Identity Center attribution, CloudTrail delivery,
  PostgreSQL ledger verification, provider readback, or artifact identity is
  unavailable, record the exact unavailable state and stop.

## Production readiness sign-off

All boxes require attached raw evidence, not assertions:

- [ ] Exact local source, Terraform, manifest, wheel, image, SBOM, and policy
      digests recorded.
- [ ] Hosted CI completed on the exact source revision.
- [ ] Bootstrap and current saved plans reviewed and applied without drift.
- [ ] EKS VPC CNI is healthy with strict network-policy enforcement.
- [ ] Default-deny, immutable-image admission, and additive-policy prevention
      negative tests passed.
- [ ] Network Firewall endpoints, routes, logs, and symmetric paths read back.
- [ ] Sandbox subnet-to-route-table associations, dedicated node security-group
      rules, and current VPC Flow Log delivery read back from AWS.
- [ ] Runtime Sign simulation is explicit deny; exact Verify simulation is allow.
- [ ] Three distinct identity-enhanced Identity Center users, exact user/store
      context keys, exact role/key mappings, and CloudTrail `onBehalfOf` verified.
- [ ] Exclusive EC2 Linux sandbox node group is active at the exact launch
      template; private subnet/firewall routes, taint/labels, minimal node role,
      IMDSv2/hop-limit 1, encrypted root, policy-agent readiness,
      token/RBAC/provider-identity absence, quota/deadline enforcement, and
      zero-egress metadata negative tests passed.
- [ ] Exact OIDC JWKS HTTPS path works only through the reviewed CIDR or proxy,
      and an uncached-key denial test failed closed when that path was blocked.
- [ ] Production and witness CloudTrail trails are healthy and digest validation
      passed.
- [ ] Independent auditor receipt covers witness object versions and hashes.
- [ ] PostgreSQL migrations, TLS, audit-chain verification, backup restore, and
      least-privilege identities tested.
- [ ] Immutable Kubernetes rollout is ready at the exact approved digest.
- [ ] Control ServiceAccount cannot patch `safe-qa-service`; only the distinct
      tokenless/RBAC-free `safe-qa-managed-workload` is rollout-allowlisted,
      ready at its exact digest with image-defined entrypoint, protected by the
      exact managed-workload admission boundary, and zero-network isolated by
      the sole admitted selecting NetworkPolicy.
- [ ] Sandbox pod admission rejects `spec.nodeName`, every volume source,
      init/second/ephemeral containers, and direct ephemeral-container updates.
- [ ] Authenticated browser/API/data/evidence flow passed at the deployed
      revision.
- [ ] Any credential/session containment target was explicitly approved and its
      after-state independently read back.
- [ ] Named operators, witness, incident owner, rollback owner, and expiration
      windows are recorded.

Until every applicable item is evidenced, report the narrow state achieved and
keep all unsupported clinical or biological claims explicitly unverified.
