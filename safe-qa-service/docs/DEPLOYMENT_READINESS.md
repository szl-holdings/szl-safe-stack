# Deployment and readiness

## Current disposition

`NOT APPROVED FOR PRODUCTION`

`DEPLOYMENT_STATUS: NOT_DEPLOYED`

Version 0.2 contains a production-oriented AWS/EKS reference skeleton, not production
evidence. No Terraform apply, EKS admission, firewall route change, OIDC-provider enrollment,
credential revocation, KMS human approval, cross-account witness, or production rollout is claimed.

## Runtime gates

- Liveness proves only that the HTTP process responds.
- Readiness requires PostgreSQL, the audit schema, and a valid complete v1 audit chain.
- The v1 intake requires `evaluate`; ledger verification requires `audit:read`.
- Production mode requires organizational OIDC. Plan creation requires an MFA-qualified human
  principal with `control:plan`; execution requires a workload principal with `control:execute`.
- Plan creation reads exact provider state and makes no provider mutation.
- Execution requires an issued, unexpired, one-use plan; two independently verified human KMS
  approvals; a cross-account human witness; unchanged provider state; allowlisted exact targets;
  durable execution claim; provider readback; and append-only receipts.
- Any identity, schema, policy, signature, CloudTrail, provider, or database ambiguity fails closed.
- The v1 truth boundary remains deny-only regardless of v2 state.

## Required production inputs and evidence

1. An exact reviewed source revision and an immutable image reference by registry digest.
2. SBOM, vulnerability results, build provenance, dependency review, and signatures for that digest.
3. A production PostgreSQL endpoint using TLS verification, separate least-privilege migration and
   runtime roles, all three migrations, backups, point-in-time recovery, and an independently exercised
   restore.
4. Exact OIDC issuer, JWKS URL, audience, algorithm, ACR/AMR, token-lifetime, human/workload claim,
   scope, and group configuration with tested key rotation and outage behavior.
5. Named production and witness AWS accounts, Regions, Identity Stores, human user IDs, role ARNs,
   asymmetric KMS key ARNs, CloudTrail trails, evidence retention, and key policies that prevent the
   runtime from signing.
6. Exact allowlisted EKS cluster, namespace, deployment/container, IAM users/access keys, and IAM
   roles. Never discover a mutation target by fuzzy name or broad enumeration.
7. EKS VPC CNI compatibility and strict network-policy startup enforcement; namespace default deny,
   reviewed minimum egress, immutable-image admission, Pod Security, workload identity, and narrow
   RBAC.
8. AWS Network Firewall endpoints, stateful rules, alert/flow logs, route-table changes, symmetric
   traffic proof, failure behavior, change window, and rollback.
9. A bootstrap approval path independent of the KMS keys and trails being created.
10. Two detached KMS approvals from distinct Identity Center humans and one detached witness from an
    independently administered account, all bound to the exact plan and independently found in
    CloudTrail.
11. Rate limits, request-size limits, TLS ingress, secret rotation, log redaction, metrics, alerts,
    SLOs, on-call ownership, load tests, failure injection, and incident exercises.
12. Protected deployment, exact post-apply AWS/Kubernetes/database/API readback, and an independent
    evidence receipt at the same source, image, policy, and provider state.

The application production configuration is
`SAFE_QA_PRODUCTION_MODE=true`, `SAFE_QA_AUTH_MODE=oidc`,
`SAFE_QA_OIDC_ISSUERS_JSON`, `SAFE_QA_AWS_TARGET_POLICY_JSON`,
`SAFE_QA_APPROVAL_POLICY_JSON`, `SAFE_QA_AWS_EVIDENCE_ROUTES_JSON`, and a `DATABASE_URL` with
`sslmode=verify-full` plus `sslrootcert`. The Kubernetes v2 template uses the recognized production
mode and OIDC variable names. That source alignment is not deployment evidence: render the template,
scan out every placeholder, and complete admission/readback before requesting approvals.

## Consequential action rules

- `EKS_DEPLOY_IMMUTABLE_IMAGE` accepts only an allowlisted deployment/container and an image digest
  equal to the plan's container digest. Completion requires rollout and exact image readback.
- `EKS_ISOLATE_NAMESPACE` installs the named emergency default-deny policy only in an allowlisted
  namespace. Isolation is not established until Kubernetes readback matches the expected object.
- `IAM_DISABLE_ACCESS_KEY` targets one allowlisted user and exact access-key ID. Never retrieve,
  print, or store secret access-key material. Completion requires `Inactive` readback.
- `IAM_REVOKE_ROLE_SESSIONS` targets one allowlisted non-service-linked role and installs the exact
  `AWSRevokeOlderSessions` time-bound deny. Completion requires policy readback.

Provider request IDs and before/after digests are receipts, not proof of an unrelated outcome. If an
action is partially applied, the execution remains a recorded failure and requires an independently
approved recovery plan; it must never be silently retried under a consumed approval.

## Rollback and recovery

Application rollback may select only a previously approved immutable image digest and requires a new
plan, fresh provider preview, approvals, witness, apply, and readback. Do not delete or roll back the
audit/control ledger. Database schema correction uses a separately reviewed forward migration.

Firewall, KMS, CloudTrail, IAM, and isolation rollback can enlarge access or destroy evidence, so
each is a new consequential change with its own exact plan and authorization. Loss of witness access
is a failed witness gate, not permission to self-witness.

## State labels

Report only the narrowest observed state:

- `LOCALLY_VERIFIED`: named local commands passed against identified artifacts.
- `HOSTED_CI_VERIFIED`: the protected provider run passed at the exact revision.
- `CLOUD_CONFIGURED`: provider configuration exists and was read back.
- `HUMAN_APPROVED`: both configured human approvals were verified.
- `THIRD_PARTY_WITNESSED`: the independent witness record was verified.
- `PROVIDER_ENFORCED`: an exact action and its post-action state were read back.
- `DEPLOYED`: the exact image/source is live and ready with end-to-end checks.
- `CREDENTIALS_REVOKED`: the exact credential/session action was read back.
- `NOT_DEPLOYED`: no exact live workload and complete production readback has been observed.

Do not infer a later state from an earlier one. Local tests do not establish clinical performance,
biological safety, regulatory compliance, security accreditation, human approval, or deployment.
