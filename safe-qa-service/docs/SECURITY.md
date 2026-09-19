# Security and trust boundaries

## Protected assets

- evidence metadata, claim text, and v1 audit ordering
- OIDC identity, scopes, groups, authentication context, and token identifiers
- exact plan nonces/digests and provider before/after state
- approval, KMS verification, CloudTrail, witness, and execution receipts
- PostgreSQL, AWS, Kubernetes, container-registry, and signing credentials

Never place tokens, passwords, private keys, secret access-key values, recovery codes, or plaintext
KMS signing material in a plan, approval bundle, ledger payload, log, or support conversation.

## Enforced application controls

- v1 release, clinical, and biological authorization fields are literal false schema values;
- unknown fields are rejected, including caller-injected approval fields;
- local static-token configuration stores SHA-256 digests and compares them in constant time;
- production mode requires exact OIDC/JWKS trust, registered claims, approved asymmetric algorithms,
  maximum token lifetime, principal type, scopes/groups, and configured ACR/AMR;
- human planning and workload execution are distinct identity boundaries;
- v2 plan preview reads allowlisted exact targets and binds canonical provider state without mutation;
- two fixed, non-interchangeable approval roles require distinct Identity Center users and distinct
  configured asymmetric KMS keys;
- the witness requires a third distinct human, key, and independently administered AWS account;
- the runtime verifies detached digests with KMS and independently looks up matching CloudTrail
  `Sign` events with `onBehalfOf` Identity Center attribution;
- no runtime signing operation exists; production IAM must also explicitly deny `kms:Sign`;
- plans are expiring and one-use, and provider state is rechecked immediately before mutation;
- AWS/EKS actions require exact account/Region/cluster/namespace/resource allowlists;
- each successful provider action requires exact post-action readback and receipt IDs;
- v1 ledger writes are serialized and hash chained, and database triggers reject update/delete;
- v2 plans, execution claims, and action events are append-only and reject update/delete/truncate;
- a mandatory ledger/repository failure prevents a successful API response; and
- container/Kubernetes references use non-root execution, read-only filesystems, dropped Linux
  capabilities, workload identity, narrow RBAC, default-deny network policy, and immutable images.

## Security invariants outside the application

The source cannot prove these properties. Production owners must configure and read them back:

- one human cannot assume both approval roles or administer every Identity Center account/key;
- the witness account and evidence store are independently administered;
- KMS key policies grant each `Sign` permission only to its named human role and prevent runtime Sign;
- CloudTrail management events, log-file validation, retention, encryption, and delivery are healthy;
- AWS Network Firewall routes are symmetric and fail according to the reviewed availability design;
- EKS VPC CNI supports network policy and uses strict startup enforcement;
- no additive Kubernetes `NetworkPolicy`, admission exception, IAM policy, route, or security group
  silently widens the reviewed policy;
- PostgreSQL uses certificate-verified TLS, separated roles, restricted schema ownership, backups,
  restore tests, and independent checkpoints; and
- deployed source, image, configuration, database schema, and evidence all identify the same release.

## Known residual risks and gaps

- SHA-256 token digests are suitable only for high-entropy development machine tokens, not human
  passwords. Static auth is not a production mode.
- A configured OIDC issuer remains dependent on the identity provider, group governance, key
  rotation, account recovery, and token-revocation processes.
- CloudTrail `onBehalfOf` attribution is evidence about the provider event, not proof that the named
  person alone controlled the human account at that moment.
- Hash chaining detects many mutations but a database owner could rewrite a complete chain or disable
  controls. Export signed checkpoints to independently administered immutable storage.
- Emergency isolation may disrupt evidence export, identity, DNS, or database access. Preview exact
  state and use a separately reviewed break-glass/recovery design; do not add a hidden bypass.
- IAM access-key disablement and role-session revocation are destructive operational actions. Exact
  target authorization and post-action readback are mandatory.
- The ledger may contain request payloads. Complete classification, minimization, retention,
  legal-hold/deletion-exception, and privacy review before accepting real evidence.
- The GitHub workflow currently uses major-version action tags and the PostgreSQL container uses a
  version tag rather than verified immutable action/container digests. Pin reviewed commit and image
  digests before protected release; no SHA is invented in this repository.
- The Kubernetes v2 template uses the recognized `SAFE_QA_PRODUCTION_MODE=true` and
  `SAFE_QA_AUTH_MODE=oidc` settings. The template remains `NOT_DEPLOYED`; render/admission/live
  readback, OIDC negative tests, and exact runtime configuration are still required.
- No production penetration test, SBOM attestation, vulnerability waiver, independent code review,
  hosted CI result, cloud apply, or production provider readback is claimed by documentation.

Report suspected vulnerabilities through the organization's private security channel. Do not put
secrets, exploit payloads, live target identifiers, or customer evidence in a public issue.
