# Approval and witness requirements

No approval or witness has been granted by this repository, Codex, a test, or a generated JSON
file. Files under `approvals/` are intentionally inert request/templates: they contain no real
identity, decision, KMS key, signature, provider request ID, or CloudTrail event.

Current authorization state: `NOT_APPROVED`. Current deployment state: `NOT_DEPLOYED`.

## Production control quorum

A v2 provider execution requires all of the following over one exact, unexpired plan:

1. A detached `APPROVE` statement from the configured `security_owner`.
2. A detached `APPROVE` statement from the configured `release_owner`.
3. A detached witness statement from the configured cross-account witness.

The two approvers must be different IAM Identity Center user IDs, use different asymmetric KMS
`SIGN_VERIFY` keys, and occupy non-interchangeable configured roles. The witness must be a third
distinct Identity Center human, use the configured witness key, and operate in an account distinct
from the production account and the approvers' accounts. Distinct key bytes alone do not establish
independent humans.

Every signed statement binds the plan ID, canonical plan digest, one-use nonce, exact source
revision, immutable container digest, evidence-manifest digest, policy-bundle digest,
provider-state digest, environment, requested provider actions, and expiry through the plan digest.
The witness additionally binds both complete approval-record digests.

The runtime accepts no submitted assertion at face value. It must:

- verify each detached digest signature with AWS KMS `Verify`;
- independently retrieve the corresponding KMS `Sign` management event from CloudTrail;
- match the KMS key ARN, signing algorithm, message type, request ID, account, Region, configured
  principal ARN, Identity Store ARN, and `onBehalfOf` user ID;
- reject a denial, expired record, missing or ambiguous event, reused plan, duplicated identity,
  wrong key, wrong account, changed provider state, or incomplete durable record; and
- keep the runtime unable to call KMS `Sign`.

CloudTrail lookup and a KMS verification response prove only the observed provider records. The
organization must still establish that the named Identity Center accounts are individually
controlled and that the witness account is independently administered.

## Broader approval matrix

| Gate | Required evidence | Authorized authority | Current state |
|---|---|---|---|
| Independent code review | exact revision, diff, tests, open findings | reviewer independent of author | NOT PROVIDED |
| Security architecture | threat model, OIDC/KMS/IAM design, penetration results, remediation | security authority | NOT PROVIDED |
| Privacy/data governance | inventory, classification, minimization, retention, jurisdiction | privacy/data owner | NOT PROVIDED |
| Database operations | migrations, least privilege, backup, restore, RPO/RTO | database/service operations owner | NOT PROVIDED |
| Software supply chain | lock review, SBOM, scans, signed provenance, immutable image digest | release/security owner | NOT PROVIDED |
| Network/firewall change | reviewed routes, symmetry proof, rules, logs, rollback | network authority | NOT PROVIDED |
| Identity and KMS bootstrap | named humans, Identity Center ownership, key policies, CloudTrail | identity/security authority | NOT PROVIDED |
| Operational readiness | SLOs, monitoring, alerts, on-call, load/failure/DR tests | service operations owner | NOT PROVIDED |
| Clinical validation | approved protocol, representative data, statistics, limitations | clinical validation authority | NOT PROVIDED |
| Regulatory/quality | intended-use classification and applicable determination | regulatory/quality authority | NOT PROVIDED |
| Biological/biosafety | risk, containment, dual-use, institutional requirements | institutional biosafety authority | NOT PROVIDED |
| Production execution | exact v2 plan, two valid approvals, witness, protected change path | configured release path | BLOCKED |

The exact legal and regulatory requirements depend on intended use, organization, and jurisdiction.
This table is an engineering gate list, not legal, medical, regulatory, or biosafety advice.

## Bootstrap boundary

KMS keys, CloudTrail trails, Identity Center assignments, and the witness account cannot approve
their own creation. Bootstrap must use an existing independently governed change system, named
owners, reviewed infrastructure plan, and preserved provider readback. Only later changes may rely
on the resulting KMS/CloudTrail approval path.

Self-approval, one process holding every signing permission, shared human accounts, HMAC secrets,
signatures created by the runtime, and caller-populated identity fields are not acceptable
multi-person evidence.
