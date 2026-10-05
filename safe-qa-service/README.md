# Safe QA Service

Safe QA Service 0.2 is production-oriented, fail-closed evidence and AWS/EKS control software.
Version 1 remains permanently deny-only. Version 2 can preview exact provider changes and, only
after externally created authorization evidence is verified, execute a bounded set of allowlisted
AWS/EKS actions. The live v2 provider boundary is disabled unless
`SAFE_QA_PRODUCTION_MODE=true`; this wording describes the architecture, not observed production
readiness or deployment.

This repository does not verify a clinical or biological claim and does not authorize a release by
itself. No AWS account, EKS cluster, firewall route, IAM credential, human approval, independent
witness, or production deployment is evidenced merely because the implementation or Terraform is
present.

Current production state: `NOT_DEPLOYED`.

## Truth boundary

The `/api/v1` contract is unchanged:

- all caller evidence is `unverified_caller_supplied`;
- `release_authorized`, `clinical_claim_verified`, and `biological_claim_verified` remain literal
  `false` values;
- caller-supplied decisions and approvals are ignored;
- an audit-ledger failure returns HTTP `503` before a decision envelope is returned; and
- no v2 approval can turn a v1 evidence response into a clinical, biological, or release decision.

The `/api/v2` control path separates preview from execution:

1. A human OIDC principal with `control:plan` requests an unsigned plan.
2. The service reads the exact allowlisted provider targets and binds their state digest into the
   plan. This endpoint performs no provider mutation.
3. A security owner and a release owner, authenticated as two distinct AWS IAM Identity Center
   humans, independently create detached asymmetric KMS signatures over the exact plan digest.
4. A distinct human in an independently administered witness account signs a witness statement
   over both complete approval-record digests.
5. A workload OIDC principal with `control:execute` submits the bundle. The runtime calls KMS
   `Verify`, independently looks up each KMS `Sign` event in CloudTrail, atomically consumes the
   one-use plan, rechecks provider state, performs only the exact actions, reads the result back, and
   records append-only receipts.

The API has no KMS signing command. Production runtime permissions must allow verification and
evidence lookup while denying signing.

## Implemented components

- FastAPI v1 evidence intake and v2 production-control endpoints
- strict Pydantic v1 and v2 schemas with unknown fields rejected
- local static high-entropy bearer authentication and production OIDC/JWKS authentication
- deterministic v1 fail-closed policy engine
- serialized, hash-chained PostgreSQL audit ledger
- append-only PostgreSQL v2 plans, execution claims, and action-event records
- KMS `Verify` plus independent CloudTrail lookup and Identity Center attribution checks
- exact-target AWS/EKS provider adapters for:
  - immutable EKS image deployment by `sha256` digest;
  - EKS namespace isolation with a named default-deny `NetworkPolicy`;
  - IAM access-key disablement without reading or storing secret material; and
  - IAM role-session revocation using the named `AWSRevokeOlderSessions` policy;
- AWS Network Firewall, EKS VPC CNI strict network-policy, KMS, IAM, CloudTrail, Kubernetes,
  container, CI, and readiness reference configuration; and
- unit, API, approval-verification, provider-control, and PostgreSQL integration tests.

“Implemented” is a source statement, not proof that a hosted CI run, cloud apply, approval,
witness, mutation, or deployment occurred. See [the evidence register](docs/EVIDENCE.md).

## Local verification

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\pytest.exe -m "not integration" --cov=safe_qa_service --cov-report=term-missing
```

PostgreSQL integration tests **drop and recreate audit and control tables**. Run them
only against a separately provisioned disposable test database containing no evidence to
retain. Never point `TEST_DATABASE_URL` at the normal Compose database, a service's
evidence volume, or a production database.

Initialize all three migrations in that disposable database, explicitly set
`TEST_DATABASE_URL` to its connection URL, and verify the target before running
`.\.venv\Scripts\pytest.exe -m integration`. The isolated PostgreSQL service and migration
setup in the [root CI workflow](../.github/workflows/ci.yml) provide the reference.
If a disposable database is unavailable, run only the non-integration suite above.

For the local service, Compose mounts `001_audit_ledger.sql`, `002_control_plane.sql`, and
`003_durable_evidence_outbox.sql` into a new local PostgreSQL volume.
Migration `003` adds durable, retryable secondary-ledger export state; it does not replace the
primary append-only control-event receipts created by migration `002`.
PostgreSQL only runs initialization scripts when its data directory is empty. If an older local
volume already exists, apply migrations `002` and `003` in order through a reviewed migration
process; do not delete a volume that contains evidence.
The exact upgrade contract, verification queries, and forward-only recovery rules are documented in
[`docs/MIGRATION_003.md`](docs/MIGRATION_003.md).

For local v1 testing, configure only the SHA-256 digest of a randomly generated token:

```powershell
$token = [guid]::NewGuid().ToString('N')
$hash = ($token | python -c "import hashlib,sys; print(hashlib.sha256(sys.stdin.read().strip().encode()).hexdigest())")
$env:SAFE_QA_AUTH_TOKEN_HASHES_JSON = '{"' + $hash + '":{"subject":"local-operator","scopes":["evaluate","audit:read"]}}'
docker compose up --build
```

The plaintext token remains in the local shell. Static authentication and the Compose password are
development-only. Production mode requires exact OIDC issuer configuration and all AWS target,
approval, witness, and evidence routes; an incomplete boundary fails with `503`.

The application reads these production configuration names exactly:

- `SAFE_QA_PRODUCTION_MODE=true`
- `SAFE_QA_AUTH_MODE=oidc`
- `SAFE_QA_OIDC_ISSUERS_JSON`
- `SAFE_QA_AWS_TARGET_POLICY_JSON`
- `SAFE_QA_APPROVAL_POLICY_JSON`
- `SAFE_QA_AWS_EVIDENCE_ROUTES_JSON`
- `DATABASE_URL`, with `sslmode=verify-full` and an explicit `sslrootcert`

`AWS_REGION` configures the SDK environment, but it does not replace the exact account/Region values
inside the target policy and evidence-route records. `SAFE_QA_ENVIRONMENT` is not an application
production-mode switch. The v2 Kubernetes template now uses the recognized
`SAFE_QA_PRODUCTION_MODE=true` setting, but that authored value is still `NOT_DEPLOYED` until the
rendered manifest is admitted and read back in the exact target cluster.

## API surface

- `GET /health/live`
- `GET /health/ready`
- `GET /api/v1/schemas/evaluation-request`
- `GET /api/v1/schemas/evaluation-response`
- `POST /api/v1/evaluations` — scope `evaluate`
- `GET /api/v1/audit/verify` — scope `audit:read`
- `GET /api/v2/schemas/deployment-plan`
- `GET /api/v2/schemas/approval-bundle`
- `POST /api/v2/control/plans` — human OIDC principal, scope `control:plan`, read-only preview
- `POST /api/v2/control/executions` — workload OIDC principal, scope `control:execute`, exact
  detached approvals and witness required

Read [approval requirements](docs/APPROVALS.md), [security boundaries](docs/SECURITY.md), and the
[deployment-readiness gates](docs/DEPLOYMENT_READINESS.md) before considering any non-local use.
