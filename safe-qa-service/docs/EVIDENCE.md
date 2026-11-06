# Evidence register

This register distinguishes observed execution from authored controls. The machine-readable local
record is `evidence/verification-report.json`; if that file and this summary diverge, preserve both
and refresh them from newly executed commands rather than rewriting history.

In the consolidated `szl-holdings/szl-safe-stack` repository, `evidence/` is ignored by Git
(`.gitignore`) and excluded from the source archive (`tools/publish_hf_source.py`), so that report
and the `evidence/implementation-manifest.sha256` cited below are not tracked here. The dated
observations in this register are preserved as text; they are not backed by files in this tree.

Evidence states:

- `OBSERVED_PASS`: the named command ran in this workspace and returned the recorded successful
  result.
- `OBSERVED_FAIL`: the named command ran and failed; the failure is retained.
- `IMPLEMENTED_NOT_EXECUTED`: source/configuration exists but the stated behavior was not observed in
  the target environment.
- `UNAVAILABLE`: an attempted check could not run in this environment.
- `NOT_PERFORMED`: no check was attempted.
- `NOT_RUN`: a current workflow or environment-specific check was not executed.
- `LOCAL_POSTGRES_INTEGRATION_VERIFIED`: both PostgreSQL integration tests passed against the named
  local Compose database; this is not hosted or production database evidence.
- `NOT_DEPLOYED`: no exact live workload and complete production readback has been observed.

Local engineering evidence is not clinical, biological, regulatory, security, human-approval,
third-party-witness, cloud-enforcement, credential-revocation, or deployment evidence.

## Preserved v0.1 observation -- 2026-08-09

| Check | Observed result | State |
|---|---|---|
| Ruff static analysis | all checks passed | OBSERVED_PASS |
| Pytest | 34 passed, 1 PostgreSQL test skipped | OBSERVED_PASS with explicit gap |
| Coverage | 97.49%, required minimum 90% | OBSERVED_PASS |
| Python compilation | package and tests compiled | OBSERVED_PASS |
| Dependency consistency | no broken requirements | OBSERVED_PASS |
| OpenAPI generation | 6 expected paths present | OBSERVED_PASS |
| Kubernetes YAML parse | 2 documents parsed | OBSERVED_PASS |
| Compose config parse | valid with a synthetic hash-only local principal | OBSERVED_PASS |
| Python wheel | built; digest recorded in the then-current verification report | OBSERVED_PASS |
| HTTP smoke | liveness 200; readiness 503 without ledger; v1 truth boundary retained | OBSERVED_PASS |
| PostgreSQL integration | no reachable test database at that observation | UNAVAILABLE |
| Container image build | Docker engine timed out at that observation | UNAVAILABLE |
| Hosted CI | workflow authored but no provider run observed | NOT_PERFORMED |

These results predate the v0.2 control-plane changes and must not be used as v0.2 verification.

The checked-in `evidence/implementation-manifest.sha256` is likewise a preserved, 23-entry v0.1-era
artifact. It omits v0.2 control-plane source, tests, deployments, and migrations. It is explicitly
historical and must not be used as a current source, build, approval, or deployment binding.

## Observed v0.2 local test run -- 2026-08-11

The following command was executed against the current top-level project:

```text
python -m pytest -m "not integration" --cov=safe_qa_service --cov-report=term --cov-fail-under=0 -q
```

Observed result: `115 passed, 2 deselected`; coverage reported `1858` statements, `318` missed, and
`83%` total. The two PostgreSQL integration tests were deliberately deselected and therefore were not
executed. No cloud-provider or container action was part of this command. Critical focused modules
included `aws_evidence` at 92%, `identity` at 95%, `approval_cli` at 96%, and
`production_settings` at 99%; these module figures do not replace the 83% repository-wide result.

The checked-in CI policy is `--cov-fail-under=80`, an evidence-backed floor below the observed 83%
that retains limited headroom for coverage rounding. This local command does not prove the full CI
job: CI also provisions PostgreSQL, applies all three migrations, runs integration tests, validates
Compose, and builds the container. A separate local PostgreSQL run is recorded below. No hosted CI
run was observed.

## Observed v0.2 local PostgreSQL integration -- 2026-08-11

The canonical full suite was run against the local Compose PostgreSQL 16.4 service at
`127.0.0.1:5432`, using the exact Compose database coordinates:

```powershell
$env:TEST_DATABASE_URL='postgresql://safeqa:local-development-only@127.0.0.1:5432/safeqa'
python -m pytest -q
```

Observed result: `117 passed in 3.30s`. Both integration tests executed and passed:

- the audit-ledger integration verified the PostgreSQL hash chain and append-only enforcement; and
- the control-plane integration verified plan issuance, atomic single-use consumption, replay
  rejection, and append-only control evidence.

State: `LOCAL_POSTGRES_INTEGRATION_VERIFIED`.

This establishes behavior only for the local Compose PostgreSQL 16.4 instance and the tested source.
It does not establish production TLS, least-privilege roles, backup/restore, point-in-time recovery,
hosted CI, managed-database configuration, or deployment.

## v0.2 evidence still required

| Surface | Required observed evidence |
|---|---|
| v1 compatibility | unit/API tests prove deny-only literals, schema rejection, and mandatory audit failure |
| OIDC | signature/issuer/audience/algorithm/time/principal/ACR/AMR/scope negative and positive tests |
| Approval verifier | distinct roles/humans/keys, denial/expiry/replay, KMS Verify, CloudTrail lookup, witness-account negative and positive tests |
| AWS/EKS provider | exact-target allowlist, provider-state drift, immutable image, isolation, key disable, role revocation, partial failure, and readback tests |
| PostgreSQL | LOCAL_POSTGRES_INTEGRATION_VERIFIED for migrations 001/002/003, hash chain, append-only controls, durable audit outbox, single-use claim, and replay rejection; production TLS/roles/backup/restore remain unverified |
| Packaging | dependency consistency, compilation, Ruff, coverage gate, wheel, manifest/archive digests |
| Container | image build, non-root/read-only smoke, health behavior, SBOM and vulnerability scan at exact digest |
| Kubernetes/Terraform | formatting/validation, no placeholders, server dry-run, admission results, exact live readback |
| Hosted CI | a protected run URL and conclusion at the exact commit with reviewed action/container digests; for `7ea4577` the run URL and conclusion were read back on 2026-11-06 (below), but no digest review is recorded; every later commit needs its own run, conclusion and digest review |

## Production evidence status

| Claim | State | What would change it |
|---|---|---|
| Hosted CI | OBSERVED_PASS for `7ea4577` only: GitHub readback of the run and its conclusion (2026-11-06, below); action/container digest review not recorded | protected provider run and exact-revision readback for each later revision |
| Overall production deployment | NOT_DEPLOYED | exact live workload and complete production readback |
| AWS infrastructure configured | NOT_PERFORMED | successful governed apply plus exact AWS readback |
| EKS workload deployed | NOT_DEPLOYED | immutable image rollout and ready/live identity readback |
| Network firewall installed/enforced | NOT_PERFORMED | firewall, logs, endpoints, routes, and symmetric traffic readback |
| Organizational OIDC enforced | NOT_PERFORMED | deployed issuer configuration and successful/failed authentication observations |
| Two independent humans approved | NOT_PERFORMED | two verified KMS/CloudTrail records plus identity-control evidence |
| Independent third party witnessed | NOT_PERFORMED | cross-account verified witness record and independently held receipt |
| Access key disabled | NOT_PERFORMED | exact provider request and `Inactive` readback |
| Role sessions revoked | NOT_PERFORMED | exact deny-policy provider request and readback |
| Clinical/biological/regulatory claim validated | NOT_PERFORMED | approved protocol, authority, data, result, and applicable determination |

The Kubernetes v2 template uses the application-recognized `SAFE_QA_PRODUCTION_MODE=true` and
`SAFE_QA_AUTH_MODE=oidc` names. This is source alignment only; no rendered admission, live OIDC
enforcement, or production deployment has been observed.

The source is not evidence of a Git commit, signature, pull request, protected check, or independent
review unless the package is placed in a repository and those provider records are independently
read back at the exact artifact identity.

## Observed v0.2 local release verification -- 2026-09-08

The following checks were executed against the current top-level project after the v0.1 wheel and
duplicate project were moved, byte-for-byte, to `quarantine/legacy-v0.1/`:

| Check | Observed result | State |
|---|---|---|
| Ruff | `All checks passed!` | OBSERVED_PASS |
| Non-integration suite | `137 passed, 2 deselected in 5.23s` | OBSERVED_PASS |
| PostgreSQL integration suite | `2 passed, 137 deselected in 8.90s` against disposable Compose PostgreSQL 16.4 | LOCAL_POSTGRES_INTEGRATION_VERIFIED |
| Current wheel | `dist/safe_qa_service-0.2.0-py3-none-any.whl`, 61,503 bytes, SHA-256 `6d49c037464b435c1a2e82b0480b010b6488e7c6f0d7d3fa5c288f41022d92ae` | OBSERVED_PASS |
| Container | `safe-qa-service:0.2.0-local-20260907`, 89,366,331 bytes, manifest-list digest `sha256:310d0a8723c999e610ce2a289ed9a7d567a3a2b4f4d7d083de55bfed2c293f54` | OBSERVED_PASS |
| Hardened container smoke | UID/GID `10001:10001`, no network, read-only root, all capabilities dropped, `no-new-privileges`, version 0.2.0 and migration 003 present | OBSERVED_PASS |
| Compose API smoke | liveness `200`, readiness `200`, valid synthetic v1 evaluation `202`; release, clinical, and biological verification literals all `false` | OBSERVED_PASS |
| Cleanup | disposable projects read back with zero containers, volumes, and networks after `down --volumes --remove-orphans` | OBSERVED_PASS |

The first post-integration readiness attempt exposed an order-dependent test defect: the ledger test
used `DROP TABLE audit_events CASCADE`, which also removed migration 003's expression index when that
test ran last. The integration test now reapplies migration 003 after recreating `audit_events` and
asserts the complete schema healthcheck. A repeat integration run passed, and readiness transitioned
from `503` to `200` while the background worker drained the deliberately pending control outbox.

These are local engineering observations only. No AWS API, EKS cluster, cloud database, CloudTrail
trail, KMS authority, human approver, third-party witness, production credential, hosted CI provider,
or production endpoint was called or changed. Production and approval states remain `NOT_DEPLOYED`
and `NOT_PERFORMED` as listed above.

## Final provider-outcome bookkeeping verification -- 2026-09-08

A regression reproduced a false zero unknown-outcome count when a provider mutation was followed by
a readback error and then the primary write for `PROVIDER_OUTCOME_UNKNOWN` failed. The in-process
unknown count now advances before that write. The existing durable `PROVIDER_ACTION_INTENT` remains
available, and a successfully written failure terminal retains `mutation_may_have_occurred=true`,
one unknown outcome, and no automatic rollback. The test injects both failures and verifies the
provider remains mutated, exactly one apply call occurred, and the intent and terminal were retained.

These results supersede the wheel, container, and non-integration results in the preceding table:

| Check | Observed result | State |
|---|---|---|
| Regression before correction | failed because the terminal unknown count was `0` instead of `1` | OBSERVED_FAIL |
| Regression after correction | `1 passed, 16 deselected in 0.04s` | OBSERVED_PASS |
| Ruff | `All checks passed!` | OBSERVED_PASS |
| Non-integration suite | `138 passed, 2 deselected in 2.14s` | OBSERVED_PASS |
| Current wheel | `dist/safe_qa_service-0.2.0-py3-none-any.whl`, 61,581 bytes, SHA-256 `08906b9074e2aa61164199cfcdee4b9137a93418467fb00d78b20ade242eb117` | OBSERVED_PASS |
| Container | `safe-qa-service:0.2.0-local-20260907`, 89,366,226 bytes, manifest-list digest `sha256:94b4666d47df76151625c2affb646d2688dc536466b731216b153faf10c734c0` | OBSERVED_PASS |
| Hardened container smoke | UID/GID `10001:10001`, no network, read-only root, all capabilities dropped, `no-new-privileges`, version 0.2.0 and `003_durable_evidence_outbox.sql` present | OBSERVED_PASS |
| Container source binding | installed `control_plane.py` SHA-256 `94f64a1e50b3d558933568d3c5035c4356bbc21dae3b8409804c332a75e7e52b` equals the current source file | OBSERVED_PASS |

The first local wheel attempt was refused because the virtual environment had setuptools 84.0.0
instead of the locked 75.9.1. Installing `build-requirements.lock` with hash verification corrected
that mismatch, and `python -m build --wheel --no-isolation` then succeeded. An initial container smoke
looked up an incorrect migration filename; the corrected check asserted the actual checked-in
`003_durable_evidence_outbox.sql` and passed.

PostgreSQL integration and Compose API smoke were not repeated for this final in-process bookkeeping
change. Their successful observations in the preceding section apply to the source before this
correction. No database schema, SQL persistence behavior, provider adapter, or deployment setting
changed in this correction, and no external provider was called.

## Observed hosted CI and local re-run -- 2026-11-06

Recorded by an automated audit session from GitHub REST readback and commands that session executed.
Source revision: `7ea4577a31fcbc27d774a64ca4e1bb5c2f01076a` on `main`.

| Check | Observed result | State |
|---|---|---|
| Branch protection readback | `GET /repos/szl-holdings/szl-safe-stack/branches/main` reported `protected: true` and required check `source-contract` from app `15368` (GitHub Actions), enforcement `everyone`; the full protection document needs Administration read and returned HTTP `403` to that session | OBSERVED_PASS (partial readback) |
| Hosted `source-contract` | [run 42212006464](https://github.com/szl-holdings/szl-safe-stack/actions/runs/42212006464), `push` of the revision above, attempt 1: job `source-contract` and every step `success` | OBSERVED_PASS |
| Local hash-locked install | CPython 3.13.18, Linux x86_64: runtime, build and test locks installed with `--require-hashes --only-binary=:all:`; `pip check` reported `No broken requirements found.` | OBSERVED_PASS |
| Local Ruff | `All checks passed!` | OBSERVED_PASS |
| Local full suite | migrations 001/002/003 applied to a disposable PostgreSQL 16.15 cluster (not a Compose volume), then `196 passed` with both PostgreSQL integration tests executed; total coverage `84.91%` against the `80%` floor | OBSERVED_PASS |
| Local pip-audit | the CI auditor lock in a separate CPython 3.12.13 environment reported `No known vulnerabilities found` for each of the six locks | OBSERVED_PASS (point in time) |
| Local container build and Compose API smoke | no Docker daemon was available in that environment | NOT_RUN |

For the two hosted rows, `OBSERVED_PASS` means a provider record read back through the GitHub API,
not a command run in this workspace. The hosted run is evidence for that exact revision only. That
session did not review the run's action and container digests against their upstream releases: the
workflow, Compose file and Dockerfiles pin them by commit SHA and `sha256` digest, but pinning is not
review, so that part of the Hosted CI requirement above remains open. The local results are engineering observations on one
machine. Neither establishes hosted evidence for a later commit, a deployed workload, AWS
enforcement, human approval, witnessing, or any clinical or biological claim; the production states
listed above are otherwise unchanged.
