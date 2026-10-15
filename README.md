# SZL Safe Stack

<!-- szl:header v1 -->
<!-- Native identity: szl-brand@4309f6fce89179331b0b3ed8c99494e76c5be256; Orbit v2 icon. -->
<p>
  <a href="https://github.com/szl-holdings">
    <img src="https://raw.githubusercontent.com/szl-holdings/szl-brand/4309f6fce89179331b0b3ed8c99494e76c5be256/kit/logos/orbit-v2/suite/szl-icon-32.svg" alt="SZL Holdings — Orbit v2" width="32" height="32" />
  </a>
</p>

**Control before action. Evidence after.**

[Product](https://a-11-oy.com) · [Proof](https://a11oy.net) · [GitHub organization](https://github.com/szl-holdings)
<!-- /szl:header -->

Python evidence services with local Docker orchestration and a common GitHub CI gate.

| Component | API | Persistence | Scope |
|---|---|---|---|
| [Safe QA](safe-qa-service/README.md) | Loopback `8080` | PostgreSQL, three migrations | Evidence intake and audit; production AWS control requires separate configuration and externally verified approvals |
| [Frontier Gateway](frontier-evidence-gateway/README.md) | Loopback `8787` | Separate SQLite receipt volume | Deterministic software-evidence classification; optional model observations in separately configured deployments |

The root Compose file connects Safe QA to PostgreSQL. The gateway uses its own
receipt ledger and authentication; it has no adapter that exports to the Safe QA
ledger. Both model providers and Safe QA production mode are disabled in this
local deployment. Separate bridge networks keep the gateway outside the
database network; published ports bind only to host loopback. Docker bridges
still allow outbound networking. The local stack does not install an outbound
firewall, and its configuration must not be treated as a cloud isolation policy.
Passing its tests does not establish AWS deployment or independent approval.

## Start locally

For a persistent Windows setup with encrypted local credentials and an optional
already-installed Ollama model, follow the
[self-hosted Windows runbook](docs/SELF_HOSTED_WINDOWS.md). This is a
single-operator local service; it does not substitute for independent cloud
approval. The manual procedure below works without the Windows launcher.

Requirements: Docker with Linux containers and Compose v2, plus Python 3.12 for
the token-generation commands. Run from this repository root in PowerShell:

```powershell
$safeQaToken = python -c 'import secrets; print(secrets.token_urlsafe(32))'
$safeQaDigest = $safeQaToken | python -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.read().strip().encode()).hexdigest())'
$env:SAFE_QA_AUTH_TOKEN_HASHES_JSON = @{
    $safeQaDigest = @{ subject = 'local-operator'; scopes = @('evaluate', 'audit:read') }
} | ConvertTo-Json -Compress
$env:SZL_GATEWAY_BEARER_TOKEN = python -c 'import secrets; print(secrets.token_urlsafe(32))'
docker compose config --quiet
docker compose up --build --wait --wait-timeout 180
```

The plaintext Safe QA token stays in `$safeQaToken`; its API container receives
only the digest. The gateway receives its separate token. Keep this shell open
for the verification commands and do not publish its environment or token values.
The database password is explicitly local-development-only; PostgreSQL has no
published host port. The API processes use read-only roots, dropped capabilities,
and persistent named volumes. Set `SAFE_QA_LOCAL_PORT` or `SZL_GATEWAY_LOCAL_PORT`
before starting if another local application uses either port, and use those
ports in the verification URLs below.

```powershell
$safeQaHeaders = @{ Authorization = "Bearer $safeQaToken" }
$gatewayHeaders = @{ Authorization = "Bearer $env:SZL_GATEWAY_BEARER_TOKEN" }
Invoke-RestMethod http://127.0.0.1:8080/health/ready
Invoke-RestMethod http://127.0.0.1:8080/api/v1/audit/verify -Headers $safeQaHeaders
Invoke-RestMethod http://127.0.0.1:8787/health/ready -Headers $gatewayHeaders
$case = @{
    schema_version = 'szl.frontier.evidence.request.v1'
    request_id = [guid]::NewGuid().ToString()
    case_id = 'deployment-readiness-gap'
    provider = 'none'
    domain = 'software_infrastructure'
} | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:8787/v1/evaluate -Method Post -Headers $gatewayHeaders -ContentType application/json -Body $case
docker compose ps
```

Gateway readiness checks its running API and complete receipt chain. Safe QA
readiness checks the PostgreSQL schema, audit chain and pending evidence exports.
The built-in case returns `INSUFFICIENT_EVIDENCE`, with deployment and model
promotion `NOT_GRANTED`. It appends a local receipt without calling a model.
The same readiness checks run as container health checks.

Stop with `docker compose down`; this preserves both evidence volumes. Do not
delete them to work around migration or integrity failures. Initialization SQL
runs only for a new PostgreSQL volume; existing installations must use the
[migration procedure](safe-qa-service/docs/MIGRATION_003.md).

## Verify the Python build

The root workflow `.github/workflows/ci.yml` runs as check `source-contract`.
It installs runtime, build and test dependencies with `--require-hashes`, builds
and tests the installed Safe QA wheel, runs the gateway and publication tests,
applies all migrations to disposable PostgreSQL, runs the real database tests,
builds both images and checks both APIs through the local Compose stack. It has
read-only repository permissions and receives no provider credentials.
Before installing application dependencies, a separately hash-locked `pip-audit`
environment scans the runtime, build, test, publication and auditor locks.
Vulnerabilities and audit errors fail the check; no advisory exemptions are used.
The scan queries the public vulnerability service and is point-in-time evidence,
not proof that an application or its operating system has no vulnerabilities.

To run the non-integration suites locally:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes --only-binary=:all: -r safe-qa-service/requirements.lock -r safe-qa-service/build-requirements.lock -r .github/test-requirements.lock
.\.venv\Scripts\python.exe -m pip install --no-deps --no-build-isolation ./safe-qa-service
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m ruff check safe-qa-service
.\.venv\Scripts\python.exe -m pytest safe-qa-service/tests -m 'not integration' -p no:cacheprovider -q
Push-Location frontier-evidence-gateway
..\.venv\Scripts\python.exe -m unittest discover -s tests -v
Pop-Location
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Database integration tests recreate tables. Run them only against a disposable
test database, never a service's evidence volume. CI supplies that database
separately from its disposable Compose smoke stack. On Unix, use `.venv/bin/python`.

## Release boundaries

GitHub is the source authority. A Hugging Face source mirror must bind the
immutable GitHub revision and complete allowed-file hashes after this revision's
`source-contract` check succeeds. Source publication alone does not start these
APIs or deploy AWS resources. A static source-status page is not API readiness.
With GitHub CLI access to the clean, signed current main revision, prepare its
verified archive and single-block Markdown/Python installer using
`python tools/publish_hf_source.py --output ../safe-stack-release` (the output
directory must be new). The publisher verifies the successful main-branch CI run
before packaging. Publishing also requires the documented Hugging Face SDK and
login, an existing private static `SZLHOLDINGS/szl-safe-stack` Space, `--publish`,
and `--expected-parent` set to the exact observed 40-character Space commit.
Install the publisher dependency closure in a separate Python 3.12 environment
with `python -m pip install --require-hashes --only-binary=:all: -r requirements-publish.lock`,
then run `python -m pip check` before invoking it. The
tool never creates a target, manufactures credentials, or retries an uncertain
write. Read the generated receipt to distinguish prepared source from observed
publication. The committed writer is the dispatch-only workflow
[`hf-space.yml`](.github/workflows/hf-space.yml): it runs the same publisher on
`main` with the hash-locked SDK and the per-asset lock
`hf-write/space/SZLHOLDINGS/szl-safe-stack`, takes the observed Space commit as
its `expected_parent` input, and needs the repository secrets `HF_TOKEN` and
`BRANCH_PROTECTION_READ_TOKEN` (Administration: read, for the branch-protection
check).

The [production runbook](safe-qa-service/docs/AWS_PRODUCTION_RUNBOOK.md) requires
actual AWS/EKS targets, organizational OIDC, separately controlled signing keys,
independently attributed human approvals, a witness account, production database
roles/TLS/backups, immutable images and provider readback. The supplied templates
still require these inputs. Two keys held by one operator do not prove two humans.

Ollama is an explicit local opt-in through the self-hosted runbook and
`compose.ollama.yaml`; the default root stack disables both model providers.
OpenRouter remains disabled in the local launcher. The gateway's
[provider boundary](frontier-evidence-gateway/docs/DEPLOYMENT_READINESS.md) explains
the fixed-origin adapter and missing production rate, replay and spending controls.
Cloudflare and Tailscale configuration is not changed by Compose or CI.
Clinical and biological claims remain unverified; this software grants no such approval.
