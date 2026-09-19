# SZL Frontier Evidence Gateway

Version 0.2.1.

This is a local-first evidence classifier for **software infrastructure only**. It gives deterministic evidence-gap results, can optionally ask a fixed local Ollama model or an explicitly enabled OpenRouter model for an unverified observation, and appends content-minimized receipts to a SQLite SHA-256 hash chain.

It complements the canonical `szl-holdings/a11oy` governed-inference integration at audited revision `0505a41a5600c6d71ea3e2523bb6107c9fa5e18f`. That repository already contains the Ollama/OpenRouter registry, sovereign Tailscale mesh, bounded provider HTTP transport, budget router, Cloudflare worker, and container integration. This gateway is only a local evidence/readiness wrapper; it does not replace or silently route around `a11oy`. The audited `a11oy` CI is currently failing, so no deployment claim follows from either codebase.

It does not promote models, deploy workloads, administer Cloudflare or Tailscale, revoke credentials, make clinical or biological decisions, or turn a model response into approval. Provider output is always `UNVERIFIED_MODEL_OUTPUT`. `READY` means only that the gateway and complete local receipt chain passed their checks.

## Run locally

Python 3.11 or newer is sufficient; there are no third-party Python dependencies.

PowerShell:

```powershell
$env:SZL_GATEWAY_BEARER_TOKEN = ([guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N'))
$env:SZL_OLLAMA_MODEL = 'szl-nemo:latest'
python -m unittest discover -s tests -v
python -m frontier_gateway self-check
python -m frontier_gateway evaluate-case deployment-readiness-gap --provider ollama
python -m frontier_gateway serve
```

The default provider origin is the exact loopback URL `http://127.0.0.1:11434`. The API defaults to `127.0.0.1:8787` and refuses to start without a bearer token containing 32 to 512 bearer-safe ASCII characters. It stores its ledger at `var/frontier-receipts.sqlite3` and does not store prompt or response content in receipts. Receipts contain only bounded identifiers, classifications, provider/model labels, outcome flags, and SHA-256 digests of the evidence inventory, generated model input, and model output. Every provider call carries the same operator-controlled generation cap: `SZL_MAX_GENERATION_TOKENS` defaults to 256, accepts only integers from 16 through 512, maps to Ollama `options.num_predict`, and maps to OpenRouter `max_tokens`.

An authenticated request can be sent from another PowerShell window:

```powershell
$headers = @{ Authorization = "Bearer $env:SZL_GATEWAY_BEARER_TOKEN" }
Invoke-RestMethod http://127.0.0.1:8787/health/ready -Headers $headers
$body = @{
  schema_version = 'szl.frontier.evidence.request.v1'
  request_id = [guid]::NewGuid().ToString()
  case_id = 'deployment-readiness-gap'
  provider = 'ollama'
  domain = 'software_infrastructure'
} | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:8787/v1/evaluate -Method Post -Headers $headers -ContentType application/json -Body $body
```

## OpenRouter opt-in

OpenRouter is disabled by default. The origin is pinned to `https://openrouter.ai`, redirects are refused, the model is fixed by the operator, and the key is read only from the environment:

```powershell
$env:SZL_ENABLE_OPENROUTER = 'true'
$env:SZL_OPENROUTER_MODEL = 'provider/model-approved-by-operator'
```

Inject `OPENROUTER_API_KEY` through an OS or deployment secret manager; do not put credentials in command history, source, compose files, or URLs.

OpenRouter remains a development-only opt-in in this version. The per-call generation cap limits response tokens, not request frequency or cumulative spend. Production use is blocked until a named external control plane enforces all of the following:

- authenticated per-principal and global rate limits before requests reach this process;
- explicit idempotency/replay behavior so retrying the same operation cannot silently create another billable provider call (the current `request_id` is an audit label, not an idempotency key);
- a provider-side hard budget or prepaid ceiling, metering readback, alerts, and a tested kill switch independent of this process.

The bearer token, local SQLite ledger, provider timeout, and generation cap do not provide those controls. `READY` therefore does not authorize paid-provider traffic.

## Container boundary

The Dockerfile is pinned to the same immutable Python 3.12.14 slim digest used by the Safe QA service. The root stack pins PostgreSQL 16.15 as well. These current source pins supersede the base versions in historical local verification snapshots. Validate the component compose model without pulling or starting anything:

```powershell
$env:SZL_GATEWAY_BEARER_TOKEN = 'replace-with-a-secret-containing-at-least-32-bytes'
docker compose config --quiet
```

`compose.yaml` maps only host loopback. It uses `host.docker.internal` for Ollama, but a host Ollama process listening only on `127.0.0.1` is normally unreachable from a Docker Desktop VM/container. In that state provider requests fail closed. Do not expose Ollama broadly just to make this route work; use a reviewed authenticated local proxy or another explicitly isolated networking design.

See [docs/DEPLOYMENT_READINESS.md](docs/DEPLOYMENT_READINESS.md) before enabling Tailscale, Cloudflare, OpenRouter, or any non-loopback bind.

## Version 0.2.1 security baseline

- The receipt hash covers the sequence, event ID, timestamp, previous hash, and canonical event. Databases from the earlier unbound format are recognized but fail closed rather than being silently extended.
- HTTP requests reject transfer encoding, missing or duplicate `Content-Length`, duplicate authorization/content-type headers, oversized bodies, incomplete bodies, and GET bodies.
- Provider HTTP disables inherited proxy settings, refuses redirects, pins provider origins, bounds response size and timeout, and returns sanitized transport failures.
- Every Ollama and OpenRouter request includes a validated 16-to-512 generation-token cap (256 by default). This is a per-call output bound, not a rate limiter or external spend budget.
- Built-in cases are explicitly unverified fixtures. A `VERIFIED` caller artifact requires a real SHA-256 digest, but remains caller-declared metadata and is never treated as independent approval.
- The one-block installer validates a deterministically compressed archive against an explicit allowlist and per-file SHA-256 manifest, refuses to overwrite an existing target or traverse link/reparse-point paths, and creates files without overwriting. It is not an isolation boundary against a hostile same-user process racing the installation.

These controls make the gateway fail closed; they do not make its SQLite chain independently witnessed or tamper-proof against an administrator. Production witnessing requires an append-only external sink, signed checkpoints, or another named independent verifier.
