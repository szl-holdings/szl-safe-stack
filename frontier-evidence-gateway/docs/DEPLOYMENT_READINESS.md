# Deployment and readiness boundaries

Artifact version: 0.2.1.

The checked-in configuration is a reference build, not evidence that a deployment occurred. Each external boundary remains a separate, named proof layer.

The canonical integration surface remains `szl-holdings/a11oy` at audited revision `0505a41a5600c6d71ea3e2523bb6107c9fa5e18f`: `szl_llm_registry.py`, `szl_provider_http.py`, `szl_budget_router.py`, `cloudflare/a11oy-governed-inference-worker.mjs`, and its Dockerfile. This project adds evidence probes and receipts around that architecture. It is not a replacement router. Because the live audit found CI drift/failure in the canonical repository, deployment remains blocked pending an exact-head green run and subsequent provider readback.

| Layer | Current artifact behavior | Evidence required before claiming operational |
|---|---|---|
| Gateway | Local code and tests | Process identity, supervised runtime, authenticated readiness receipt |
| Ollama | Exact loopback adapter and fixed model | Live version/model inventory plus bounded evaluation receipts |
| OpenRouter | Disabled; exact HTTPS origin and per-call generation cap only | Operator-selected model, secret-manager injection, authenticated rate limiting, explicit idempotency/replay semantics, provider-side hard budget and kill switch, egress controls, evaluation receipt |
| Docker | Pinned Dockerfile and validated compose source | Image build digest, SBOM/scan, signature/attestation, runtime receipt |
| Tailscale | No automatic mutation | ACL/grant review, device identity, HTTPS Serve status, authenticated request receipt |
| Cloudflare | No automatic mutation | Named zone/account, AI Gateway creation, scoped token, route/WAF configuration, provider readback and logs |
| Model promotion | Unsupported | Independent evaluation, signed policy decision, human authorization and rollback plan |
| Clinical/biological use | Unsupported | Appropriate scientific evidence, ethics/regulatory review and accountable approval outside this software |

## Tailscale manual opt-in

Keep the gateway bound to loopback and authentication enabled. After reviewing the tailnet ACLs/grants and the device identity, a human operator may expose the loopback service to the tailnet with the current installed Tailscale CLI syntax. A typical recent command is:

```powershell
tailscale serve --bg --https=443 http://127.0.0.1:8787
tailscale serve status
```

CLI syntax is version-sensitive; inspect `tailscale serve --help` before running it. This repository does not execute the command. Tailscale identity supplements rather than replaces the gateway bearer token. Keep the token in a secret manager, never in the Serve command.

## Cloudflare boundary

Cloudflare AI Gateway is **BLOCKED/UNCONFIGURED** in this build. Do not repurpose an unrelated Worker, zone, or down tunnel as evidence of an AI Gateway. Before wiring it, create a named gateway in the intended account, issue a least-privilege token via the provider secret mechanism, restrict accepted providers/models and egress, configure redaction/retention, and capture API readback. The gateway code intentionally permits only direct exact-origin OpenRouter today; adding a Cloudflare route requires a new versioned origin policy and tests rather than an environment-string bypass.

## Paid-provider production blockers

This service deliberately has no in-process or distributed rate limiter, no idempotency/replay cache, and no independent external spend authority. A repeated canonical `request_id` can still cause another provider call and another receipt; it must not be treated as an idempotency guarantee. The generation cap only bounds tokens requested in one response. It does not bound requests per second, retries, total tokens, account charges, or another process using the same provider key.

Before any paid-provider production claim, place the service behind an authenticated rate limiter keyed to a stable principal, define and test an idempotency contract with durable replay storage, and enforce a hard provider-side or independent budget ceiling with metering readback, alerts, and an emergency disable path. Evidence for those controls must name the enforcing system and include configuration plus runtime readback. Until then paid-provider readiness is **BLOCKED**, even when `/health/ready` returns `READY` for the gateway-and-ledger scope.

## Verification commands

```powershell
python -m unittest discover -s tests -v
python -m frontier_gateway self-check
python -m frontier_gateway verify-ledger
```

Limits are enforced before provider calls: request body 64 KiB by default (maximum configurable 256 KiB), provider response 256 KiB by default (maximum configurable 1 MiB), timeout 10 seconds (maximum 30), generation cap 256 tokens by default (integer range 16 through 512, applied to both supported provider payloads), at most 32 evidence artifacts, and no caller-controlled prompt, provider origin, or model name.

## Local verification snapshot

On 2026-09-07, this source tree passed 25 standard-library unit tests and a provider-free self-check on Python 3.11.9. The one-block payload was generated twice with identical bytes and contains exactly one Python fence and 15 allowlisted files; its final digest and byte count are recorded alongside the generated artifact rather than self-referenced inside it. A fresh temporary extraction compiled the installer, installed and hash-verified every file, confirmed the exact existing-target refusal, passed the same 25 tests, passed a provider-free self-check, rendered Docker Compose with an ephemeral validation-only bearer value, and removed its temporary directory.

The pinned 0.2.1 container built locally with Dockerfile `RUN` networking disabled as manifest-list ID `sha256:8162aaa52e6c6d93497ab87e399fb0a97ba9c2dd7d9b81bd15203e77fe1259d8` (43,205,700 bytes). Its configured `gateway:gateway` identity resolves to UID/GID 999. A disposable run explicitly selected UID/GID 999, network mode `none`, a read-only root filesystem, all capabilities dropped, `no-new-privileges`, and a writable 16 MiB `/tmp` only; its provider-free self-check passed and the exact named container was removed. No matching container, volume, or network remained. No Ollama, OpenRouter, Cloudflare, or Tailscale request was made during this 0.2.1 verification.

One bounded call to the already-running loopback Ollama 0.33.2 service used the fixed `receiptagent:latest` model for the built-in `deployment-readiness-gap` case. The deterministic result remained `INSUFFICIENT_EVIDENCE`; deployment and model-promotion authorization remained `NOT_GRANTED`; and the model observation remained `UNVERIFIED_MODEL_OUTPUT`.

The resulting one-entry local SQLite chain verified under `szl.frontier.receipt_hash.v1`. Its canonical event contains only metadata and SHA-256 digests, carries `content_stored: false`, and has no prompt, response, content, or raw model-output field. The model text was observed only in process memory for validation and is not packaged. The local image is unsigned and was not registry-published, SBOM-verified, vulnerability-scanned, or independently attested. This snapshot is local evidence, not a deployment, a model evaluation, a quality claim, an independent witness, or a reusable authorization.
