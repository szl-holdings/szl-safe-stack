# Security policy

`szl-holdings/szl-safe-stack` follows the
[SZL Holdings organization security policy](https://github.com/szl-holdings/.github/blob/main/SECURITY.md).
That policy names the private reporting address, the disclosure timeline and
the good-faith research terms. This file records what is specific to this
repository.

## Report a vulnerability privately

Send reports to the reporting address in the organization policy. This
repository is private, so GitHub private vulnerability reporting and
repository security advisories are not available for it. Do not describe an
unfixed vulnerability in an issue, discussion, pull request or commit message.

Include, when available:

- the commit SHA you tested, or the `source_revision` recorded in a source
  distribution's `source-manifest.json`;
- the affected component, entrypoint, endpoint or workflow;
- minimal reproduction steps using synthetic data, with the observed and
  expected result.

Never include tokens, passwords, private keys, live target identifiers,
customer evidence or real ledger contents. Revoke or rotate an exposed
credential through its provider before sending a redacted report.

## Supported versions

Only the current `main` branch is supported. The repository has no tags or
GitHub releases, and neither component is published to a package index: the
`safe-qa-service` and `szl-frontier-evidence-gateway` project files carry the
`Private :: Do Not Upload` classifier, which PyPI rejects. A private Hugging
Face source distribution is a snapshot of the single `main` revision recorded
in its `source-manifest.json`; compare that revision with current `main`
before reporting.

## Scope

- Safe QA API, approval verification and PostgreSQL migrations
  (`safe-qa-service/`).
- Frontier Evidence Gateway and its SQLite receipt ledger
  (`frontier-evidence-gateway/`).
- The root Compose stack, both container definitions and the Windows launcher
  (`compose.yaml`, `compose.ollama.yaml`, `tools/local_stack.py`).
- CI workflows and hash-locked dependency files (`.github/`,
  `requirements-publish.lock`).
- The private Hugging Face source publisher (`tools/publish_hf_source.py`,
  `.github/workflows/hf-space.yml`).

The AWS and Kubernetes files under `safe-qa-service/deploy/` are reference
templates that the repository records as `NOT_DEPLOYED`
([deployment readiness](safe-qa-service/docs/DEPLOYMENT_READINESS.md)); they
are in scope as infrastructure-as-code. Report vulnerabilities in third-party
dependencies to their maintainers. CI's hash-locked `pip-audit` step fails on
known advisories in every committed lock; that is point-in-time evidence only.

The organization policy's notes on Iron Bank and UBI9 base images and on DSSE
receipts describe other SZL components. This repository's container images use
the digest-pinned `python` slim base named in each Dockerfile, and its Safe QA
audit ledger and gateway receipt ledger are SHA-256 hash chains; it produces no
DSSE envelopes.

## Trust boundaries and known gaps

[safe-qa-service/docs/SECURITY.md](safe-qa-service/docs/SECURITY.md) lists the
protected assets, enforced application controls, invariants outside the
application and known residual risks. The gateway's provider boundary is in
[frontier-evidence-gateway/docs/DEPLOYMENT_READINESS.md](frontier-evidence-gateway/docs/DEPLOYMENT_READINESS.md).
This policy is a reporting channel. It is not evidence of a security review,
penetration test, certification or production deployment.
