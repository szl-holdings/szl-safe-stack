# Source consolidation and evidence boundaries

This repository consolidates the user's existing Safe QA and Frontier Evidence
Gateway implementations. It does not supply any private model implementation,
backdoor, credential, jailbreak, biological evidence, or clinical approval.

The starting components were the verified allowlisted source distribution of
Safe QA 0.2.0 and Frontier Evidence Gateway 0.2.1. Safe QA was then reconciled to
the user's September 12, 2026 x20 source at version 0.2.1: request parsing,
synthetic QA, version references, and tests. The prior source directories were
left intact. No private configuration, token, provider identity, or private
evidence directory was copied.

The synthetic kernel is a bounded deterministic software exercise. An
independent rational-arithmetic test oracle checks its results; these tests do
not establish model quality, clinical validity, or authorization. Its responses
retain `simulation_only=true`, `evidence_verified=false`, and
`release_authorized=false`.

Repository integration adds the root CI workflow, hash-locked test dependencies,
local Compose wiring, lifecycle regression tests, and a private Hugging Face
source-distribution publisher. The publisher verifies a signed current GitHub
main revision and its exact successful CI before generating a release. It binds
one write to an explicitly observed Hub parent and verifies every published byte
at the resulting immutable revision. It does not launch a hosted API.

There are separate evidence layers: source and unit tests; database integration;
container/API behavior; hosted exact-revision CI; GitHub protection; Hugging Face
publication; cloud provider enforcement; and independent human/witness approval.
No layer is a substitute for a later one. CI fixtures and local development
tokens are not production identities. The root Compose networks do not install
a host firewall or change any existing Tailscale or Cloudflare configuration.

The production templates are configuration inputs, not a deployable assertion.
Follow the service production runbook to select real targets, establish named
identity boundaries, review plans, produce signatures and witness evidence,
and verify provider readback. Clinical and biological claims remain unverified
unless separately established by the appropriate evidence and authority.
