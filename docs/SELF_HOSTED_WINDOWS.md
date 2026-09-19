# Self-hosted Windows operation

This mode runs real authenticated APIs and persistent ledgers on Docker Desktop.
It does not depend on AWS or on a paid inference service. It is a single-operator,
loopback-only service, not multi-person production authorization. Existing cloud
and human-identity policy checks are not bypassed or marked approved.

Prerequisites: a clean committed copy of this repository, Windows Python 3.12,
Git, Docker Desktop's `desktop-linux` context, and free loopback ports 18081 and
18787. For local inference, Ollama must already contain `a11oy-mini-r2:latest`.
The launcher neither downloads nor trains a model. Linux operators can use the
manual, portable Compose procedure in the root README instead.

The single-file source payload intentionally contains no Git history. Use its
manual Compose procedure, or clone the canonical private repository with your
own GitHub authorization before using this source-bound launcher:

```powershell
gh repo clone szl-holdings/szl-safe-stack
Set-Location szl-safe-stack
```

From the repository root:

```powershell
py -3.12 -I -B tools/local_stack.py init --ollama
py -3.12 -I -B tools/local_stack.py up
py -3.12 -I -B tools/local_stack.py verify
py -3.12 -I -B tools/local_stack.py status
```

Omit `--ollama` at initialization to run both deterministic services without any
model. Initialization creates two random service credentials and encrypts them
with Windows CurrentUser DPAPI in `private/local-runtime.dpapi`. No plaintext
credential is printed or passed on a command line. Safe QA receives only its
token digest. The gateway receives its separate token inside the local container.
Local Docker administrators can inspect container environments; DPAPI does not
protect against compromise of the signed-in Windows account or Docker daemon.

The launcher pins a dedicated Compose project, the two loopback ports, the
committed source revision, and the observed installed model digest. It ignores
ambient Compose files, Docker host overrides, and default `.env` files. The
optional Ollama override permits only the gateway's fixed Docker host origin;
OpenRouter remains disabled. Bridge networks are not an egress firewall. This
mode does not open Tailscale, Cloudflare, host firewall, or public internet routes.

Verification checks unauthorized requests are rejected, an authenticated Safe QA
request is appended to PostgreSQL, both receipt chains remain ready, and the
gateway grants neither deployment nor model promotion. If Ollama is enabled it
makes a real bounded inference call and verifies the model digest before and
after. Model text remains `UNVERIFIED_MODEL_OUTPUT`, not evidence or approval.
Each verification writes a new local JSON receipt in `private/`; it is a local
observation, not an independent attestation.

Stopping preserves data:

```powershell
py -3.12 -I -B tools/local_stack.py down
```

Do not delete an identity file or database volume to make a failed integrity check
pass. Back up PostgreSQL and the receipt volume using a tested backup/restore
procedure before upgrading. A source change is intentionally not auto-admitted:
the launcher rejects a different or dirty checkout until a reviewed migration
and identity-state transition are performed. This initial launcher does not
automate upgrades, independent key recovery, or unattended Windows login/startup.

The local database password is development-only and its port is not published.
Do not expose this mode as a multi-user internet service. Production publication
requires organizational authentication, TLS, least-privilege database roles,
rate/spending controls, backups, runtime/source attestation, and the actual
approval/witness boundaries documented by the production runbook.
