# Local readiness snapshot contract

This change repairs local receipt-ledger verification. It does not authorize deployment, model promotion, cloud changes or credential operations.

## Verification and continuity

A full verification executes within one SQLite read transaction. Append acquires `BEGIN IMMEDIATE` before verification and writes its new receipt within that same transaction. The process retains the last accepted sequence/hash as a continuity anchor: subsequent audits must include that anchor. Silent replacement by another valid chain or truncation below the anchor is rejected. The anchor is process-local and is not an independently signed checkpoint.

Every attempted full verification first invalidates the readiness cache. A failed full or cached verification cannot preserve the previous successful cached state. Read operations use SQLite URI `mode=ro`; a missing database is not recreated. Appends invalidate the read cache after committing rather than labeling an arbitrary post-commit storage observation as verified.

## Bounded cache

A proof may be reused for at most 30 monotonic seconds and only when local main-database/WAL identity, size and modification/change timestamps agree with the audited snapshot. A zero-byte WAL is normalized to absence because it contains no committed frames and SQLite readers may create it as bookkeeping. Nonempty WALs remain part of the change signal. Shared-memory bookkeeping is not an integrity signal.

The stable path uses an indexed tail lookup, validates the complete tail envelope, and checks its predecessor and cached head. It does not issue `COUNT(*)`. A changed storage stamp, expired age or backward clock observation requires a fresh full audit. This is not an unconditional O(1) claim: fallback and append verification remain O(n).

The verification-v2 response fields remain unchanged. `VERIFIED` refers to the local audited snapshot under these assumptions; it is not a claim of independently witnessed storage or instantaneous global integrity.

## Threat boundary and remaining release gates

Filesystem metadata is a change detector, not cryptographic evidence. An administrator capable of rewriting bytes, forging metadata, replacing process state or restarting the service is outside this local trust boundary. Independently verifiable persistence still requires an external append-only witness or signed checkpoint with separate custody. The existing README's administrator-tampering limitation remains in force.

Qualification must include the target Linux runtime, real workload sizes, storage/lock latency, restart and recovery rehearsal, and approved source/image/runtime bindings. A successful Windows synthetic suite is source evidence only. The 30-second fallback may still exceed a readiness budget on a sufficiently large or contended ledger; no production latency SLO is claimed.

## Reproduction

From `frontier-evidence-gateway`, run:

```sh
python -B -m unittest discover -s tests -p test_readiness_snapshot.py -v
python -B -m unittest discover -s tests -v
```

From the repository root, run:

```sh
python -B -m unittest discover -s tests -v
python -m ruff check --select E9,F frontier-evidence-gateway tools tests
git diff --check
```

The new regressions use disposable synthetic SQLite files and deny outbound socket connections. No test opens a live production ledger. One existing cache test now explicitly audits after append before asserting cache reuse; its no-rehash assertion is retained.
