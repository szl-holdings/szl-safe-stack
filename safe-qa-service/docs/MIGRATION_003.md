# Migration 003: durable evidence and audit outbox

`db/migrations/003_durable_evidence_outbox.sql` is the forward migration from the v0.2 control
schema in migration `002`. It is required by the current application. It does not prove that any
production database was upgraded.

## What changes

- Historical `control_executions` rows are explicitly classified as evidence persistence version 1.
- New execution claims must be version 2 and retain both the complete approval bundle and normalized
  verification evidence in the same transaction as the single-use claim.
- Provider intent, confirmed receipts, `PROVIDER_OUTCOME_UNKNOWN`, and terminal events are committed
  to the primary append-only control tables with durable secondary-ledger outbox records.
- A unique terminal-state rule and trigger prevent contradictory completion/failure states or later
  event appends.
- Expiring leases coordinate outbox workers; immutable export receipts make ambiguous secondary
  acknowledgements retryable without rewriting primary evidence.

An action error after its provider call begins is not recorded as zero mutations. The primary event
is `PROVIDER_OUTCOME_UNKNOWN` with `mutation_may_have_occurred: true`, followed by a failed-closed
terminal event. Operators must perform an independent provider readback before authorizing any new
recovery plan. A missing confirmed receipt is not proof that no mutation occurred.

## Preconditions

1. Identify and preserve the exact database, migration file digest, application version, and backup
   or snapshot. Exercise restore in the applicable environment before a production change.
2. Confirm migration `001` and then migration `002` are already present. Do not apply `003` directly
   to an unrelated or partially reconstructed schema.
3. Use a separately reviewed migration identity. The runtime identity should not own tables or have
   permission to alter schema, disable triggers, or truncate evidence.
4. Stop or drain control-execution writers for the bounded migration window. Keep evidence readers
   available only if the operational design supports it.

## Apply

Use the environment's secret-safe connection mechanism; do not place credentials in shell history.
The equivalent command must stop on the first SQL error:

```text
psql --set=ON_ERROR_STOP=1 --file db/migrations/003_durable_evidence_outbox.sql
```

Compose mounts `001`, `002`, and `003` into `/docker-entrypoint-initdb.d` only for a new, empty local
volume. PostgreSQL does not use those files to upgrade an existing volume. Never delete an existing
volume merely to force initialization scripts to run.

## Readback

Run reviewed equivalents of these read-only checks and retain their output with the exact database
identity and migration digest:

```sql
SELECT column_name, is_nullable, column_default
FROM information_schema.columns
WHERE table_schema = 'public' AND table_name = 'control_executions'
ORDER BY ordinal_position;

SELECT conname, pg_get_constraintdef(oid)
FROM pg_constraint
WHERE conrelid IN (
  'control_executions'::regclass,
  'control_execution_events'::regclass
)
ORDER BY conname;

SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name IN (
    'control_audit_outbox',
    'control_audit_leases',
    'control_audit_exports'
  )
ORDER BY table_name;
```

Then run the integration suite against a disposable database created from all three migrations. The
suite must prove the hash chain, append-only triggers, evidence-version constraint, single-use claim,
unknown-outcome durability, lease coordination, retryable export, and replay rejection.

## Failure and recovery

Migration `003` is transactional. Treat a failed invocation as failed until transaction state and
schema readback prove otherwise. Do not drop evidence tables, remove constraints, or edit historical
rows as a rollback. Restore only under an approved database-recovery procedure, or write a separately
reviewed forward migration. Application rollout remains blocked until schema readback and the exact
integration suite pass.
