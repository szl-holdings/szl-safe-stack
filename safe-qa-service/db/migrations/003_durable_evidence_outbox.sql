BEGIN;

-- Version 1 rows are historical claims created before the complete detached
-- evidence bundle was retained.  New application code always writes version 2
-- and both JSONB evidence documents in the same transaction as the claim.
ALTER TABLE control_executions
    ADD COLUMN IF NOT EXISTS evidence_persistence_version SMALLINT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS approval_bundle JSONB,
    ADD COLUMN IF NOT EXISTS normalized_approval_evidence JSONB;

-- Existing rows keep the explicit version 1 value assigned when the column was
-- added. Any later insert that omits the version fails the version 2 evidence
-- constraint instead of silently creating another legacy evidence gap.
ALTER TABLE control_executions
    ALTER COLUMN evidence_persistence_version SET DEFAULT 2;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'control_executions'::regclass
          AND conname = 'control_executions_evidence_version_check'
    ) THEN
        ALTER TABLE control_executions
            ADD CONSTRAINT control_executions_evidence_version_check
            CHECK (
                (
                    evidence_persistence_version = 1
                    AND approval_bundle IS NULL
                    AND normalized_approval_evidence IS NULL
                )
                OR
                (
                    evidence_persistence_version = 2
                    AND jsonb_typeof(approval_bundle) = 'object'
                    AND jsonb_typeof(normalized_approval_evidence) = 'object'
                    AND octet_length(approval_bundle::text) <= 256000
                    AND octet_length(normalized_approval_evidence::text) <= 256000
                )
            );
    END IF;
END;
$$;

CREATE UNIQUE INDEX IF NOT EXISTS control_execution_one_terminal_state_idx
    ON control_execution_events (plan_id)
    WHERE event_type IN ('EXECUTION_COMPLETED', 'EXECUTION_FAILED_CLOSED');

CREATE OR REPLACE FUNCTION reject_control_event_after_terminal()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- Serialize all event writers for one execution, including direct SQL
    -- writers that do not use the application repository.
    PERFORM 1
    FROM control_executions
    WHERE plan_id = NEW.plan_id
    FOR UPDATE;

    IF EXISTS (
        SELECT 1
        FROM control_execution_events
        WHERE plan_id = NEW.plan_id
          AND event_type IN ('EXECUTION_COMPLETED', 'EXECUTION_FAILED_CLOSED')
    ) THEN
        RAISE EXCEPTION 'safe-qa control execution is already terminal';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS control_events_reject_after_terminal ON control_execution_events;
CREATE TRIGGER control_events_reject_after_terminal
BEFORE INSERT ON control_execution_events
FOR EACH ROW EXECUTE FUNCTION reject_control_event_after_terminal();

CREATE TABLE IF NOT EXISTS control_audit_outbox (
    outbox_id UUID PRIMARY KEY,
    plan_id UUID NOT NULL REFERENCES control_plans(plan_id),
    control_event_id UUID UNIQUE REFERENCES control_execution_events(event_id),
    actor_subject TEXT NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 256),
    audit_action TEXT NOT NULL CHECK (length(audit_action) BETWEEN 1 AND 128),
    request_id UUID NOT NULL,
    payload JSONB NOT NULL CHECK (
        jsonb_typeof(payload) = 'object'
        AND octet_length(payload::text) <= 256000
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS control_audit_outbox_created_idx
    ON control_audit_outbox (created_at, outbox_id);

-- Secondary-ledger retry is exactly-once for a durable outbox item. The
-- payload field is part of the event hash, and this partial unique index lets
-- the ledger return the original receipt after an ambiguous acknowledgement.
CREATE UNIQUE INDEX IF NOT EXISTS audit_events_control_outbox_id_idx
    ON audit_events ((payload ->> 'control_outbox_id'))
    WHERE payload ? 'control_outbox_id';

-- This table is mutable coordination state, not evidence. Expiring leases plus
-- SELECT ... FOR UPDATE SKIP LOCKED allow any replica to drain the outbox while
-- ensuring only one live worker owns a delivery attempt at a time.
CREATE TABLE IF NOT EXISTS control_audit_leases (
    outbox_id UUID PRIMARY KEY REFERENCES control_audit_outbox(outbox_id),
    lease_owner UUID NOT NULL,
    lease_token UUID NOT NULL UNIQUE,
    leased_until TIMESTAMPTZ NOT NULL,
    attempt_count BIGINT NOT NULL CHECK (attempt_count > 0),
    last_leased_at TIMESTAMPTZ NOT NULL,
    CHECK (leased_until > last_leased_at)
);

CREATE INDEX IF NOT EXISTS control_audit_leases_expiry_idx
    ON control_audit_leases (leased_until, outbox_id);

CREATE TABLE IF NOT EXISTS control_audit_exports (
    export_id UUID PRIMARY KEY,
    outbox_id UUID NOT NULL UNIQUE REFERENCES control_audit_outbox(outbox_id),
    ledger_event_id UUID NOT NULL UNIQUE,
    ledger_sequence_id BIGINT NOT NULL CHECK (ledger_sequence_id > 0),
    ledger_event_hash CHAR(64) NOT NULL CHECK (ledger_event_hash ~ '^[0-9a-f]{64}$'),
    exported_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

DROP TRIGGER IF EXISTS control_outbox_reject_update_delete ON control_audit_outbox;
CREATE TRIGGER control_outbox_reject_update_delete
BEFORE UPDATE OR DELETE ON control_audit_outbox
FOR EACH ROW EXECUTE FUNCTION reject_immutable_control_change();

DROP TRIGGER IF EXISTS control_exports_reject_update_delete ON control_audit_exports;
CREATE TRIGGER control_exports_reject_update_delete
BEFORE UPDATE OR DELETE ON control_audit_exports
FOR EACH ROW EXECUTE FUNCTION reject_immutable_control_change();

DROP TRIGGER IF EXISTS control_outbox_reject_truncate ON control_audit_outbox;
CREATE TRIGGER control_outbox_reject_truncate
BEFORE TRUNCATE ON control_audit_outbox
FOR EACH STATEMENT EXECUTE FUNCTION reject_control_truncate();

DROP TRIGGER IF EXISTS control_exports_reject_truncate ON control_audit_exports;
CREATE TRIGGER control_exports_reject_truncate
BEFORE TRUNCATE ON control_audit_exports
FOR EACH STATEMENT EXECUTE FUNCTION reject_control_truncate();

COMMIT;
