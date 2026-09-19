BEGIN;

CREATE TABLE IF NOT EXISTS control_plans (
    plan_id UUID PRIMARY KEY,
    plan_digest CHAR(64) NOT NULL CHECK (plan_digest ~ '^[0-9a-f]{64}$'),
    requester_subject TEXT NOT NULL CHECK (length(requester_subject) BETWEEN 1 AND 256),
    issued_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    plan JSONB NOT NULL CHECK (jsonb_typeof(plan) = 'object'),
    CHECK (expires_at > issued_at)
);

CREATE TABLE IF NOT EXISTS control_executions (
    plan_id UUID PRIMARY KEY REFERENCES control_plans(plan_id),
    plan_digest CHAR(64) NOT NULL CHECK (plan_digest ~ '^[0-9a-f]{64}$'),
    bundle_digest CHAR(64) NOT NULL CHECK (bundle_digest ~ '^[0-9a-f]{64}$'),
    executor_subject TEXT NOT NULL CHECK (length(executor_subject) BETWEEN 1 AND 256),
    approval_verification JSONB NOT NULL CHECK (jsonb_typeof(approval_verification) = 'object'),
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS control_execution_events (
    event_id UUID PRIMARY KEY,
    plan_id UUID NOT NULL REFERENCES control_executions(plan_id),
    sequence_id BIGINT NOT NULL CHECK (sequence_id > 0),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 80),
    payload JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    UNIQUE (plan_id, sequence_id)
);

CREATE INDEX IF NOT EXISTS control_execution_events_plan_idx
    ON control_execution_events (plan_id, sequence_id);

CREATE OR REPLACE FUNCTION reject_immutable_control_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'safe-qa control evidence is append-only';
END;
$$;

DROP TRIGGER IF EXISTS control_plans_reject_update_delete ON control_plans;
CREATE TRIGGER control_plans_reject_update_delete
BEFORE UPDATE OR DELETE ON control_plans
FOR EACH ROW EXECUTE FUNCTION reject_immutable_control_change();

DROP TRIGGER IF EXISTS control_executions_reject_update_delete ON control_executions;
CREATE TRIGGER control_executions_reject_update_delete
BEFORE UPDATE OR DELETE ON control_executions
FOR EACH ROW EXECUTE FUNCTION reject_immutable_control_change();

DROP TRIGGER IF EXISTS control_events_reject_update_delete ON control_execution_events;
CREATE TRIGGER control_events_reject_update_delete
BEFORE UPDATE OR DELETE ON control_execution_events
FOR EACH ROW EXECUTE FUNCTION reject_immutable_control_change();

CREATE OR REPLACE FUNCTION reject_control_truncate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'safe-qa control evidence cannot be truncated';
END;
$$;

DROP TRIGGER IF EXISTS control_plans_reject_truncate ON control_plans;
CREATE TRIGGER control_plans_reject_truncate
BEFORE TRUNCATE ON control_plans
FOR EACH STATEMENT EXECUTE FUNCTION reject_control_truncate();

DROP TRIGGER IF EXISTS control_executions_reject_truncate ON control_executions;
CREATE TRIGGER control_executions_reject_truncate
BEFORE TRUNCATE ON control_executions
FOR EACH STATEMENT EXECUTE FUNCTION reject_control_truncate();

DROP TRIGGER IF EXISTS control_events_reject_truncate ON control_execution_events;
CREATE TRIGGER control_events_reject_truncate
BEFORE TRUNCATE ON control_execution_events
FOR EACH STATEMENT EXECUTE FUNCTION reject_control_truncate();

COMMIT;
