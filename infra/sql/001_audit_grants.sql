-- Append-only enforcement for the audit ledger.
--
-- The application role is granted INSERT and SELECT on audit tables only.
-- UPDATE and DELETE are explicitly revoked so that tampering with history
-- requires superuser access, not merely application-level compromise.
-- Retention pruning, if ever enabled, must go through a separate audited
-- "tombstone" procedure rather than a DELETE statement.

CREATE SCHEMA IF NOT EXISTS agentshield;

CREATE TABLE IF NOT EXISTS agentshield.audit_entry (
    seq             BIGSERIAL PRIMARY KEY,
    session_id      UUID NOT NULL,
    event_type      TEXT NOT NULL,
    payload         JSONB NOT NULL,
    prev_hash       TEXT NOT NULL,
    entry_hash      TEXT NOT NULL UNIQUE,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_entry_session ON agentshield.audit_entry (session_id);

CREATE TABLE IF NOT EXISTS agentshield.merkle_batch (
    id              UUID PRIMARY KEY,
    start_seq       BIGINT NOT NULL,
    end_seq         BIGINT NOT NULL,
    merkle_root     TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agentshield.checkpoint (
    id              UUID PRIMARY KEY,
    batch_id        UUID NOT NULL REFERENCES agentshield.merkle_batch (id),
    signature       TEXT NOT NULL,
    prev_checkpoint_hash TEXT NOT NULL,
    anchor_ref      TEXT,
    signed_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agentshield.audit_tombstone (
    id              UUID PRIMARY KEY,
    pruned_entry_hash TEXT NOT NULL,
    reason          TEXT NOT NULL,
    pruned_by       TEXT NOT NULL,
    pruned_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Dedicated low-privilege application role. The gateway connects as this
-- role, never as the migration/owner role.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'agentshield_app') THEN
        CREATE ROLE agentshield_app LOGIN PASSWORD 'change-me-in-production';
    END IF;
END
$$;

GRANT USAGE ON SCHEMA agentshield TO agentshield_app;

GRANT INSERT, SELECT ON agentshield.audit_entry TO agentshield_app;
GRANT INSERT, SELECT ON agentshield.merkle_batch TO agentshield_app;
GRANT INSERT, SELECT ON agentshield.checkpoint TO agentshield_app;
GRANT INSERT, SELECT ON agentshield.audit_tombstone TO agentshield_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA agentshield TO agentshield_app;

REVOKE UPDATE, DELETE, TRUNCATE ON agentshield.audit_entry FROM agentshield_app;
REVOKE UPDATE, DELETE, TRUNCATE ON agentshield.merkle_batch FROM agentshield_app;
REVOKE UPDATE, DELETE, TRUNCATE ON agentshield.checkpoint FROM agentshield_app;
REVOKE UPDATE, DELETE, TRUNCATE ON agentshield.audit_tombstone FROM agentshield_app;
