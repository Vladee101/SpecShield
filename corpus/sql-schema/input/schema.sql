-- Vantor billing schema. Owned by the billing team.
-- Target: Postgres 16.

CREATE TYPE plan_tier AS ENUM ('trial', 'standard', 'enterprise');

CREATE TABLE customer_subscription (
    subscription_id  UUID PRIMARY KEY,
    customer_id      UUID NOT NULL,
    tier             plan_tier NOT NULL DEFAULT 'trial',
    started_at       TIMESTAMPTZ NOT NULL,
    cancelled_at     TIMESTAMPTZ
);

CREATE INDEX idx_customer_subscription_customer
    ON customer_subscription (customer_id);

CREATE TABLE invoice (
    invoice_id       UUID PRIMARY KEY,
    customer_id      UUID NOT NULL,
    subscription_id  UUID NOT NULL REFERENCES customer_subscription (subscription_id),
    amount_cents     BIGINT NOT NULL,
    issued_at        TIMESTAMPTZ NOT NULL
);

CREATE TABLE payment_attempt (
    attempt_id       UUID PRIMARY KEY,
    invoice_id       UUID NOT NULL REFERENCES invoice (invoice_id),
    customer_id      UUID NOT NULL,
    paylane_charge_id TEXT,
    amount_cents     BIGINT NOT NULL,
    succeeded        BOOLEAN NOT NULL DEFAULT FALSE
);
