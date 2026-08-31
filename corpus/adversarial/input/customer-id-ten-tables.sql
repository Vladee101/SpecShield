-- Ten tables, ten distinct `customer_id` column identities (SDD B1).

CREATE TABLE account (
    account_id    UUID PRIMARY KEY,
    customer_id  UUID NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL
);

CREATE TABLE invoice (
    invoice_id    UUID PRIMARY KEY,
    customer_id  UUID NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL
);

CREATE TABLE payment_attempt (
    payment_attempt_id    UUID PRIMARY KEY,
    customer_id  UUID NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL
);

CREATE TABLE refund (
    refund_id    UUID PRIMARY KEY,
    customer_id  UUID NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL
);

CREATE TABLE dunning_event (
    dunning_event_id    UUID PRIMARY KEY,
    customer_id  UUID NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL
);

CREATE TABLE usage_record (
    usage_record_id    UUID PRIMARY KEY,
    customer_id  UUID NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL
);

CREATE TABLE credit_note (
    credit_note_id    UUID PRIMARY KEY,
    customer_id  UUID NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL
);

CREATE TABLE tax_line (
    tax_line_id    UUID PRIMARY KEY,
    customer_id  UUID NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL
);

CREATE TABLE payout (
    payout_id    UUID PRIMARY KEY,
    customer_id  UUID NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL
);

CREATE TABLE audit_entry (
    audit_entry_id    UUID PRIMARY KEY,
    customer_id  UUID NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL
);
