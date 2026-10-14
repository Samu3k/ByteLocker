CREATE TABLE email_outbox (
    registration_id BLOB PRIMARY KEY REFERENCES email_verifications(registration_id) ON DELETE CASCADE,
    message_id BLOB NOT NULL UNIQUE CHECK (length(message_id) = 16),
    emission INTEGER NOT NULL CHECK (emission BETWEEN 1 AND 10),
    payload BLOB NOT NULL CHECK (length(payload) BETWEEN 38 AND 291),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms >= 0),
    available_at_ms INTEGER NOT NULL CHECK (available_at_ms >= 0),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    lease_token BLOB CHECK (lease_token IS NULL OR length(lease_token) = 16),
    lease_until_ms INTEGER NOT NULL DEFAULT 0 CHECK (lease_until_ms >= 0),
    CHECK ((lease_token IS NULL AND lease_until_ms = 0) OR (lease_token IS NOT NULL AND lease_until_ms > 0))
) STRICT;

CREATE INDEX email_outbox_ready ON email_outbox(available_at_ms, lease_until_ms);

CREATE TABLE email_delivery_emissions (
    message_id BLOB PRIMARY KEY CHECK (length(message_id) = 16),
    recipient_digest BLOB NOT NULL CHECK (length(recipient_digest) = 32),
    issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms >= 0)
) STRICT;

CREATE INDEX email_delivery_recipient ON email_delivery_emissions(recipient_digest, issued_at_ms);
