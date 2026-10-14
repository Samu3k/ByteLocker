CREATE TABLE accounts (
    account_id BLOB PRIMARY KEY CHECK(length(account_id)=16),
    email TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK(role IN ('admin','user')),
    vault_id BLOB NOT NULL UNIQUE CHECK(length(vault_id)=16),
    epoch_id BLOB NOT NULL CHECK(length(epoch_id)=16),
    descriptor BLOB NOT NULL CHECK(length(descriptor)=30),
    verifier BLOB NOT NULL CHECK(length(verifier)=63),
    password_envelope BLOB NOT NULL CHECK(length(password_envelope)=226),
    credential_generation TEXT NOT NULL DEFAULT '1',
    recovery_generation TEXT NOT NULL DEFAULT '0',
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0)
) STRICT;

CREATE TABLE registrations (
    registration_id BLOB PRIMARY KEY CHECK(length(registration_id)=16),
    token_digest BLOB NOT NULL UNIQUE CHECK(length(token_digest)=32),
    invitation_id BLOB NOT NULL REFERENCES invitations(invitation_id),
    email TEXT NOT NULL,
    scope TEXT NOT NULL CHECK(scope IN ('admin','user')),
    account_id BLOB NOT NULL UNIQUE CHECK(length(account_id)=16),
    vault_id BLOB NOT NULL CHECK(length(vault_id)=16),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>created_at_ms),
    status TEXT NOT NULL CHECK(status IN ('awaiting_material','verification_pending','verified')),
    suppressed INTEGER NOT NULL CHECK(suppressed IN (0,1)),
    epoch_id BLOB CHECK(epoch_id IS NULL OR length(epoch_id)=16),
    descriptor BLOB CHECK(descriptor IS NULL OR length(descriptor)=30),
    verifier BLOB CHECK(verifier IS NULL OR length(verifier)=63),
    password_envelope BLOB CHECK(password_envelope IS NULL OR length(password_envelope)=226),
    verified_at_ms INTEGER,
    CHECK((status='verification_pending' AND epoch_id IS NOT NULL AND descriptor IS NOT NULL AND verifier IS NOT NULL AND password_envelope IS NOT NULL AND verified_at_ms IS NULL)
       OR (status='awaiting_material' AND epoch_id IS NULL AND descriptor IS NULL AND verifier IS NULL AND password_envelope IS NULL AND verified_at_ms IS NULL)
       OR (status='verified' AND epoch_id IS NULL AND descriptor IS NULL AND verifier IS NULL AND password_envelope IS NULL AND verified_at_ms IS NOT NULL))
) STRICT;
CREATE INDEX registrations_email ON registrations(email,expires_at_ms);
CREATE INDEX registrations_invitation ON registrations(invitation_id,expires_at_ms);

CREATE TABLE registration_attempts (
    event_id BLOB PRIMARY KEY CHECK(length(event_id)=16),
    ip_digest BLOB NOT NULL CHECK(length(ip_digest)=32),
    email_digest BLOB NOT NULL CHECK(length(email_digest)=32),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0)
) STRICT;
CREATE INDEX registration_attempts_time ON registration_attempts(created_at_ms);
