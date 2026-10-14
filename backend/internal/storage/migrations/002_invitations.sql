ALTER TABLE instance ADD COLUMN bootstrap_closed INTEGER NOT NULL DEFAULT 0 CHECK (bootstrap_closed IN (0, 1));

CREATE TABLE invitations (
    invitation_id BLOB PRIMARY KEY CHECK (length(invitation_id) = 16 AND hex(invitation_id) != '00000000000000000000000000000000'),
    secret_digest BLOB NOT NULL UNIQUE CHECK (length(secret_digest) = 32),
    scope TEXT NOT NULL CHECK (scope IN ('admin', 'user')),
    email TEXT,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > created_at_ms),
    consumed_at_ms INTEGER CHECK (consumed_at_ms >= created_at_ms),
    revoked_at_ms INTEGER CHECK (revoked_at_ms >= created_at_ms)
) STRICT;

CREATE INDEX invitations_live ON invitations(scope, expires_at_ms)
    WHERE consumed_at_ms IS NULL AND revoked_at_ms IS NULL;
