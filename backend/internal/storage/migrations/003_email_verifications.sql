CREATE TABLE email_verifications (
    registration_id BLOB PRIMARY KEY CHECK (length(registration_id) = 16 AND hex(registration_id) != '00000000000000000000000000000000'),
    deadline_ms INTEGER NOT NULL CHECK (deadline_ms >= 0),
    code_mac BLOB CHECK (code_mac IS NULL OR length(code_mac) = 32),
    issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > issued_at_ms AND expires_at_ms <= deadline_ms),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    emissions INTEGER NOT NULL CHECK (emissions BETWEEN 1 AND 10),
    consumed INTEGER NOT NULL DEFAULT 0 CHECK (consumed IN (0, 1)),
    CHECK ((consumed = 0 AND code_mac IS NOT NULL) OR (consumed = 1 AND code_mac IS NULL))
) STRICT;

CREATE TABLE email_verification_emissions (
    registration_id BLOB NOT NULL REFERENCES email_verifications(registration_id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK (sequence BETWEEN 1 AND 10),
    issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms >= 0),
    PRIMARY KEY (registration_id, sequence)
) STRICT;
