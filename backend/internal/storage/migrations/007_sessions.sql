ALTER TABLE accounts ADD COLUMN status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled'));

CREATE TABLE sessions (
    session_id BLOB PRIMARY KEY CHECK(length(session_id)=16),
    account_id BLOB NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    credential_generation TEXT NOT NULL,
    device_id BLOB NOT NULL CHECK(length(device_id)=16),
    device_name TEXT NOT NULL,
    platform TEXT NOT NULL CHECK(platform IN ('android','windows')),
    created_at_ms INTEGER NOT NULL,
    last_used_at_ms INTEGER NOT NULL,
    session_expires_at_ms INTEGER NOT NULL,
    refresh_expires_at_ms INTEGER NOT NULL,
    access_digest BLOB NOT NULL UNIQUE CHECK(length(access_digest)=32),
    access_expires_at_ms INTEGER NOT NULL,
    revoked_at_ms INTEGER,
    CHECK(created_at_ms>=0 AND last_used_at_ms>=created_at_ms AND session_expires_at_ms>created_at_ms),
    CHECK(access_expires_at_ms<=session_expires_at_ms AND refresh_expires_at_ms<=session_expires_at_ms)
) STRICT;
CREATE INDEX sessions_account ON sessions(account_id,session_expires_at_ms);

CREATE TABLE refresh_tokens (
    digest BLOB PRIMARY KEY CHECK(length(digest)=32),
    session_id BLOB NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0,1))
) STRICT;
CREATE INDEX refresh_tokens_family ON refresh_tokens(session_id);

CREATE TABLE auth_rate_events (
    event_id BLOB PRIMARY KEY CHECK(length(event_id)=16),
    kind TEXT NOT NULL CHECK(kind IN ('login','refresh')),
    principal_digest BLOB NOT NULL CHECK(length(principal_digest)=32),
    ip_digest BLOB NOT NULL CHECK(length(ip_digest)=32),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0)
) STRICT;
CREATE INDEX auth_rate_time ON auth_rate_events(created_at_ms);
CREATE INDEX auth_rate_principal ON auth_rate_events(kind,principal_digest,created_at_ms);
CREATE INDEX auth_rate_ip ON auth_rate_events(kind,ip_digest,created_at_ms);
