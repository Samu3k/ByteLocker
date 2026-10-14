CREATE TABLE vault_state (
 account_id BLOB PRIMARY KEY REFERENCES accounts(account_id) ON DELETE CASCADE,
 epoch_id BLOB NOT NULL CHECK(length(epoch_id)=16),
 revision BLOB NOT NULL CHECK(length(revision)=8),
 object_count INTEGER NOT NULL DEFAULT 0 CHECK(object_count>=0),
 stored_bytes INTEGER NOT NULL DEFAULT 0 CHECK(stored_bytes>=0)
) STRICT;
CREATE TABLE vault_objects (
 account_id BLOB NOT NULL REFERENCES vault_state(account_id) ON DELETE CASCADE,
 object_id BLOB NOT NULL CHECK(length(object_id)=16),
 revision BLOB NOT NULL CHECK(length(revision)=8),
 sequence BLOB NOT NULL CHECK(length(sequence)=8),
 envelope BLOB NOT NULL,
 PRIMARY KEY(account_id,object_id),
 UNIQUE(account_id,sequence)
) STRICT;
CREATE TABLE vault_writes (
 account_id BLOB NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
 operation_id BLOB NOT NULL CHECK(length(operation_id)=16),
 fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
 response BLOB NOT NULL,
 expires_at_ms INTEGER NOT NULL,
 PRIMARY KEY(account_id,operation_id)
) STRICT;
CREATE INDEX vault_writes_expiry ON vault_writes(expires_at_ms);

