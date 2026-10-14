CREATE TABLE admin_panel_key (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    account_id BLOB NOT NULL REFERENCES accounts(account_id),
    digest BLOB NOT NULL CHECK(length(digest)=32),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>=0)
) STRICT;
