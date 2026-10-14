CREATE TABLE instance (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    server_id BLOB NOT NULL CHECK (length(server_id) = 16 AND hex(server_id) != '00000000000000000000000000000000'),
    created_at_ms INTEGER NOT NULL
) STRICT;
