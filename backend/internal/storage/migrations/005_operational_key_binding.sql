CREATE TABLE operational_key_binding (
    singleton INTEGER PRIMARY KEY CHECK (singleton=1),
    fingerprint BLOB NOT NULL CHECK (length(fingerprint)=32)
) STRICT;
