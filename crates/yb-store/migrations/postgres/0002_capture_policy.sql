-- Whether prompts and responses are captured, how they are redacted before
-- they are stored, and how long they are kept. One row: the gateway has one
-- policy, which an operator changes at runtime.
CREATE TABLE capture_policy (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    enabled         BOOLEAN NOT NULL,
    redaction       TEXT NOT NULL,
    retention_days  INTEGER NOT NULL,
    updated_at      TEXT NOT NULL
);
