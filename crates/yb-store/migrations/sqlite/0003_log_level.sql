-- How much the gateway logs. One row, which an operator changes at runtime.
CREATE TABLE log_level (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    level       TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
