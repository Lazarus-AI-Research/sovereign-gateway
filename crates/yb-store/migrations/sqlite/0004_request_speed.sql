-- How fast each turn was served: time to its first token, the time its
-- answer took to write, and the time it waited before the engine began.
-- NULL where it could not be told.
ALTER TABLE request_telemetry ADD COLUMN first_token_ms BIGINT;
ALTER TABLE request_telemetry ADD COLUMN generation_ms BIGINT;
ALTER TABLE request_telemetry ADD COLUMN queue_ms BIGINT;
