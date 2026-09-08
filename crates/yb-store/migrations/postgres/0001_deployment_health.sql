-- The last health-check result per deployment, so the console can show status
-- on load without calling every upstream.
--
-- A separate table rather than columns on `deployments`: a result is a
-- transient observation with its own lifetime, not part of the deployment's
-- definition, and keeping it apart means a check never rewrites a config row.
CREATE TABLE deployment_health (
    deployment_id   TEXT PRIMARY KEY REFERENCES deployments(id) ON DELETE CASCADE,
    healthy         BOOLEAN NOT NULL,
    -- The check that produced this result (`probe`, `http_ok`, …), so the UI
    -- can say what was actually measured.
    check_kind      TEXT NOT NULL,
    status          INTEGER,
    latency_ms      BIGINT NOT NULL DEFAULT 0,
    detail          TEXT,
    checked_at      TIMESTAMPTZ NOT NULL
);
