-- The chat API shapes a provider serves natively, as a JSON array of
-- {"format": "anthropic" | "openai_chat" | "openai_responses" | "gemini",
--  "api_base": optional base URL for that shape}. A request in one of these
-- shapes is relayed unchanged; other shapes are translated to the
-- deployment's upstream_format. '[]' (every existing row): only each
-- deployment's own upstream_format, as before.
ALTER TABLE providers ADD COLUMN shapes TEXT NOT NULL DEFAULT '[]';
