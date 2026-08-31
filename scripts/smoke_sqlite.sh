#!/usr/bin/env bash
#
# scripts/smoke_sqlite.sh — end-to-end offline smoke test for the gateway.
#
# The gateway is configured by a single TOML file and reads NO environment
# variables. This script writes a throwaway gateway.toml (sqlite + offline mock
# upstream + reqlog), boots the binary with just that file as its argument, and
# proves the full lifecycle works with no network and no provider API keys:
#
#   1. binary boots and /health returns ok
#   2. the seed model from the config is in the DB (GET /admin/v1/deployments)
#   3. a deployment is added at runtime via POST /admin/v1/deployments (hot-reload)
#   4. a virtual key (yb_...) is issued via the admin API for the admin user (a DB write)
#   5. all four inference surfaces are exercised with that key:
#        POST /v1/messages                            (Anthropic Messages)
#        POST /v1/chat/completions                    (OpenAI Chat)
#        POST /v1/responses                           (OpenAI Responses)
#        POST /v1beta/models/<model>:generateContent  (Gemini)
#   6. a telemetry row is asserted in request_telemetry
#   7. a parquet reqlog shard is asserted under the reqlog dir
#
# Everything runs in a fresh temp dir and is cleaned up on exit, so the script is
# idempotent and leaves no state behind.
#
# Requirements: bash, curl, jq, sqlite3 (only for the telemetry assertion).
#
# To run against REAL upstreams, set `upstream.mode = "http"` in the config and
# put each deployment's `api_key` (and `api_base`) in the models file — but then
# steps 7/8 depend on a live upstream.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

need() { command -v "$1" >/dev/null 2>&1 || { echo "FATAL: missing required tool: $1" >&2; exit 1; }; }
need curl
need jq
need sqlite3

# Mock upstream replays an Anthropic response, so the seed deployment must use
# upstream_format = anthropic. The gateway still translates it into all four
# client surfaces.
MODEL="smoke-claude"
PORT="${GATEWAY_SMOKE_PORT:-8723}"
BASE="http://127.0.0.1:${PORT}"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gateway-smoke.XXXXXX")"
DB_PATH="$WORK_DIR/gateway.db"
REQLOG_DIR="$WORK_DIR/reqlog"
CONFIG_PATH="$WORK_DIR/gateway.toml"
SERVER_LOG="$WORK_DIR/server.log"
JAR="$WORK_DIR/cookies.txt"
mkdir -p "$REQLOG_DIR"

SERVER_PID=""
cleanup() {
  local code=$?
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK_DIR"
  exit $code
}
trap cleanup EXIT INT TERM

say()  { printf '\n=== %s\n' "$*"; }
pass() { printf '  ok  %s\n' "$*"; }
fail() { printf '  FAIL %s\n' "$*" >&2; echo "---- server.log (tail) ----" >&2; tail -40 "$SERVER_LOG" >&2 || true; exit 1; }

# ---- 0. build --------------------------------------------------------------

say "building gateway"
( cd "$REPO_DIR" && cargo build -p yb-bin 2>&1 | tail -3 )
BIN="$REPO_DIR/target/debug/gateway"
[[ -x "$BIN" ]] || fail "binary not found at $BIN"
pass "built $BIN"

# ---- 1. write the whole config (TOML; the only configuration source) -------

say "writing config -> $CONFIG_PATH"
cat > "$CONFIG_PATH" <<TOML
[server]
bind = "127.0.0.1:${PORT}"
deployment_mode = "selfhosted"

[database]
backend = "sqlite"
path = "${DB_PATH}"

[upstream]
mode = "mock"

[reqlog]
enabled = true
dir = "${REQLOG_DIR}"
rotate_secs = 1

[routing]
strategy = "simple"
TOML
pass "sqlite + mock upstream + reqlog (no models in the serve config)"

# ---- 1b. write the dedicated models file ----------------------------------

MODELS_PATH="${WORK_DIR}/models.toml"
say "writing models file -> $MODELS_PATH"
cat > "$MODELS_PATH" <<TOML
[[model]]
model_name = "${MODEL}"
  [[model.deployments]]
  provider = "anthropic"
  upstream_model = "claude-3-5-sonnet-20241022"
  upstream_format = "anthropic"
  weight = 1
TOML
pass "one seed model ($MODEL) in a dedicated models file"

# ---- 2. import models into the DB, then boot ------------------------------

say "importing models into the DB (gateway import <models-file> <config>) — models live in the DB, not the serve config"
( cd "$WORK_DIR" && "$BIN" import "$MODELS_PATH" "$CONFIG_PATH" )

say "booting gateway on $BASE  (cmd: gateway $CONFIG_PATH)"
RUST_LOG="${RUST_LOG:-info}" "$BIN" "$CONFIG_PATH" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

say "waiting for /health"
healthy=""
for _ in $(seq 1 100); do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then fail "server process exited during boot"; fi
  if curl -fsS "$BASE/health" >/dev/null 2>&1; then healthy=1; break; fi
  sleep 0.2
done
[[ -n "$healthy" ]] || fail "/health never became ready"
status="$(curl -fsS "$BASE/health" | jq -r '.status')"
[[ "$status" == "ok" ]] || fail "/health returned status=$status"
pass "/health -> ok"

# ---- 2b. sign in (serve auto-creates admin/admin on first run) -------------

say "signing in to the admin API (session cookie; admin/admin auto-created)"
curl -fsS -c "$JAR" -X POST "$BASE/admin/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"admin"}' >/dev/null || fail "login failed"
ME="$(curl -fsS -b "$JAR" "$BASE/admin/v1/auth/me")" || fail "/auth/me failed"
[[ "$(jq -r '.role' <<<"$ME")" == "admin" ]] || fail "expected admin role: $ME"
pass "authenticated as $(jq -r '.username' <<<"$ME") (role=$(jq -r '.role' <<<"$ME"))"

# ---- 3. the seed model is in the DB; add another at runtime ----------------

say "listing deployments (GET /admin/v1/deployments) — proves the file model was seeded into the DB"
MODELS="$(curl -fsS "$BASE/admin/v1/deployments" -b "$JAR")" || fail "list deployments failed"
COUNT="$(jq 'length' <<<"$MODELS")"
[[ "$COUNT" -ge 1 ]] || fail "expected >=1 seeded model, got: $MODELS"
pass "$COUNT model(s) in DB: $(jq -r '[.[].model_name]|join(",")' <<<"$MODELS")"

say "adding a deployment at runtime (POST /admin/v1/deployments) — hot-reloads the router"
curl -fsS -X POST "$BASE/admin/v1/deployments" \
  -b "$JAR" -H 'content-type: application/json' \
  -d '{"model_name":"runtime-added","provider":"openai","upstream_model":"gpt-4o","upstream_format":"openai_chat"}' \
  >/dev/null || fail "create model failed"
COUNT2="$(curl -fsS "$BASE/admin/v1/deployments" -b "$JAR" | jq 'length')"
[[ "$COUNT2" -eq $((COUNT + 1)) ]] || fail "model count did not grow after add ($COUNT -> $COUNT2)"
pass "model count $COUNT -> $COUNT2 (DB-backed, no restart)"

# ---- 4. issue a virtual key for the admin user (a DB write) ---------------

say "issuing virtual key (admin API; owned by the signed-in admin user)"
KEY_JSON="$(curl -fsS -X POST "$BASE/admin/v1/keys" \
  -b "$JAR" -H 'content-type: application/json' \
  -d '{"name":"smoke-key"}')" || fail "issue key failed"
TOKEN="$(jq -r '.token' <<<"$KEY_JSON")"
[[ "$TOKEN" == yb_* ]] || fail "issued token has no yb_ prefix: $KEY_JSON"
pass "issued key ${TOKEN:0:12}... (prefix yb_)"

# ---- 5. exercise all four inference surfaces ------------------------------

post_surface() {
  local label="$1" path="$2" body="$3" out
  out="$(curl -fsS -X POST "$BASE$path" \
    -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' -d "$body")" \
    || fail "$label POST $path failed"
  jq -e . >/dev/null 2>&1 <<<"$out" || fail "$label returned non-JSON: $out"
  pass "$label -> 200 ($(wc -c <<<"$out" | tr -d ' ') bytes)"
}

say "POST /v1/messages (Anthropic)"
post_surface "anthropic" "/v1/messages" \
  "{\"model\":\"$MODEL\",\"max_tokens\":64,\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}"

say "POST /v1/chat/completions (OpenAI Chat)"
post_surface "openai-chat" "/v1/chat/completions" \
  "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}"

say "POST /v1/responses (OpenAI Responses)"
post_surface "openai-responses" "/v1/responses" \
  "{\"model\":\"$MODEL\",\"input\":\"hi\"}"

say "POST /v1beta/models/$MODEL:generateContent (Gemini)"
post_surface "gemini" "/v1beta/models/$MODEL:generateContent" \
  '{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}'

# ---- 6. assert telemetry rows ---------------------------------------------

say "asserting telemetry rows in request_telemetry"
TELEM=0
for _ in $(seq 1 25); do
  TELEM="$(sqlite3 "$DB_PATH" 'SELECT COUNT(*) FROM request_telemetry;' 2>/dev/null || echo 0)"
  [[ "$TELEM" -gt 0 ]] && break
  sleep 0.2
done
[[ "$TELEM" -gt 0 ]] || fail "no rows in request_telemetry"
pass "request_telemetry has $TELEM row(s)"
SURFACES="$(sqlite3 "$DB_PATH" 'SELECT DISTINCT surface FROM request_telemetry ORDER BY surface;' | paste -sd, -)"
pass "telemetry surfaces: ${SURFACES:-<none>}"

# ---- 7. assert a parquet reqlog shard exists ------------------------------

say "asserting a parquet reqlog shard under $REQLOG_DIR/shards"
SHARD=""
for _ in $(seq 1 50); do
  SHARD="$(find "$REQLOG_DIR/shards" -name '*.parquet' -type f 2>/dev/null | head -1 || true)"
  [[ -n "$SHARD" ]] && break
  sleep 0.2
done
[[ -n "$SHARD" ]] || fail "no .parquet shard appeared under $REQLOG_DIR/shards"
SHARD_BYTES="$(wc -c <"$SHARD" | tr -d ' ')"
[[ "$SHARD_BYTES" -gt 0 ]] || fail "parquet shard is empty: $SHARD"
pass "parquet shard $(basename "$SHARD") ($SHARD_BYTES bytes)"

# ---- done ------------------------------------------------------------------

say "SMOKE PASSED"
echo "  models       : $COUNT2 (DB-backed; $COUNT seeded + 1 runtime)"
echo "  key          : ${TOKEN:0:12}... (owned by admin user)"
echo "  telemetry    : $TELEM row(s) [$SURFACES]"
echo "  reqlog shard : $(basename "$SHARD") ($SHARD_BYTES bytes)"
echo "  workdir      : $WORK_DIR (removed on exit)"
