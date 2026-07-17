#!/usr/bin/env bash
# Boot a throwaway gateway (sqlite + mock upstream, no network) and verify
# docs/openapi.yaml against it. See check_openapi.py for what is asserted.
#
# Needs: python3 with pyyaml + jsonschema.
set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gateway-openapi.XXXXXX")"
PORT="${PORT:-8796}"
PID=""

cleanup() {
  [[ -n "$PID" ]] && kill "$PID" 2>/dev/null
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

say() { printf '\n=== %s\n' "$*"; }
fail() { printf '  FAIL %s\n' "$*" >&2; tail -20 "$WORK_DIR/server.log" >&2 || true; exit 1; }

say "building gateway"
( cd "$REPO_DIR" && cargo build -p yb-bin 2>&1 | tail -2 )
BIN="$REPO_DIR/target/debug/gateway"
[[ -x "$BIN" ]] || fail "no binary at $BIN"

cat > "$WORK_DIR/gateway.toml" <<TOML
[server]
bind = "127.0.0.1:${PORT}"
deployment_mode = "selfhosted"

[database]
backend = "sqlite"
path = "${WORK_DIR}/gateway.db"

[upstream]
mode = "mock"

[reqlog]
enabled = false

[routing]
strategy = "simple"
TOML

cat > "$WORK_DIR/models.toml" <<'TOML'
[[model]]
model_name = "spec-model"
aliases = ["spec-alias"]
  [[model.deployments]]
  provider = "anthropic"
  upstream_model = "claude-3-5-sonnet-20241022"
  upstream_format = "anthropic"
  api_key = "sk-spec"
  weight = 1
TOML

say "seeding + booting on :$PORT"
"$BIN" import "$WORK_DIR/models.toml" "$WORK_DIR/gateway.toml" > "$WORK_DIR/import.log" 2>&1 \
  || fail "import failed: $(tail -3 "$WORK_DIR/import.log")"
"$BIN" "$WORK_DIR/gateway.toml" > "$WORK_DIR/server.log" 2>&1 &
PID=$!
for _ in $(seq 1 80); do
  curl -sf "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1 && break
  sleep 0.25
done
curl -sf "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1 || fail "gateway did not come up"

say "verifying docs/openapi.yaml against the live server"
python3 "$REPO_DIR/scripts/check_openapi.py" "http://127.0.0.1:${PORT}" "$REPO_DIR"
