#!/bin/sh
# Starts a throwaway gateway in front of a QE server, for check.py.
#
#   QE_BASE   QE server base URL            (default http://127.0.0.1:27900/v1)
#   QE_KEY    file holding QE's API key     (default ~/qe-stub/key; never printed)
#   QE_MODEL  QE's served model name        (default DeepSeek-V4.1-Flash)
#   GATEWAY   the gateway binary            (default ./target/release/gateway)
#   WORK      scratch directory             (default ~/qe-lossless-work)
#   PORT      gateway port                  (default 27910)
#
# Three public models, all on the same QE server:
#   relay  provider serves anthropic, openai_chat and openai_responses: every
#          shape is relayed unchanged (provider shapes)
#   chat   provider serves only its deployment's openai_chat, dialect "qe":
#          Anthropic and Responses are translated with the QE dialect
#   ir     as chat, without the dialect: the cross-provider IR translation
# The gateway's own inference key (a control key) is written to
# $WORK/gateway.key (mode 600) for check.py.
set -eu
QE_BASE=${QE_BASE:-http://127.0.0.1:27900/v1}
QE_KEY=${QE_KEY:-$HOME/qe-stub/key}
QE_MODEL=${QE_MODEL:-DeepSeek-V4.1-Flash}
GATEWAY=${GATEWAY:-./target/release/gateway}
WORK=${WORK:-$HOME/qe-lossless-work}
PORT=${PORT:-27910}

mkdir -p "$WORK"
chmod 700 "$WORK"
if [ -f "$WORK/gateway.pid" ] && kill -0 "$(cat "$WORK/gateway.pid")" 2>/dev/null; then
  kill "$(cat "$WORK/gateway.pid")"
  sleep 1
fi
rm -f "$WORK/gateway.db" "$WORK/gateway.db-wal" "$WORK/gateway.db-shm"
umask 077
[ -f "$WORK/gateway.key" ] || od -An -tx1 -N24 /dev/urandom | tr -d ' \n' > "$WORK/gateway.key"
GATEWAY=$(cd "$(dirname "$GATEWAY")" && pwd)/$(basename "$GATEWAY")

cat > "$WORK/gateway.toml" <<EOF
[server]
bind = "127.0.0.1:$PORT"
deployment_mode = "selfhosted"
[database]
backend = "sqlite"
path = "$WORK/gateway.db"
[security]
control_key_env = "QE_CHECK_CONTROL_KEY"
[upstream]
mode = "http"
EOF

key=$(cat "$QE_KEY")
sampling='qe_sampling = { temperature = 1.0, top_p = 0.95 }'
cat > "$WORK/models.toml" <<EOF
[[provider]]
name = "qe-shapes"
api_base = "$QE_BASE"
api_key = "$key"
extra = { dialect = "qe", $sampling }
shapes = [{ format = "anthropic" }, { format = "openai_chat" }, { format = "openai_responses" }]

[[provider]]
name = "qe-chat"
api_base = "$QE_BASE"
api_key = "$key"
extra = { dialect = "qe", $sampling }

[[provider]]
name = "qe-ir"
api_base = "$QE_BASE"
api_key = "$key"

[[model]]
model_name = "relay"
  [[model.deployments]]
  provider = "qe-shapes"
  upstream_model = "$QE_MODEL"
  upstream_format = "openai_chat"

[[model]]
model_name = "chat"
  [[model.deployments]]
  provider = "qe-chat"
  upstream_model = "$QE_MODEL"
  upstream_format = "openai_chat"

[[model]]
model_name = "ir"
  [[model.deployments]]
  provider = "qe-ir"
  upstream_model = "$QE_MODEL"
  upstream_format = "openai_chat"
EOF
unset key

cd "$WORK"
"$GATEWAY" import models.toml gateway.toml > import.log 2>&1
QE_CHECK_CONTROL_KEY=$(cat gateway.key) nohup "$GATEWAY" serve gateway.toml > gateway.log 2>&1 &
echo $! > gateway.pid
i=0
until curl -sf "http://127.0.0.1:$PORT/health" > /dev/null; do
  i=$((i + 1)); [ $i -gt 50 ] && { echo "gateway did not start; see $WORK/gateway.log"; exit 1; }
  sleep 0.2
done
echo "gateway pid $(cat gateway.pid) on 127.0.0.1:$PORT (log $WORK/gateway.log)"
