# SovereignGateway

SovereignGateway is a low-dependency, single-binary LLM gateway in Rust for teams that route inference traffic through infrastructure they own.

It accepts four chat wire formats in front, normalizes through a provider-agnostic intermediate representation, and dispatches to any configured upstream — any client surface can target any provider.

## What is included

- **Four inference dialects** — Anthropic Messages, OpenAI Chat Completions, OpenAI Responses, and Gemini `generateContent`, all served from one binary. The gateway translates between the client's wire format and the upstream's.
- **Embeddings, including multimodal text+image** — OpenAI `/v1/embeddings` (plus Jina-style multimodal inputs), Gemini `:embedContent`/`:batchEmbedContents`, Cohere `/v2/embed`, and Voyage `/v1/multimodalembeddings` in front; OpenAI-compatible, Gemini, Cohere, Voyage, and Ollama upstreams behind.
- **Provider-agnostic IR** — a hand-rolled intermediate representation (`yb-wire`) covering requests, responses, and SSE streams.
- **Deterministic routing** — model-to-deployment mapping with ordered fallbacks. No ML routing.
- **Access control** — virtual keys, spend tracking and budgets, rate limits, users and teams with RBAC, and per-key model access.
- **Scoped virtual keys** — `inference` and/or `admin`. An `admin`-scoped key is machine auth for `/admin/v1` (Bearer), disjoint from inference.
- **Storage-agnostic persistence** — SQLite (default) or Postgres.
- **Request/response logging** — DuckDB WAL rotated into size-based zstd parquet shards, suitable for building training data.
- **OpenTelemetry export** — metrics via OTLP push and/or Prometheus `GET /metrics`, plus one OTLP event and span per turn. Structured metadata only; request and response bodies are never exported.

## Build

```sh
cargo build --release
# binary at target/release/gateway
```

## Configure

The gateway is configured by one TOML file and reads no environment variables (only `RUST_LOG`). There is no environment indirection for upstream keys either — each deployment carries its own `api_key` directly.

```sh
cp gateway.example.toml gateway.toml
$EDITOR gateway.toml
```

The serve config covers `[server]`, `[database]`, `[security]` (optional `byok_key`), `[reqlog]`, `[features]`, `[upstream]`, and `[routing]` (strategy and fallbacks). Models are not in the serve config. A separate models file lists each public model, its deployments, and any aliases:

```toml
# models.toml — loaded into the DB with `gateway import models.toml gateway.toml`
[[model]]
model_name = "claude-3-5-sonnet"
  aliases = ["sonnet", "claude"]        # extra public names that resolve here
  [[model.deployments]]
  provider = "anthropic"                # free-form attribution label
  upstream_model = "claude-3-5-sonnet-20241022"
  upstream_format = "anthropic"         # adapter shape: anthropic | openai_chat | openai_responses | gemini
  api_key = "sk-ant-..."                # the upstream provider key, stored on the deployment
  weight = 1
```

The model list lives in the database. `import` is the only path that loads it from a file; `serve` reads it from the DB. After importing, manage models and aliases at runtime via the admin API — changes hot-reload without a restart. See `gateway.example.toml` and `models.example.toml` for fully commented references.

## First use

```sh
./target/release/gateway import models.toml gateway.toml   # one-time: load models into the DB
./target/release/gateway gateway.toml                      # serve (path optional; default ./gateway.toml)
# listens on [server].bind (default 0.0.0.0:8080)
```

Database backend, bind address, secrets, request logging, and feature flags all come from the TOML file; upstream keys come from the models file. To collect training data, set `[reqlog] enabled = true`. To use Postgres, set `[database] backend = "postgres"` and `dsn = "postgres://…"`.

Open `http://localhost:8080/` for the bundled admin console (Preact, compiled into the binary). Sign in as a user — the login account is the user (username and password, Argon2-hashed in the DB). On first run `serve` auto-creates `admin` / `admin`. Change this credential immediately, in the UI or with `gateway setup --password <new>`, before exposing the gateway to a network.

Users have roles: **admin** (full control) and **member** (use the gateway, manage their own keys). Users own keys; there is no password in the TOML.

## CLI usage

```
gateway [serve] [config.toml]                     Run the gateway (default config ./gateway.toml)
gateway import <models-file> [config.toml]        Upsert a models file into the DB, then exit
gateway setup [config] [--user U] [--password P]  Initialize the DB and admin account
gateway set-role <user> <admin|member> [config]   Set a user's role (creates the user if needed)
```

## Admin API

The same API backs the console under `/admin/v1/*`, authenticated by the session cookie from `POST /admin/v1/auth/login`:

```sh
# Sign in -> session cookie (admin/admin by default).
curl -s -c cookies.txt -X POST localhost:8080/admin/v1/auth/login \
  -H 'content-type: application/json' -d '{"username":"admin","password":"admin"}'

# Issue a virtual key for the signed-in user (yb_… token shown once). An admin can
# also issue for any user by passing "owner_user_id"; a member only gets their own.
TOKEN=$(curl -s -b cookies.txt -X POST localhost:8080/admin/v1/keys \
  -H 'content-type: application/json' \
  -d '{"name":"prod"}' | jq -r .token)

# Manage models at runtime (router hot-reloads, no restart).
# A model is the public name clients request; a deployment is one concrete
# upstream behind it. One model can have several deployments — that is the
# load-balancing fan-out.
curl -s -b cookies.txt localhost:8080/admin/v1/models        # the entities
curl -s -b cookies.txt localhost:8080/admin/v1/deployments   # their upstreams
curl -s -b cookies.txt -X POST localhost:8080/admin/v1/deployments \
  -H 'content-type: application/json' \
  -d '{"model_name":"gpt-4o","provider":"openai","upstream_model":"gpt-4o","upstream_format":"openai_chat","api_key":"sk-..."}'

# Rename a model. The old name is kept as an alias automatically, so clients
# that still send it keep working.
curl -s -b cookies.txt -X PUT localhost:8080/admin/v1/models/$MODEL_ID/name \
  -H 'content-type: application/json' -d '{"name":"gpt-4o-2024"}'

# Aliases: extra public names that resolve to a model (e.g. "gpt-4" -> "gpt-4o").
curl -s -b cookies.txt -X POST localhost:8080/admin/v1/aliases \
  -H 'content-type: application/json' -d '{"alias":"gpt-4","target":"gpt-4o"}'
```

## Inference surfaces

Authenticate inference requests with the virtual key via `Authorization: Bearer yb_…`, the Anthropic-style `x-api-key` header (so native Anthropic clients and SDKs work unchanged), or the `x-gateway-key` header.

```sh
AUTH="Authorization: Bearer $TOKEN"
M=claude-3-5-sonnet

# Anthropic Messages
curl -s localhost:8080/v1/messages -H "$AUTH" -H 'content-type: application/json' \
  -d "{\"model\":\"$M\",\"max_tokens\":256,\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}"

# OpenAI Chat Completions
curl -s localhost:8080/v1/chat/completions -H "$AUTH" -H 'content-type: application/json' \
  -d "{\"model\":\"$M\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}"

# OpenAI Responses
curl -s localhost:8080/v1/responses -H "$AUTH" -H 'content-type: application/json' \
  -d "{\"model\":\"$M\",\"input\":\"hi\"}"

# Gemini generateContent (model + action travel in the URL path)
curl -s "localhost:8080/v1beta/models/$M:generateContent" -H "$AUTH" -H 'content-type: application/json' \
  -d '{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}'
```

Add `"stream": true` (or call `:streamGenerateContent` for Gemini) for SSE.

## Offline smoke test

`scripts/smoke_sqlite.sh` writes a throwaway serve config and a separate models file (SQLite, the offline `upstream.mode = "mock"` canned upstream, and reqlog), boots the binary, and asserts: boot, health, the seed model imported into the DB, a runtime deployment add via `/admin/v1/deployments`, admin key issuance, all four inference surfaces, a telemetry row, and a parquet reqlog shard. Fully offline — no environment variables, no provider keys. It cleans up after itself and is safe to re-run:

```sh
./scripts/smoke_sqlite.sh
```

## Architecture

The gateway is a Cargo workspace. Dependencies point strictly inward; only the `yb-bin` composition root constructs concrete adapters.

```
                 +-------------+
client request → |  yb-server  |  axum HTTP surface: 4 inference dialects,
                 |             |  /health, /v1/models, /admin/v1/*
                 +------+------+  auth (yb_ bearer) · rate-limit · budgets
                        |
                 +------v------+
                 |  yb-gateway |  parse → route → dispatch w/ fallback →
                 |             |  translate → record telemetry/spend/reqlog
                 +--+---+---+--+
            +-------+   |   +--------+
   +--------v--+  +-----v------+  +--v---------+
   | yb-wire   |  |yb-providers|  | yb-reqlog  |
   | IR + 4    |  | upstream   |  | DuckDB WAL |
   | wire fmts |  | HTTP/Mock  |  | → parquet  |
   +-----------+  +------------+  +------------+
                        |
                 +------v------+
                 |  yb-store   |  SQLite / Postgres (impl yb_core::Store)
                 +------+------+
                 +------v------+
                 |   yb-core   |  frozen domain contract: ids, errors, model,
                 |             |  routing, spend, ratelimit, rbac, crypto traits
                 +-------------+
```

| Crate | Responsibility |
|-------|----------------|
| **yb-core** | Frozen public contract: domain types, errors, and the `Store` / `Router` / `RequestLogger` / `Encryptor` / `PasswordHasher` traits. Depends on nothing internal. |
| **yb-wire** | Hand-rolled provider-agnostic IR plus parse/emit (request, response, and SSE) for all four wire formats. Standalone (no `yb-core` dep); cassette-tested offline. |
| **yb-store** | `SqliteStore` + `PostgresStore` implementing `yb_core::Store`, with embedded idempotent migrations, AES-GCM BYOK encryption, Argon2 password hashing, and `yb_`-prefixed key issuance. |
| **yb-providers** | `UpstreamClient` trait with a `reqwest`-backed `HttpClient` and a canned `MockClient`; per-`WireFormat` URL/auth builders and retry classifiers. |
| **yb-reqlog** | `DuckLogger`: a non-blocking `RequestLogger` that buffers turns into a DuckDB WAL on a dedicated thread and rotates them into zstd parquet shards by size/interval/date. |
| **yb-otel** | OpenTelemetry export implementing `yb_core::Observer`: OTLP metrics/logs/traces push and the Prometheus text endpoint. |
| **yb-gateway** | `DeploymentRouter` (hot-swappable DB-backed model table → ordered candidates) and the `Gateway` service that orchestrates parse → route → dispatch-with-fallback → translate → record. |
| **yb-server** | axum router: four inference surfaces, health/catalog, and the selfhosted admin API (users, models, keys, teams, budgets, rate limits, spend). Auth, rate-limit, and budget enforcement live here. |
| **yb-bin** | The `gateway` binary: the only place concrete adapters are built. Loads one TOML config (no env vars), opens the store, builds the router from the DB, assembles `AppState`, and serves. |

### Request lifecycle

1. **yb-server** authenticates the `yb_` bearer against the store, applies rate limits and budgets, and hands the raw body to the gateway tagged with the client surface.
2. **yb-gateway** parses the body into the IR (`yb-wire`), builds a route request from the caller's access policy, resolves an ordered candidate list, and dispatches to each candidate in turn — emitting the request in that deployment's upstream format and failing over on retryable or model-not-found statuses until bytes are committed.
3. The upstream response (buffered or streamed) is translated back into the client's surface format, and the turn is recorded: a telemetry row and spend rollup in the store, and a request/response capture in the reqlog sink.

Defaults preserve "off": `[reqlog] enabled = false` selects `NullLogger`; `[telemetry] enabled = false` selects `NullObserver`; budgets and rate limits are disabled unless enabled in `[features]`.

## Documentation

- [Implementation contract](docs/CONTRACT.md) — crate-by-crate design contract.
- [Identity model v2](docs/CONTRACT-v2.md) — the users-own-keys identity model.
- [`gateway.example.toml`](gateway.example.toml) — fully commented serve config reference.
- [`models.example.toml`](models.example.toml) — fully commented models file reference.
- [`examples/`](examples/) — a worked deployment (serve config plus models file).

## Repository layout

| Path | Purpose |
|------|---------|
| `crates/` | Workspace crates (see Architecture) |
| `docs/` | Design contracts |
| `examples/` | Worked example configuration |
| `scripts/smoke_sqlite.sh` | Offline end-to-end smoke test |
| `gateway.example.toml` | Serve config reference |
| `models.example.toml` | Models file reference |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
