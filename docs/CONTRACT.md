# SovereignGateway — implementation contract (read this first)

SovereignGateway is a low-dependency, single-binary LLM gateway in Rust.

## What is authoritative

| Question | Answer lives in |
| --- | --- |
| The HTTP surface — routes, payloads, status codes, auth | **`docs/openapi.yaml`**, verified against a running server by `scripts/check_openapi.sh` |
| Exact Rust type signatures | **the source** — `crates/yb-core/src/{model,principal,store,spend,rbac,config}.rs` |
| Invariants, layering, naming, defaults | **this file** |

This document deliberately does **not** restate type signatures. It used to, and
they rotted twice: once when the identity model changed (leaving a `CONTRACT.md`
and a `CONTRACT-v2.md` that contradicted each other and the code), and once when
configuration moved from environment variables to TOML while the doc still
described a `GATEWAY_*` env surface that no longer existed. A contract that
duplicates the code drifts from it. Signatures live in one place: the code.

## Naming rules (hard)

Do not reuse any identifier from the upstream design ("Weave"/"workweave",
`rk_`, `ROUTER_*`, `WV_*`, `X-Weave-*`, `model_router_*`). Gateway names only.

- Virtual key prefix: `yb_` (e.g. `yb_a1b2c3d4…`).
- HTTP headers we introduce: `X-Gateway-Key`, `x-gateway-*`.
- DB tables: `api_keys`, `budgets`, `deployments`, `external_keys`,
  `model_aliases`, `rate_limit_counters`, `request_telemetry`, `sessions`,
  `spend_rollup`, `team_memberships`, `teams`, `users`.

## Identity model

- **No installations, no tenancy layer.** There is no `Installation` type, no
  `installations` table, and no `installation_id` column anywhere — including
  the request log.
- **`User` IS the login account** (table `users`), keyed by a unique `username`,
  Argon2-hashed password.
- **Roles are `admin` and `member`** only. `Role::Member` is the default;
  `"user"` parses to `Member`.
- **Keys belong to a user.** `ApiKey.owner_user_id` is required. A member
  creates and revokes their own keys; an admin acts for any user and sees all.
- **Scopes are disjoint**: `inference` may call `/v1`; `admin` is machine auth
  for `/admin/v1`. A key may hold both. A key holding only `admin` cannot run
  inference, and vice versa.
- **Teams** grant access collectively. A key's effective policy is its own
  merged with its team's: deny wins, allow-lists are ceilings.
- **Spend and budgets** attach to a subject: `key | user | team`. Period is
  `day | week | month | total`.
- **Money is `Micros`** (i64, 1 USD = 1_000_000). Never a float.

## Workspace layout and layering

`crates/yb-core` (the frozen contract), `yb-wire`, `yb-store`, `yb-providers`,
`yb-reqlog`, `yb-otel`, `yb-gateway`, `yb-server`, `yb-bin`.

**Imports point inward; only `yb-bin` constructs concrete adapters.** `yb-core`
owns the domain types and the traits (`Store`, `Router`, `Encryptor`,
`PasswordHasher`, `RequestLogger`, `Observer`); the outer crates implement them.
`yb-server` owns transport only — it never speaks a concrete backend.
`yb-wire` MUST NOT depend on `yb-core`: it stays standalone with its own error,
mapped to `Error::Wire` at the gateway boundary.

Every crate must pass `cargo check -p <crate>` and `cargo test -p <crate>`, and
should be clippy-clean.

## Build features

Both default to **off**, and the default build is what ships.

| Feature | Adds | Why off |
| --- | --- | --- |
| `console` | The bundled Preact admin console (`GET /`, `/ui/app.js`) | It is the only thing pulling the `rolldown`/`oxc` build-dependency, which does not compile on the pinned stable toolchain. A deployment that must not expose a gateway UI simply never builds one. |
| `reqlog` | Request/response body capture to DuckDB → parquet | It records prompt and response **content**, and bundles DuckDB. Opt in deliberately. |

The console is **not part of the HTTP contract**. `/admin/v1` is the whole
management surface and does not depend on it — a control plane drives the JSON
API directly.

`[reqlog] enabled = true` on a binary built without the feature is a **startup
error**, never a silent no-op: an operator who asked for logging must not be
left believing it is on.

## Configuration

- **One TOML file. No environment variables** (only `RUST_LOG`). There is no env
  indirection for upstream keys either — each deployment carries its own
  `api_key`.
- Serve config: `[server] [database] [security] [reqlog] [features] [upstream]
  [routing]`. Default path `./gateway.toml`, overridable as the first CLI arg.
- **Models are not in the serve config.** They live in the DB. `gateway import
  <models-file> <config>` is the only path that loads them from a file; `serve`
  reads the DB and never seeds. After import, manage models via `/admin/v1/models`
  — the router hot-reloads, no restart.

## Defaults preserve "off"

`budgets_enabled`, `ratelimit_enabled`, and `[reqlog] enabled` all default to
`false`. No reqlog ⇒ `NullLogger`. `[security] byok_key` unset ⇒ upstream
provider keys are stored **in plaintext**; set it for AES-256-GCM at rest.

On first run `serve` auto-creates `admin`/`admin` when no users exist. Change it
before binding to a network (`gateway setup --password`, or the console).

## Errors

One envelope, `{"error":{"code","message"}}`, for every non-2xx. `code` is the
stable machine string (`Error::code()`); `Error::http_status()` maps the variant
to its status. Clients match on `code`, never on `message`. Rate-limit responses
carry `Retry-After`.

## Testing

- `yb-wire` round-trips through committed cassettes under
  `crates/yb-wire/tests/cassettes/` — offline, no network, no provider keys.
- `scripts/smoke_sqlite.sh` boots the real binary against SQLite and the mock
  upstream and asserts the whole path end to end: boot, health, seeded model,
  runtime model add, key issuance, all four inference surfaces, telemetry, and a
  parquet shard. It builds `--features reqlog` because it asserts the shard.
- `scripts/check_openapi.sh` verifies `docs/openapi.yaml` against a live server:
  structure, coverage in both directions (every mounted route documented, every
  documented route mounted), and response shapes.
