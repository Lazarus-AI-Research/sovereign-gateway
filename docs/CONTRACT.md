# SovereignGateway — implementation contract (read this first)

SovereignGateway is a low-dependency, single-binary LLM gateway in Rust (a less-buggy LiteLLM).
This file is the shared contract every crate is built against. **Do not** reuse any
identifier from the upstream design ("Weave"/"workweave", `rk_`, `ROUTER_*`, `WV_*`,
`X-Weave-*`, `model_router_*`). Gateway names only.

## Naming rules (hard)
- Virtual key prefix: `yb_` (e.g. `yb_a1b2c3d4...`).
- Env vars: `GATEWAY_*`. Provider key envs keep their vendor names (`OPENAI_API_KEY`,
  `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`).
- HTTP headers we introduce: `X-Gateway-Key`, `x-gateway-*`.
- DB tables: `installations`, `api_keys`, `external_keys`, `users`,
  `teams`, `team_memberships`, `request_telemetry`, `feedback`,
  `credit_balance`, `credit_ledger`, `billing_overrides`,
  `spend_rollup`, `budgets`, `rate_limit_counters`.

## Workspace layout
`crates/yb-core` (done, frozen), `yb-wire`, `yb-store`, `yb-providers`, `yb-reqlog`,
`yb-gateway`, `yb-server`, `yb-bin`. Imports point inward; only `yb-bin` constructs
concrete adapters. Every crate must compile under `cargo check -p <crate>` and pass
`cargo test -p <crate>`. Clippy-clean preferred (`cargo clippy -p <crate>`).

## yb-core public API (frozen — implement against exactly this)
Re-exported from `yb_core`:
- ids: `type Id = String`, `type Micros = i64`, `type Timestamp = chrono::DateTime<Utc>`,
  `new_id() -> Id`, `now() -> Timestamp`, `usd_to_micros(f64)`, `micros_to_usd(i64)`.
- `Error` (enum) + `Result<T>`. Variants: `NotFound, BadRequest, Unauthorized, Forbidden,
  Conflict, BudgetExceeded, RateLimited{retry_after:Duration,reason:String},
  NoEligibleProvider(String), Upstream{provider,status:u16,message}, Storage, Crypto,
  Config, Wire, Internal`. `Error::http_status()->u16`, `Error::code()->&str`.
  `From<serde_json::Error>` exists.
- model: `Installation{id,external_id,name,excluded_models:Vec<String>,
  excluded_providers,preferred_models,rpm_limit:Option<i64>,tpm_limit,max_concurrent,
  created_at,updated_at,deleted_at:Option<Timestamp>,created_by:Option<String>}`,
  `NewInstallation{external_id,name,created_by:Option<String>}`,
  `AccessPolicy{allowed_model_ids,denied_model_ids,allowed_provider_ids,denied_provider_ids:Vec<String>}`
  with `is_unrestricted()`, `permits_model(&str)`, `permits_provider(&str)` — both
  take **ids**, which is what keeps a rule matching after a rename.
  `ApiKey{id,installation_id,hash:String,key_prefix,key_suffix,name:Option<String>,
  owner_user_id:Option<Id>,team_id:Option<Id>,access:AccessPolicy,rpm_limit,tpm_limit,
  max_concurrent:Option<i64>,created_at,last_used_at,deleted_at}` + `fingerprint()`.
  `IssuedKey{key:ApiKey,token:String}`.
  `ExternalKey{id,installation_id,provider:String,ciphertext:Vec<u8>,key_prefix,key_suffix,
  created_at,last_used_at}`. `ResolvedCredential{provider,plaintext}`.
  `User{id,installation_id,email,display_name:Option<String>,password_hash:Option<String>,
  role:Role,last_login_at,rpm_limit,tpm_limit,max_concurrent,created_at,deleted_at}`.
  `Team{id,installation_id,name,access:AccessPolicy,created_at,updated_at,deleted_at,created_by}`.
  `TeamMembership{id,team_id,user_id,role:Role,created_at}`.
  `Role` enum `{Viewer,Member,Admin}` (Ord; `at_least`, `as_str`, `parse`).
  `TelemetryRecord{id,request_id,trace_id:Option<String>,installation_id,api_key_id:Option<Id>,
  user_id:Option<Id>,surface:String,requested_model,decision_model,decision_provider,
  input_tokens:i64,output_tokens,cache_read_tokens,cache_write_tokens,cost_micros:i64,
  status:i32,is_error:bool,latency_ms:i64,created_at}`.
- routing: `WireFormat{Anthropic,OpenaiChat,OpenaiResponses,Gemini}` (`as_str`),
  `ProviderKind{Anthropic,Openai,OpenaiCompat,Gemini}` (`default_format()->WireFormat`),
  `ModelRecord{id,name,created_at,updated_at}` — the public model entity; one
  model has N deployments and N aliases, and `name` is mutable via
  `Store::rename_model`, which leaves the old name behind as an alias.
  `ProviderRecord{id,name,api_base,api_key,extra,…}` — one upstream endpoint,
  its credential, and its edge settings, shared by every deployment through it.
  `Deployment{model_id,model_name,provider_id,provider:String,kind:ProviderKind,upstream_model,
  api_base:Option<String>,api_key_env:Option<String>,upstream_format:WireFormat,
  weight:u32,pricing:Option<ModelPrice>}`,
  `RouteRequest{requested_model,estimated_input_tokens:u32,has_tools,has_images:bool,
  excluded_model_ids:BTreeSet<String>,enabled_providers:Option<BTreeSet<String>>,
  denied_providers:BTreeSet<String>,preferred_models:Vec<String>}` (Default),
  `Decision{candidates:Vec<Deployment>,reason:String}`,
  `trait Router{ fn resolve(&self,&RouteRequest)->Result<Decision> }`.
- catalog: `ModelPrice{input_per_1m,output_per_1m,cache_read_multiplier,cache_write_multiplier:f64}`
  with `new(i,o)`, `cost_micros(input,output,cache_read,cache_write:i64)->i64`;
  `builtin_price(&str)->Option<ModelPrice>`.
- spend: `SubjectType{Key,User,Installation,Team}` (`as_str`,`parse`),
  `Period{Day,Week,Month,Total}` (`as_str`,`parse`,`bucket_start(Timestamp)->Timestamp`),
  `BudgetAction{Block,Alert}`, `Budget{id,installation_id,subject_type,subject_id:String,
  period,hard_limit_micros:i64,soft_limit_micros:Option<i64>,action,enabled:bool,
  created_at,updated_at,deleted_at}`, `BreachKind{None,Soft,Hard}`,
  `BudgetDecision{allowed,breach,spent_micros,limit_micros,period,period_reset_at}` (`ok()`),
  `RollupDelta{installation_id,subject_type,subject_id,period,period_start,spend_micros,
  request_count,input_tokens,output_tokens}`, `SpendRow{...}`.
- ratelimit: `Limits{rpm,tpm,max_concurrent:i64}` (0=unlimited), `Limiter::new(Duration)`,
  `Limiter::check(scope,Limits,now)->(RateDecision,ConcurrencyGuard)`,
  `charge_tokens(...)->bool`, `tpm_exhausted(...)->(bool,Duration)`. `RateDecision{allowed,
  retry_after:Duration,reason:&'static str}`.
- rbac: `Action{ManageKeys,ViewSpend,EditConfig,ManageMembers,ReadCatalog}` (`min_role`),
  `authorize(Role,Action)->Result<()>`.
- crypto: `trait Encryptor{encrypt(&[u8],aad:&[u8])->Result<Vec<u8>>;decrypt(...)}`,
  `trait PasswordHasher{hash(&str)->Result<String>;verify(&str,&str)->bool}`, `NoopEncryptor`.
- reqlog: `RequestLogRecord{ts,request_id,trace_id:Option<String>,installation_id,surface,
  requested_model,decision_model,decision_provider,upstream_status:i32,is_error,
  request_bytes:i64,response_bytes,response_truncated:bool,request_body:Vec<u8>,response_body:Vec<u8>}`,
  `trait RequestLogger{ fn log(&self,RequestLogRecord) }`, `NullLogger`.
- principal: `KeyAuth{installation:Installation,api_key:ApiKey}`,
  `UserPrincipal{user_id,installation_id,role,team_ids:Vec<Id>,expires_at}`,
  `AdminPrincipal`, `Principal{User(..),Admin(..)}` (`role()`,`installation_id()`).
- config: `DeploymentMode{Selfhosted,Managed}`, `Strategy{Simple,RoundRobin,LeastBusy}`,
  `DeploymentConfig{provider,kind,upstream_model,api_base,api_key_env,
  upstream_format:Option<WireFormat>,weight:u32,pricing:Option<ModelPrice>}`,
  `ModelConfig{model_name,deployments:Vec<DeploymentConfig>}`,
  `RoutingConfig{model_list:Vec<ModelConfig>,fallbacks:HashMap<String,Vec<String>>,strategy}`.
- store: `trait Store` (async_trait) — full CRUD; see `crates/yb-core/src/store.rs` for the
  exact method list. `LimitColumns{rpm,tpm,max_concurrent:Option<i64>}`.

## yb-wire — the IR (self-implemented, deps: serde, serde_json, thiserror only)
A provider-agnostic intermediate representation + parse/emit for all 4 wire formats.
- IR types: `ChatRequest{model:String,messages:Vec<Message>,system:Option<Vec<ContentBlock>>,
  tools:Vec<Tool>,tool_choice:Option<ToolChoice>,max_tokens:Option<u32>,temperature:Option<f32>,
  top_p:Option<f32>,stop:Vec<String>,stream:bool,reasoning:Option<Reasoning>,
  metadata:serde_json::Map,extra:serde_json::Map}`.
  `Role{System,User,Assistant,Tool}`.
  `ContentBlock` enum: `Text{text}`, `Image{media_type,data(base64)|url}`,
  `ToolUse{id,name,input:Value}`, `ToolResult{tool_use_id,content,is_error}`, `Thinking{text}`.
  `Tool{name,description:Option<String>,input_schema:Value}`. `ToolChoice{Auto,None,Required,Tool(name)}`.
  `Reasoning{effort:Option<String>,budget_tokens:Option<u32>}`.
  `ChatResponse{id,model,content:Vec<ContentBlock>,stop_reason:StopReason,usage:Usage}`.
  `StopReason{EndTurn,MaxTokens,StopSequence,ToolUse,Other(String)}`.
  `Usage{input_tokens,output_tokens,cache_read_tokens,cache_write_tokens:u32}`.
  `StreamEvent` enum: `MessageStart{model}`, `TextDelta{text}`, `ThinkingDelta{text}`,
  `ToolUseStart{id,name}`, `ToolUseDelta{partial_json}`, `UsageDelta{usage}`, `Done{stop_reason}`.
- Per-format module (`anthropic`,`openai_chat`,`openai_responses`,`gemini`), each exposing:
  `parse_request(&[u8])->Result<ChatRequest>`,
  `emit_request(&ChatRequest,&EmitOptions)->Result<(Vec<u8>,Vec<(String,String)>)>` (body+headers),
  `parse_response(&[u8])->Result<ChatResponse>`,
  `emit_response(&ChatResponse)->Result<Vec<u8>>`,
  and streaming: a function that turns one upstream SSE event line into `Vec<StreamEvent>`
  (`decode_sse(line:&str, state:&mut SseState)->Vec<StreamEvent>`), and an emitter that turns
  `StreamEvent`s into client-native SSE bytes (`encode_sse(&[StreamEvent],&mut EmitState)->Vec<u8>`).
- `EmitOptions{target_model:String,force_reasoning_effort:Option<String>,stream:bool}`.
- `WireError` -> map to `yb_core::Error::Wire` at the boundary (gateway). yb-wire MUST NOT depend
  on yb-core; keep it standalone with its own `thiserror` error.
- Tests: a cassette harness. `tests/cassettes/<name>.json` =
  `{"inbound_format","inbound_body"(json),"target_format","expected_upstream_body"(json),
  "upstream_sse":[lines],"client_format","expected_client_sse"(string)}`.
  A loader replays: assert `emit_request(parse_request(inbound))` round-trips semantically
  (compare parsed JSON, not bytes), and SSE translation matches. Ship at least: anthropic<->openai
  request round-trip (text + tools), openai streaming -> anthropic SSE, gemini parse.
  Provide a `record` helper but tests run offline from committed fixtures.

## yb-store (deps: yb-core, sqlx[sqlite,postgres], argon2, aes-gcm, sha2, rand, base64)
- `SqliteStore` and `PostgresStore`, both `impl yb_core::Store`. Construct via
  `SqliteStore::connect(path:&str)->Result<Self>` (pragmas: WAL, busy_timeout=5000,
  foreign_keys=ON, single writer via `SqlitePoolOptions::max_connections(1)` for writes is ok,
  but a small pool is fine) and `PostgresStore::connect(dsn:&str)->Result<Self>`.
- Migrations embedded as `&str` constants applied in `migrate()`; idempotent
  (`CREATE TABLE IF NOT EXISTS`). Two dialect bodies (sqlite/postgres). Use runtime `sqlx::query`
  (NOT the compile-time macros — no live DB at build). Map rows manually.
- Type deltas: ids TEXT; timestamps stored as RFC3339 TEXT in sqlite (use chrono to_rfc3339),
  `TIMESTAMPTZ` in postgres; money BIGINT micros; `Vec<String>` columns as JSON TEXT (serde_json).
- crypto module: `AesGcmEncryptor` (impl Encryptor; 32-byte key, random 12-byte nonce prepended
  to ciphertext, AAD bound) and `Argon2Hasher` (impl PasswordHasher). Plus free fns:
  `hash_token(token:&str)->String` (hex sha256), `generate_api_key()->(token:String,prefix,suffix)`
  with `yb_` prefix, and `issue_api_key(store,installation_id,name,...)->IssuedKey` helper.
- Tests: round-trip an installation+key+telemetry+budget on a temp sqlite file
  (`SqliteStore::connect(":memory:")` won't share across pool connections — use a tempfile).

## yb-providers (deps: yb-core, yb-wire, reqwest[stream,rustls,json], futures, bytes)
- `trait UpstreamClient{ async fn send(&self, req:UpstreamRequest) -> Result<UpstreamResponse> }`
  where `UpstreamRequest{url:String,headers:Vec<(String,String)>,body:Vec<u8>,stream:bool}` and
  `UpstreamResponse{status:u16,headers,stream: impl Stream<Item=Result<Bytes>>}` (box it:
  `Pin<Box<dyn Stream<Item=Result<bytes::Bytes,yb_core::Error>>+Send>>`). Non-stream returns full body.
- One reqwest-backed `HttpClient` is enough for all kinds (they only differ in URL + auth headers,
  which the gateway/emitter set). Provide helpers to build the URL+auth headers per `ProviderKind`
  (`build_url(kind,api_base,upstream_model,stream)`, `auth_headers(kind,api_key)`).
- `is_retryable(status)->bool` (5xx,408,429) and `is_model_not_found(status)->bool` (404).
- A `MockClient` (feature or always-compiled) returning canned responses for tests/smoke.

## yb-reqlog (deps: yb-core, duckdb[bundled], tokio, serde_json)
- `DuckLogger` impl `yb_core::RequestLogger`. `DuckLogger::new(cfg:ReqlogConfig)->Result<Self>`.
  `ReqlogConfig{dir:PathBuf,queue_size:usize,shard_max_bytes:u64,rotate_interval:Duration,
  retention_days:u32,max_body_bytes:usize}`.
- `log()` enqueues onto a bounded `std::sync::mpsc`/`tokio` channel and returns immediately
  (drop + count on full). A background worker thread opens `dir/wal.duckdb`, creates the `turns`
  table, batch-inserts. A rotator: when `wal.duckdb` file size > `shard_max_bytes` OR on interval/
  date change, `COPY (SELECT * FROM turns) TO 'dir/shards/<rfc3339>.parquet' (FORMAT parquet,
  COMPRESSION zstd)`, then `DELETE FROM turns; CHECKPOINT;`. Prune shards older than retention.
- `turns` columns: id UBIGINT, ts TIMESTAMP, log_date DATE, request_id VARCHAR, trace_id VARCHAR,
  installation_id VARCHAR, surface VARCHAR, requested_model VARCHAR, decision_model VARCHAR,
  decision_provider VARCHAR, upstream_status INTEGER, is_error BOOLEAN, request_bytes INTEGER,
  response_bytes INTEGER, response_truncated BOOLEAN, request_body BLOB, response_body BLOB.
- duckdb is a sync C API; run it on a dedicated `std::thread`, not the tokio runtime.
- Test: log N records, force a rotate, assert a `.parquet` shard exists and WAL is truncated.

## yb-gateway (deps: yb-core, yb-wire, yb-providers, yb-reqlog)
- `DeploymentRouter` impl `yb_core::Router`: built from `RoutingConfig`; `resolve` returns the
  candidate list = [primary deployments for requested model (filtered by excluded_models/
  enabled/denied providers, weighted-shuffled per strategy)] ++ [deployments of each fallback model].
  Empty after filtering -> `Error::NoEligibleProvider`.
- `Gateway` service: `handle(surface:WireFormat, body:&[u8], ctx:RequestCtx) -> GatewayResponse`.
  Steps: parse body -> ChatRequest (yb-wire), build RouteRequest (apply ctx access policy +
  installation exclusions), router.resolve, then `dispatch`: for each candidate, emit_request to
  the candidate's upstream_format, call UpstreamClient, on retryable/404 try next; translate the
  upstream response/stream back into `surface` format (yb-wire). Record telemetry (cost via pricing),
  spend rollup, and a reqlog record. Stop failover once first upstream byte is committed.
- `RequestCtx{installation:Installation,api_key:Option<ApiKey>,request_id,trace_id}` carrying
  resolved excluded models/providers from access policy.
- Streaming: return an `impl Stream<Item=Result<Bytes>>` for the client; non-stream returns bytes.

## yb-server (deps: yb-core, yb-wire, yb-gateway, axum, tower)
- `build_router(AppState)->axum::Router`. Inference routes: `POST /v1/messages` (Anthropic),
  `POST /v1/chat/completions` (OpenAI chat), `POST /v1/responses` (OpenAI responses),
  `POST /v1beta/models/:model::action` or `/v1beta/*path` (Gemini generateContent/streamGenerateContent).
  Plus `GET /health`, `GET /v1/models`. Admin under `/admin/v1/*` (selfhosted only): keys, users,
  teams, budgets, rate-limits, spend, key access. Middleware layers: auth (verify `yb_` bearer from
  `Authorization`/`x-gateway-key`), rate-limit, budget. 402/429/403 mapping via `Error::http_status`.
- `AppState{store:Arc<dyn Store>, gateway:Arc<Gateway>, limiter:Arc<Limiter>, encryptor, hasher,
  session_secret, mode:DeploymentMode, admin_password}`.

## yb-bin (the `gateway` binary)
- Read env (`GATEWAY_DB_BACKEND` sqlite|postgres, `GATEWAY_SQLITE_PATH`, `GATEWAY_POSTGRES_DSN`,
  `GATEWAY_DEPLOYMENT_MODE`, `GATEWAY_ADMIN_PASSWORD`, `GATEWAY_SESSION_SECRET`,
  `GATEWAY_BUDGETS_ENABLED`, `GATEWAY_RATELIMIT_*`, `GATEWAY_REQLOG_DIR` + knobs,
  `GATEWAY_BYOK_KEY`, `GATEWAY_BIND` default `0.0.0.0:8080`, `GATEWAY_CONFIG` default
  `gateway.yaml`). Build the chosen Store, run `migrate()`, load `gateway.yaml` into RoutingConfig,
  build DeploymentRouter+Gateway+Limiter+reqlog, serve axum. Ship an example `gateway.yaml`.

## Env defaults preserve "off": no reqlog dir => NullLogger; budgets/ratelimit disabled by default.
