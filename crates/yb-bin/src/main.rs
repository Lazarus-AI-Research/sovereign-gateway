//! # gateway — the binary (composition root)
//!
//! The only place in the workspace that constructs concrete adapters and wires
//! them together. Every other crate speaks in terms of the `yb-core` traits
//! (`Store`, `Router`, `UpstreamClient`, `RequestLogger`, `Encryptor`,
//! `PasswordHasher`).
//!
//! ## Configuration: one TOML file, no environment variables
//! The gateway is configured **entirely** by a single TOML file (default
//! `./gateway.toml`, or the first CLI argument). There are no `GATEWAY_*`
//! environment variables, and no environment indirection for upstream keys —
//! each deployment carries its own `api_key` directly. The only environment
//! variable read at all is `RUST_LOG` (standard tracing).
//!
//! ## Models live in the database (one source of truth)
//! `serve` builds the router from the `deployments` table and **never** reads
//! models from the serve config — the config carries none. Configure models in
//! exactly one place:
//! - bulk-load from a dedicated models file once with
//!   `gateway import <models-file> [config]` (upserts its `[[model]]` entries
//!   into the DB, idempotent by natural key), and/or
//! - manage them live via `POST/DELETE /admin/v1/models` (hot-reloads the router).
//!
//! ## Commands
//! - `gateway [serve] [config.toml]` — run the gateway (router from the DB).
//! - `gateway import <models-file> [config.toml]` — upsert a models file into the DB, exit.
//!
//! ## Serve sequence
//! 1. Initialise `tracing-subscriber` (honours `RUST_LOG`).
//! 2. Load `gateway.toml` into a [`Config`].
//! 3. Open the configured [`Store`] backend and run [`Store::migrate`].
//! 4. Load deployments from the DB and build the [`DeploymentRouter`].
//! 5. Build the upstream client, request-log sink, gateway, limiter, encryptor,
//!    and password hasher.
//! 6. Assemble [`AppState`], call [`build_router`], and serve.
//!
//! ## Example `gateway.toml`
//! See `gateway.example.toml` in the repository root.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;

use yb_core::config::{
    Config, DatabaseConfig, DbBackend, ModelConfig, ModelsFile, ReqlogSettings, UpstreamMode,
};
use yb_core::crypto::{Encryptor, NoopEncryptor, PasswordHasher};
use yb_core::ratelimit::Limiter;
use yb_core::{NewDeployment, NullLogger, NullObserver, Observer, RequestLogger, Store};
use yb_gateway::{DeploymentRouter, Gateway};
use yb_otel::OtelSink;
use yb_providers::{HttpClient, MockClient, UpstreamClient};
use yb_reqlog::{DuckLogger, ReqlogConfig};
use yb_server::{build_router, AppState};
use yb_store::{AesGcmEncryptor, Argon2Hasher, PostgresStore, SqliteStore};

/// Default config path when no CLI argument is given.
const DEFAULT_CONFIG: &str = "gateway.toml";

#[tokio::main]
async fn main() {
    init_tracing();
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        // `gateway setup [config] [--user U] [--password P]` — initialize the DB
        // and create/reset an admin user (defaults to admin/admin). Optional:
        // `serve` auto-creates admin/admin on first run if no users exist.
        Some("setup") => run_setup(&args).await,
        // `gateway set-role <user> <admin|member> [config]` — upsert a user's
        // role directly in the DB. Creates the user (sso/saml-loginable, no
        // password) if absent, so a role can be assigned BEFORE first login.
        Some("set-role") => run_set_role(&args).await,
        // `gateway import <models-file> [config]` — one-shot: upsert a dedicated
        // models file into the database, then exit. Models live ONLY in the DB;
        // the serve config never carries them and `serve` never seeds.
        Some("import") => run_import(&args).await,
        Some("serve") => run_serve(&arg_or_default(&args, 2)).await,
        // Backward-compatible: `gateway [config]` serves.
        Some(other) if !other.starts_with('-') => run_serve(other).await,
        _ => run_serve(DEFAULT_CONFIG).await,
    };
    if let Err(e) = result {
        tracing::error!(error = %e, "gateway failed");
        std::process::exit(1);
    }
}

/// The positional arg at `idx`, or the default config path.
fn arg_or_default(args: &[String], idx: usize) -> String {
    args.get(idx).cloned().unwrap_or_else(|| DEFAULT_CONFIG.to_string())
}

/// Initialise the global tracing subscriber. Honours `RUST_LOG`; defaults to
/// `info`. (`RUST_LOG` is the standard tracing knob, not a gateway config var.)
fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();
}

/// `gateway setup [config] [--user U] [--password P]` — initialize the database
/// and create (or reset) an admin user. Username/password default to
/// `admin`/`admin`. Passwords are Argon2-hashed and stored in the DB, never in
/// the config file. Idempotent: re-running resets the named admin's password.
async fn run_setup(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut config_path = DEFAULT_CONFIG.to_string();
    let mut username = "admin".to_string();
    let mut password = "admin".to_string();
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--user" | "-u" => { i += 1; username = args.get(i).cloned().unwrap_or(username); }
            "--password" | "-p" => { i += 1; password = args.get(i).cloned().unwrap_or(password); }
            other if !other.starts_with('-') => config_path = other.to_string(),
            other => return Err(format!("unknown setup flag: {other}").into()),
        }
        i += 1;
    }

    let cfg = load_config(&config_path)?;
    let store: Arc<dyn Store> = build_store(&cfg.database).await?;
    store.migrate().await?;
    println!("database initialized ({})", describe_db(&cfg.database));

    let created = upsert_admin(store.as_ref(), &username, &password).await?;
    let verb = if created { "created" } else { "reset password for" };
    println!("{verb} admin user \"{username}\".");
    if password == "admin" {
        println!("  ↳ default password is \"admin\" — change it after first sign-in.");
    }
    Ok(())
}

/// Create the named admin user, or reset its password if it already exists.
/// Returns `true` when a new user was created.
async fn upsert_admin(
    store: &dyn Store,
    username: &str,
    password: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    use yb_core::crypto::PasswordHasher;
    let hash = Argon2Hasher::new().hash(password)?;
    if let Some(existing) = store.get_user_by_username(username).await? {
        store.set_user_password(&existing.id, &hash).await?;
        store.set_user_role(&existing.id, yb_core::Role::Admin).await?;
        Ok(false)
    } else {
        store
            .create_user(&yb_core::User {
                id: yb_core::new_id(),
                username: username.to_string(),
                password_hash: hash,
                role: yb_core::Role::Admin,
                rpm_limit: None,
                tpm_limit: None,
                max_concurrent: None,
                created_at: yb_core::now(),
                last_login_at: None,
                deleted_at: None,
            })
            .await?;
        Ok(true)
    }
}

/// `gateway set-role <user> <admin|member> [config]` — set a user's role,
/// creating the user if it does not exist yet. A created user has no usable
/// password (sso/saml login only), so an operator can designate an admin *before*
/// that person's first sign-in. Idempotent.
async fn run_set_role(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let username = args.get(2).ok_or("usage: gateway set-role <user> <admin|member> [config]")?;
    let role_str = args.get(3).ok_or("usage: gateway set-role <user> <admin|member> [config]")?;
    let config_path = arg_or_default(args, 4);
    let role = yb_core::Role::parse(role_str)?;

    let cfg = load_config(&config_path)?;
    let store: Arc<dyn Store> = build_store(&cfg.database).await?;
    store.migrate().await?;

    let username = username.trim().to_lowercase();
    match store.get_user_by_username(&username).await? {
        Some(user) => {
            store.set_user_role(&user.id, role).await?;
            println!("set role of \"{username}\" to {}.", role.as_str());
        }
        None => {
            // Pre-provision an external-login user with a non-verifying password
            // (mirrors how the server provisions sso users on first login).
            store
                .create_user(&yb_core::User {
                    id: yb_core::new_id(),
                    username: username.clone(),
                    password_hash: "!sso".to_string(),
                    role,
                    rpm_limit: None,
                    tpm_limit: None,
                    max_concurrent: None,
                    created_at: yb_core::now(),
                    last_login_at: None,
                    deleted_at: None,
                })
                .await?;
            println!(
                "created \"{username}\" as {} (no password — sign in via sso/saml).",
                role.as_str()
            );
        }
    }
    Ok(())
}

/// A short human description of the database target for setup output.
fn describe_db(db: &yb_core::config::DatabaseConfig) -> String {
    match db.backend {
        DbBackend::Sqlite => format!("sqlite: {}", db.path),
        DbBackend::Postgres => "postgres".to_string(),
    }
}

/// `gateway import <models-file> [config]` — upsert a dedicated models file's
/// `[[model]]` entries into the database (idempotent by natural key), then exit.
/// This is the *only* path that writes models from a file; the live model list
/// lives in the DB and is otherwise managed via `POST/DELETE /admin/v1/models`.
/// The serve config (arg 3, default `gateway.toml`) supplies only the database
/// connection — it carries no models of its own.
async fn run_import(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let models_path = args.get(2).ok_or(
        "usage: gateway import <models-file> [config]  (the models file holds [[model]] entries)",
    )?;
    let config_path = arg_or_default(args, 3);
    let cfg = load_config(&config_path)?;
    let models = load_models_file(models_path)?;
    let store: Arc<dyn Store> = build_store(&cfg.database).await?;
    store.migrate().await?;

    let total: usize = models.models.iter().map(|m| m.deployments.len()).sum();
    if total == 0 {
        println!("no [[model]] entries in {models_path}; nothing to import");
        return Ok(());
    }
    let provider_count = seed_providers(store.as_ref(), &models.providers).await?;
    let hoisted = hoist_legacy_deployment_credentials(store.as_ref(), &models.models).await?;
    let inserted = seed_models(store.as_ref(), &models.models).await?;
    let alias_count = seed_aliases(store.as_ref(), &models.models).await?;
    println!(
        "imported {inserted} new deployment(s) into the database; {} already present ({total} in file)",
        total - inserted
    );
    if provider_count > 0 {
        println!("configured {provider_count} provider(s)");
    }
    if hoisted > 0 {
        println!(
            "hoisted credentials for {hoisted} provider(s) off their deployments \
             — declare them in [[provider]] blocks instead"
        );
    }
    if alias_count > 0 {
        println!("seeded {alias_count} model alias(es)");
    }
    Ok(())
}

/// `gateway serve [config]` — run the gateway. The router is built entirely from
/// the **database**; the serve config carries no model list. Use
/// `gateway import` to load models from a file.
async fn run_serve(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // --- 1. configuration ---------------------------------------------------
    let cfg = load_config(config_path)?;
    tracing::info!(config = %config_path, "configuration loaded");

    // --- 2. store backend ---------------------------------------------------
    let store: Arc<dyn Store> = build_store(&cfg.database).await?;
    store.migrate().await?;
    tracing::info!("store migrated");

    if store.count_users().await.unwrap_or(0) == 0 {
        // First run: implicitly create a default admin user so the console is
        // usable immediately. Customize with `gateway setup --user … --password …`.
        match upsert_admin(store.as_ref(), "admin", "admin").await {
            Ok(_) => tracing::warn!(
                "no users existed — created a default admin (username \"admin\", password \"admin\"). \
                 CHANGE IT: sign in to the admin UI, or run `gateway setup --password <new>`"
            ),
            Err(e) => tracing::error!(error = %e, "failed to create the default admin user"),
        }
    }

    // --- 3. build the router from the DB (the single source of truth) -------
    let deployments = store.list_deployments().await?;
    if deployments.is_empty() {
        tracing::warn!(
            "no models in the database; every request will 4xx until you add some \
             (`gateway import <file>` or POST /admin/v1/models)"
        );
    }
    tracing::info!(deployments = deployments.len(), "model deployments loaded from db");
    let aliases: std::collections::HashMap<String, String> = store
        .list_aliases()
        .await?
        .into_iter()
        .map(|a| (a.alias, a.target))
        .collect();
    let router = Arc::new(DeploymentRouter::from_deployments(
        &deployments,
        cfg.routing.strategy,
        cfg.routing.fallbacks.clone(),
        aliases,
    ));

    // --- 4. upstream client + request log + telemetry + gateway --------------
    let client = build_upstream_client(cfg.upstream.mode);
    let logger: Arc<dyn RequestLogger> = build_reqlog(&cfg.reqlog)?;
    let observer: Arc<dyn Observer> = if cfg.telemetry.enabled {
        tracing::info!(
            otlp = cfg.telemetry.otlp_endpoint.as_deref().unwrap_or("(push off)"),
            prometheus = cfg.telemetry.prometheus,
            "telemetry export enabled (metrics + per-turn events/spans)"
        );
        OtelSink::start(&cfg.telemetry)
    } else {
        Arc::new(NullObserver)
    };
    if cfg.upstream.cloudflare_access.as_ref().is_some_and(|c| c.is_complete()) {
        tracing::info!(
            "cloudflare access service token loaded; deployments flagged \
             extra.cloudflare_access will present it"
        );
    }
    let gateway = Arc::new(
        Gateway::with_observer(
            client,
            router.clone(),
            store.clone(),
            logger,
            observer.clone(),
        )
        .with_cloudflare_access(cfg.upstream.cloudflare_access.clone()),
    );

    // --- 5. limiter, crypto, hasher -----------------------------------------
    let window = Duration::from_secs(cfg.features.ratelimit_window_secs.max(1));
    let limiter = Arc::new(Limiter::new(window));
    let encryptor: Arc<dyn Encryptor> = build_encryptor(cfg.security.byok_key.as_deref());
    let hasher: Arc<dyn PasswordHasher> = Arc::new(Argon2Hasher::new());

    // --- 6. assemble + serve ------------------------------------------------
    let mode = cfg.server.deployment_mode;

    // Admin-console auth: the enabled login providers, plus an IdP client built
    // once when `sso` is configured. A misconfigured/unavailable sso config
    // yields `None` (the provider is simply not offered).
    let auth = Arc::new(cfg.auth.clone());
    let sso = auth
        .sso
        .as_ref()
        .filter(|_| auth.has(yb_core::config::AuthProvider::Sso))
        .and_then(yb_server::sso::SsoClient::from_config)
        .map(Arc::new);
    if auth.has(yb_core::config::AuthProvider::Sso) {
        tracing::info!(configured = sso.is_some(), "admin auth: sso provider enabled");
    }

    let state = AppState {
        store,
        gateway,
        router,
        limiter,
        encryptor,
        hasher,
        observer,
        mode,
        auth,
        sso,
        budgets_enabled: cfg.features.budgets_enabled,
        ratelimit_enabled: cfg.features.ratelimit_enabled,
    };

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&cfg.server.bind).await?;
    tracing::info!(addr = %cfg.server.bind, mode = ?mode, "gateway listening");
    axum::serve(listener, app).await?;
    Ok(())
}

// ---- config ----------------------------------------------------------------

/// Load and parse `path` into a [`Config`]. A missing file yields the default
/// configuration (sqlite, empty model list) so the server can still boot for
/// health checks; a present-but-invalid file is a hard error.
fn load_config(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(toml::from_str(&text).map_err(|e| format!("parsing {path}: {e}"))?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(config = %path, "config file not found; using defaults (sqlite, no models)");
            Ok(Config::default())
        }
        Err(e) => Err(format!("reading {path}: {e}").into()),
    }
}

// ---- store -----------------------------------------------------------------

/// Construct the configured [`Store`] backend.
async fn build_store(db: &DatabaseConfig) -> Result<Arc<dyn Store>, Box<dyn std::error::Error>> {
    match db.backend {
        DbBackend::Sqlite => {
            tracing::info!(backend = "sqlite", path = %db.path, "opening store");
            Ok(Arc::new(SqliteStore::connect(&db.path).await?))
        }
        DbBackend::Postgres => {
            let dsn = db
                .dsn
                .as_deref()
                .ok_or("database.backend = \"postgres\" requires database.dsn")?;
            tracing::info!(backend = "postgres", "opening store");
            Ok(Arc::new(PostgresStore::connect(dsn).await?))
        }
    }
}

// ---- model seeding ---------------------------------------------------------

/// Load and parse a dedicated models file (a list of `[[model]]` entries).
fn load_models_file(path: &str) -> Result<ModelsFile, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))?;
    let models: ModelsFile = toml::from_str(&text).map_err(|e| format!("parsing {path}: {e}"))?;
    Ok(models)
}

/// Upsert a models file's deployments into the `deployments` table (idempotent
/// by natural key). Returns the number of newly-inserted deployments.
async fn seed_models(
    store: &dyn Store,
    models: &[ModelConfig],
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut inserted = 0usize;
    for mc in models {
        // Once per block, before its deployments: a `[[model]]` that declares
        // only aliases still needs a model row for `seed_aliases` to target.
        store.ensure_model(&mc.model_name).await?;
        for dc in &mc.deployments {
            let rec = NewDeployment {
                model_name: mc.model_name.clone(),
                provider_name: dc.provider.clone(),
                upstream_model: dc.upstream_model.clone(),
                upstream_format: dc.upstream_format,
                weight: dc.weight,
                pricing: dc.pricing,
                health_check: dc.health_check,
                health_path: dc.health_path.clone(),
            };
            if store.seed_deployment(&rec).await? {
                inserted += 1;
            }
        }
    }
    Ok(inserted)
}

/// Upsert each `[[provider]]` block: the endpoint, its credential, its extras.
///
/// Run before the models, so a deployment naming a provider finds it already
/// configured rather than creating a credential-less stub.
async fn seed_providers(
    store: &dyn Store,
    providers: &[yb_core::config::ProviderConfig],
) -> Result<usize, Box<dyn std::error::Error>> {
    for pc in providers {
        if pc.name.trim().is_empty() {
            return Err("a [[provider]] block is missing its name".into());
        }
        let existing = store.ensure_provider(&pc.name).await?;
        store
            .update_provider(
                &existing.id,
                &pc.name,
                pc.api_base.as_deref(),
                pc.api_key.as_deref(),
                &pc.extra,
            )
            .await?;
    }
    Ok(providers.len())
}

/// Hoist credentials that a pre-provider models file still carries on its
/// deployments up onto the provider they name.
///
/// `api_base`/`api_key`/`extra` moved from the deployment to the provider. A
/// file written before that keeps working: the first deployment naming a
/// provider donates its settings, and a later disagreement is reported rather
/// than silently dropped.
async fn hoist_legacy_deployment_credentials(
    store: &dyn Store,
    models: &[ModelConfig],
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut hoisted: std::collections::HashMap<String, (Option<String>, Option<String>)> =
        std::collections::HashMap::new();
    for mc in models {
        for dc in &mc.deployments {
            if dc.api_base.is_none() && dc.api_key.is_none() && dc.extra.is_empty() {
                continue;
            }
            let provider = store.ensure_provider(&dc.provider).await?;
            // Already configured explicitly by a [[provider]] block, or by an
            // earlier deployment: leave it alone.
            if provider.api_base.is_some() || provider.api_key.is_some() {
                if let Some((base, key)) = hoisted.get(&dc.provider) {
                    if base != &dc.api_base || key != &dc.api_key {
                        eprintln!(
                            "warning: deployments of provider \"{}\" disagree on api_base/api_key; \
                             keeping the first. Move them to a [[provider]] block.",
                            dc.provider
                        );
                    }
                }
                continue;
            }
            store
                .update_provider(
                    &provider.id,
                    &dc.provider,
                    dc.api_base.as_deref(),
                    dc.api_key.as_deref(),
                    &dc.extra,
                )
                .await?;
            hoisted.insert(dc.provider.clone(), (dc.api_base.clone(), dc.api_key.clone()));
        }
    }
    Ok(hoisted.len())
}

/// Upsert each model's declared `aliases` into the `model_aliases` table
/// (`alias` → `model_name`). Returns the number of aliases written.
async fn seed_aliases(
    store: &dyn Store,
    models: &[ModelConfig],
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut count = 0usize;
    for mc in models {
        if mc.aliases.is_empty() {
            continue;
        }
        let model = store.ensure_model(&mc.model_name).await?;
        for alias in &mc.aliases {
            store.upsert_alias(alias, &model.id).await?;
            count += 1;
        }
    }
    Ok(count)
}

// ---- upstream client -------------------------------------------------------

/// Canned Anthropic Messages response replayed by the offline mock upstream.
const MOCK_ANTHROPIC_RESPONSE: &str = r#"{
  "id": "msg_gateway_mock",
  "type": "message",
  "role": "assistant",
  "model": "gateway-mock",
  "content": [
    { "type": "text", "text": "Hello from the gateway mock upstream." }
  ],
  "stop_reason": "end_turn",
  "usage": { "input_tokens": 11, "output_tokens": 7 }
}"#;

/// Build the upstream client. `upstream.mode = "mock"` returns a non-networked
/// client replaying a canned Anthropic Messages response (fully offline; the
/// routed deployment must speak the `anthropic` upstream format so the body
/// parses). Otherwise a real `reqwest`-backed client.
fn build_upstream_client(mode: UpstreamMode) -> Arc<dyn UpstreamClient> {
    match mode {
        UpstreamMode::Mock => {
            tracing::warn!("upstream.mode = mock: upstream calls return a canned response (offline)");
            Arc::new(MockClient::json(MOCK_ANTHROPIC_RESPONSE.as_bytes().to_vec()))
        }
        UpstreamMode::Http => Arc::new(HttpClient::new()),
    }
}

// ---- request log -----------------------------------------------------------

/// Build the request-log sink: a [`DuckLogger`] when `reqlog.enabled`, else the
/// no-op [`NullLogger`].
fn build_reqlog(r: &ReqlogSettings) -> Result<Arc<dyn RequestLogger>, Box<dyn std::error::Error>> {
    if !r.enabled {
        return Ok(Arc::new(NullLogger));
    }
    let cfg = ReqlogConfig {
        dir: PathBuf::from(&r.dir),
        queue_size: r.queue_size,
        shard_max_bytes: r.shard_max_bytes,
        rotate_interval: Duration::from_secs(r.rotate_secs.max(1)),
        retention_days: r.retention_days,
        max_body_bytes: r.max_body_bytes,
        on_roll: r.on_roll.clone(),
    };
    tracing::info!(dir = %cfg.dir.display(), "request logging enabled (duckdb)");
    Ok(Arc::new(DuckLogger::new(cfg)?))
}

// ---- crypto ----------------------------------------------------------------

/// Build the BYOK encryptor from `security.byok_key`. A 32-byte base64/hex value
/// enables AES-GCM; anything else logs a warning and stores external keys in the
/// clear via [`NoopEncryptor`].
fn build_encryptor(key: Option<&str>) -> Arc<dyn Encryptor> {
    match key {
        Some(raw) if !raw.is_empty() => match decode_key(raw) {
            Some(bytes) if bytes.len() == 32 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(&bytes);
                tracing::info!("BYOK encryption enabled (aes-gcm-256)");
                Arc::new(AesGcmEncryptor::new(k))
            }
            _ => {
                tracing::warn!("security.byok_key is not a 32-byte base64/hex value; external keys stored unencrypted");
                Arc::new(NoopEncryptor)
            }
        },
        _ => {
            tracing::warn!("security.byok_key unset; external keys stored unencrypted");
            Arc::new(NoopEncryptor)
        }
    }
}

/// Decode a key string as standard base64, then hex.
fn decode_key(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(s) {
        return Some(bytes);
    }
    decode_hex(s)
}

/// Decode an even-length hex string into bytes.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| Some((nibble(p[0])? << 4) | nibble(p[1])?))
        .collect()
}
