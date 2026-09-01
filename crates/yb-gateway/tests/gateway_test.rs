//! End-to-end gateway test: an Anthropic-surface client request routed to a mock
//! OpenAI deployment, with the OpenAI response translated back to Anthropic, and
//! telemetry + a spend rollup recorded.
//!
//! The store is a tiny in-memory [`RecordingStore`] implementing `yb_core::Store`
//! so the test can assert directly on the telemetry row and rollup the gateway
//! wrote (the real `SqliteStore` exposes no telemetry-read on the trait).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{json, Value};

use yb_core::config::{DeploymentConfig, ModelConfig, Strategy};
use yb_core::model::{
    AccessPolicy, ApiKey, ExternalKey, Role, Team, TeamMembership, TelemetryRecord, User,
};
use yb_core::principal::KeyAuth;
use yb_core::spend::{Budget, Period, RollupDelta, SpendRow, SubjectType};
use yb_core::store::LimitColumns;
use yb_core::{now, Micros, NullLogger, Result, Store, Timestamp, WireFormat};

use yb_gateway::{DeploymentRouter, Gateway, GatewayResponse, RequestCtx};
use yb_providers::{MockClient, UpstreamClient};

/// A minimal `Store` that captures telemetry rows and spend rollups in memory
/// and stubs everything else.
#[derive(Default)]
struct RecordingStore {
    telemetry: Mutex<Vec<TelemetryRecord>>,
    rollups: Mutex<Vec<RollupDelta>>,
}

impl RecordingStore {
    fn telemetry(&self) -> Vec<TelemetryRecord> {
        self.telemetry.lock().unwrap().clone()
    }
    fn rollups(&self) -> Vec<RollupDelta> {
        self.rollups.lock().unwrap().clone()
    }
}

#[async_trait]
impl Store for RecordingStore {
    async fn migrate(&self) -> Result<()> {
        Ok(())
    }

    // ---- users -----------------------------------------------------------
    async fn create_user(&self, _user: &User) -> Result<()> {
        Ok(())
    }
    async fn get_user(&self, _id: &str) -> Result<Option<User>> {
        Ok(None)
    }
    async fn get_user_by_username(&self, _username: &str) -> Result<Option<User>> {
        Ok(None)
    }
    async fn list_users(&self) -> Result<Vec<User>> {
        Ok(vec![])
    }
    async fn set_user_password(&self, _id: &str, _password_hash: &str) -> Result<()> {
        Ok(())
    }
    async fn set_user_role(&self, _id: &str, _role: Role) -> Result<()> {
        Ok(())
    }
    async fn set_user_limits(&self, _id: &str, _limits: LimitColumns) -> Result<()> {
        Ok(())
    }
    async fn mark_user_login(&self, _id: &str) -> Result<()> {
        Ok(())
    }
    async fn delete_user(&self, _id: &str) -> Result<()> {
        Ok(())
    }
    async fn count_users(&self) -> Result<i64> {
        Ok(0)
    }
    async fn count_admins(&self) -> Result<i64> {
        Ok(0)
    }

    // ---- web sessions ----------------------------------------------------
    async fn create_session(&self, _s: &yb_core::model::Session) -> Result<()> {
        Ok(())
    }
    async fn get_session(&self, _token: &str) -> Result<Option<yb_core::model::Session>> {
        Ok(None)
    }
    async fn delete_session(&self, _token: &str) -> Result<()> {
        Ok(())
    }

    // ---- api keys --------------------------------------------------------
    async fn create_api_key(&self, _key: &ApiKey) -> Result<()> {
        Ok(())
    }
    async fn verify_api_key(&self, _token_hash: &str) -> Result<Option<KeyAuth>> {
        Ok(None)
    }
    async fn get_api_key(&self, _id: &str) -> Result<Option<ApiKey>> {
        Ok(None)
    }
    async fn list_api_keys(&self) -> Result<Vec<ApiKey>> {
        Ok(vec![])
    }
    async fn list_api_keys_for_user(&self, _user_id: &str) -> Result<Vec<ApiKey>> {
        Ok(vec![])
    }
    async fn mark_api_key_used(&self, _id: &str) -> Result<()> {
        Ok(())
    }
    async fn delete_api_key(&self, _id: &str) -> Result<()> {
        Ok(())
    }
    async fn update_api_key_access(&self, _id: &str, _policy: &AccessPolicy) -> Result<()> {
        Ok(())
    }
    async fn update_api_key_limits(&self, _id: &str, _limits: LimitColumns) -> Result<()> {
        Ok(())
    }

    // ---- external keys ---------------------------------------------------
    async fn upsert_external_key(&self, _key: &ExternalKey) -> Result<()> {
        Ok(())
    }
    async fn list_external_keys(&self, _user_id: &str) -> Result<Vec<ExternalKey>> {
        Ok(vec![])
    }
    async fn delete_external_key(&self, _user_id: &str, _provider: &str) -> Result<()> {
        Ok(())
    }

    // ---- teams & memberships ---------------------------------------------
    async fn create_team(&self, _team: &Team) -> Result<()> {
        Ok(())
    }
    async fn get_team(&self, _id: &str) -> Result<Option<Team>> {
        Ok(None)
    }
    async fn list_teams(&self) -> Result<Vec<Team>> {
        Ok(vec![])
    }
    async fn delete_team(&self, _id: &str) -> Result<()> {
        Ok(())
    }
    async fn update_team_access(&self, _id: &str, _policy: &AccessPolicy) -> Result<()> {
        Ok(())
    }
    async fn upsert_membership(&self, _m: &TeamMembership) -> Result<()> {
        Ok(())
    }
    async fn list_memberships_for_user(&self, _user_id: &str) -> Result<Vec<TeamMembership>> {
        Ok(vec![])
    }
    async fn list_team_members(&self, _team_id: &str) -> Result<Vec<TeamMembership>> {
        Ok(vec![])
    }
    async fn delete_membership(&self, _team_id: &str, _user_id: &str) -> Result<()> {
        Ok(())
    }

    // ---- telemetry -------------------------------------------------------
    async fn insert_telemetry(&self, rec: &TelemetryRecord) -> Result<()> {
        self.telemetry.lock().unwrap().push(rec.clone());
        Ok(())
    }

    // ---- spend & budgets -------------------------------------------------
    async fn upsert_rollup(&self, delta: &RollupDelta) -> Result<()> {
        self.rollups.lock().unwrap().push(delta.clone());
        Ok(())
    }
    async fn period_spend(
        &self,
        _subject_type: SubjectType,
        _subject_id: &str,
        _period: Period,
        _period_start: Timestamp,
    ) -> Result<Micros> {
        Ok(self
            .rollups
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.spend_micros)
            .sum())
    }
    async fn list_budgets(
        &self,
        _subject_type: SubjectType,
        _subject_id: &str,
    ) -> Result<Vec<Budget>> {
        Ok(vec![])
    }
    async fn list_all_budgets(&self) -> Result<Vec<Budget>> {
        Ok(vec![])
    }
    async fn upsert_budget(&self, _budget: &Budget) -> Result<()> {
        Ok(())
    }
    async fn delete_budget(&self, _id: &str) -> Result<()> {
        Ok(())
    }
    async fn spend_rows(&self) -> Result<Vec<SpendRow>> {
        Ok(vec![])
    }

    // ---- rate-limit counters ---------------------------------------------
    async fn incr_rate_counter(
        &self,
        _scope: &str,
        _dimension: &str,
        _window_start: Timestamp,
        _n: i64,
    ) -> Result<i64> {
        Ok(0)
    }

    // ---- deployments -----------------------------------------------------
    async fn list_deployments(&self) -> Result<Vec<yb_core::DeploymentRecord>> {
        Ok(vec![])
    }
    async fn get_deployment(&self, _id: &str) -> Result<Option<yb_core::DeploymentRecord>> {
        Ok(None)
    }
    async fn create_deployment(
        &self,
        _dep: &yb_core::NewDeployment,
    ) -> Result<yb_core::DeploymentRecord> {
        unimplemented!("RecordingStore only serves the request path")
    }
    async fn delete_deployment(&self, _id: &str) -> Result<()> {
        Ok(())
    }
    async fn seed_deployment(&self, _dep: &yb_core::NewDeployment) -> Result<bool> {
        Ok(true)
    }
    async fn list_providers(&self) -> Result<Vec<yb_core::ProviderRecord>> {
        Ok(vec![])
    }
    async fn get_provider(&self, _id: &str) -> Result<Option<yb_core::ProviderRecord>> {
        Ok(None)
    }
    async fn get_provider_by_name(&self, _name: &str) -> Result<Option<yb_core::ProviderRecord>> {
        Ok(None)
    }
    async fn ensure_provider(&self, _name: &str) -> Result<yb_core::ProviderRecord> {
        unimplemented!("RecordingStore only serves the request path")
    }
    async fn update_provider(
        &self,
        _id: &str,
        _name: &str,
        _api_base: Option<&str>,
        _api_key: Option<&str>,
        _extra: &yb_core::Extra,
    ) -> Result<yb_core::ProviderRecord> {
        unimplemented!("RecordingStore only serves the request path")
    }
    async fn delete_provider(&self, _id: &str) -> Result<()> {
        Ok(())
    }
    async fn list_models(&self) -> Result<Vec<yb_core::ModelRecord>> {
        Ok(vec![])
    }
    async fn get_model(&self, _id: &str) -> Result<Option<yb_core::ModelRecord>> {
        Ok(None)
    }
    async fn get_model_by_name(&self, _name: &str) -> Result<Option<yb_core::ModelRecord>> {
        Ok(None)
    }
    async fn ensure_model(&self, _name: &str) -> Result<yb_core::ModelRecord> {
        unimplemented!("RecordingStore only serves the request path")
    }
    async fn rename_model(&self, _id: &str, _new_name: &str) -> Result<yb_core::ModelRecord> {
        unimplemented!("RecordingStore only serves the request path")
    }
    async fn list_aliases(&self) -> Result<Vec<yb_core::ModelAlias>> {
        Ok(vec![])
    }
    async fn upsert_alias(&self, _alias: &str, _model_id: &str) -> Result<yb_core::ModelAlias> {
        unimplemented!("RecordingStore only serves the request path")
    }
    async fn delete_alias(&self, _alias: &str) -> Result<()> {
        Ok(())
    }
}

/// Build a one-model router whose only deployment is a native OpenAI model
/// (`gpt-4o`), so the upstream wire format is OpenAI chat.
fn test_router() -> DeploymentRouter {
    let models = vec![ModelConfig {
        model_name: "my-model".into(),
        aliases: vec![],
        deployments: vec![DeploymentConfig {
            provider: "openai".into(),
            upstream_model: "gpt-4o".into(),
            api_base: None,
            api_key: None,
            upstream_format: WireFormat::OpenaiChat.into(),
            weight: 1,
            pricing: None, // falls back to the built-in gpt-4o price
            health_check: Default::default(),
            health_path: None,
            extra: Default::default(),
        }],
    }];
    DeploymentRouter::from_models(models, HashMap::new(), HashMap::new(), Strategy::Simple)
}

/// A request context carrying a key + its owner user and team, so the test can
/// assert telemetry/rollups are keyed by key/user/team.
fn ctx_with_identity() -> RequestCtx {
    let mut ctx = RequestCtx::new();
    ctx.api_key = Some(ApiKey {
        id: "key-1".into(),
        owner_user_id: "user-1".into(),
        team_id: Some("team-1".into()),
        hash: String::new(),
        key_prefix: "yb_a".into(),
        key_suffix: "wxyz".into(),
        name: None,
        scopes: Default::default(),
        access: AccessPolicy::default(),
        rpm_limit: None,
        tpm_limit: None,
        max_concurrent: None,
        created_at: now(),
        last_used_at: None,
        deleted_at: None,
    });
    ctx.user_id = Some("user-1".into());
    ctx.team_id = Some("team-1".into());
    ctx
}

#[tokio::test]
async fn openai_deployment_translated_to_anthropic_surface() {
    // A canned OpenAI chat completion the mock upstream replays.
    let upstream = json!({
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 0,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "Hello there!"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    });
    let mock = MockClient::json(serde_json::to_vec(&upstream).unwrap());
    // Clones of a MockClient share the same recorded-request buffer, so we can
    // hand a boxed clone to the gateway and still inspect `mock` afterwards.
    let client: Arc<dyn UpstreamClient> = Arc::new(mock.clone());

    let router = Arc::new(test_router());
    let store = Arc::new(RecordingStore::default());
    let logger = Arc::new(NullLogger);

    let gateway = Gateway::new(client, router, store.clone(), logger);

    // Inbound request is on the Anthropic surface.
    let inbound = json!({
        "model": "my-model",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "hi"}]
    });
    let ctx = ctx_with_identity();

    let resp = gateway
        .handle(
            WireFormat::Anthropic,
            &serde_json::to_vec(&inbound).unwrap(),
            ctx,
        )
        .await
        .expect("handle succeeds");

    // --- The client gets an Anthropic-shaped response -----------------------
    let body = match resp {
        GatewayResponse::Full { status, body, .. } => {
            assert_eq!(status, 200);
            body
        }
        GatewayResponse::Stream { .. } => panic!("expected a buffered response"),
    };
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["type"], "message", "Anthropic envelope");
    assert_eq!(v["role"], "assistant");
    assert_eq!(v["content"][0]["type"], "text");
    assert_eq!(v["content"][0]["text"], "Hello there!");
    assert_eq!(v["usage"]["input_tokens"], 10);
    assert_eq!(v["usage"]["output_tokens"], 5);

    // The upstream actually received an OpenAI-chat body for gpt-4o.
    let sent_req = mock.last_request().expect("one upstream call");
    let sent: Value = serde_json::from_slice(&sent_req.body).unwrap();
    assert_eq!(sent["model"], "gpt-4o");
    assert!(sent_req.url.ends_with("/v1/chat/completions"));

    // --- A telemetry row was recorded ---------------------------------------
    let rows = store.telemetry();
    assert_eq!(rows.len(), 1, "exactly one telemetry row");
    let row = &rows[0];
    assert_eq!(row.surface, "anthropic");
    assert_eq!(row.requested_model, "my-model");
    assert_eq!(row.decision_model, "my-model");
    assert_eq!(row.decision_provider, "openai");
    assert_eq!(row.input_tokens, 10);
    assert_eq!(row.output_tokens, 5);
    assert!(!row.is_error);
    assert_eq!(row.status, 200);
    // gpt-4o built-in price: 10*2.50 + 5*10.0 = 75 micros.
    assert_eq!(row.cost_micros, 75);
    // Telemetry is keyed by key/user/team, not installation.
    assert_eq!(row.api_key_id.as_deref(), Some("key-1"));
    assert_eq!(row.user_id.as_deref(), Some("user-1"));
    assert_eq!(row.team_id.as_deref(), Some("team-1"));

    // --- Spend rollups were upserted for key / user / team ------------------
    let rollups = store.rollups();
    assert_eq!(rollups.len(), 3, "one rollup per subject (key, user, team)");
    for r in &rollups {
        assert_eq!(r.spend_micros, 75);
        assert_eq!(r.request_count, 1);
        assert_eq!(r.input_tokens, 10);
        assert_eq!(r.output_tokens, 5);
    }
    let subject = |t: SubjectType| {
        rollups
            .iter()
            .find(|r| r.subject_type == t)
            .map(|r| r.subject_id.clone())
    };
    assert_eq!(subject(SubjectType::Key).as_deref(), Some("key-1"));
    assert_eq!(subject(SubjectType::User).as_deref(), Some("user-1"));
    assert_eq!(subject(SubjectType::Team).as_deref(), Some("team-1"));
}

#[tokio::test]
async fn aggregates_streaming_upstream_for_nonstreaming_client() {
    // The upstream streams OpenAI-chat SSE; the client asked (by default) for a
    // NON-streaming Anthropic response. Because the gateway always calls upstreams
    // in streaming mode, the gateway must fold the SSE into one buffered body.
    let chunks: Vec<bytes::Bytes> = vec![
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}]}\n\n".into(),
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"}}]}\n\n".into(),
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\" world\"}}]}\n\n".into(),
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n".into(),
        "data: [DONE]\n\n".into(),
    ];
    let client: Arc<dyn UpstreamClient> = Arc::new(MockClient::sse(chunks));
    let router = Arc::new(test_router());
    let store = Arc::new(RecordingStore::default());
    let gateway = Gateway::new(client, router, store.clone(), Arc::new(NullLogger));

    let inbound = json!({
        "model": "my-model",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "hi"}]
    });
    let resp = gateway
        .handle(WireFormat::Anthropic, &serde_json::to_vec(&inbound).unwrap(), RequestCtx::new())
        .await
        .expect("handle succeeds");

    let body = match resp {
        GatewayResponse::Full { status, body, .. } => {
            assert_eq!(status, 200);
            body
        }
        GatewayResponse::Stream { .. } => panic!("non-streaming client must get a buffered body"),
    };
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["type"], "message", "aggregated into an Anthropic envelope");
    assert_eq!(v["content"][0]["text"], "Hello world", "deltas were concatenated");

    let rows = store.telemetry();
    assert_eq!(rows.len(), 1, "one telemetry row for the aggregated turn");
    assert_eq!(rows[0].surface, "anthropic");
    assert!(!rows[0].is_error);
}

// ---------------------------------------------------------------------------
// Embeddings path
// ---------------------------------------------------------------------------

/// A router with one embed model and one chat model, for the embed happy path
/// and both kind-mismatch 400s.
fn embed_router() -> DeploymentRouter {
    use yb_core::EmbedFormat;
    let models = vec![
        ModelConfig {
            model_name: "my-embed".into(),
            aliases: vec![],
            deployments: vec![DeploymentConfig {
                provider: "openai".into(),
                upstream_model: "text-embedding-3-small".into(),
                api_base: None,
                api_key: None,
                upstream_format: EmbedFormat::OpenaiEmbed.into(),
                weight: 1,
                pricing: None,
                health_check: Default::default(),
                health_path: None,
                extra: Default::default(),
            }],
        },
        ModelConfig {
            model_name: "my-model".into(),
            aliases: vec![],
            deployments: vec![DeploymentConfig {
                provider: "openai".into(),
                upstream_model: "gpt-4o".into(),
                api_base: None,
                api_key: None,
                upstream_format: WireFormat::OpenaiChat.into(),
                weight: 1,
                pricing: None,
                health_check: Default::default(),
                health_path: None,
                extra: Default::default(),
            }],
        },
    ];
    DeploymentRouter::from_models(models, HashMap::new(), HashMap::new(), Strategy::Simple)
}

#[tokio::test]
async fn embed_happy_path_records_telemetry() {
    use yb_core::EmbedFormat;
    let upstream = json!({
        "object": "list", "model": "text-embedding-3-small",
        "data": [{"object": "embedding", "index": 0, "embedding": [1.0, 2.0]}],
        "usage": {"prompt_tokens": 3, "total_tokens": 3}
    });
    let client: Arc<dyn UpstreamClient> =
        Arc::new(MockClient::json(serde_json::to_vec(&upstream).unwrap()));
    let store = Arc::new(RecordingStore::default());
    let router = Arc::new(embed_router());
    let gateway = Gateway::new(client, router, store.clone(), Arc::new(NullLogger));

    let body = serde_json::to_vec(&json!({
        "model": "my-embed", "input": "hello", "encoding_format": "base64"
    }))
    .unwrap();
    let resp = gateway
        .handle_embed(EmbedFormat::OpenaiEmbed, &body, RequestCtx::new())
        .await
        .unwrap();
    let GatewayResponse::Full { status, body, .. } = resp else {
        panic!("expected a buffered response")
    };
    assert_eq!(status, 200);
    let v: Value = serde_json::from_slice(&body).unwrap();
    // base64 echo honored on the client surface
    assert!(v["data"][0]["embedding"].is_string());

    // Observability parity: the turn is recorded with the embed surface label,
    // input-only usage, and no output tokens.
    let telemetry = store.telemetry();
    assert_eq!(telemetry.len(), 1);
    assert_eq!(telemetry[0].surface, "openai_embed");
    assert_eq!(telemetry[0].requested_model, "my-embed");
    assert_eq!(telemetry[0].input_tokens, 3);
    assert_eq!(telemetry[0].output_tokens, 0);
    assert!(!telemetry[0].is_error);
}

#[tokio::test]
async fn kind_mismatch_is_a_clean_400_both_ways() {
    use yb_core::EmbedFormat;
    let client: Arc<dyn UpstreamClient> = Arc::new(MockClient::json(b"{}".to_vec()));
    let store = Arc::new(RecordingStore::default());
    let router = Arc::new(embed_router());
    let gateway = Gateway::new(client, router, store.clone(), Arc::new(NullLogger));

    // Embed request for a chat-only model -> 400.
    let body = serde_json::to_vec(&json!({"model": "my-model", "input": "x"})).unwrap();
    let err = gateway
        .handle_embed(EmbedFormat::OpenaiEmbed, &body, RequestCtx::new())
        .await
        .unwrap_err();
    assert_eq!(err.http_status(), 400, "embed->chat: {err}");

    // Chat request for an embed-only model -> 400.
    let body = serde_json::to_vec(&json!({
        "model": "my-embed", "messages": [{"role": "user", "content": "x"}]
    }))
    .unwrap();
    let err = gateway
        .handle(WireFormat::OpenaiChat, &body, RequestCtx::new())
        .await
        .unwrap_err();
    assert_eq!(err.http_status(), 400, "chat->embed: {err}");

    // Both failed turns were still recorded (guard).
    assert_eq!(store.telemetry().len(), 2);
    assert!(store.telemetry().iter().all(|t| t.is_error));
}
