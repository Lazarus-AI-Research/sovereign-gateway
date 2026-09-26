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

use yb_gateway::media::VideoLookup;
use yb_gateway::{DeploymentRouter, Gateway, GatewayResponse, RequestCtx};
use yb_providers::{HttpMethod, MockClient, UpstreamClient};

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
    async fn rename_api_key(&self, _id: &str, _name: Option<&str>) -> Result<()> {
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
    async fn capture_policy(&self) -> Result<Option<yb_core::CapturePolicy>> {
        Ok(None)
    }
    async fn set_capture_policy(&self, _policy: &yb_core::CapturePolicy) -> Result<()> {
        Ok(())
    }
    async fn log_level(&self) -> Result<Option<yb_core::LogLevel>> {
        Ok(None)
    }
    async fn set_log_level(&self, _level: yb_core::LogLevel) -> Result<()> {
        Ok(())
    }
    async fn usage(
        &self,
        _from: Timestamp,
        _to: Timestamp,
    ) -> Result<Vec<yb_core::spend::UsageRow>> {
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
    async fn list_health(&self) -> Result<Vec<yb_core::HealthRecord>> {
        Ok(vec![])
    }
    async fn record_health(&self, _rec: &yb_core::HealthRecord) -> Result<()> {
        Ok(())
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
        .handle(
            WireFormat::Anthropic,
            &serde_json::to_vec(&inbound).unwrap(),
            RequestCtx::new(),
        )
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
    assert_eq!(
        v["type"], "message",
        "aggregated into an Anthropic envelope"
    );
    assert_eq!(
        v["content"][0]["text"], "Hello world",
        "deltas were concatenated"
    );

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

fn media_router() -> DeploymentRouter {
    let deployment = |name: &str, upstream: &str, format: yb_core::MediaFormat| ModelConfig {
        model_name: name.into(),
        aliases: vec![],
        deployments: vec![DeploymentConfig {
            provider: "host-agent".into(),
            upstream_model: upstream.into(),
            api_base: Some(format!("http://agent:9100/deployments/{name}/v1")),
            api_key: Some("env:YB_TEST_AGENT_TOKEN".into()),
            upstream_format: format.into(),
            weight: 1,
            pricing: None,
            health_check: Default::default(),
            health_path: None,
            extra: Default::default(),
        }],
    };
    DeploymentRouter::from_models(
        vec![
            deployment(
                "assistant-speech",
                "piper",
                yb_core::MediaFormat::OpenaiSpeech,
            ),
            deployment(
                "assistant-transcribe",
                "whisper",
                yb_core::MediaFormat::OpenaiTranscription,
            ),
            deployment(
                "assistant-video",
                "assistant-video",
                yb_core::MediaFormat::OpenaiVideos,
            ),
        ],
        HashMap::new(),
        HashMap::new(),
        Strategy::Simple,
    )
}

/// Speech is forwarded to the deployment's endpoint with its model and key,
/// and the audio comes back untouched under the upstream's content type.
#[tokio::test]
async fn speech_is_forwarded_and_recorded() {
    std::env::set_var("YB_TEST_AGENT_TOKEN", "agent-secret");
    let audio = b"RIFF\x24\x00\x00\x00WAVEfmt ".to_vec();
    let mock = Arc::new(MockClient::full(audio.clone()).with_header("content-type", "audio/wav"));
    let client: Arc<dyn UpstreamClient> = mock.clone();
    let store = Arc::new(RecordingStore::default());
    let gateway = Gateway::new(
        client,
        Arc::new(media_router()),
        store.clone(),
        Arc::new(NullLogger),
    );

    let body = br#"{"model":"assistant-speech","input":"hello","voice":"default"}"#;
    let resp = gateway
        .handle_media(
            yb_core::MediaFormat::OpenaiSpeech,
            body,
            "application/json",
            RequestCtx::new(),
        )
        .await
        .unwrap();
    let GatewayResponse::Full {
        status,
        headers,
        body: answer,
    } = resp
    else {
        panic!("expected a buffered response")
    };
    assert_eq!(status, 200);
    assert_eq!(answer, audio);
    assert!(headers.contains(&("content-type".to_string(), "audio/wav".to_string())));

    let sent = mock.last_request().expect("the upstream was called");
    assert_eq!(
        sent.url,
        "http://agent:9100/deployments/assistant-speech/v1/audio/speech"
    );
    assert!(sent.headers.contains(&(
        "authorization".to_string(),
        "Bearer agent-secret".to_string()
    )));
    let sent_body: Value = serde_json::from_slice(&sent.body).unwrap();
    assert_eq!(sent_body["model"], "piper");
    assert_eq!(sent_body["input"], "hello");

    let telemetry = store.telemetry();
    assert_eq!(telemetry.len(), 1);
    assert_eq!(telemetry[0].surface, "openai_speech");
    assert_eq!(telemetry[0].requested_model, "assistant-speech");
    assert!(!telemetry[0].is_error);
}

/// Making a video is a turn forwarded like any media request; asking after
/// it, fetching it and deleting it go to the deployment its id names, with
/// the method each takes, and are not turns.
#[tokio::test]
async fn a_video_is_made_then_asked_after_by_its_id() {
    std::env::set_var("YB_TEST_AGENT_TOKEN", "agent-secret");
    let mock = Arc::new(
        MockClient::full(br#"{"id":"video_x","status":"queued"}"#.to_vec())
            .with_header("content-type", "application/json"),
    );
    let client: Arc<dyn UpstreamClient> = mock.clone();
    let store = Arc::new(RecordingStore::default());
    let gateway = Gateway::new(
        client,
        Arc::new(media_router()),
        store.clone(),
        Arc::new(NullLogger),
    );
    gateway
        .handle_media(
            yb_core::MediaFormat::OpenaiVideos,
            br#"{"model":"assistant-video","prompt":"a kite"}"#,
            "application/json",
            RequestCtx::new(),
        )
        .await
        .unwrap();
    let sent = mock.last_request().unwrap();
    assert_eq!(
        sent.url,
        "http://agent:9100/deployments/assistant-video/v1/videos"
    );
    assert_eq!(store.telemetry().len(), 1);
    assert_eq!(store.telemetry()[0].surface, "openai_videos");

    // "assistant-video/job_1/sig", as the engine names and signs the video.
    let id = "video_YXNzaXN0YW50LXZpZGVvL2pvYl8xL3NpZw";
    for (lookup, url, method) in [
        (VideoLookup::Status, format!("videos/{id}"), HttpMethod::Get),
        (
            VideoLookup::Content,
            format!("videos/{id}/content"),
            HttpMethod::Get,
        ),
        (
            VideoLookup::Delete,
            format!("videos/{id}"),
            HttpMethod::Delete,
        ),
    ] {
        let resp = gateway
            .handle_video(id, lookup, RequestCtx::new())
            .await
            .unwrap();
        let GatewayResponse::Full { status, .. } = resp else {
            panic!("expected a buffered response")
        };
        assert_eq!(status, 200);
        let sent = mock.last_request().unwrap();
        assert_eq!(
            sent.url,
            format!("http://agent:9100/deployments/assistant-video/v1/{url}")
        );
        assert_eq!(sent.method, method);
        assert!(sent.headers.contains(&(
            "authorization".to_string(),
            "Bearer agent-secret".to_string()
        )));
    }
    assert_eq!(store.telemetry().len(), 1, "only the making is a turn");

    // An id that names no video model, or no model at all, is no video.
    for id in [
        "video_YXNzaXN0YW50LXNwZWVjaC9qb2JfMS9zaWc",
        "video_!!",
        "job_1",
    ] {
        let err = gateway
            .handle_video(id, VideoLookup::Status, RequestCtx::new())
            .await
            .unwrap_err();
        assert_eq!(err.http_status(), 404, "{id}: {err}");
    }
}

/// An engine that knows only the videos made on its second deployment.
struct SecondEngine(Mutex<Vec<String>>);

#[async_trait]
impl UpstreamClient for SecondEngine {
    async fn send(
        &self,
        req: yb_providers::UpstreamRequest,
    ) -> Result<yb_providers::UpstreamResponse> {
        self.0.lock().unwrap().push(req.url.clone());
        let status = if req.url.contains("engine-one") {
            404
        } else {
            200
        };
        Ok(yb_providers::UpstreamResponse {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: yb_providers::ResponseBody::Full(b"{}".to_vec()),
        })
    }
}

/// A video is found by the upstream model its id names, whatever public
/// name serves it, on whichever deployment of that model made it; a key
/// denied the model finds nothing.
#[tokio::test]
async fn a_video_is_found_on_the_deployment_that_made_it() {
    let deployment = |base: &str| DeploymentConfig {
        provider: "host-agent".into(),
        upstream_model: "wan".into(),
        api_base: Some(format!("http://{base}/v1")),
        api_key: None,
        upstream_format: yb_core::MediaFormat::OpenaiVideos.into(),
        weight: 1,
        pricing: None,
        health_check: Default::default(),
        health_path: None,
        extra: Default::default(),
    };
    let router = DeploymentRouter::from_models(
        vec![ModelConfig {
            model_name: "video".into(),
            aliases: vec![],
            deployments: vec![deployment("engine-one"), deployment("engine-two")],
        }],
        HashMap::new(),
        HashMap::new(),
        Strategy::Simple,
    );
    let engine = Arc::new(SecondEngine(Mutex::new(Vec::new())));
    let client: Arc<dyn UpstreamClient> = engine.clone();
    let gateway = Gateway::new(
        client,
        Arc::new(router),
        Arc::new(RecordingStore::default()),
        Arc::new(NullLogger),
    );
    // "wan/job_1/sig".
    let id = "video_d2FuL2pvYl8xL3NpZw";
    let resp = gateway
        .handle_video(id, VideoLookup::Status, RequestCtx::new())
        .await
        .unwrap();
    let GatewayResponse::Full { status, .. } = resp else {
        panic!("expected a buffered response")
    };
    assert_eq!(status, 200);
    let asked = engine.0.lock().unwrap().clone();
    assert!(
        asked.last().unwrap().starts_with("http://engine-two/"),
        "{asked:?}"
    );

    let mut denied = RequestCtx::new();
    denied.access.denied_model_ids = vec!["cfg-model:video".into()];
    let err = gateway
        .handle_video(id, VideoLookup::Status, denied)
        .await
        .unwrap_err();
    assert_eq!(err.http_status(), 404, "{err}");
}

/// A model that serves another endpoint refuses the request plainly.
#[tokio::test]
async fn media_goes_only_to_the_endpoint_a_model_serves() {
    let client: Arc<dyn UpstreamClient> = Arc::new(MockClient::full(Vec::new()));
    let store = Arc::new(RecordingStore::default());
    let gateway = Gateway::new(
        client,
        Arc::new(media_router()),
        store.clone(),
        Arc::new(NullLogger),
    );
    let err = gateway
        .handle_media(
            yb_core::MediaFormat::OpenaiSpeech,
            br#"{"model":"assistant-transcribe","input":"x"}"#,
            "application/json",
            RequestCtx::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.http_status(), 400, "{err}");
    assert_eq!(store.telemetry().len(), 1);
}

/// A client stops reading once its answer has ended; the turn is still
/// complete, not abandoned, whether or not the upstream has closed yet.
#[tokio::test]
async fn a_client_that_stops_at_the_end_leaves_a_complete_turn() {
    use futures::StreamExt;
    let chunks = vec![
        r#"data: {"id":"c","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"hi"}}]}"#.to_string() + "\n\n",
        r#"data: {"id":"c","model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#.to_string() + "\n\n",
        r#"data: {"id":"c","model":"gpt-4o","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}"#.to_string() + "\n\n",
        "data: [DONE]".to_string() + "\n\n",
    ];
    let client: Arc<dyn UpstreamClient> = Arc::new(MockClient::sse(chunks));
    let store = Arc::new(RecordingStore::default());
    let gateway = Gateway::new(
        client,
        Arc::new(test_router()),
        store.clone(),
        Arc::new(NullLogger),
    );
    let body = serde_json::to_vec(&json!({
        "model": "my-model", "stream": true, "stream_options": {"include_usage": true},
        "messages": [{"role": "user", "content": "hi"}]
    }))
    .unwrap();
    let GatewayResponse::Stream { mut stream, .. } = gateway
        .handle(WireFormat::OpenaiChat, &body, RequestCtx::new())
        .await
        .unwrap()
    else {
        panic!("expected a stream")
    };
    let mut seen = String::new();
    while let Some(chunk) = stream.next().await {
        seen.push_str(&String::from_utf8_lossy(&chunk.unwrap()));
        if seen.contains("data: [DONE]") {
            break;
        }
    }
    drop(stream);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let telemetry = store.telemetry();
    assert_eq!(telemetry.len(), 1, "{telemetry:?}");
    assert_eq!(telemetry[0].status, 200);
    assert!(!telemetry[0].is_error);
    assert_eq!(telemetry[0].output_tokens, 1);
}
