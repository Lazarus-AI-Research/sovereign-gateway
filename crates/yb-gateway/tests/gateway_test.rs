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
    async fn set_deployment_shapes(
        &self,
        _id: &str,
        _shapes: Option<&[yb_core::UpstreamFormat]>,
    ) -> Result<yb_core::DeploymentRecord> {
        unimplemented!("RecordingStore only serves the request path")
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
    async fn set_provider_shapes(
        &self,
        _id: &str,
        _shapes: &[yb_core::ProviderShape],
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
            upstream_format: Some(WireFormat::OpenaiChat.into()),
            shapes: None,
            weight: 1,
            pricing: None, // falls back to the built-in gpt-4o price
            health_check: Default::default(),
            health_path: None,
            extra: Default::default(),
        }],
    }];
    DeploymentRouter::from_models(models, HashMap::new(), HashMap::new(), Strategy::Simple)
}

fn responses_router() -> DeploymentRouter {
    let models = vec![ModelConfig {
        model_name: "fake-responses".into(),
        aliases: vec![],
        deployments: vec![DeploymentConfig {
            provider: "fake".into(),
            upstream_model: "fake-upstream".into(),
            api_base: None,
            api_key: None,
            upstream_format: Some(WireFormat::OpenaiResponses.into()),
            shapes: None,
            weight: 1,
            pricing: None,
            health_check: Default::default(),
            health_path: None,
            extra: Default::default(),
        }],
    }];
    DeploymentRouter::from_models(models, HashMap::new(), HashMap::new(), Strategy::Simple)
}

#[tokio::test]
async fn same_shape_responses_preserves_incomplete_and_failed_terminal_events() {
    use futures::StreamExt;

    for (terminal_type, response_status) in [
        ("response.incomplete", "incomplete"),
        ("response.failed", "failed"),
    ] {
        let (incomplete_details, error) = if terminal_type == "response.incomplete" {
            (
                json!({"reason": "max_output_tokens"}),
                serde_json::Value::Null,
            )
        } else {
            (
                serde_json::Value::Null,
                json!({"code": "server_error", "message": "fake failure"}),
            )
        };
        let terminal = json!({
            "type": terminal_type,
            "sequence_number": 1,
            "response": {
                "id": "resp_fake", "object": "response", "model": "fake-upstream", "output": [], "status": response_status,
                "incomplete_details": incomplete_details,
                "error": error,
                "usage": {"input_tokens": 42, "output_tokens": 64}
            }
        });
        let chunks = vec![
            format!("event: {terminal_type}\ndata: {terminal}\n"),
            "\n".to_string(),
        ];
        let expected = chunks.concat();
        let store = Arc::new(RecordingStore::default());
        let gateway = Gateway::new(
            Arc::new(MockClient::sse(chunks)),
            Arc::new(responses_router()),
            store.clone(),
            Arc::new(NullLogger),
        );
        let body = serde_json::to_vec(&json!({
            "model": "fake-responses", "stream": true, "input": "test"
        }))
        .unwrap();
        let GatewayResponse::Stream { mut stream, .. } = gateway
            .handle(WireFormat::OpenaiResponses, &body, RequestCtx::new())
            .await
            .unwrap()
        else {
            panic!("expected Responses SSE stream")
        };
        let mut actual = String::new();
        while let Some(chunk) = stream.next().await {
            actual.push_str(&String::from_utf8_lossy(&chunk.unwrap()));
        }
        assert_eq!(actual, expected);
        let telemetry = store.telemetry();
        assert_eq!(telemetry.len(), 1);
        assert_eq!(telemetry[0].output_tokens, 64);
        assert!(telemetry[0].is_error);
    }
}

#[tokio::test]
async fn native_responses_eof_without_terminal_is_a_stream_error() {
    use futures::StreamExt;

    let gateway = Gateway::new(
        Arc::new(MockClient::sse(vec![
            "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\",\"sequence_number\":1}\n\n".to_string(),
        ])),
        Arc::new(responses_router()),
        Arc::new(RecordingStore::default()),
        Arc::new(NullLogger),
    );
    let body = serde_json::to_vec(&json!({
        "model": "fake-responses", "stream": true, "input": "test"
    }))
    .unwrap();
    let GatewayResponse::Stream { mut stream, .. } = gateway
        .handle(WireFormat::OpenaiResponses, &body, RequestCtx::new())
        .await
        .unwrap()
    else {
        panic!("expected Responses SSE stream")
    };
    assert!(stream.next().await.unwrap().is_ok());
    assert!(stream.next().await.unwrap().is_err());
}

#[tokio::test]
async fn responses_route_replays_request_body_except_the_model_id() {
    let models = vec![ModelConfig {
        model_name: "client-alias".into(),
        aliases: vec![],
        deployments: vec![DeploymentConfig {
            provider: "fake".into(),
            upstream_model: "upstream-model".into(),
            api_base: None,
            api_key: None,
            upstream_format: Some(WireFormat::OpenaiResponses.into()),
            shapes: None,
            weight: 1,
            pricing: None,
            health_check: Default::default(),
            health_path: None,
            extra: Default::default(),
        }],
    }];
    let router =
        DeploymentRouter::from_models(models, HashMap::new(), HashMap::new(), Strategy::Simple);
    let mock = MockClient::json(
        serde_json::to_vec(&json!({
            "id": "resp_1", "model": "upstream-model", "status": "completed",
            "output": [], "usage": {"input_tokens": 3, "output_tokens": 1}
        }))
        .unwrap(),
    );
    let gateway = Gateway::new(
        Arc::new(mock.clone()),
        Arc::new(router),
        Arc::new(RecordingStore::default()),
        Arc::new(NullLogger),
    );
    let original = json!({
        "model": "client-alias", "stream": false, "input": "test",
        "max_output_tokens": 64,
        "reasoning": {"effort": "max", "summary": "detailed"},
        "provider_extension": {"retain": true}
    });
    gateway
        .handle(
            WireFormat::OpenaiResponses,
            &serde_json::to_vec(&original).unwrap(),
            RequestCtx::new(),
        )
        .await
        .unwrap();
    let sent = mock.last_request().expect("one upstream call");
    let actual: Value = serde_json::from_slice(&sent.body).unwrap();
    let mut expected = original;
    expected["model"] = json!("upstream-model");
    // A relay keeps the client's stream choice: a buffered request gets the
    // provider's own buffered body.
    assert!(!sent.stream);
    assert_eq!(actual, expected);
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
                upstream_format: Some(EmbedFormat::OpenaiEmbed.into()),
                shapes: None,
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
                upstream_format: Some(WireFormat::OpenaiChat.into()),
                shapes: None,
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

/// An upstream whose first requests fail with the given error; it counts
/// every request it is sent.
struct FailingFirst {
    sent: std::sync::atomic::AtomicUsize,
    failures: usize,
    error: fn() -> yb_core::Error,
}

#[async_trait]
impl UpstreamClient for FailingFirst {
    async fn send(
        &self,
        _req: yb_providers::UpstreamRequest,
    ) -> Result<yb_providers::UpstreamResponse> {
        let sent = self.sent.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if sent < self.failures {
            return Err((self.error)());
        }
        let upstream = json!({
            "object": "list", "model": "text-embedding-3-small",
            "data": [{"object": "embedding", "index": 0, "embedding": [1.0]}],
            "usage": {"prompt_tokens": 1, "total_tokens": 1}
        });
        Ok(yb_providers::UpstreamResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: yb_providers::ResponseBody::Full(serde_json::to_vec(&upstream).unwrap()),
        })
    }
}

fn connection_lost() -> yb_core::Error {
    yb_core::Error::ConnectionLost("connection closed before message completed".into())
}

fn connect_failed() -> yb_core::Error {
    yb_core::Error::Upstream {
        provider: "upstream".into(),
        status: 502,
        message: "error trying to connect".into(),
    }
}

/// How many first requests fail and with what, the answer the caller gets,
/// and how many requests the upstream is sent.
type Case = (
    usize,
    fn() -> yb_core::Error,
    std::result::Result<u16, u16>,
    usize,
);

/// An embedding whose connection is lost as it is sent goes to the same
/// deployment once more, and a second loss is the answer; a failed connect
/// is not retried.
#[tokio::test]
async fn an_embedding_is_sent_again_once_after_its_connection_is_lost() {
    use yb_core::EmbedFormat;
    let body = serde_json::to_vec(&json!({"model": "my-embed", "input": "hello"})).unwrap();
    let cases: [Case; 3] = [
        (1, connection_lost, Ok(200), 2),
        (2, connection_lost, Err(502), 2),
        (1, connect_failed, Err(502), 1),
    ];
    for (failures, error, want, sends) in cases {
        let client = Arc::new(FailingFirst {
            sent: Default::default(),
            failures,
            error,
        });
        let gateway = Gateway::new(
            client.clone(),
            Arc::new(embed_router()),
            Arc::new(RecordingStore::default()),
            Arc::new(NullLogger),
        );
        let got = gateway
            .handle_embed(EmbedFormat::OpenaiEmbed, &body, RequestCtx::new())
            .await
            .map(|resp| match resp {
                GatewayResponse::Full { status, .. } => status,
                _ => panic!("expected a buffered response"),
            })
            .map_err(|err| err.http_status());
        assert_eq!(got, want, "after {failures} failures");
        assert_eq!(client.sent.load(std::sync::atomic::Ordering::SeqCst), sends);
    }
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
            upstream_format: Some(format.into()),
            shapes: None,
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
        upstream_format: Some(yb_core::MediaFormat::OpenaiVideos.into()),
        shapes: None,
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

/// An engine whose first deployment cannot be reached, and whose second
/// answers with the given status.
struct FirstUnreachable(u16);

#[async_trait]
impl UpstreamClient for FirstUnreachable {
    async fn send(
        &self,
        req: yb_providers::UpstreamRequest,
    ) -> Result<yb_providers::UpstreamResponse> {
        if req.url.contains("engine-one") {
            return Err(yb_core::Error::Upstream {
                provider: "engine-one".into(),
                status: 503,
                message: "connection refused".into(),
            });
        }
        Ok(yb_providers::UpstreamResponse {
            status: self.0,
            headers: vec![("content-type".into(), "application/json".into())],
            body: yb_providers::ResponseBody::Full(b"{}".to_vec()),
        })
    }
}

/// An engine that cannot be reached is passed over for one that knows the
/// video; when the other does not know it, the unreachable one may be the
/// maker, and its error is the answer.
#[tokio::test]
async fn an_unreachable_video_engine_is_passed_over() {
    let deployment = |base: &str| DeploymentConfig {
        provider: "host-agent".into(),
        upstream_model: "wan".into(),
        api_base: Some(format!("http://{base}/v1")),
        api_key: None,
        upstream_format: Some(yb_core::MediaFormat::OpenaiVideos.into()),
        shapes: None,
        weight: 1,
        pricing: None,
        health_check: Default::default(),
        health_path: None,
        extra: Default::default(),
    };
    // "wan/job_1/sig".
    let id = "video_d2FuL2pvYl8xL3NpZw";
    for (second, want) in [(200, Ok(200)), (404, Err(503))] {
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
        let gateway = Gateway::new(
            Arc::new(FirstUnreachable(second)),
            Arc::new(router),
            Arc::new(RecordingStore::default()),
            Arc::new(NullLogger),
        );
        let got = gateway
            .handle_video(id, VideoLookup::Status, RequestCtx::new())
            .await
            .map(|resp| match resp {
                GatewayResponse::Full { status, .. } => status,
                _ => 0,
            })
            .map_err(|e| e.http_status());
        assert_eq!(got, want, "the second engine answering {second}");
    }
}

// ---------------------------------------------------------------------------
// Same-shape relay: a provider that serves the client's shape gets the
// client's bytes (model id aside) and the client gets the provider's bytes.
// ---------------------------------------------------------------------------

/// One model, `glm`, on a provider serving `shapes`, whose deployment's own
/// (translation) format is `own`.
fn shaped_router(own: WireFormat, shapes: &[(WireFormat, Option<&str>)]) -> DeploymentRouter {
    let rec = yb_core::DeploymentRecord {
        id: "d1".into(),
        model_id: "m1".into(),
        model_name: "glm".into(),
        provider_id: "p1".into(),
        provider: "cluster".into(),
        upstream_model: "glm-upstream".into(),
        api_base: Some("http://cluster.test/v1".into()),
        api_key: Some("k".into()),
        upstream_format: own.into(),
        weight: 1,
        pricing: None,
        health_check: Default::default(),
        health_path: None,
        extra: Default::default(),
        shapes: None,
        provider_shapes: shapes
            .iter()
            .map(|(f, b)| yb_core::ProviderShape {
                format: (*f).into(),
                api_base: b.map(str::to_string),
            })
            .collect(),
        created_at: now(),
        updated_at: now(),
        deleted_at: None,
    };
    DeploymentRouter::from_deployments(&[rec], Strategy::Simple, HashMap::new(), HashMap::new())
}

async fn collect(resp: GatewayResponse) -> Vec<u8> {
    use futures::StreamExt;
    match resp {
        GatewayResponse::Full { body, .. } => body,
        GatewayResponse::Stream { mut stream, .. } => {
            let mut out = Vec::new();
            while let Some(chunk) = stream.next().await {
                out.extend_from_slice(&chunk.unwrap());
            }
            out
        }
    }
}

#[tokio::test]
async fn a_served_shape_is_relayed_byte_for_byte() {
    let answer = br#"{"id":"msg_1","type":"message","role":"assistant","model":"glm-upstream",
"content":[{"type":"thinking","thinking":"hm","signature":"sig1abc"},{"type":"text","text":"hi"}],
"stop_reason":"stop_sequence","stop_sequence":"END","usage":{"input_tokens":7,"output_tokens":2,
"cache_read_input_tokens":5,"cache_creation_input_tokens":0}}"#;
    let mock = MockClient::json(answer.to_vec());
    let store = Arc::new(RecordingStore::default());
    let gateway = Gateway::new(
        Arc::new(mock.clone()),
        Arc::new(shaped_router(
            WireFormat::OpenaiChat,
            &[(WireFormat::Anthropic, Some("http://cluster.test/anthropic"))],
        )),
        store.clone(),
        Arc::new(NullLogger),
    );
    let body = br#"{"model":"glm","max_tokens":64,"stop_sequences":["a","b","c","d","END"],
 "thinking":{"type":"enabled","budget_tokens":100},"output_config":{"effort":"max"},
 "messages":[{"role":"user","content":[{"type":"text","text":"x","cache_control":{"type":"ephemeral"}}]}]}"#;
    let resp = gateway
        .handle(WireFormat::Anthropic, body, RequestCtx::new())
        .await
        .unwrap();
    assert_eq!(collect(resp).await, answer.to_vec());
    let sent = mock.last_request().unwrap();
    assert_eq!(sent.url, "http://cluster.test/anthropic/v1/messages");
    assert!(!sent.stream);
    let want = String::from_utf8_lossy(body).replace("\"glm\"", "\"glm-upstream\"");
    assert_eq!(String::from_utf8_lossy(&sent.body), want);
    assert!(sent
        .headers
        .iter()
        .any(|(k, v)| k == "x-api-key" && v == "k"));
    let t = store.telemetry();
    assert_eq!(t.len(), 1);
    assert_eq!((t[0].output_tokens, t[0].cache_read_tokens), (2, 5));
}

#[tokio::test]
async fn a_relayed_chat_stream_meters_usage_the_client_did_not_ask_for() {
    let frames = vec![
        "data: {\"id\":\"c\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"c\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"c\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
        "data: {\"id\":\"c\",\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":1,\"total_tokens\":10}}\n\n",
        "data: [DONE]\n\n",
    ];
    let mock = MockClient::sse(frames.clone());
    let store = Arc::new(RecordingStore::default());
    let gateway = Gateway::new(
        Arc::new(mock.clone()),
        Arc::new(shaped_router(WireFormat::OpenaiChat, &[])),
        store.clone(),
        Arc::new(NullLogger),
    );
    let body = br#"{"model":"glm","stream":true,"messages":[{"role":"user","content":"x"}]}"#;
    let resp = gateway
        .handle(WireFormat::OpenaiChat, body, RequestCtx::new())
        .await
        .unwrap();
    let got = String::from_utf8(collect(resp).await).unwrap();
    let want: String = frames
        .iter()
        .filter(|f| !f.contains("\"choices\":[]"))
        .copied()
        .collect();
    assert_eq!(
        got, want,
        "the provider's frames, less the usage it was asked for"
    );
    let sent: Value = serde_json::from_slice(&mock.last_request().unwrap().body).unwrap();
    assert_eq!(sent["stream_options"]["include_usage"], true);
    assert_eq!(sent["model"], "glm-upstream");
    let t = store.telemetry();
    assert_eq!((t[0].input_tokens, t[0].output_tokens), (9, 1));
}

#[tokio::test]
async fn a_relayed_chat_stream_keeps_usage_the_client_asked_for() {
    let frames = vec![
        "data: {\"id\":\"c\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
        "data: {\"id\":\"c\",\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":1,\"total_tokens\":10}}\n\n",
        "data: [DONE]\n\n",
    ];
    let mock = MockClient::sse(frames.clone());
    let gateway = Gateway::new(
        Arc::new(mock.clone()),
        Arc::new(shaped_router(WireFormat::OpenaiChat, &[])),
        Arc::new(RecordingStore::default()),
        Arc::new(NullLogger),
    );
    let body =
        br#"{"model":"glm","stream":true,"stream_options":{"include_usage":true},"messages":[]}"#;
    let resp = gateway
        .handle(WireFormat::OpenaiChat, body, RequestCtx::new())
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8(collect(resp).await).unwrap(),
        frames.concat()
    );
    let sent = mock.last_request().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&sent.body),
        String::from_utf8_lossy(body).replace("\"glm\"", "\"glm-upstream\"")
    );
}

#[tokio::test]
async fn an_unserved_shape_is_still_translated() {
    let mock = MockClient::sse(vec![
        "data: {\"id\":\"c\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"},\"finish_reason\":\"stop\"}]}\n\n",
        "data: [DONE]\n\n",
    ]);
    let gateway = Gateway::new(
        Arc::new(mock.clone()),
        Arc::new(shaped_router(
            WireFormat::OpenaiChat,
            &[
                (WireFormat::OpenaiChat, None),
                (WireFormat::OpenaiResponses, None),
            ],
        )),
        Arc::new(RecordingStore::default()),
        Arc::new(NullLogger),
    );
    let body = br#"{"model":"glm","max_tokens":8,"messages":[{"role":"user","content":"x"}]}"#;
    let resp = gateway
        .handle(WireFormat::Anthropic, body, RequestCtx::new())
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&collect(resp).await).unwrap();
    assert_eq!(v["content"][0]["text"], "hi");
    let sent = mock.last_request().unwrap();
    assert_eq!(sent.url, "http://cluster.test/v1/chat/completions");
    assert!(sent.stream);
}

#[tokio::test]
async fn a_deployment_serving_the_clients_shape_is_tried_first() {
    let rec = |id: &str, fmt: WireFormat, base: &str| yb_core::DeploymentRecord {
        id: id.into(),
        model_id: "m1".into(),
        model_name: "glm".into(),
        provider_id: format!("p-{id}"),
        provider: id.into(),
        upstream_model: "glm-upstream".into(),
        api_base: Some(base.into()),
        api_key: None,
        upstream_format: fmt.into(),
        weight: 1,
        pricing: None,
        health_check: Default::default(),
        health_path: None,
        extra: Default::default(),
        shapes: None,
        provider_shapes: Vec::new(),
        created_at: now(),
        updated_at: now(),
        deleted_at: None,
    };
    let router = DeploymentRouter::from_deployments(
        &[
            rec("chat", WireFormat::OpenaiChat, "http://chat.test/v1"),
            rec("msgs", WireFormat::Anthropic, "http://msgs.test/v1"),
        ],
        Strategy::Simple,
        HashMap::new(),
        HashMap::new(),
    );
    let mock = MockClient::json(
        br#"{"id":"m","type":"message","role":"assistant","content":[],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}"#.to_vec(),
    );
    let gateway = Gateway::new(
        Arc::new(mock.clone()),
        Arc::new(router),
        Arc::new(RecordingStore::default()),
        Arc::new(NullLogger),
    );
    for _ in 0..4 {
        gateway
            .handle(
                WireFormat::Anthropic,
                br#"{"model":"glm","max_tokens":8,"messages":[]}"#,
                RequestCtx::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            mock.last_request().unwrap().url,
            "http://msgs.test/v1/messages"
        );
    }
}

// ---------------------------------------------------------------------------
// Relayed Responses state: GET/DELETE/cancel/input_items forward to the
// provider that answered the relayed turn, scoped to the owning user.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn relayed_responses_lookup_forwards_to_owning_provider() {
    let answer = serde_json::to_vec(&json!({
        "id": "resp_abc123",
        "object": "response",
        "status": "completed",
        "model": "glm-upstream",
        "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "ok"}]}],
        "usage": {"input_tokens": 5, "output_tokens": 1, "total_tokens": 6}
    }))
    .unwrap();
    let mock = MockClient::json(answer);
    let gateway = Gateway::new(
        Arc::new(mock.clone()),
        Arc::new(shaped_router(
            WireFormat::OpenaiChat,
            &[(
                WireFormat::OpenaiResponses,
                Some("http://cluster.test/r/v1"),
            )],
        )),
        Arc::new(RecordingStore::default()),
        Arc::new(NullLogger),
    );
    let mut ctx = RequestCtx::new();
    ctx.user_id = Some("u1".into());
    let req = json!({"model": "glm", "input": "hello"});
    gateway
        .handle(
            WireFormat::OpenaiResponses,
            &serde_json::to_vec(&req).unwrap(),
            ctx.clone(),
        )
        .await
        .unwrap();
    assert_eq!(
        mock.last_request().unwrap().url,
        "http://cluster.test/r/v1/responses"
    );

    let got = gateway
        .response_op("resp_abc123", yb_gateway::service::ResponseOp::Get, &ctx)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&collect(got).await).unwrap();
    assert_eq!(v["id"], "resp_abc123");
    assert_eq!(
        mock.last_request().unwrap().url,
        "http://cluster.test/r/v1/responses/resp_abc123"
    );

    let mut other = RequestCtx::new();
    other.user_id = Some("u2".into());
    assert!(gateway
        .response_op("resp_abc123", yb_gateway::service::ResponseOp::Get, &other)
        .await
        .is_err());
}

// ---------------------------------------------------------------------------
// SystemOne (`jev`) & OpenAI/LiteLLM Decisions (`decisions`) + multi-family
// provider & deployment shapes.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn systemone_jev_same_shape_relays_bytes_and_meters_usage() {
    let upstream_resp = br#"{"id":"s1_live01","object":"systemone","created":1731542000,"model":"qwen-upstream","decisions":{"allow":{"yes":0.94,"no":0.06,"value":true}},"usage":{"prompt_tokens":128,"completion_tokens":0,"total_tokens":128,"prompt_tokens_details":{"cached_tokens":96}}}"#;
    let mock = MockClient::json(upstream_resp.to_vec());
    let store = Arc::new(RecordingStore::default());

    let rec = yb_core::DeploymentRecord {
        id: "d-s1".into(),
        model_id: "m-s1".into(),
        model_name: "fast-judge".into(),
        provider_id: "p-s1".into(),
        provider: "s1-cluster".into(),
        upstream_model: "qwen-upstream".into(),
        api_base: Some("http://s1.test:8000/v1".into()),
        api_key: Some("secret-k".into()),
        upstream_format: WireFormat::OpenaiChat.into(),
        weight: 1,
        pricing: Some(yb_core::catalog::ModelPrice::new(1.0, 2.0)),
        health_check: Default::default(),
        health_path: None,
        extra: Default::default(),
        shapes: None,
        provider_shapes: vec![
            yb_core::ProviderShape {
                format: WireFormat::OpenaiChat.into(),
                api_base: None,
            },
            yb_core::ProviderShape {
                format: yb_core::DecisionFormat::Jev.into(),
                api_base: Some("http://s1.test:8000/s1/v1".into()),
            },
        ],
        created_at: now(),
        updated_at: now(),
        deleted_at: None,
    };
    let router = DeploymentRouter::from_deployments(
        &[rec],
        Strategy::Simple,
        HashMap::new(),
        HashMap::new(),
    );
    let gateway = Gateway::new(
        Arc::new(mock.clone()),
        Arc::new(router),
        store.clone(),
        Arc::new(NullLogger),
    );

    let req_body = br#"{"model":"fast-judge","state":[{"role":"user","content":"Approve PR #42?"}],"questions":{"allow":{"type":"noul","question":"Should PR #42 merge?"}},"thinking_budget":0,"prompt_cache_key":"pr-judge-v1"}"#;
    let resp = gateway
        .handle_decision(yb_core::DecisionFormat::Jev, req_body, RequestCtx::new())
        .await
        .unwrap();
    let got_bytes = collect(resp).await;
    assert_eq!(
        got_bytes,
        upstream_resp.to_vec(),
        "same-shape jev relays verbatim"
    );

    let sent = mock.last_request().unwrap();
    assert_eq!(sent.url, "http://s1.test:8000/s1/v1/systemone");
    assert!(!sent.stream);
    assert!(sent
        .headers
        .iter()
        .any(|(k, v)| k == "authorization" && v == "Bearer secret-k"));
    let expected_req =
        String::from_utf8_lossy(req_body).replace("\"fast-judge\"", "\"qwen-upstream\"");
    assert_eq!(String::from_utf8_lossy(&sent.body), expected_req);

    let t = store.telemetry();
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].surface, "jev");
    assert_eq!(t[0].input_tokens, 128);
    assert_eq!(t[0].output_tokens, 0);
    assert_eq!(t[0].cache_read_tokens, 96);
    assert!(!t[0].is_error);
}

#[tokio::test]
async fn decisions_and_jev_translate_envelopes_across_decision_shapes() {
    // 1. Client calls `decisions` (`/v1/decisions`), deployment only serves `jev` (`/v1/systemone`).
    let jev_resp = serde_json::to_vec(&json!({
        "id": "s1_abc999",
        "object": "systemone",
        "model": "qwen-upstream",
        "decisions": {
            "route": {"billing": 0.8, "tech": 0.2, "choice": "billing"}
        },
        "usage": {"prompt_tokens": 40, "completion_tokens": 0, "total_tokens": 40}
    }))
    .unwrap();
    let mock = MockClient::json(jev_resp);
    let rec = yb_core::DeploymentRecord {
        id: "d-jev".into(),
        model_id: "m-router".into(),
        model_name: "triage".into(),
        provider_id: "p-jev".into(),
        provider: "jev-only".into(),
        upstream_model: "qwen-upstream".into(),
        api_base: Some("http://jev.test/v1".into()),
        api_key: None,
        upstream_format: yb_core::DecisionFormat::Jev.into(),
        weight: 1,
        pricing: None,
        health_check: Default::default(),
        health_path: None,
        extra: Default::default(),
        shapes: None,
        provider_shapes: vec![yb_core::ProviderShape {
            format: yb_core::DecisionFormat::Jev.into(),
            api_base: None,
        }],
        created_at: now(),
        updated_at: now(),
        deleted_at: None,
    };
    let gateway = Gateway::new(
        Arc::new(mock.clone()),
        Arc::new(DeploymentRouter::from_deployments(
            &[rec],
            Strategy::Simple,
            HashMap::new(),
            HashMap::new(),
        )),
        Arc::new(RecordingStore::default()),
        Arc::new(NullLogger),
    );
    let req = serde_json::to_vec(&json!({
        "model": "triage",
        "state": "My invoice is wrong",
        "questions": {
            "route": {
                "type": "enum",
                "question": "Which queue?",
                "options": {"billing": "Billing", "tech": "Tech"}
            }
        }
    }))
    .unwrap();
    let resp = gateway
        .handle_decision(yb_core::DecisionFormat::Decisions, &req, RequestCtx::new())
        .await
        .unwrap();
    assert_eq!(
        mock.last_request().unwrap().url,
        "http://jev.test/v1/systemone"
    );
    let v: Value = serde_json::from_slice(&collect(resp).await).unwrap();
    assert_eq!(v["object"], "decision");
    assert_eq!(v["id"], "dec_abc999");
    assert_eq!(v["decisions"]["route"]["choice"], "billing");

    // 2. Client calls `jev` (`/v1/systemone`), deployment only serves `decisions` (`/v1/decisions`).
    let dec_resp = serde_json::to_vec(&json!({
        "id": "dec_xyz111",
        "object": "decision",
        "model": "dec-upstream",
        "decisions": {"ok": {"yes": 0.5, "no": 0.5, "value": true}},
        "usage": {"input_tokens": 12}
    }))
    .unwrap();
    let mock2 = MockClient::json(dec_resp);
    let rec2 = yb_core::DeploymentRecord {
        id: "d-dec".into(),
        model_id: "m-router".into(),
        model_name: "triage".into(),
        provider_id: "p-dec".into(),
        provider: "dec-only".into(),
        upstream_model: "dec-upstream".into(),
        api_base: Some("http://dec.test/v1".into()),
        api_key: None,
        upstream_format: yb_core::DecisionFormat::Decisions.into(),
        weight: 1,
        pricing: None,
        health_check: Default::default(),
        health_path: None,
        extra: Default::default(),
        shapes: None,
        provider_shapes: vec![yb_core::ProviderShape {
            format: yb_core::DecisionFormat::Decisions.into(),
            api_base: None,
        }],
        created_at: now(),
        updated_at: now(),
        deleted_at: None,
    };
    let store2 = Arc::new(RecordingStore::default());
    let gateway2 = Gateway::new(
        Arc::new(mock2.clone()),
        Arc::new(DeploymentRouter::from_deployments(
            &[rec2],
            Strategy::Simple,
            HashMap::new(),
            HashMap::new(),
        )),
        store2.clone(),
        Arc::new(NullLogger),
    );
    let resp2 = gateway2
        .handle_decision(yb_core::DecisionFormat::Jev, &req, RequestCtx::new())
        .await
        .unwrap();
    assert_eq!(
        mock2.last_request().unwrap().url,
        "http://dec.test/v1/decisions"
    );
    let v2: Value = serde_json::from_slice(&collect(resp2).await).unwrap();
    assert_eq!(v2["object"], "systemone");
    assert_eq!(v2["id"], "s1_xyz111");
    assert_eq!(store2.telemetry()[0].input_tokens, 12);
}

#[tokio::test]
async fn provider_shapes_route_chat_embed_and_jev_with_per_shape_bases_and_narrowing() {
    let provider_shapes = vec![
        yb_core::ProviderShape {
            format: WireFormat::Anthropic.into(),
            api_base: Some("https://api.z.test/api/anthropic".into()),
        },
        yb_core::ProviderShape {
            format: WireFormat::OpenaiChat.into(),
            api_base: Some("https://api.z.test/api/paas/v4".into()),
        },
        yb_core::ProviderShape {
            format: yb_core::EmbedFormat::OpenaiEmbed.into(),
            api_base: Some("https://api.z.test/api/paas/v4".into()),
        },
    ];

    // Chat-only deployment narrowed to [Anthropic, OpenaiChat], and embed-only narrowed to [OpenaiEmbed].
    let chat_dep = yb_core::DeploymentRecord {
        id: "d-chat".into(),
        model_id: "m-chat".into(),
        model_name: "glm-5".into(),
        provider_id: "p-z".into(),
        provider: "zai".into(),
        upstream_model: "glm-5".into(),
        api_base: Some("https://api.z.test/api/anthropic".into()),
        api_key: Some("zk".into()),
        upstream_format: WireFormat::Anthropic.into(),
        weight: 1,
        pricing: None,
        health_check: Default::default(),
        health_path: None,
        extra: Default::default(),
        shapes: Some(vec![
            WireFormat::Anthropic.into(),
            WireFormat::OpenaiChat.into(),
        ]),
        provider_shapes: provider_shapes.clone(),
        created_at: now(),
        updated_at: now(),
        deleted_at: None,
    };
    let embed_dep = yb_core::DeploymentRecord {
        id: "d-emb".into(),
        model_id: "m-emb".into(),
        model_name: "z-embed".into(),
        provider_id: "p-z".into(),
        provider: "zai".into(),
        upstream_model: "embedding-3".into(),
        api_base: Some("https://api.z.test/api/anthropic".into()),
        api_key: Some("zk".into()),
        upstream_format: yb_core::EmbedFormat::OpenaiEmbed.into(),
        weight: 1,
        pricing: None,
        health_check: Default::default(),
        health_path: None,
        extra: Default::default(),
        shapes: Some(vec![yb_core::EmbedFormat::OpenaiEmbed.into()]),
        provider_shapes,
        created_at: now(),
        updated_at: now(),
        deleted_at: None,
    };

    let router = Arc::new(DeploymentRouter::from_deployments(
        &[chat_dep, embed_dep],
        Strategy::Simple,
        HashMap::new(),
        HashMap::new(),
    ));

    // 1. OpenAI Chat call to `glm-5` hits `/api/paas/v4/chat/completions` (NO `/v4/v1` bug!).
    let chat_mock = MockClient::json(
        serde_json::to_vec(&json!({
            "id": "c1",
            "object": "chat.completion",
            "model": "glm-5",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 4, "completion_tokens": 1, "total_tokens": 5}
        }))
        .unwrap(),
    );
    let gw = Gateway::new(
        Arc::new(chat_mock.clone()),
        router.clone(),
        Arc::new(RecordingStore::default()),
        Arc::new(NullLogger),
    );
    gw.handle(
        WireFormat::OpenaiChat,
        br#"{"model":"glm-5","messages":[{"role":"user","content":"hi"}]}"#,
        RequestCtx::new(),
    )
    .await
    .unwrap();
    assert_eq!(
        chat_mock.last_request().unwrap().url,
        "https://api.z.test/api/paas/v4/chat/completions"
    );

    // 2. Calling embed on narrowed chat-only `glm-5` is rejected with 400 BadRequest.
    let err = gw
        .handle_embed(
            yb_core::EmbedFormat::OpenaiEmbed,
            br#"{"model":"glm-5","input":"hello"}"#,
            RequestCtx::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.http_status(), 400);

    // 3. Calling decision on `glm-5` (no decision shape enabled) is rejected with 400 BadRequest.
    let err = gw
        .handle_decision(
            yb_core::DecisionFormat::Jev,
            br#"{"model":"glm-5","state":"hi","questions":{"q":{"type":"noul","question":"ok?"}}}"#,
            RequestCtx::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.http_status(), 400);

    // 4. Calling embed on `z-embed` uses the provider's `openai_embed` shape base `/api/paas/v4/embeddings`.
    let emb_mock = MockClient::json(
        serde_json::to_vec(&json!({
            "object": "list",
            "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2]}],
            "model": "embedding-3",
            "usage": {"prompt_tokens": 3, "total_tokens": 3}
        }))
        .unwrap(),
    );
    let gw_emb = Gateway::new(
        Arc::new(emb_mock.clone()),
        router,
        Arc::new(RecordingStore::default()),
        Arc::new(NullLogger),
    );
    gw_emb
        .handle_embed(
            yb_core::EmbedFormat::OpenaiEmbed,
            br#"{"model":"z-embed","input":"hello"}"#,
            RequestCtx::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        emb_mock.last_request().unwrap().url,
        "https://api.z.test/api/paas/v4/embeddings"
    );
}
