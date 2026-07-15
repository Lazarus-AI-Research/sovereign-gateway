//! End-to-end exercise of `SqliteStore` against a real temp-file database.
//!
//! `:memory:` SQLite databases are not shared across pool connections, so we
//! create the DB in the OS temp dir and clean it up on drop.
//!
//! Identity model: a **user** is the login account that owns keys. There is no
//! installation/tenancy layer.

use std::path::PathBuf;

use yb_core::crypto::{Encryptor, PasswordHasher};
use yb_core::model::{Role, Team, TeamMembership, TelemetryRecord, User};
use yb_core::spend::{Budget, BudgetAction, Period, RollupDelta, SubjectType};
use yb_core::{new_id, now, AccessPolicy, ExternalKey, LimitColumns, Store};
use yb_store::crypto::{AesGcmEncryptor, Argon2Hasher};
use yb_store::keys::{hash_token, issue_api_key};
use yb_store::SqliteStore;

/// A temp DB path that deletes its files (incl. WAL/SHM) on drop.
struct TempDb {
    path: PathBuf,
}

impl TempDb {
    fn new() -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("yb_store_test_{}.db", new_id()));
        TempDb { path }
    }
    fn as_str(&self) -> &str {
        self.path.to_str().unwrap()
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let p = format!("{}{}", self.path.display(), suffix);
            let _ = std::fs::remove_file(p);
        }
    }
}

async fn fresh_store() -> (SqliteStore, TempDb) {
    let db = TempDb::new();
    let store = SqliteStore::connect(db.as_str()).await.expect("connect");
    store.migrate().await.expect("migrate");
    // migrate is idempotent — running twice must not error.
    store.migrate().await.expect("migrate twice");
    (store, db)
}

/// Create a login user with the given username/role and return its id.
async fn make_user(store: &SqliteStore, username: &str, role: Role) -> String {
    let hasher = Argon2Hasher;
    let user = User {
        id: new_id(),
        username: username.into(),
        password_hash: hasher.hash("hunter2").unwrap(),
        role,
        rpm_limit: None,
        tpm_limit: None,
        max_concurrent: None,
        created_at: now(),
        last_login_at: None,
        deleted_at: None,
    };
    store.create_user(&user).await.unwrap();
    user.id
}

#[tokio::test]
async fn users_login_roles_and_admin_count() {
    let (store, _db) = fresh_store().await;
    let hasher = Argon2Hasher;

    assert_eq!(store.count_users().await.unwrap(), 0);

    // The login account *is* the user.
    let admin = User {
        id: new_id(),
        username: "admin".into(),
        password_hash: hasher.hash("hunter2").unwrap(),
        role: Role::Admin,
        rpm_limit: None,
        tpm_limit: None,
        max_concurrent: None,
        created_at: now(),
        last_login_at: None,
        deleted_at: None,
    };
    store.create_user(&admin).await.unwrap();
    assert_eq!(store.count_users().await.unwrap(), 1);
    assert_eq!(store.count_admins().await.unwrap(), 1);

    // Login: resolve by username (unique), then argon2-verify.
    let by_name = store
        .get_user_by_username("admin")
        .await
        .unwrap()
        .expect("admin resolves");
    assert_eq!(by_name.id, admin.id);
    assert!(hasher.verify("hunter2", &by_name.password_hash));

    // Demote -> no admins left (last-admin guard input).
    store.set_user_role(&admin.id, Role::Member).await.unwrap();
    assert_eq!(store.count_admins().await.unwrap(), 0);

    // Password reset + login mark + limits.
    let new_hash = hasher.hash("newpass").unwrap();
    store.set_user_password(&admin.id, &new_hash).await.unwrap();
    store.mark_user_login(&admin.id).await.unwrap();
    store
        .set_user_limits(
            &admin.id,
            LimitColumns {
                rpm: Some(120),
                tpm: Some(50_000),
                max_concurrent: Some(8),
            },
        )
        .await
        .unwrap();
    let reloaded = store.get_user(&admin.id).await.unwrap().unwrap();
    assert_eq!(reloaded.role, Role::Member);
    assert!(reloaded.last_login_at.is_some());
    assert_eq!(reloaded.rpm_limit, Some(120));
    assert!(hasher.verify("newpass", &reloaded.password_hash));

    assert_eq!(store.list_users().await.unwrap().len(), 1);

    // Soft delete removes it from the active set and username lookups.
    store.delete_user(&admin.id).await.unwrap();
    assert_eq!(store.count_users().await.unwrap(), 0);
    assert!(store.get_user_by_username("admin").await.unwrap().is_none());
}

#[tokio::test]
async fn api_key_issue_and_verify_owned_by_user() {
    let (store, _db) = fresh_store().await;
    let user_id = make_user(&store, "alice", Role::Member).await;

    let issued = issue_api_key(
        &store,
        &user_id,
        Some("ci-key".into()),
        None,
        Default::default(),
        AccessPolicy {
            denied_models: vec!["secret-model".into()],
            ..Default::default()
        },
        LimitColumns {
            rpm: Some(10),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert!(issued.token.starts_with("yb_"));
    assert_eq!(issued.key.owner_user_id, user_id);

    // Hot auth path: verify by hashing the plaintext token -> KeyAuth{user, key}.
    let auth = store
        .verify_api_key(&hash_token(&issued.token))
        .await
        .unwrap()
        .expect("key resolves");
    assert_eq!(auth.user.id, user_id);
    assert_eq!(auth.user.username, "alice");
    assert_eq!(auth.api_key.id, issued.key.id);
    assert_eq!(auth.api_key.owner_user_id, user_id);
    assert_eq!(auth.api_key.rpm_limit, Some(10));
    assert!(!auth.api_key.access.permits_model("secret-model"));

    // Admin listing returns all keys; per-user listing scopes to the owner.
    assert_eq!(store.list_api_keys().await.unwrap().len(), 1);
    let mine = store.list_api_keys_for_user(&user_id).await.unwrap();
    assert_eq!(mine.len(), 1);
    let by_id = store.get_api_key(&issued.key.id).await.unwrap().unwrap();
    assert_eq!(by_id.key_prefix, issued.key.key_prefix);

    // Keys owned by another user do not show up under this user.
    let other = make_user(&store, "bob", Role::Member).await;
    assert!(store.list_api_keys_for_user(&other).await.unwrap().is_empty());

    // Mark-used updates last_used_at.
    store.mark_api_key_used(&issued.key.id).await.unwrap();
    let used = store.get_api_key(&issued.key.id).await.unwrap().unwrap();
    assert!(used.last_used_at.is_some());

    // Update access + limits (no installation scope).
    store
        .update_api_key_access(&issued.key.id, &AccessPolicy::default())
        .await
        .unwrap();
    store
        .update_api_key_limits(
            &issued.key.id,
            LimitColumns {
                rpm: Some(99),
                tpm: None,
                max_concurrent: None,
            },
        )
        .await
        .unwrap();
    let updated = store.get_api_key(&issued.key.id).await.unwrap().unwrap();
    assert!(updated.access.is_unrestricted());
    assert_eq!(updated.rpm_limit, Some(99));

    // Delete removes it from verify + listings.
    store.delete_api_key(&issued.key.id).await.unwrap();
    assert!(store
        .verify_api_key(&hash_token(&issued.token))
        .await
        .unwrap()
        .is_none());
    assert!(store.list_api_keys().await.unwrap().is_empty());

    // Unknown hash resolves to None.
    assert!(store.verify_api_key("deadbeef").await.unwrap().is_none());
}

#[tokio::test]
async fn external_keys_encrypted_roundtrip() {
    let (store, _db) = fresh_store().await;
    let user_id = make_user(&store, "byok", Role::Member).await;

    let enc = AesGcmEncryptor::new([42u8; 32]);
    let aad = format!("{}\0openai", user_id);
    let ciphertext = enc.encrypt(b"sk-live-123", aad.as_bytes()).unwrap();

    let ext = ExternalKey {
        id: new_id(),
        user_id: user_id.clone(),
        provider: "openai".into(),
        ciphertext: ciphertext.clone(),
        key_prefix: "sk-li".into(),
        key_suffix: "-123".into(),
        created_at: now(),
        last_used_at: None,
    };
    store.upsert_external_key(&ext).await.unwrap();

    // Upsert again with a new ciphertext (same user+provider).
    let ciphertext2 = enc.encrypt(b"sk-live-456", aad.as_bytes()).unwrap();
    let mut ext2 = ext.clone();
    ext2.ciphertext = ciphertext2.clone();
    ext2.key_suffix = "-456".into();
    store.upsert_external_key(&ext2).await.unwrap();

    let listed = store.list_external_keys(&user_id).await.unwrap();
    assert_eq!(listed.len(), 1, "upsert must not duplicate");
    let stored = &listed[0];
    assert_eq!(stored.key_suffix, "-456");
    let plaintext = enc.decrypt(&stored.ciphertext, aad.as_bytes()).unwrap();
    assert_eq!(plaintext, b"sk-live-456");

    store.delete_external_key(&user_id, "openai").await.unwrap();
    assert!(store.list_external_keys(&user_id).await.unwrap().is_empty());
}

#[tokio::test]
async fn teams_and_memberships() {
    let (store, _db) = fresh_store().await;

    let team = Team {
        id: new_id(),
        name: "Platform".into(),
        access: AccessPolicy::default(),
        created_at: now(),
        updated_at: now(),
        deleted_at: None,
        created_by: Some("seed".into()),
    };
    store.create_team(&team).await.unwrap();
    assert_eq!(store.list_teams().await.unwrap().len(), 1);

    store
        .update_team_access(
            &team.id,
            &AccessPolicy {
                allowed_providers: vec!["anthropic".into()],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let got = store.get_team(&team.id).await.unwrap().unwrap();
    assert!(got.access.permits_provider("anthropic"));
    assert!(!got.access.permits_provider("openai"));

    let alice = make_user(&store, "alice", Role::Member).await;
    let bob = make_user(&store, "bob", Role::Member).await;
    let m = TeamMembership {
        id: new_id(),
        team_id: team.id.clone(),
        user_id: alice.clone(),
        created_at: now(),
    };
    store.upsert_membership(&m).await.unwrap();
    // Upsert again — should be idempotent, not duplicate.
    store.upsert_membership(&m).await.unwrap();
    store
        .upsert_membership(&TeamMembership {
            id: new_id(),
            team_id: team.id.clone(),
            user_id: bob.clone(),
            created_at: now(),
        })
        .await
        .unwrap();

    let for_alice = store.list_memberships_for_user(&alice).await.unwrap();
    assert_eq!(for_alice.len(), 1);
    assert_eq!(for_alice[0].team_id, team.id);

    let members = store.list_team_members(&team.id).await.unwrap();
    assert_eq!(members.len(), 2);

    store.delete_membership(&team.id, &alice).await.unwrap();
    assert!(store
        .list_memberships_for_user(&alice)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(store.list_team_members(&team.id).await.unwrap().len(), 1);

    store.delete_team(&team.id).await.unwrap();
    assert!(store.list_teams().await.unwrap().is_empty());
}

#[tokio::test]
async fn telemetry_insert_by_key_user_team() {
    let (store, _db) = fresh_store().await;
    let user_id = make_user(&store, "alice", Role::Member).await;
    let issued = issue_api_key(&store, &user_id, None, None, Default::default(), AccessPolicy::default(), LimitColumns::default())
        .await
        .unwrap();

    let rec = TelemetryRecord {
        id: new_id(),
        request_id: "req-1".into(),
        trace_id: Some("trace-1".into()),
        api_key_id: Some(issued.key.id.clone()),
        user_id: Some(user_id.clone()),
        team_id: None,
        surface: "anthropic".into(),
        requested_model: "claude".into(),
        decision_model: "claude-3".into(),
        decision_provider: "anthropic".into(),
        input_tokens: 100,
        output_tokens: 50,
        cache_read_tokens: 10,
        cache_write_tokens: 0,
        cost_micros: 1_234,
        status: 200,
        is_error: false,
        latency_ms: 321,
        created_at: now(),
    };
    store.insert_telemetry(&rec).await.unwrap();
}

#[tokio::test]
async fn spend_rollup_and_period_spend_by_key_and_user() {
    let (store, _db) = fresh_store().await;

    let at = now();
    let period_start = Period::Day.bucket_start(at);

    // Roll up spend against a key subject and a user subject.
    for (st, sid) in [(SubjectType::Key, "key-1"), (SubjectType::User, "user-1")] {
        let delta = RollupDelta {
            subject_type: st,
            subject_id: sid.into(),
            period: Period::Day,
            period_start,
            spend_micros: 500,
            request_count: 1,
            input_tokens: 100,
            output_tokens: 20,
        };
        store.upsert_rollup(&delta).await.unwrap();
        // Second increment accumulates.
        store.upsert_rollup(&delta).await.unwrap();
    }

    let by_key = store
        .period_spend(SubjectType::Key, "key-1", Period::Day, period_start)
        .await
        .unwrap();
    assert_eq!(by_key, 1_000, "two 500-micro deltas must sum");
    let by_user = store
        .period_spend(SubjectType::User, "user-1", Period::Day, period_start)
        .await
        .unwrap();
    assert_eq!(by_user, 1_000);

    let rows = store.spend_rows().await.unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r.request_count == 2 && r.input_tokens == 200));
}

#[tokio::test]
async fn budgets_by_user_subject() {
    let (store, _db) = fresh_store().await;
    let user_id = make_user(&store, "alice", Role::Member).await;

    let budget = Budget {
        id: new_id(),
        subject_type: SubjectType::User,
        subject_id: user_id.clone(),
        period: Period::Day,
        hard_limit_micros: 10_000,
        soft_limit_micros: Some(8_000),
        action: BudgetAction::Block,
        enabled: true,
        created_at: now(),
        updated_at: now(),
        deleted_at: None,
    };
    store.upsert_budget(&budget).await.unwrap();
    // Upsert same id raises the cap.
    let mut b2 = budget.clone();
    b2.hard_limit_micros = 20_000;
    store.upsert_budget(&b2).await.unwrap();

    let budgets = store
        .list_budgets(SubjectType::User, &user_id)
        .await
        .unwrap();
    assert_eq!(budgets.len(), 1);
    assert_eq!(budgets[0].hard_limit_micros, 20_000);
    assert_eq!(budgets[0].action, BudgetAction::Block);
    assert!(budgets[0].enabled);

    // Admin overview lists across subjects.
    assert_eq!(store.list_all_budgets().await.unwrap().len(), 1);

    store.delete_budget(&budget.id).await.unwrap();
    assert!(store
        .list_budgets(SubjectType::User, &user_id)
        .await
        .unwrap()
        .is_empty());
    assert!(store.list_all_budgets().await.unwrap().is_empty());
}

#[tokio::test]
async fn rate_counter_accumulates() {
    let (store, _db) = fresh_store().await;

    let window = Period::Day.bucket_start(now());
    let a = store.incr_rate_counter("key-1", "rpm", window, 1).await.unwrap();
    let b = store.incr_rate_counter("key-1", "rpm", window, 2).await.unwrap();
    assert_eq!(a, 1);
    assert_eq!(b, 3);
}

#[tokio::test]
async fn deployments_seed_create_and_list() {
    use yb_core::routing::{DeploymentRecord, WireFormat};
    let (store, _db) = fresh_store().await;

    let dep = DeploymentRecord {
        id: new_id(),
        model_name: "gpt-4o".into(),
        provider: "openai".into(),
        upstream_model: "gpt-4o".into(),
        api_base: None,
        api_key: None,
        upstream_format: WireFormat::OpenaiChat.into(),
        weight: 2,
        health_check: Default::default(),
        health_path: None,
        pricing: Some(yb_core::catalog::ModelPrice::new(2.5, 10.0)),
        created_at: now(),
        updated_at: now(),
        deleted_at: None,
    };

    // Seeding is idempotent on the natural key.
    assert!(store.seed_deployment(&dep).await.unwrap());
    assert!(!store.seed_deployment(&dep).await.unwrap());

    let all = store.list_deployments().await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].model_name, "gpt-4o");
    assert_eq!(all[0].weight, 2);
    assert_eq!(all[0].upstream_format, WireFormat::OpenaiChat.into());
    assert!(all[0].pricing.is_some());

    // Explicit create + soft delete.
    let mut dep2 = dep.clone();
    dep2.id = new_id();
    dep2.provider = "azure".into();
    store.create_deployment(&dep2).await.unwrap();
    assert_eq!(store.list_deployments().await.unwrap().len(), 2);

    store.delete_deployment(&dep2.id).await.unwrap();
    assert_eq!(store.list_deployments().await.unwrap().len(), 1);
    assert!(store.get_deployment(&dep2.id).await.unwrap().is_none());
}

#[tokio::test]
async fn model_aliases_upsert_list_delete() {
    use yb_core::ModelAlias;
    let (store, _db) = fresh_store().await;

    assert!(store.list_aliases().await.unwrap().is_empty());

    store
        .upsert_alias(&ModelAlias { alias: "gpt-4".into(), target: "gpt-4o".into(), created_at: now() })
        .await
        .unwrap();
    // Upsert on the same alias key replaces the target (uniqueness via PK).
    store
        .upsert_alias(&ModelAlias { alias: "gpt-4".into(), target: "gpt-4o-mini".into(), created_at: now() })
        .await
        .unwrap();

    let all = store.list_aliases().await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].alias, "gpt-4");
    assert_eq!(all[0].target, "gpt-4o-mini");

    store.delete_alias("gpt-4").await.unwrap();
    assert!(store.list_aliases().await.unwrap().is_empty());
}

#[tokio::test]
async fn embed_format_deployment_roundtrips() {
    use yb_core::routing::{DeploymentRecord, EmbedFormat, UpstreamFormat};
    let (store, _db) = fresh_store().await;
    let dep = DeploymentRecord {
        id: new_id(),
        model_name: "embedding-omni-default".into(),
        provider: "runtime".into(),
        upstream_model: "LCO-Embedding-Omni".into(),
        api_base: Some("http://runtime:8000/v1".into()),
        api_key: None,
        upstream_format: EmbedFormat::OpenaiEmbed.into(),
        weight: 1,
        pricing: None,
        health_check: Default::default(),
        health_path: None,
        created_at: now(),
        updated_at: now(),
        deleted_at: None,
    };
    store.create_deployment(&dep).await.unwrap();
    let all = store.list_deployments().await.unwrap();
    assert_eq!(all[0].upstream_format, UpstreamFormat::Embed(EmbedFormat::OpenaiEmbed));
}

#[tokio::test]
async fn api_key_scopes_roundtrip_and_legacy_single_value() {
    use yb_core::model::KeyScope;
    let (store, _db) = fresh_store().await;
    let user_id = make_user(&store, "scoped", Role::Admin).await;

    // A key holding BOTH scopes round-trips as a set.
    let issued = issue_api_key(
        &store,
        &user_id,
        Some("dual".into()),
        None,
        vec![KeyScope::Inference, KeyScope::Admin],
        AccessPolicy::default(),
        LimitColumns::default(),
    )
    .await
    .unwrap();
    let auth = store.verify_api_key(&hash_token(&issued.token)).await.unwrap().unwrap();
    assert!(auth.api_key.has_scope(KeyScope::Inference));
    assert!(auth.api_key.has_scope(KeyScope::Admin));
    assert_eq!(auth.api_key.scopes.len(), 2);

    // A pre-existing row storing a single bare value (the old storage form)
    // parses to a one-element set — no migration needed.
    sqlx::query("UPDATE api_keys SET scope = 'admin' WHERE id = ?")
        .bind(&auth.api_key.id)
        .execute(store.pool())
        .await
        .unwrap();
    let auth = store.verify_api_key(&hash_token(&issued.token)).await.unwrap().unwrap();
    assert_eq!(auth.api_key.scopes, vec![KeyScope::Admin]);
}
