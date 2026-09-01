//! Domain value types: identity (users, keys, teams), access policy, telemetry.
//!
//! Identity model: a **user** is the login account (username + password + role).
//! A user owns **api keys**. Users group into **teams** (many-to-many). Spend,
//! budgets, and access grants attach to a key, a user, or a team. There is no
//! separate tenancy ("installation") layer.

use crate::ids::{Id, Micros, Timestamp};
use serde::{Deserialize, Serialize};

/// A per-key / per-team model & provider allow/deny list. Empty allow lists mean
/// "no restriction at this scope"; deny always wins.
///
/// Models are held as **ids**, providers as **names**. That asymmetry is
/// deliberate and not an oversight: a model is an entity with a row and a stable
/// id, whereas a provider is a free-form attribution label with no row anywhere.
/// Holding model ids is what stops a rename from silently un-denying a denied
/// model — with names, `denied_models: ["gpt-4o"]` simply stops matching the
/// moment someone renames it, granting access with no error and no log line.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessPolicy {
    #[serde(default)]
    pub allowed_model_ids: Vec<String>,
    #[serde(default)]
    pub denied_model_ids: Vec<String>,
    #[serde(default)]
    pub allowed_providers: Vec<String>,
    #[serde(default)]
    pub denied_providers: Vec<String>,
}

impl AccessPolicy {
    pub fn is_unrestricted(&self) -> bool {
        self.allowed_model_ids.is_empty()
            && self.denied_model_ids.is_empty()
            && self.allowed_providers.is_empty()
            && self.denied_providers.is_empty()
    }

    /// Does this policy permit the given model? Deny wins; a non-empty allow
    /// list is a ceiling (anything not listed is denied).
    ///
    /// Takes a model **id**, so the answer is stable across renames.
    pub fn permits_model(&self, model_id: &str) -> bool {
        if self.denied_model_ids.iter().any(|m| m == model_id) {
            return false;
        }
        if !self.allowed_model_ids.is_empty()
            && !self.allowed_model_ids.iter().any(|m| m == model_id)
        {
            return false;
        }
        true
    }

    /// Does this policy permit the given provider? Same precedence as models.
    pub fn permits_provider(&self, provider: &str) -> bool {
        if self.denied_providers.iter().any(|p| p == provider) {
            return false;
        }
        if !self.allowed_providers.is_empty()
            && !self.allowed_providers.iter().any(|p| p == provider)
        {
            return false;
        }
        true
    }

    /// Combine two access grants (e.g. a key within a team). Denies are unioned
    /// (a deny at any scope wins); allow-lists are intersected when both restrict
    /// (the narrower grant wins), and an empty allow-list means "no ceiling" so it
    /// defers to the other scope.
    pub fn merge(&self, other: &AccessPolicy) -> AccessPolicy {
        fn union(a: &[String], b: &[String]) -> Vec<String> {
            let mut out: Vec<String> = a.to_vec();
            for x in b {
                if !out.contains(x) {
                    out.push(x.clone());
                }
            }
            out
        }
        fn intersect_allow(a: &[String], b: &[String]) -> Vec<String> {
            if a.is_empty() {
                return b.to_vec();
            }
            if b.is_empty() {
                return a.to_vec();
            }
            a.iter().filter(|x| b.contains(x)).cloned().collect()
        }
        AccessPolicy {
            allowed_model_ids: intersect_allow(&self.allowed_model_ids, &other.allowed_model_ids),
            denied_model_ids: union(&self.denied_model_ids, &other.denied_model_ids),
            allowed_providers: intersect_allow(&self.allowed_providers, &other.allowed_providers),
            denied_providers: union(&self.denied_providers, &other.denied_providers),
        }
    }
}

/// Access level. Two roles: `admin` (full control) and `member` (use the
/// gateway, manage their own keys).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    #[default]
    Member,
    Admin,
}

impl Role {
    pub fn at_least(self, other: Role) -> bool {
        self >= other
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Member => "member",
            Role::Admin => "admin",
        }
    }
    pub fn parse(s: &str) -> crate::Result<Role> {
        match s {
            "admin" => Ok(Role::Admin),
            // `user` is accepted as an alias for `member`.
            "member" | "user" => Ok(Role::Member),
            other => Err(crate::Error::BadRequest(format!("unknown role: {other}"))),
        }
    }
}

/// A login account — the unit that owns keys and authenticates to the admin
/// console. Passwords are stored only as an Argon2 hash. Bootstrap with
/// `gateway setup` (defaults to admin/admin).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Id,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: Role,
    /// Per-user rate limits (null = unlimited / fall back to defaults).
    pub rpm_limit: Option<i64>,
    pub tpm_limit: Option<i64>,
    pub max_concurrent: Option<i64>,
    pub created_at: Timestamp,
    pub last_login_at: Option<Timestamp>,
    pub deleted_at: Option<Timestamp>,
}

/// A web console session: an opaque random token (stored in the cookie) that
/// maps to a user, with a DB-side expiry. Looked up on every request, so logout
/// (delete the row) and role changes (role is read fresh from the user) take
/// effect immediately. Replaces stateless signed cookies.
#[derive(Debug, Clone)]
pub struct Session {
    pub token: String,
    pub user_id: Id,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
}

/// One grant on a virtual key. A key carries a **set** of scopes:
/// `inference` drives the model surfaces; `admin` authenticates to the
/// management API (`/admin/v1`) as the owner user — machine auth for a control
/// plane. A key holding both may do both; a key holding neither can do nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyScope {
    #[default]
    Inference,
    Admin,
}

impl KeyScope {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyScope::Inference => "inference",
            KeyScope::Admin => "admin",
        }
    }
    pub fn parse(s: &str) -> crate::Result<KeyScope> {
        match s {
            "inference" => Ok(KeyScope::Inference),
            "admin" => Ok(KeyScope::Admin),
            other => Err(crate::Error::BadRequest(format!("unknown key scope: {other}"))),
        }
    }

    /// Parse a scope set from the delimited string form used for DB storage.
    /// Tolerant of spaces, commas, or tabs, so both the current space form and
    /// the comma form written by earlier code parse; a single bare value parses
    /// to a one-element set, so existing rows need no migration. An empty/blank
    /// string defaults to inference-only.
    pub fn parse_set(s: &str) -> crate::Result<Vec<KeyScope>> {
        let mut out = Vec::new();
        for part in s.split([' ', ',', '\t']).map(str::trim).filter(|p| !p.is_empty()) {
            let scope = KeyScope::parse(part)?;
            if !out.contains(&scope) {
                out.push(scope);
            }
        }
        if out.is_empty() {
            out.push(KeyScope::Inference);
        }
        Ok(out)
    }

    /// Render a scope set as the space-delimited string form used for DB
    /// storage (stable order). The wire form is a JSON array, not this.
    pub fn render_set(scopes: &[KeyScope]) -> String {
        let mut parts: Vec<&str> = scopes.iter().map(|s| s.as_str()).collect();
        parts.sort_unstable();
        parts.dedup();
        parts.join(" ")
    }
}

/// The default scope set: inference only.
pub fn default_scopes() -> Vec<KeyScope> {
    vec![KeyScope::Inference]
}

/// A router-issued virtual key (`yb_…`), owned by a user. Stored only as a
/// SHA-256 hash plus safe display parts; the raw token is shown once at creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: Id,
    /// The owning user.
    pub owner_user_id: Id,
    /// Optional team the key belongs to (inherits the team's access + budgets).
    pub team_id: Option<Id>,
    #[serde(skip_serializing)]
    pub hash: String,
    pub key_prefix: String,
    pub key_suffix: String,
    pub name: Option<String>,
    /// The set of things this key may do (`inference`, `admin`, or both). A
    /// JSON array on the wire; stored as a delimited string in the DB.
    #[serde(default = "default_scopes")]
    pub scopes: Vec<KeyScope>,
    #[serde(default)]
    pub access: AccessPolicy,
    pub rpm_limit: Option<i64>,
    pub tpm_limit: Option<i64>,
    pub max_concurrent: Option<i64>,
    pub created_at: Timestamp,
    pub last_used_at: Option<Timestamp>,
    pub deleted_at: Option<Timestamp>,
}

impl ApiKey {
    /// Whether the key carries `scope`.
    pub fn has_scope(&self, scope: KeyScope) -> bool {
        self.scopes.contains(&scope)
    }

    /// The log-safe fingerprint: `yb_a1b2c3d4…wxyz`.
    pub fn fingerprint(&self) -> String {
        format!("{}…{}", self.key_prefix, self.key_suffix)
    }
}

/// A freshly created key, returned exactly once with its plaintext token.
#[derive(Debug, Clone, Serialize)]
pub struct IssuedKey {
    pub key: ApiKey,
    /// The full `yb_…` token. Surface to the caller once; never stored.
    pub token: String,
}

/// A customer-owned upstream provider credential (BYOK), owned by a user and
/// encrypted at rest.
#[derive(Debug, Clone)]
pub struct ExternalKey {
    pub id: Id,
    pub user_id: Id,
    pub provider: String,
    /// AES-256-GCM ciphertext (AAD-bound to user+provider).
    pub ciphertext: Vec<u8>,
    pub key_prefix: String,
    pub key_suffix: String,
    pub created_at: Timestamp,
    pub last_used_at: Option<Timestamp>,
}

/// A decrypted upstream credential, alive only for a request's lifetime.
#[derive(Debug, Clone)]
pub struct ResolvedCredential {
    pub provider: String,
    pub plaintext: String,
}

/// A grouping of users with a shared access policy (and optional shared budget).
/// Membership is many-to-many via [`TeamMembership`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Team {
    pub id: Id,
    pub name: String,
    #[serde(default)]
    pub access: AccessPolicy,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub deleted_at: Option<Timestamp>,
    pub created_by: Option<String>,
}

/// A user's membership in a team.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamMembership {
    pub id: Id,
    pub team_id: Id,
    pub user_id: Id,
    pub created_at: Timestamp,
}

/// A public model alias: requests for `alias` resolve as if they named the
/// model's own name. Distinct from fallbacks (which are failover, not aliasing).
///
/// Stored against `model_id`; `target` is the model's **current** name, joined
/// at read time. So renaming a model retargets every one of its aliases with no
/// write, and an alias can never dangle or chain — it is always exactly one hop
/// from a canonical name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelAlias {
    pub alias: String,
    pub model_id: Id,
    pub target: String,
    pub created_at: Timestamp,
}

/// One wide row written per served turn, for the dashboard/reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryRecord {
    pub id: Id,
    pub request_id: String,
    pub trace_id: Option<String>,
    pub api_key_id: Option<Id>,
    pub user_id: Option<Id>,
    pub team_id: Option<Id>,
    /// Client-facing surface: `anthropic` | `openai_chat` | `openai_responses` | `gemini`.
    pub surface: String,
    pub requested_model: String,
    pub decision_model: String,
    pub decision_provider: String,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_read_tokens: i64,
    pub cache_write_tokens: i64,
    pub cost_micros: Micros,
    pub status: i32,
    pub is_error: bool,
    pub latency_ms: i64,
    pub created_at: Timestamp,
}

#[cfg(test)]
mod access_tests {
    use super::*;

    fn pol(allow: &[&str], deny: &[&str]) -> AccessPolicy {
        AccessPolicy {
            allowed_model_ids: allow.iter().map(|s| s.to_string()).collect(),
            denied_model_ids: deny.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn merge_deny_wins_and_allow_intersects() {
        let team = pol(&["a", "b"], &["d"]);
        let key = pol(&["b", "c"], &[]);
        let eff = key.merge(&team);
        assert!(eff.permits_model("b"));
        assert!(!eff.permits_model("a"));
        assert!(!eff.permits_model("c"));
        assert!(!eff.permits_model("d"));
    }

    #[test]
    fn empty_allowlist_defers() {
        let eff = pol(&[], &[]).merge(&pol(&["x"], &[]));
        assert!(eff.permits_model("x"));
        assert!(!eff.permits_model("y"));
    }

    #[test]
    fn roles_are_admin_and_member_only() {
        assert_eq!(Role::parse("user").unwrap(), Role::Member);
        assert!(Role::parse("viewer").is_err());
        assert!(Role::Admin.at_least(Role::Member));
        assert!(!Role::Member.at_least(Role::Admin));
    }
}
