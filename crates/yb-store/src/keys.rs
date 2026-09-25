//! Virtual API-key generation, token hashing, and a convenience issue helper.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore;
use sha2::{Digest, Sha256};
use yb_core::{
    new_id, now, AccessPolicy, ApiKey, IssuedKey, KeyScope, LimitColumns, Result, Role, Store, User,
};

/// The gateway virtual-key prefix. Every issued token starts with `yb_`.
pub const KEY_PREFIX: &str = "yb_";

/// Number of random bytes behind the base64 body of a token.
const TOKEN_RANDOM_BYTES: usize = 24;

/// Hex-encode a byte slice (lowercase, no separators).
fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Two lowercase hex nibbles per byte.
        const HEX: &[u8; 16] = b"0123456789abcdef";
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

/// The stable lookup hash for a raw token: hex-encoded SHA-256.
///
/// This is what `Store::verify_api_key` is keyed on, so the raw token need
/// never be persisted.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    to_hex(&hasher.finalize())
}

/// Generate a fresh virtual key, returning `(token, key_prefix, key_suffix)`.
///
/// - `token`   — the full `yb_<base64url>` secret, shown to the user once.
/// - `key_prefix` — log-safe leading slice, e.g. `yb_a1b2c3d4`.
/// - `key_suffix` — log-safe trailing 4 chars.
pub fn generate_api_key() -> (String, String, String) {
    let mut raw = [0u8; TOKEN_RANDOM_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let body = URL_SAFE_NO_PAD.encode(raw);
    let token = format!("{KEY_PREFIX}{body}");
    let prefix = format!("{KEY_PREFIX}{}", &body[..8]);
    let suffix = body[body.len() - 4..].to_string();
    (token, prefix, suffix)
}

/// Mint a new virtual key owned by `owner_user_id`, persist it via the store,
/// and return the plaintext token alongside the stored [`ApiKey`] (which carries
/// only the hash).
pub async fn issue_api_key(
    store: &dyn Store,
    owner_user_id: &str,
    name: Option<String>,
    team_id: Option<String>,
    scopes: Vec<KeyScope>,
    access: AccessPolicy,
    limits: LimitColumns,
) -> Result<IssuedKey> {
    let (token, key_prefix, key_suffix) = generate_api_key();
    let key = ApiKey {
        id: new_id(),
        owner_user_id: owner_user_id.to_string(),
        team_id,
        hash: hash_token(&token),
        key_prefix,
        key_suffix,
        name,
        scopes,
        access,
        rpm_limit: limits.rpm,
        tpm_limit: limits.tpm,
        max_concurrent: limits.max_concurrent,
        created_at: now(),
        last_used_at: None,
        deleted_at: None,
    };
    store.create_api_key(&key).await?;
    Ok(IssuedKey { key, token })
}

/// The account the control key acts as.
pub const CONTROL_USERNAME: &str = "control";

/// Makes `token` the control key: a key scoped for inference and
/// administration, owned by the `control` administrator, which has no usable
/// password and so can only act through the key. A control key issued under
/// an earlier token is revoked, so rotating the token is a restart.
pub async fn ensure_control_key(store: &dyn Store, token: &str) -> Result<ApiKey> {
    let owner = match store.get_user_by_username(CONTROL_USERNAME).await? {
        Some(user) => {
            if user.role != Role::Admin {
                store.set_user_role(&user.id, Role::Admin).await?;
            }
            user
        }
        None => {
            let user = User {
                id: new_id(),
                username: CONTROL_USERNAME.to_string(),
                // Not a password hash, so no password ever matches it.
                password_hash: "!".to_string(),
                role: Role::Admin,
                rpm_limit: None,
                tpm_limit: None,
                max_concurrent: None,
                created_at: now(),
                last_login_at: None,
                deleted_at: None,
            };
            store.create_user(&user).await?;
            user
        }
    };
    let hash = hash_token(token);
    let mut current = None;
    for key in store.list_api_keys_for_user(&owner.id).await? {
        if key.deleted_at.is_some() || key.name.as_deref() != Some(CONTROL_USERNAME) {
            continue;
        }
        if key.hash == hash {
            current = Some(key);
        } else {
            store.delete_api_key(&key.id).await?;
        }
    }
    if let Some(key) = current {
        return Ok(key);
    }
    let visible = |range: std::ops::Range<usize>| token.get(range).unwrap_or_default().to_string();
    let key = ApiKey {
        id: new_id(),
        owner_user_id: owner.id,
        team_id: None,
        hash,
        key_prefix: visible(0..token.len().min(8)),
        key_suffix: visible(token.len().saturating_sub(4)..token.len()),
        name: Some(CONTROL_USERNAME.to_string()),
        scopes: vec![KeyScope::Inference, KeyScope::Admin],
        access: AccessPolicy::default(),
        rpm_limit: None,
        tpm_limit: None,
        max_concurrent: None,
        created_at: now(),
        last_used_at: None,
        deleted_at: None,
    };
    store.create_api_key(&key).await?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_shape_and_hash() {
        let (token, prefix, suffix) = generate_api_key();
        assert!(token.starts_with("yb_"));
        assert!(prefix.starts_with("yb_"));
        assert_eq!(prefix.len(), 3 + 8);
        assert_eq!(suffix.len(), 4);
        assert!(token.ends_with(&suffix));
        // Hash is stable and 64 hex chars.
        let h = hash_token(&token);
        assert_eq!(h.len(), 64);
        assert_eq!(h, hash_token(&token));
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_token_known_vector() {
        // SHA-256("") = e3b0c442...
        assert_eq!(
            hash_token(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
