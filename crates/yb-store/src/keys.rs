//! Virtual API-key generation, token hashing, and a convenience issue helper.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore;
use sha2::{Digest, Sha256};
use yb_core::{
    new_id, now, AccessPolicy, ApiKey, IssuedKey, KeyScope, LimitColumns, Result, Store,
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
