//! Crypto ports: secret-at-rest encryption and password hashing.
//!
//! These are *traits* in the inner ring; concrete implementations (AES-256-GCM,
//! Argon2id) live in an adapter crate so the domain stays dependency-light.

/// Authenticated encryption for BYOK secrets at rest. Implementations must bind
/// the ciphertext to associated data (typically `installation_id \0 provider`)
/// so a blob cannot be replayed under a different scope.
pub trait Encryptor: Send + Sync {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> crate::Result<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> crate::Result<Vec<u8>>;
}

/// A slow, constant-time password hasher (Argon2id). Never a fast hash.
pub trait PasswordHasher: Send + Sync {
    fn hash(&self, password: &str) -> crate::Result<String>;
    fn verify(&self, password: &str, hash: &str) -> bool;
}

/// A no-op encryptor for tests / when BYOK is disabled. Stores plaintext.
pub struct NoopEncryptor;

impl Encryptor for NoopEncryptor {
    fn encrypt(&self, plaintext: &[u8], _aad: &[u8]) -> crate::Result<Vec<u8>> {
        Ok(plaintext.to_vec())
    }
    fn decrypt(&self, ciphertext: &[u8], _aad: &[u8]) -> crate::Result<Vec<u8>> {
        Ok(ciphertext.to_vec())
    }
}
