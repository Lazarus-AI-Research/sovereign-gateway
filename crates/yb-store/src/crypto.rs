//! Concrete crypto adapters: AES-256-GCM secret encryption and Argon2id
//! password hashing. These implement the [`yb_core::crypto`] ports.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier, SaltString};
use argon2::Argon2;
use yb_core::crypto::{Encryptor, PasswordHasher};
use yb_core::{Error, Result};

/// Length of the random nonce prepended to every ciphertext.
const NONCE_LEN: usize = 12;

/// AES-256-GCM authenticated encryption for BYOK secrets at rest.
///
/// The wire layout is `nonce(12) || ciphertext+tag`. The 12-byte nonce is
/// freshly random per call and prepended to the output. The caller-supplied
/// AAD (typically `installation_id \0 provider`) is bound into the GCM tag, so
/// a blob cannot be replayed under a different scope.
pub struct AesGcmEncryptor {
    cipher: Aes256Gcm,
}

impl AesGcmEncryptor {
    /// Build an encryptor from a 32-byte key.
    pub fn new(key: [u8; 32]) -> Self {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        Self { cipher }
    }

    /// Build an encryptor from a key slice, erroring unless it is exactly 32 bytes.
    pub fn from_slice(key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(Error::Crypto(format!(
                "AES-256-GCM key must be 32 bytes, got {}",
                key.len()
            )));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(key);
        Ok(Self::new(k))
    }
}

impl Encryptor for AesGcmEncryptor {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = self
            .cipher
            .encrypt(&nonce, Payload { msg: plaintext, aad })
            .map_err(|e| Error::Crypto(format!("encrypt failed: {e}")))?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < NONCE_LEN {
            return Err(Error::Crypto("ciphertext shorter than nonce".to_string()));
        }
        let (nonce_bytes, body) = ciphertext.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher
            .decrypt(nonce, Payload { msg: body, aad })
            .map_err(|e| Error::Crypto(format!("decrypt failed: {e}")))
    }
}

/// Argon2id password hasher producing PHC-format strings.
#[derive(Debug, Default, Clone)]
pub struct Argon2Hasher;

impl Argon2Hasher {
    pub fn new() -> Self {
        Self
    }
}

impl PasswordHasher for Argon2Hasher {
    fn hash(&self, password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| Error::Crypto(format!("hash failed: {e}")))
    }

    fn verify(&self, password: &str, hash: &str) -> bool {
        match PasswordHash::new(hash) {
            Ok(parsed) => Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok(),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_roundtrip_with_aad() {
        let enc = AesGcmEncryptor::new([7u8; 32]);
        let aad = b"install\0openai";
        let ct = enc.encrypt(b"sk-secret", aad).unwrap();
        // Nonce is prepended, so output is strictly larger than plaintext.
        assert!(ct.len() > 9 + NONCE_LEN);
        assert_eq!(enc.decrypt(&ct, aad).unwrap(), b"sk-secret");
        // Wrong AAD must fail authentication.
        assert!(enc.decrypt(&ct, b"install\0anthropic").is_err());
    }

    #[test]
    fn aes_distinct_nonces() {
        let enc = AesGcmEncryptor::new([1u8; 32]);
        let a = enc.encrypt(b"x", b"").unwrap();
        let b = enc.encrypt(b"x", b"").unwrap();
        assert_ne!(a, b, "fresh nonce should randomize ciphertext");
    }

    #[test]
    fn argon2_hash_and_verify() {
        let h = Argon2Hasher;
        let hash = h.hash("hunter2").unwrap();
        assert!(h.verify("hunter2", &hash));
        assert!(!h.verify("wrong", &hash));
        assert!(!h.verify("hunter2", "not-a-phc-string"));
    }
}
