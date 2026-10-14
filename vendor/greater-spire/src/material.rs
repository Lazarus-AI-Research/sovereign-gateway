//! Validation shared by every credential provider.
use std::collections::BTreeMap;
use std::io::{BufReader, Cursor};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use spiffe::{SpiffeId, TrustDomain};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::tls::{check_leaf, ensure_crypto_provider, exact_server_verifier, root_store};

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct WorkloadMaterial {
    pub spiffe_id: SpiffeId,
    pub key_pkcs8: Vec<u8>,
    pub cert_chain: Vec<Vec<u8>>,
    /// Leaf notAfter, never supplied by the caller.
    pub expires_at: i64,
    /// Earliest notAfter and latest notBefore in the presented chain.
    pub valid_until: i64,
    pub valid_from: i64,
    pub bundles: BTreeMap<String, Vec<Vec<u8>>>,
    /// Applied embedded-SPIRE registration revision; absent for files/PEM.
    /// It belongs to this immutable generation so rejected credentials cannot
    /// advance renewal bookkeeping independently of the published identity.
    pub spire_entry_revision: Option<i64>,
}

impl Drop for WorkloadMaterial {
    fn drop(&mut self) {
        self.key_pkcs8.zeroize();
    }
}

impl WorkloadMaterial {
    pub fn from_pem(expected: &SpiffeId, chain: &[u8], key: &[u8], bundle: &[u8]) -> Result<Self> {
        let bundles =
            BTreeMap::from([(expected.trust_domain().to_string(), certificates(bundle)?)]);
        Self::from_der(
            expected,
            certificates(chain)?,
            private_key(key)?.to_vec(),
            bundles,
        )
    }

    pub fn from_der(
        expected: &SpiffeId,
        cert_chain: Vec<Vec<u8>>,
        key: Vec<u8>,
        bundles: BTreeMap<String, Vec<Vec<u8>>>,
    ) -> Result<Self> {
        let key = Zeroizing::new(key);
        ensure_crypto_provider();
        let leaf = cert_chain
            .first()
            .ok_or_else(|| Error::Certificate("empty certificate chain".into()))?;
        let id = spiffe::cert::spiffe_id_from_der(leaf).map_err(cert_error)?;
        if &id != expected {
            return Err(Error::Certificate(format!(
                "certificate identity {id} does not match expected {expected}"
            )));
        }
        let leaf_der = CertificateDer::from(leaf.as_slice());
        check_leaf(&leaf_der).map_err(cert_error)?;
        let (_, parsed) = x509_parser::parse_x509_certificate(leaf).map_err(cert_error)?;
        let expires_at = parsed.validity().not_after.timestamp();
        let mut valid_from = parsed.validity().not_before.timestamp();
        let mut valid_until = expires_at;
        for der in &cert_chain {
            let (remaining, cert) = x509_parser::parse_x509_certificate(der).map_err(cert_error)?;
            if !remaining.is_empty() {
                return Err(Error::Certificate(
                    "trailing bytes after certificate".into(),
                ));
            }
            valid_from = valid_from.max(cert.validity().not_before.timestamp());
            valid_until = valid_until.min(cert.validity().not_after.timestamp());
        }
        let now = unix_now();
        if now < valid_from || now >= valid_until {
            return Err(Error::IdentityExpired);
        }
        for (domain, authorities) in &bundles {
            let _: TrustDomain = domain.as_str().try_into().map_err(cert_error)?;
            root_store(authorities)?;
        }
        let roots = root_store(
            bundles
                .get(expected.trust_domain().as_ref())
                .ok_or_else(|| Error::Certificate("missing local trust-domain bundle".into()))?,
        )?;
        let intermediates: Vec<_> = cert_chain
            .iter()
            .skip(1)
            .map(|v| CertificateDer::from(v.as_slice()))
            .collect();
        exact_server_verifier(roots.clone(), expected.clone())?
            .verify_server_cert(
                &leaf_der,
                &intermediates,
                &ServerName::try_from("unused.invalid").unwrap(),
                &[],
                UnixTime::now(),
            )
            .map_err(cert_error)?;
        rustls::server::WebPkiClientVerifier::builder(roots)
            .build()
            .map_err(cert_error)?
            .verify_client_cert(&leaf_der, &intermediates, UnixTime::now())
            .map_err(cert_error)?;
        rustls::sign::CertifiedKey::from_der(
            cert_chain
                .iter()
                .cloned()
                .map(CertificateDer::from)
                .collect(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
            rustls::crypto::CryptoProvider::get_default().expect("provider installed"),
        )
        .map_err(cert_error)?;
        Ok(Self {
            spiffe_id: id,
            key_pkcs8: key.to_vec(),
            cert_chain,
            expires_at,
            valid_from,
            valid_until,
            bundles,
            spire_entry_revision: None,
        })
    }

    pub fn check_valid(&self) -> Result<()> {
        let now = unix_now();
        if now < self.valid_from || now >= self.valid_until {
            Err(Error::IdentityExpired)
        } else {
            Ok(())
        }
    }
}

pub(crate) fn certificates(pem: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut values = Vec::new();
    for item in rustls_pemfile::read_all(&mut BufReader::new(Cursor::new(pem))) {
        match item.map_err(cert_error)? {
            rustls_pemfile::Item::X509Certificate(der) => values.push(der.to_vec()),
            _ => {
                return Err(Error::Certificate(
                    "expected only CERTIFICATE PEM blocks".into(),
                ))
            }
        }
    }
    if values.is_empty() {
        return Err(Error::Certificate(
            "empty PEM certificate chain or bundle".into(),
        ));
    }
    Ok(values)
}

pub(crate) fn private_key(pem: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut reader = BufReader::new(Cursor::new(pem));
    let Some(rustls_pemfile::Item::Pkcs8Key(key)) =
        rustls_pemfile::read_one(&mut reader).map_err(cert_error)?
    else {
        return Err(Error::Certificate(
            "expected one unencrypted PKCS#8 PRIVATE KEY PEM block".into(),
        ));
    };
    if rustls_pemfile::read_one(&mut reader)
        .map_err(cert_error)?
        .is_some()
    {
        return Err(Error::Certificate(
            "expected exactly one private key".into(),
        ));
    }
    Ok(Zeroizing::new(key.secret_pkcs8_der().to_vec()))
}

pub(crate) fn cert_error(e: impl std::fmt::Display) -> Error {
    Error::Certificate(e.to_string())
}

pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
