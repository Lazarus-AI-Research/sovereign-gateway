//! Installer-only CA creation and X.509-SVID issuance (`static-ca` feature).
//! Services receive leaf credentials; they must not receive the CA private key.
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::error::{io, Error, Result};
use crate::material::{cert_error, certificates, private_key, unix_now};
use crate::{IdentitySource, SpiffeId, TrustDomain};

pub struct StaticCa {
    domain: TrustDomain,
    issuer: Issuer<'static, KeyPair>,
    certificate_pem: String,
    not_before: i64,
    expires_at: i64,
}

impl std::fmt::Debug for StaticCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticCa")
            .field("trust_domain", &self.domain)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Public certificates and an explicitly accessible, zeroized-on-drop private key.
pub struct IssuedIdentity {
    pub spiffe_id: SpiffeId,
    pub cert_chain_pem: String,
    pub key_pkcs8_pem: Zeroizing<String>,
    pub bundle_pem: String,
    pub expires_at_unix: i64,
}

impl std::fmt::Debug for IssuedIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedIdentity")
            .field("spiffe_id", &self.spiffe_id)
            .field("expires_at_unix", &self.expires_at_unix)
            .finish_non_exhaustive()
    }
}

impl StaticCa {
    pub fn generate(domain: TrustDomain, lifetime: Duration) -> Result<Self> {
        let now = unix_now();
        let mut params = CertificateParams::new(Vec::<String>::new()).map_err(cert_error)?;
        params.not_before = date(now - 60)?;
        params.not_after = date(expiration(now, lifetime)?)?;
        params.serial_number = Some(random_bytes()?.into());
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, format!("greater-spire {domain}"));
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(cert_error)?;
        let cert = params.self_signed(&key).map_err(cert_error)?;
        Self::from_pem(
            domain,
            cert.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
        )
    }

    /// Import an existing CA; never replace a persisted CA implicitly.
    /// The installer supplies the authoritative trust-domain binding.
    pub fn from_pem(
        domain: TrustDomain,
        certificate_pem: &[u8],
        key_pkcs8_pem: &[u8],
    ) -> Result<Self> {
        crate::tls::ensure_crypto_provider();
        let certs = certificates(certificate_pem)?;
        if certs.len() != 1 {
            return Err(Error::Certificate(
                "CA import requires exactly one CA certificate".into(),
            ));
        }
        let (remaining, cert) =
            x509_parser::parse_x509_certificate(&certs[0]).map_err(cert_error)?;
        if !remaining.is_empty()
            || !cert
                .basic_constraints()
                .map_err(cert_error)?
                .is_some_and(|c| c.value.ca)
            || !cert
                .key_usage()
                .map_err(cert_error)?
                .is_some_and(|u| u.value.key_cert_sign())
        {
            return Err(Error::Certificate(
                "issuer must be a CA with keyCertSign usage".into(),
            ));
        }
        let not_before = cert.validity().not_before.timestamp();
        let expires_at = cert.validity().not_after.timestamp();
        if unix_now() < not_before || unix_now() >= expires_at {
            return Err(Error::Certificate("CA is not currently valid".into()));
        }
        let key_der = private_key(key_pkcs8_pem)?;
        rustls::sign::CertifiedKey::from_der(
            vec![CertificateDer::from(certs[0].clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.to_vec())),
            rustls::crypto::CryptoProvider::get_default().expect("provider installed"),
        )
        .map_err(cert_error)?;
        let key =
            KeyPair::try_from(&PrivatePkcs8KeyDer::from(key_der.to_vec())).map_err(cert_error)?;
        let issuer = Issuer::from_ca_cert_der(&CertificateDer::from(certs[0].clone()), key)
            .map_err(cert_error)?;
        let certificate_pem = std::str::from_utf8(certificate_pem)
            .map_err(cert_error)?
            .to_owned();
        Ok(Self {
            domain,
            issuer,
            certificate_pem,
            not_before,
            expires_at,
        })
    }

    pub fn trust_domain(&self) -> &TrustDomain {
        &self.domain
    }
    pub fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }
    pub fn private_key_pem(&self) -> Zeroizing<String> {
        Zeroizing::new(self.issuer.key().serialize_pem())
    }
    pub fn expires_at_unix(&self) -> i64 {
        self.expires_at
    }

    pub fn issue_svid(&self, id: &SpiffeId, lifetime: Duration) -> Result<IssuedIdentity> {
        if id.trust_domain() != &self.domain {
            return Err(Error::Certificate(
                "requested identity belongs to a different trust domain".into(),
            ));
        }
        let now = unix_now();
        let expires_at = expiration(now, lifetime)?;
        if now < self.not_before || now >= self.expires_at || expires_at > self.expires_at {
            return Err(Error::Certificate(
                "requested leaf validity exceeds the CA validity".into(),
            ));
        }
        let mut params = CertificateParams::new(Vec::<String>::new()).map_err(cert_error)?;
        params.distinguished_name = DistinguishedName::new();
        params.not_before = date((now - 60).max(self.not_before))?;
        params.not_after = date(expires_at)?;
        params.serial_number = Some(random_bytes()?.into());
        params.is_ca = IsCa::ExplicitNoCa;
        params.subject_alt_names =
            vec![SanType::URI(id.to_string().try_into().map_err(cert_error)?)];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(cert_error)?;
        let cert = params.signed_by(&key, &self.issuer).map_err(cert_error)?;
        let issued = IssuedIdentity {
            spiffe_id: id.clone(),
            cert_chain_pem: cert.pem(),
            key_pkcs8_pem: Zeroizing::new(key.serialize_pem()),
            bundle_pem: self.certificate_pem.clone(),
            expires_at_unix: expires_at,
        };
        issued.identity_source()?;
        Ok(issued)
    }

    /// Write a new CA directory, refusing to overwrite an existing installation.
    pub fn write_new(&self, directory: impl AsRef<Path>) -> Result<()> {
        let directory = directory.as_ref();
        create_private_directory(directory)?;
        write_new(
            &directory.join("ca.pem"),
            self.certificate_pem.as_bytes(),
            false,
        )?;
        write_new(
            &directory.join("ca-key.pem"),
            self.private_key_pem().as_bytes(),
            true,
        )?;
        write_new(
            &directory.join("trust-domain"),
            self.domain.to_string().as_bytes(),
            false,
        )?;
        sync_dir(directory)
    }

    pub fn load(directory: impl AsRef<Path>) -> Result<Self> {
        let directory = directory.as_ref();
        let domain =
            fs::read_to_string(directory.join("trust-domain")).map_err(|e| io(directory, e))?;
        let domain: TrustDomain = domain.trim().try_into().map_err(cert_error)?;
        Self::from_pem(
            domain,
            &crate::runtime::read_file(&directory.join("ca.pem"), false)?,
            &crate::runtime::read_file(&directory.join("ca-key.pem"), true)?,
        )
    }
}

impl IssuedIdentity {
    pub fn identity_source(&self) -> Result<IdentitySource> {
        IdentitySource::from_pem(
            &self.spiffe_id,
            self.cert_chain_pem.as_bytes(),
            self.key_pkcs8_pem.as_bytes(),
            self.bundle_pem.as_bytes(),
        )
    }

    /// Write a fresh immutable generation. The directory must not already exist.
    pub fn write_generation(&self, directory: impl AsRef<Path>) -> Result<()> {
        self.identity_source()?;
        let directory = directory.as_ref();
        create_private_directory(directory)?;
        write_new(
            &directory.join("cert-chain.pem"),
            self.cert_chain_pem.as_bytes(),
            false,
        )?;
        write_new(
            &directory.join("key.pem"),
            self.key_pkcs8_pem.as_bytes(),
            true,
        )?;
        write_new(
            &directory.join("bundle.pem"),
            self.bundle_pem.as_bytes(),
            false,
        )?;
        sync_dir(directory)
    }

    /// Publish a fresh generation by atomically replacing directory/current.
    /// Old generations are retained for rollback; the installer owns retention.
    #[cfg(unix)]
    pub fn publish(&self, directory: impl AsRef<Path>) -> Result<PathBuf> {
        use std::os::unix::fs::symlink;
        let directory = directory.as_ref();
        if !directory.exists() {
            create_private_directory(directory)?;
        }
        let meta = fs::symlink_metadata(directory).map_err(|e| io(directory, e))?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(Error::UnsafeState(
                "publication directory must be a real directory".into(),
            ));
        }
        let current = directory.join("current");
        if let Ok(meta) = fs::symlink_metadata(&current) {
            if !meta.file_type().is_symlink() {
                return Err(Error::UnsafeState(
                    "current must be a generation symlink".into(),
                ));
            }
        }
        let nonce = random_bytes()?
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let generation = format!("generation-{nonce}");
        self.write_generation(directory.join(&generation))?;
        let pending = directory.join(format!(".current-{nonce}"));
        symlink(&generation, &pending).map_err(|e| io(&pending, e))?;
        fs::rename(&pending, &current).map_err(|e| io(&current, e))?;
        sync_dir(directory)?;
        Ok(current)
    }
}

fn expiration(now: i64, lifetime: Duration) -> Result<i64> {
    let seconds = i64::try_from(lifetime.as_secs()).map_err(cert_error)?;
    if seconds <= 0 {
        return Err(Error::Certificate(
            "certificate lifetime must be at least one second".into(),
        ));
    }
    now.checked_add(seconds)
        .ok_or_else(|| Error::Certificate("certificate lifetime overflow".into()))
}
fn date(unix: i64) -> Result<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(unix).map_err(cert_error)
}
fn random_bytes() -> Result<Vec<u8>> {
    crate::tls::ensure_crypto_provider();
    let mut bytes = vec![0; 20];
    rustls::crypto::CryptoProvider::get_default()
        .expect("provider installed")
        .secure_random
        .fill(&mut bytes)
        .map_err(|_| Error::Certificate("secure random generator failed".into()))?;
    bytes[0] = (bytes[0] & 0x7f) | 1;
    Ok(bytes)
}
fn create_private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|e| io(path, e))
}
fn write_new(path: &Path, data: &[u8], private: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options.open(path).map_err(|e| io(path, e))?;
    file.write_all(data).map_err(|e| io(path, e))?;
    file.sync_all().map_err(|e| io(path, e))
}
fn sync_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(path)
            .and_then(|f| f.sync_all())
            .map_err(|e| io(path, e))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
