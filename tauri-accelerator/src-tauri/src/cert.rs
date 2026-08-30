use std::collections::HashMap;
use std::io::IoSlice;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, DistinguishedName,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, PrivateKeyDer};

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("key: {0}")]
    Key(String),
}

pub type Result<T> = std::result::Result<T, CertError>;

/// 根 CA + 动态叶子证书管理器。根 CA 持久化，叶子证书按主机名缓存。
pub struct CertManager {
    ca_cert: Certificate,
    ca_key: KeyPair,
    cache: Mutex<HashMap<String, Arc<rustls::sign::CertifiedKey>>>,
}

impl CertManager {
    pub fn load_or_create(data_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&data_dir).ok();
        let ca_cert_path = data_dir.join("root-ca.pem");
        let ca_key_path = data_dir.join("root-ca.key.pem");

        let (ca_cert, ca_key) = if ca_cert_path.exists() && ca_key_path.exists() {
            let cert_pem = std::fs::read_to_string(&ca_cert_path)?;
            let key_pem = std::fs::read_to_string(&ca_key_path)?;
            let key = KeyPair::from_pem(&key_pem)?;
            // from_ca_cert_pem 返回 CertificateParams；用持久化的 CA 私钥重建 Certificate。
            let params = CertificateParams::from_ca_cert_pem(&cert_pem)?;
            let cert = params.self_signed(&key)?;
            (cert, key)
        } else {
            let (ca_cert, ca_key) = Self::generate_ca()?;
            std::fs::write(&ca_cert_path, ca_cert.pem())?;
            std::fs::write(&ca_key_path, ca_key.serialize_pem())?;
            (ca_cert, ca_key)
        };

        Ok(Self {
            ca_cert,
            ca_key,
            cache: Mutex::new(HashMap::new()),
        })
    }

    fn generate_ca() -> Result<(Certificate, KeyPair)> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::new(vec!["Steam++ Accelerator Root CA".to_string()])?;
        params.distinguished_name = smart_name("Steam++ Accelerator Root CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let cert = params.self_signed(&key)?;
        Ok((cert, key))
    }

    fn leaf_key_pair() -> Result<KeyPair> {
        Ok(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?)
    }

    fn leaf_for_host(&self, host: &str) -> Result<Arc<rustls::sign::CertifiedKey>> {
        if let Some(ck) = self.cache.lock().unwrap().get(host) {
            return Ok(Arc::clone(ck));
        }
        let leaf_kp = Self::leaf_key_pair()?;
        let mut params = CertificateParams::new(vec![host.to_string()])?;
        params.distinguished_name = smart_name(host);
        params.is_ca = IsCa::NoCa;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let signed = params.signed_by(&leaf_kp, &self.ca_cert, &self.ca_key)?;

        let certified_key = to_rustls(&signed, &leaf_kp)?;
        let arc = Arc::new(certified_key);
        self.cache
            .lock()
            .unwrap()
            .insert(host.to_string(), Arc::clone(&arc));
        Ok(arc)
    }

    pub fn ca_pem(&self) -> String {
        self.ca_cert.pem()
    }

    pub fn resolver(self: &Arc<Self>) -> Arc<dyn rustls::server::ResolvesServerCert> {
        Arc::new(PerHostResolver(Arc::clone(self)))
    }
}

struct PerHostResolver(Arc<CertManager>);

impl std::fmt::Debug for PerHostResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PerHostResolver")
    }
}

impl rustls::server::ResolvesServerCert for PerHostResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let sni = client_hello.server_name()?;
        match self.0.leaf_for_host(sni) {
            Ok(ck) => Some(ck),
            Err(_) => None,
        }
    }
}

fn to_rustls(cert: &Certificate, kp: &KeyPair) -> Result<rustls::sign::CertifiedKey> {
    let cert_der = CertificateDer::from(cert.der().as_ref().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer
        ::from(kp.serialize_der()));
    let key = rustls::crypto::ring::sign::any_supported_type(&key_der)
        .map_err(|e| CertError::Key(e.to_string()))?;
    Ok(rustls::sign::CertifiedKey::new(vec![cert_der], key))
}

fn smart_name(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn.push(DnType::OrganizationName, "Steam++ Accelerator");
    dn.push(DnType::CountryName, "CN");
    dn
}

#[allow(dead_code)]
fn _send(_: &[IoSlice]) {}