use crate::acme::ACME_TLS_ALPN_NAME;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::SignatureScheme;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;

#[derive(Debug)]
pub struct ResolvesServerCertAcme {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    cert: Option<Arc<CertifiedKey>>,
    /// Alternate certificate chain for DualChain mode. When set, clients that advertise
    /// no RSA signature schemes receive this chain instead of the primary.
    alt_cert: Option<Arc<CertifiedKey>>,
    auth_keys: BTreeMap<String, Arc<CertifiedKey>>,
}

impl ResolvesServerCertAcme {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                cert: None,
                alt_cert: None,
                auth_keys: Default::default(),
            }),
        })
    }
    pub(crate) fn set_cert(&self, cert: Arc<CertifiedKey>) {
        self.inner.lock().unwrap().cert = Some(cert);
    }
    pub(crate) fn set_alt_cert(&self, cert: Option<Arc<CertifiedKey>>) {
        self.inner.lock().unwrap().alt_cert = cert;
    }
    pub(crate) fn set_auth_key(&self, domain: String, cert: Arc<CertifiedKey>) {
        self.inner.lock().unwrap().auth_keys.insert(domain, cert);
    }
}

/// Returns true if the client's signature schemes include any RSA-based scheme.
fn client_supports_rsa(client_hello: &ClientHello) -> bool {
    client_hello.signature_schemes().iter().any(|s| {
        matches!(
            s,
            SignatureScheme::RSA_PKCS1_SHA256
                | SignatureScheme::RSA_PKCS1_SHA384
                | SignatureScheme::RSA_PKCS1_SHA512
                | SignatureScheme::RSA_PSS_SHA256
                | SignatureScheme::RSA_PSS_SHA384
                | SignatureScheme::RSA_PSS_SHA512
                | SignatureScheme::RSA_PKCS1_SHA1
        )
    })
}

impl ResolvesServerCert for ResolvesServerCertAcme {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let is_acme_challenge = client_hello
            .alpn()
            .into_iter()
            .flatten()
            .eq([ACME_TLS_ALPN_NAME]);
        if is_acme_challenge {
            match client_hello.server_name() {
                None => {
                    log::debug!("client did not supply SNI");
                    None
                }
                Some(domain) => {
                    let domain = domain.to_owned();
                    let domain: String = AsRef::<str>::as_ref(&domain).into();
                    self.inner.lock().unwrap().auth_keys.get(&domain).cloned()
                }
            }
        } else {
            let inner = self.inner.lock().unwrap();
            // In DualChain mode: serve the alternate (e.g. ECDSA-only) chain to clients
            // that don't support RSA, and the default (e.g. RSA cross-signed) chain otherwise.
            if let Some(alt_cert) = &inner.alt_cert {
                if !client_supports_rsa(&client_hello) {
                    return Some(alt_cert.clone());
                }
            }
            inner.cert.clone()
        }
    }
}
