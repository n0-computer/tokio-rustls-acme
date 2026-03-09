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
struct CertWithSchemes {
    key: Arc<CertifiedKey>,
    /// Signature schemes required to verify this certificate chain.
    required_schemes: Vec<SignatureScheme>,
}

#[derive(Debug)]
struct Inner {
    cert: Option<CertWithSchemes>,
    /// Alternate certificate chain for DualChain mode. Served to clients that
    /// cannot verify the primary chain but can verify this one.
    alt_cert: Option<CertWithSchemes>,
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
    pub(crate) fn set_cert(&self, cert: Arc<CertifiedKey>, required_schemes: Vec<SignatureScheme>) {
        self.inner.lock().unwrap().cert = Some(CertWithSchemes {
            key: cert,
            required_schemes,
        });
    }
    pub(crate) fn set_alt_cert(&self, cert: Option<(Arc<CertifiedKey>, Vec<SignatureScheme>)>) {
        self.inner.lock().unwrap().alt_cert = cert.map(|(key, required_schemes)| CertWithSchemes {
            key,
            required_schemes,
        });
    }
    pub(crate) fn set_auth_key(&self, domain: String, cert: Arc<CertifiedKey>) {
        self.inner.lock().unwrap().auth_keys.insert(domain, cert);
    }
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
            let client_schemes = client_hello.signature_schemes();

            // In DualChain mode: if the client can't verify the primary chain
            // but can verify the alternate, serve the alternate.
            if let (Some(primary), Some(alt)) = (&inner.cert, &inner.alt_cert) {
                let supports_primary = primary
                    .required_schemes
                    .iter()
                    .any(|s| client_schemes.contains(s));
                if !supports_primary {
                    let supports_alt = alt
                        .required_schemes
                        .iter()
                        .any(|s| client_schemes.contains(s));
                    if supports_alt {
                        return Some(alt.key.clone());
                    }
                }
            }

            inner.cert.as_ref().map(|c| c.key.clone())
        }
    }
}
