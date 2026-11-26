use crate::acme::{ACME_TLS_ALPN_NAME, Identifier};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use tracing::debug;

/// Cert resolver that serves the issued certificate to application traffic
/// and per-domain validation certificates to `tls-alpn-01` clients.
#[derive(Debug)]
pub struct ResolvesServerCertAcme {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    cert: Option<Arc<CertifiedKey>>,
    auth_keys: BTreeMap<String, Arc<CertifiedKey>>,
}

impl ResolvesServerCertAcme {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                cert: None,
                auth_keys: Default::default(),
            }),
        })
    }
    pub(crate) fn set_cert(&self, cert: Arc<CertifiedKey>) {
        self.inner.lock().expect("poisoned").cert = Some(cert);
    }
    /// Serves `cert` to tls-alpn-01 validation requests for `identifier`.
    pub(crate) fn set_auth_key(&self, identifier: &Identifier, cert: Arc<CertifiedKey>) {
        let server_name = identifier.tls_alpn_01_server_name();
        self.inner
            .lock()
            .expect("poisoned")
            .auth_keys
            .insert(server_name, cert);
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
                    debug!("client did not supply SNI");
                    None
                }
                Some(server_name) => self
                    .inner
                    .lock()
                    .expect("poisoned")
                    .auth_keys
                    .get(challenge_server_name(server_name))
                    .cloned(),
            }
        } else {
            self.inner.lock().expect("poisoned").cert.clone()
        }
    }
}

/// Returns the received SNI `server_name` without the trailing dot that rustls keeps.
fn challenge_server_name(server_name: &str) -> &str {
    server_name.strip_suffix('.').unwrap_or(server_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_server_name_strips_one_trailing_dot() {
        // The rustls client strips the dot before sending, so a handshake cannot test this.
        assert_eq!(
            challenge_server_name("1.2.0.192.in-addr.arpa."),
            "1.2.0.192.in-addr.arpa"
        );
        assert_eq!(challenge_server_name("example.org"), "example.org");
    }
}
