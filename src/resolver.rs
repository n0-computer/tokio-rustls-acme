use crate::acme::ACME_TLS_ALPN_NAME;
use rustls::SignatureScheme;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
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
    /// Sets or clears the alternate chain served in DualChain mode.
    ///
    /// The alternate must carry the same leaf certificate as the current
    /// primary: it's the same certificate, chained to a different root. A
    /// mismatch (e.g. a cached alternate left over from an earlier
    /// certificate) clears the alternate instead. Returns whether an
    /// alternate is installed.
    pub(crate) fn set_alt_cert(
        &self,
        cert: Option<(Arc<CertifiedKey>, Vec<SignatureScheme>)>,
    ) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let alt = cert.filter(|(key, _)| {
            let primary_leaf = inner
                .cert
                .as_ref()
                .and_then(|c| c.key.end_entity_cert().ok());
            let matches = primary_leaf.is_some() && primary_leaf == key.end_entity_cert().ok();
            if !matches {
                log::warn!("alternate chain doesn't match the current certificate, not serving it");
            }
            matches
        });
        inner.alt_cert = alt.map(|(key, required_schemes)| CertWithSchemes {
            key,
            required_schemes,
        });
        inner.alt_cert.is_some()
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
            // but can verify the alternate, serve the alternate. Verifying a
            // chain takes every signature scheme in it, so a client that
            // supports only some of the primary's schemes can't use it.
            if let (Some(primary), Some(alt)) = (&inner.cert, &inner.alt_cert) {
                let supports = |c: &CertWithSchemes| {
                    c.required_schemes
                        .iter()
                        .all(|s| client_schemes.contains(s))
                };
                if !supports(primary) && supports(alt) {
                    return Some(alt.key.clone());
                }
            }

            inner.cert.as_ref().map(|c| c.key.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CertCache;
    use crate::caches::TestCache;
    use rustls::crypto::ring::sign::any_ecdsa_type;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use std::convert::{Infallible, TryFrom};

    /// Parse TestCache PEM output into a CertifiedKey + cert chain DER.
    async fn make_cert(
        cache: &TestCache<Infallible, Infallible>,
    ) -> (Arc<CertifiedKey>, Vec<CertificateDer<'static>>) {
        let pem_bytes = cache
            .load_cert(&["test.example.com".to_string()], "")
            .await
            .unwrap()
            .unwrap();
        let mut pems = pem::parse_many(&pem_bytes).unwrap();
        let pk_bytes = pems.remove(0).into_contents();
        let pk_der: PrivatePkcs8KeyDer = pk_bytes.into();
        let pk: PrivateKeyDer = pk_der.into();
        let pk = any_ecdsa_type(&pk).unwrap();
        let cert_chain: Vec<CertificateDer<'static>> = pems
            .into_iter()
            .map(|p| CertificateDer::from(p.into_contents()))
            .collect();
        let key = Arc::new(CertifiedKey::new(cert_chain.clone(), pk));
        (key, cert_chain)
    }

    /// The same certificate as `primary`, with a different chain: the leaf
    /// alone, which the test CA verifies directly.
    fn alternate_of(
        primary: &Arc<CertifiedKey>,
    ) -> (Arc<CertifiedKey>, Vec<CertificateDer<'static>>) {
        let chain = vec![primary.cert[0].clone()];
        let key = Arc::new(CertifiedKey::new(chain.clone(), primary.key.clone()));
        (key, chain)
    }

    fn make_root_store(ca_pem: &str) -> rustls::RootCertStore {
        let ca_pems = pem::parse_many(ca_pem).unwrap();
        let mut root_store = rustls::RootCertStore::empty();
        for p in ca_pems {
            root_store
                .add(CertificateDer::from(p.into_contents()))
                .unwrap();
        }
        root_store
    }

    /// Helper: do an in-process TLS handshake and return the peer certs served.
    async fn do_handshake(
        resolver: Arc<ResolvesServerCertAcme>,
        root_store: rustls::RootCertStore,
    ) -> Vec<CertificateDer<'static>> {
        do_handshake_with(
            resolver,
            root_store,
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .await
    }

    /// Like [`do_handshake`], with `client_provider` on the client side.
    async fn do_handshake_with(
        resolver: Arc<ResolvesServerCertAcme>,
        root_store: rustls::RootCertStore,
        client_provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Vec<CertificateDer<'static>> {
        let server_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(resolver),
        );
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);

        let client_config = Arc::new(
            rustls::ClientConfig::builder_with_provider(client_provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        );
        let connector = tokio_rustls::TlsConnector::from(client_config);

        let (client_io, server_io) = tokio::io::duplex(4096);
        let server_name = ServerName::try_from("test.example.com").unwrap().to_owned();

        let (client_result, server_result) = tokio::join!(
            connector.connect(server_name, client_io),
            acceptor.accept(server_io),
        );

        let _ = server_result.expect("TLS server handshake failed");
        let client_tls = client_result.expect("TLS client handshake failed");
        let (_, conn) = client_tls.get_ref();
        conn.peer_certificates().unwrap().to_vec()
    }

    /// When the client doesn't support the primary chain's signature schemes,
    /// the resolver should fall back to the alternate chain.
    ///
    /// We simulate this by setting the primary's required_schemes to ED448,
    /// which ring-based clients don't advertise support for.
    #[tokio::test]
    async fn dual_chain_fallback_to_alt() {
        let cache = TestCache::<Infallible, Infallible>::new();
        let (primary_key, _) = make_cert(&cache).await;
        let (alt_key, alt_chain) = alternate_of(&primary_key);

        let resolver = ResolvesServerCertAcme::new();
        // Primary requires ED448 (not supported by ring clients).
        resolver.set_cert(primary_key, vec![SignatureScheme::ED448]);
        // Alt requires ECDSA P-256 (supported by ring clients).
        resolver.set_alt_cert(Some((
            alt_key,
            vec![SignatureScheme::ECDSA_NISTP256_SHA256],
        )));

        let root_store = make_root_store(cache.ca_pem());
        let peer_certs = do_handshake(resolver, root_store).await;

        assert_eq!(
            peer_certs, alt_chain,
            "should serve alt cert when client doesn't support primary's schemes"
        );
    }

    /// When the client supports the primary chain's signature schemes,
    /// the resolver should serve the primary chain even if alt is available.
    #[tokio::test]
    async fn dual_chain_serves_primary_when_supported() {
        let cache = TestCache::<Infallible, Infallible>::new();
        let (primary_key, primary_chain) = make_cert(&cache).await;
        let (alt_key, _) = alternate_of(&primary_key);

        let resolver = ResolvesServerCertAcme::new();
        // Primary requires ECDSA P-256 (supported by ring clients).
        resolver.set_cert(primary_key, vec![SignatureScheme::ECDSA_NISTP256_SHA256]);
        resolver.set_alt_cert(Some((
            alt_key,
            vec![SignatureScheme::ECDSA_NISTP256_SHA256],
        )));

        let root_store = make_root_store(cache.ca_pem());
        let peer_certs = do_handshake(resolver, root_store).await;

        assert_eq!(
            peer_certs, primary_chain,
            "should serve primary cert when client supports its schemes"
        );
    }

    /// The Let's Encrypt case DualChain exists for. The default ECDSA chain
    /// has an intermediate signed by ISRG Root X1 (RSA), the alternate one
    /// signed by ISRG Root X2 (ECDSA P-384). A client without RSA support
    /// still advertises P-384, which must not count as supporting the
    /// primary.
    #[tokio::test]
    async fn dual_chain_client_without_rsa_gets_alt() {
        let cache = TestCache::<Infallible, Infallible>::new();
        let (primary_key, _) = make_cert(&cache).await;
        let (alt_key, alt_chain) = alternate_of(&primary_key);

        let resolver = ResolvesServerCertAcme::new();
        resolver.set_cert(
            primary_key,
            vec![
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA256,
            ],
        );
        resolver.set_alt_cert(Some((
            alt_key,
            vec![SignatureScheme::ECDSA_NISTP384_SHA384],
        )));

        // A ring client that doesn't advertise any RSA scheme.
        let mut provider = rustls::crypto::ring::default_provider();
        let mapping: Vec<_> = provider
            .signature_verification_algorithms
            .mapping
            .iter()
            .filter(|(scheme, _)| {
                !matches!(
                    scheme,
                    SignatureScheme::RSA_PKCS1_SHA256
                        | SignatureScheme::RSA_PKCS1_SHA384
                        | SignatureScheme::RSA_PKCS1_SHA512
                        | SignatureScheme::RSA_PSS_SHA256
                        | SignatureScheme::RSA_PSS_SHA384
                        | SignatureScheme::RSA_PSS_SHA512
                )
            })
            .cloned()
            .collect();
        provider.signature_verification_algorithms.mapping = Box::leak(mapping.into_boxed_slice());

        let root_store = make_root_store(cache.ca_pem());
        let peer_certs = do_handshake_with(resolver, root_store, Arc::new(provider)).await;

        assert_eq!(
            peer_certs, alt_chain,
            "a client without RSA must get the alternate chain"
        );
    }

    /// Without DualChain (no alt cert set), the primary is always served.
    #[tokio::test]
    async fn single_chain_serves_primary() {
        let cache = TestCache::<Infallible, Infallible>::new();
        let (primary_key, primary_chain) = make_cert(&cache).await;

        let resolver = ResolvesServerCertAcme::new();
        resolver.set_cert(primary_key, vec![SignatureScheme::ECDSA_NISTP256_SHA256]);

        let root_store = make_root_store(cache.ca_pem());
        let peer_certs = do_handshake(resolver, root_store).await;

        assert_eq!(peer_certs, primary_chain);
    }

    /// An alternate whose leaf differs from the primary's (e.g. cached from an
    /// earlier certificate) is not served.
    #[tokio::test]
    async fn alt_with_other_leaf_is_rejected() {
        let cache = TestCache::<Infallible, Infallible>::new();
        let (primary_key, primary_chain) = make_cert(&cache).await;
        let (other_key, _) = make_cert(&cache).await;

        let resolver = ResolvesServerCertAcme::new();
        resolver.set_cert(primary_key, vec![SignatureScheme::ED448]);
        let installed = resolver.set_alt_cert(Some((
            other_key,
            vec![SignatureScheme::ECDSA_NISTP256_SHA256],
        )));
        assert!(!installed);

        let root_store = make_root_store(cache.ca_pem());
        let peer_certs = do_handshake(resolver, root_store).await;
        assert_eq!(peer_certs, primary_chain);
    }
}
