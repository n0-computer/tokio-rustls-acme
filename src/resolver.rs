use crate::acme::ACME_TLS_ALPN_NAME;
use rustls::SignatureScheme;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use tracing::{debug, warn};

/// Cert resolver that serves the issued certificate to application traffic
/// and per-domain validation certificates to `tls-alpn-01` clients.
#[derive(Debug)]
pub struct ResolvesServerCertAcme {
    inner: Mutex<Inner>,
}

/// The signature schemes a client needs to verify a certificate chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RequiredSchemes {
    /// The schemes of all signatures in the chain.
    Known(Vec<SignatureScheme>),
    /// A signature in the chain has an algorithm without a known scheme.
    Unknown,
}

impl RequiredSchemes {
    /// Returns whether a client offering `offered` can verify the chain, or `None` if unknown.
    fn supported_by(&self, offered: &[SignatureScheme]) -> Option<bool> {
        match self {
            Self::Known(schemes) => Some(schemes.iter().all(|s| offered.contains(s))),
            Self::Unknown => None,
        }
    }
}

/// A certificate chain with its key, and the schemes needed to verify the chain.
#[derive(Debug)]
pub(crate) struct ServedCert {
    pub(crate) key: Arc<CertifiedKey>,
    pub(crate) schemes: RequiredSchemes,
}

#[derive(Debug)]
struct Inner {
    cert: Option<ServedCert>,
    /// Alternate chain for DualChain mode, for clients that can only verify this one.
    alt_cert: Option<ServedCert>,
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
    /// Replaces the certificate and the alternate chain, and returns whether the alternate is kept.
    ///
    /// The alternate must carry the same leaf certificate as `primary`: it is the same
    /// certificate, chained to a different root. An alternate with another leaf is dropped.
    /// Both are replaced under one lock, so no handshake sees a new primary with an old
    /// alternate.
    pub(crate) fn set_certs(&self, primary: ServedCert, alternate: Option<ServedCert>) -> bool {
        let alternate = alternate.filter(|alt| {
            let matches = primary.key.end_entity_cert().ok() == alt.key.end_entity_cert().ok();
            if !matches {
                warn!("alternate chain doesn't match the certificate, not serving it");
            }
            matches
        });
        let installed = alternate.is_some();
        let mut inner = self.inner.lock().expect("poisoned");
        inner.cert = Some(primary);
        inner.alt_cert = alternate;
        installed
    }
    pub(crate) fn set_auth_key(&self, domain: String, cert: Arc<CertifiedKey>) {
        self.inner
            .lock()
            .expect("poisoned")
            .auth_keys
            .insert(domain, cert);
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
                Some(domain) => {
                    let domain = domain.to_owned();
                    let domain: String = AsRef::<str>::as_ref(&domain).into();
                    self.inner
                        .lock()
                        .expect("poisoned")
                        .auth_keys
                        .get(&domain)
                        .cloned()
                }
            }
        } else {
            let inner = self.inner.lock().expect("poisoned");
            let offered = client_hello.signature_schemes();

            // In DualChain mode: if the client can't verify the primary chain
            // but can verify the alternate, serve the alternate. Verifying a
            // chain takes every signature scheme in it, so a client that
            // supports only some of the primary's schemes can't use it. If
            // either chain has an unknown scheme, keep the primary.
            if let (Some(primary), Some(alt)) = (&inner.cert, &inner.alt_cert)
                && primary.schemes.supported_by(offered) == Some(false)
                && alt.schemes.supported_by(offered) == Some(true)
            {
                return Some(alt.key.clone());
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
    use rustls::crypto::{CryptoProvider, ring};
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use std::convert::Infallible;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    const SERVER_NAME: &str = "test.example.com";
    /// Buffer size of the in-memory connection between client and server.
    const DUPLEX_BUFFER: usize = 4096;
    /// The scheme of the test CA's P-256 signatures, which ring clients advertise.
    const P256: SignatureScheme = SignatureScheme::ECDSA_NISTP256_SHA256;

    /// Returns a certificate from `cache` as a key and its chain.
    async fn make_cert(
        cache: &TestCache<Infallible, Infallible>,
    ) -> (Arc<CertifiedKey>, Vec<CertificateDer<'static>>) {
        let pem_bytes = cache
            .load_cert(&[SERVER_NAME.to_string()], "")
            .await
            .unwrap()
            .unwrap();
        let mut pems = pem::parse_many(&pem_bytes).unwrap();
        let pk_der: PrivatePkcs8KeyDer = pems.remove(0).into_contents().into();
        let pk = ring::default_provider()
            .key_provider
            .load_private_key(pk_der.into())
            .unwrap();
        let cert_chain: Vec<CertificateDer<'static>> = pems
            .into_iter()
            .map(|p| CertificateDer::from(p.into_contents()))
            .collect();
        (
            Arc::new(CertifiedKey::new(cert_chain.clone(), pk)),
            cert_chain,
        )
    }

    /// Returns `primary` with another chain, the leaf alone, which the test CA verifies directly.
    fn alternate_of(
        primary: &Arc<CertifiedKey>,
    ) -> (Arc<CertifiedKey>, Vec<CertificateDer<'static>>) {
        let chain = vec![primary.cert[0].clone()];
        let key = Arc::new(CertifiedKey::new(chain.clone(), primary.key.clone()));
        (key, chain)
    }

    /// Returns a served certificate with `schemes`.
    fn served(key: Arc<CertifiedKey>, schemes: RequiredSchemes) -> ServedCert {
        ServedCert { key, schemes }
    }

    /// Returns a root store with the certificates in `ca_pem`.
    fn make_root_store(ca_pem: &str) -> RootCertStore {
        let mut root_store = RootCertStore::empty();
        for p in pem::parse_many(ca_pem).unwrap() {
            root_store
                .add(CertificateDer::from(p.into_contents()))
                .unwrap();
        }
        root_store
    }

    /// Runs a TLS handshake with a ring client and returns the chain the server sent.
    async fn do_handshake(
        resolver: Arc<ResolvesServerCertAcme>,
        root_store: RootCertStore,
    ) -> Vec<CertificateDer<'static>> {
        do_handshake_with(resolver, root_store, Arc::new(ring::default_provider())).await
    }

    /// Runs a TLS handshake with `client_provider` and returns the chain the server sent.
    async fn do_handshake_with(
        resolver: Arc<ResolvesServerCertAcme>,
        root_store: RootCertStore,
        client_provider: Arc<CryptoProvider>,
    ) -> Vec<CertificateDer<'static>> {
        // Explicit provider: with both ring (dev-dependency) and aws-lc-rs
        // enabled, rustls can't pick a process default.
        let server_config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let client_config = ClientConfig::builder_with_provider(client_provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));

        let (client_io, server_io) = tokio::io::duplex(DUPLEX_BUFFER);
        let server_name = ServerName::try_from(SERVER_NAME).unwrap().to_owned();
        let (client_result, server_result) = tokio::join!(
            connector.connect(server_name, client_io),
            acceptor.accept(server_io),
        );
        server_result.expect("TLS server handshake failed");
        let client_tls = client_result.expect("TLS client handshake failed");
        client_tls.get_ref().1.peer_certificates().unwrap().to_vec()
    }

    /// Serves the alternate to a client that lacks a scheme of the primary.
    ///
    /// The primary requires ED448, which ring clients don't advertise.
    #[tokio::test]
    async fn dual_chain_fallback_to_alt() {
        let cache = TestCache::<Infallible, Infallible>::new();
        let (primary_key, _) = make_cert(&cache).await;
        let (alt_key, alt_chain) = alternate_of(&primary_key);

        let resolver = ResolvesServerCertAcme::new();
        let installed = resolver.set_certs(
            served(
                primary_key,
                RequiredSchemes::Known(vec![SignatureScheme::ED448]),
            ),
            Some(served(alt_key, RequiredSchemes::Known(vec![P256]))),
        );
        assert!(installed);

        let peer_certs = do_handshake(resolver, make_root_store(cache.ca_pem())).await;
        assert_eq!(peer_certs, alt_chain);
    }

    /// Serves the primary to a client that supports its schemes, even with an alternate set.
    #[tokio::test]
    async fn dual_chain_serves_primary_when_supported() {
        let cache = TestCache::<Infallible, Infallible>::new();
        let (primary_key, primary_chain) = make_cert(&cache).await;
        let (alt_key, _) = alternate_of(&primary_key);

        let resolver = ResolvesServerCertAcme::new();
        resolver.set_certs(
            served(primary_key, RequiredSchemes::Known(vec![P256])),
            Some(served(alt_key, RequiredSchemes::Known(vec![P256]))),
        );

        let peer_certs = do_handshake(resolver, make_root_store(cache.ca_pem())).await;
        assert_eq!(peer_certs, primary_chain);
    }

    /// Serves the alternate to a client without RSA when the primary needs RSA.
    ///
    /// This is the Let's Encrypt case DualChain exists for: the default chain
    /// needs an RSA signature, the alternate only ECDSA P-384. The client
    /// still advertises P-384, which must not count as supporting the primary.
    #[tokio::test]
    async fn dual_chain_client_without_rsa_gets_alt() {
        let cache = TestCache::<Infallible, Infallible>::new();
        let (primary_key, _) = make_cert(&cache).await;
        let (alt_key, alt_chain) = alternate_of(&primary_key);

        let resolver = ResolvesServerCertAcme::new();
        resolver.set_certs(
            served(
                primary_key,
                RequiredSchemes::Known(vec![
                    SignatureScheme::ECDSA_NISTP384_SHA384,
                    SignatureScheme::RSA_PKCS1_SHA256,
                ]),
            ),
            Some(served(
                alt_key,
                RequiredSchemes::Known(vec![SignatureScheme::ECDSA_NISTP384_SHA384]),
            )),
        );

        let mut provider = ring::default_provider();
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
        assert_eq!(peer_certs, alt_chain);
    }

    /// Serves the primary if its schemes are unknown, since the client may verify it.
    #[tokio::test]
    async fn dual_chain_unknown_primary_schemes_serve_primary() {
        let cache = TestCache::<Infallible, Infallible>::new();
        let (primary_key, primary_chain) = make_cert(&cache).await;
        let (alt_key, _) = alternate_of(&primary_key);

        let resolver = ResolvesServerCertAcme::new();
        resolver.set_certs(
            served(primary_key, RequiredSchemes::Unknown),
            Some(served(alt_key, RequiredSchemes::Known(vec![P256]))),
        );

        let peer_certs = do_handshake(resolver, make_root_store(cache.ca_pem())).await;
        assert_eq!(peer_certs, primary_chain);
    }

    /// Serves the primary when no alternate is set.
    #[tokio::test]
    async fn single_chain_serves_primary() {
        let cache = TestCache::<Infallible, Infallible>::new();
        let (primary_key, primary_chain) = make_cert(&cache).await;

        let resolver = ResolvesServerCertAcme::new();
        assert!(!resolver.set_certs(
            served(primary_key, RequiredSchemes::Known(vec![P256])),
            None
        ));

        let peer_certs = do_handshake(resolver, make_root_store(cache.ca_pem())).await;
        assert_eq!(peer_certs, primary_chain);
    }

    /// Drops an alternate whose leaf differs from the primary's.
    #[tokio::test]
    async fn alt_with_other_leaf_is_rejected() {
        let cache = TestCache::<Infallible, Infallible>::new();
        let (primary_key, primary_chain) = make_cert(&cache).await;
        let (other_key, _) = make_cert(&cache).await;

        let resolver = ResolvesServerCertAcme::new();
        let installed = resolver.set_certs(
            served(
                primary_key,
                RequiredSchemes::Known(vec![SignatureScheme::ED448]),
            ),
            Some(served(other_key, RequiredSchemes::Known(vec![P256]))),
        );
        assert!(!installed);

        let peer_certs = do_handshake(resolver, make_root_store(cache.ca_pem())).await;
        assert_eq!(peer_certs, primary_chain);
    }

    #[test]
    fn required_schemes_supported_by() {
        let offered = [P256, SignatureScheme::ED25519];
        assert_eq!(
            RequiredSchemes::Known(vec![P256]).supported_by(&offered),
            Some(true)
        );
        assert_eq!(
            RequiredSchemes::Known(vec![P256, SignatureScheme::RSA_PKCS1_SHA256])
                .supported_by(&offered),
            Some(false)
        );
        assert_eq!(RequiredSchemes::Unknown.supported_by(&offered), None);
    }
}
