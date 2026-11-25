use crate::ResolvesServerCertAcme;
use crate::acme::ACME_TLS_ALPN_NAME;
use rustls::crypto::CryptoProvider;
use rustls::server::Acceptor;
use rustls::sign::SingleCertAndKey;
use rustls::{DEFAULT_VERSIONS, ServerConfig};
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::ptr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Sleep;
use tokio_rustls::server::TlsStream;
use tokio_rustls::{Accept, LazyConfigAcceptor, StartHandshake};

/// Default limit for one TLS handshake, as in `axum_server`'s `RustlsAcceptor`.
pub(crate) const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Builds a [`ServerConfig`] that serves the certificates of `resolver`.
pub(crate) fn server_config(
    crypto_provider: Arc<CryptoProvider>,
    resolver: Arc<ResolvesServerCertAcme>,
) -> ServerConfig {
    ServerConfig::builder_with_provider(crypto_provider)
        .with_protocol_versions(DEFAULT_VERSIONS)
        // The provider comes from the ACME `ClientConfig`, so it already
        // passed this check when that config was built.
        .expect("crypto provider is usable for TLS")
        .with_no_client_auth()
        .with_cert_resolver(resolver)
}

/// Accepts incoming TLS connections, handling `tls-alpn-01` validation
/// inline and forwarding application traffic to the caller.
#[derive(Clone, Debug)]
pub struct AcmeAcceptor {
    resolver: Arc<ResolvesServerCertAcme>,
    config: Arc<ServerConfig>,
}

impl AcmeAcceptor {
    pub(crate) fn new(
        resolver: Arc<ResolvesServerCertAcme>,
        crypto_provider: Arc<CryptoProvider>,
    ) -> Self {
        let mut config = server_config(crypto_provider, resolver.clone());
        config.alpn_protocols.push(ACME_TLS_ALPN_NAME.to_vec());
        Self {
            resolver,
            config: Arc::new(config),
        }
    }

    /// Starts handshake processing on `io`.
    ///
    /// The returned future resolves to `Some(handshake)` for application
    /// traffic, which the caller must complete. It resolves to `None` for a
    /// `tls-alpn-01` validation request, which the acceptor answers itself.
    ///
    /// Complete application handshakes with [`AcmeAcceptor::into_stream`].
    ///
    /// Neither the returned future nor [`AcmeAcceptor::into_stream`] has a
    /// timeout. Wrap both stages in one [`tokio::time::timeout`], or a
    /// stalled peer holds the connection open. A timeout does not limit how
    /// many handshakes peers can open.
    pub fn accept<IO: AsyncRead + AsyncWrite + Unpin>(&self, io: IO) -> AcmeAccept<IO> {
        AcmeAccept::new(io, self.clone())
    }

    /// Completes the application handshake `handshake` with `config`.
    ///
    /// Use this instead of [`StartHandshake::into_stream`], so a client gets the alternate chain
    /// of [`CertChainPreference::DualChain`] if it needs it. That requires `config` to use the
    /// state's resolver, not a wrapper.
    ///
    /// [`CertChainPreference::DualChain`]: crate::CertChainPreference::DualChain
    pub fn into_stream<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
        handshake: StartHandshake<IO>,
        mut config: Arc<ServerConfig>,
    ) -> Accept<IO> {
        let serves_our_certs = ptr::addr_eq(
            Arc::as_ptr(&self.resolver),
            Arc::as_ptr(&config.cert_resolver),
        );
        if serves_our_certs
            && let Some(alternate) = self
                .resolver
                .alternate_for(handshake.client_hello().signature_schemes())
        {
            Arc::make_mut(&mut config).cert_resolver = Arc::new(SingleCertAndKey::from(alternate));
        }
        handshake.into_stream(config)
    }
}

/// Future returned by [`AcmeAcceptor::accept`].
pub struct AcmeAccept<IO: AsyncRead + AsyncWrite + Unpin> {
    client_hello: LazyConfigAcceptor<IO>,
    acceptor: AcmeAcceptor,
    validation_accept: Option<Accept<IO>>,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> fmt::Debug for AcmeAccept<IO> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcmeAccept").finish_non_exhaustive()
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AcmeAccept<IO> {
    fn new(io: IO, acceptor: AcmeAcceptor) -> Self {
        Self {
            client_hello: LazyConfigAcceptor::new(Acceptor::default(), io),
            acceptor,
            validation_accept: None,
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for AcmeAccept<IO> {
    type Output = io::Result<Option<StartHandshake<IO>>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            if let Some(validation_accept) = &mut self.validation_accept {
                return match Pin::new(validation_accept).poll(cx) {
                    Poll::Ready(Ok(_)) => Poll::Ready(Ok(None)),
                    Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                    Poll::Pending => Poll::Pending,
                };
            }

            return match Pin::new(&mut self.client_hello).poll(cx) {
                Poll::Ready(Ok(handshake)) => {
                    let is_validation = handshake
                        .client_hello()
                        .alpn()
                        .into_iter()
                        .flatten()
                        .eq([ACME_TLS_ALPN_NAME]);
                    if is_validation {
                        let config = self.acceptor.config.clone();
                        self.validation_accept = Some(handshake.into_stream(config));
                        continue;
                    }
                    Poll::Ready(Ok(Some(handshake)))
                }
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            };
        }
    }
}

/// Runs both handshake stages of one connection under a single deadline.
pub(crate) struct Handshake<IO: AsyncRead + AsyncWrite + Unpin> {
    stage: HandshakeStage<IO>,
    config: Arc<ServerConfig>,
    deadline: Pin<Box<Sleep>>,
}

#[allow(
    clippy::large_enum_variant,
    reason = "every handshake starts in the larger variant, so boxing it only adds an allocation"
)]
enum HandshakeStage<IO: AsyncRead + AsyncWrite + Unpin> {
    /// Reads the ClientHello and answers `tls-alpn-01` validation requests.
    Acme(AcmeAccept<IO>),
    /// Completes the handshake of application traffic.
    Tls(Accept<IO>),
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Handshake<IO> {
    /// Creates a handshake for `accept` that fails `timeout` after this call.
    pub(crate) fn new(
        accept: AcmeAccept<IO>,
        config: Arc<ServerConfig>,
        timeout: Duration,
    ) -> Self {
        Self {
            stage: HandshakeStage::Acme(accept),
            config,
            deadline: Box::pin(tokio::time::sleep(timeout)),
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Handshake<IO> {
    type Output = io::Result<Option<TlsStream<IO>>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        let poll = loop {
            match &mut this.stage {
                HandshakeStage::Acme(accept) => match Pin::new(&mut *accept).poll(cx) {
                    Poll::Ready(Ok(Some(start_handshake))) => {
                        let tls = accept
                            .acceptor
                            .into_stream(start_handshake, this.config.clone());
                        this.stage = HandshakeStage::Tls(tls);
                    }
                    Poll::Ready(Ok(None)) => break Poll::Ready(Ok(None)),
                    Poll::Ready(Err(err)) => break Poll::Ready(Err(err)),
                    Poll::Pending => break Poll::Pending,
                },
                HandshakeStage::Tls(accept) => break Pin::new(accept).poll(cx).map_ok(Some),
            }
        };
        if poll.is_pending() && this.deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TLS handshake timed out",
            )));
        }
        poll
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{self, CROSS_SIGNED_ROOT, Cert, HIERARCHIES, Hierarchy, LEAF_NAME};
    use crate::resolver::AlternateChain;
    use rustls::crypto::ring;
    use rustls::crypto::ring::cipher_suite::{
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS13_AES_128_GCM_SHA256,
    };
    use rustls::pki_types::alg_id::RSA_ENCRYPTION;
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::sign::CertifiedKey;
    use rustls::{ClientConfig, RootCertStore, SupportedCipherSuite};
    use tokio_rustls::TlsConnector;

    /// Buffer size of the in-memory connection between client and server.
    const DUPLEX_BUFFER: usize = 4096;
    /// One suite of each TLS version that the fixture's P-256 key can use.
    ///
    /// In TLS 1.2, a client that offers only ECDHE-ECDSA suites hides its RSA schemes from cert
    /// resolvers, see [`ResolvesServerCertAcme`]. It can still verify RSA signatures in
    /// certificates.
    const SUITES: [SupportedCipherSuite; 2] = [
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS13_AES_128_GCM_SHA256,
    ];

    /// A resolver that delegates to the state's.
    #[derive(Debug)]
    struct Wrapped(Arc<ResolvesServerCertAcme>);

    impl ResolvesServerCert for Wrapped {
        fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            self.0.resolve(client_hello)
        }
    }

    /// Returns an acceptor that serves `hierarchy` in DualChain mode, and its config.
    fn dual_chain(hierarchy: Hierarchy) -> (AcmeAcceptor, Arc<ServerConfig>) {
        let resolver = ResolvesServerCertAcme::new();
        let primary = Arc::new(fixture::certified_key(hierarchy.primary));
        resolver.set_cert(primary.clone());
        let alternate = AlternateChain::new(&primary, fixture::chain(hierarchy.alternate));
        assert!(resolver.set_alternate(alternate));
        let provider = Arc::new(ring::default_provider());
        let config = server_config(provider.clone(), resolver.clone());
        (AcmeAcceptor::new(resolver, provider), Arc::new(config))
    }

    /// Returns a client that trusts `root` and offers only `suite`.
    ///
    /// Without `verifies_rsa`, the client can't verify RSA signatures and doesn't offer them.
    fn client(root: Cert, verifies_rsa: bool, suite: SupportedCipherSuite) -> ClientConfig {
        let mut provider = ring::default_provider();
        provider.cipher_suites = vec![suite];
        if !verifies_rsa {
            let algorithms = &mut provider.signature_verification_algorithms;
            let all: Vec<_> = algorithms
                .all
                .iter()
                .filter(|algorithm| algorithm.public_key_alg_id() != RSA_ENCRYPTION)
                .copied()
                .collect();
            let mapping: Vec<_> = algorithms
                .mapping
                .iter()
                .filter(|(_, algorithms)| {
                    algorithms
                        .iter()
                        .all(|algorithm| algorithm.public_key_alg_id() != RSA_ENCRYPTION)
                })
                .copied()
                .collect();
            algorithms.all = Vec::leak(all);
            algorithms.mapping = Vec::leak(mapping);
        }
        let mut roots = RootCertStore::empty();
        roots.add(root.der()).expect("the fixture roots are valid");
        ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[suite.version()])
            .expect("the suite is for this version")
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    /// Runs a handshake like [`Incoming`](crate::Incoming), and returns the verified chain.
    async fn handshake(
        acceptor: &AcmeAcceptor,
        config: Arc<ServerConfig>,
        client: ClientConfig,
    ) -> Vec<CertificateDer<'static>> {
        let (client_io, server_io) = tokio::io::duplex(DUPLEX_BUFFER);
        let server_name = ServerName::try_from(LEAF_NAME).expect("the leaf name is valid");
        let (client, server) = tokio::join!(
            TlsConnector::from(Arc::new(client)).connect(server_name, client_io),
            Handshake::new(
                acceptor.accept(server_io),
                config,
                DEFAULT_HANDSHAKE_TIMEOUT
            ),
        );
        let client = client.expect("the client verifies the chain");
        assert!(matches!(server, Ok(Some(_))), "{server:?}");
        let chain = client.get_ref().1.peer_certificates();
        chain.expect("the server sent a chain").to_vec()
    }

    #[tokio::test]
    async fn dual_chain_serves_each_client_a_chain_it_verifies() {
        for hierarchy in HIERARCHIES {
            let (acceptor, config) = dual_chain(hierarchy);
            for suite in SUITES {
                let rsa_client = client(Cert::RsaRoot, true, suite);
                let chain = handshake(&acceptor, config.clone(), rsa_client).await;
                assert_eq!(chain, fixture::certs(hierarchy.primary), "{suite:?}");
                let ecdsa_client = client(Cert::EcRoot, false, suite);
                let chain = handshake(&acceptor, config.clone(), ecdsa_client).await;
                assert_eq!(chain, fixture::certs(hierarchy.alternate), "{suite:?}");
            }
        }
    }

    #[tokio::test]
    async fn configs_with_other_resolvers_serve_the_primary() {
        let (acceptor, _) = dual_chain(CROSS_SIGNED_ROOT);
        let provider = Arc::new(ring::default_provider());
        let wrapped = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(DEFAULT_VERSIONS)
            .expect("ring supports the default versions")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Wrapped(acceptor.resolver.clone())));
        // This client verifies the primary up to the intermediate, which the ECDSA root signed.
        let ecdsa_client = client(Cert::EcRoot, false, TLS13_AES_128_GCM_SHA256);
        let chain = handshake(&acceptor, Arc::new(wrapped), ecdsa_client).await;
        assert_eq!(chain, fixture::certs(CROSS_SIGNED_ROOT.primary));
    }
}
