use crate::ResolvesServerCertAcme;
use crate::acme::ACME_TLS_ALPN_NAME;
use rustls::crypto::CryptoProvider;
use rustls::server::Acceptor;
use rustls::{DEFAULT_VERSIONS, ServerConfig};
use std::future::Future;
use std::io;
use std::pin::Pin;
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
#[derive(Clone)]
pub struct AcmeAcceptor {
    config: Arc<ServerConfig>,
}

impl AcmeAcceptor {
    pub(crate) fn new(
        resolver: Arc<ResolvesServerCertAcme>,
        crypto_provider: Arc<CryptoProvider>,
    ) -> Self {
        let mut config = server_config(crypto_provider, resolver);
        config.alpn_protocols.push(ACME_TLS_ALPN_NAME.to_vec());
        Self {
            config: Arc::new(config),
        }
    }

    /// Starts handshake processing on `io`.
    ///
    /// The returned future resolves to `Some(handshake)` for application
    /// traffic, which the caller must complete. It resolves to `None` for a
    /// `tls-alpn-01` validation request, which the acceptor answers itself.
    ///
    /// Neither the returned future nor [`StartHandshake::into_stream`] has a
    /// timeout. Wrap both stages in one [`tokio::time::timeout`], or a
    /// stalled peer holds the connection open. A timeout does not limit how
    /// many handshakes peers can open.
    pub fn accept<IO: AsyncRead + AsyncWrite + Unpin>(&self, io: IO) -> AcmeAccept<IO> {
        AcmeAccept::new(io, self.config.clone())
    }
}

/// Future returned by [`AcmeAcceptor::accept`].
pub struct AcmeAccept<IO: AsyncRead + AsyncWrite + Unpin> {
    acceptor: LazyConfigAcceptor<IO>,
    config: Arc<ServerConfig>,
    validation_accept: Option<Accept<IO>>,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AcmeAccept<IO> {
    pub(crate) fn new(io: IO, config: Arc<ServerConfig>) -> Self {
        Self {
            acceptor: LazyConfigAcceptor::new(Acceptor::default(), io),
            config,
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

            return match Pin::new(&mut self.acceptor).poll(cx) {
                Poll::Ready(Ok(handshake)) => {
                    let is_validation = handshake
                        .client_hello()
                        .alpn()
                        .into_iter()
                        .flatten()
                        .eq([ACME_TLS_ALPN_NAME]);
                    if is_validation {
                        self.validation_accept = Some(handshake.into_stream(self.config.clone()));
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

// Every handshake starts in the larger variant, so boxing it only adds an allocation.
#[allow(clippy::large_enum_variant)]
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
                HandshakeStage::Acme(accept) => match Pin::new(accept).poll(cx) {
                    Poll::Ready(Ok(Some(start_handshake))) => {
                        let accept = start_handshake.into_stream(this.config.clone());
                        this.stage = HandshakeStage::Tls(accept);
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
