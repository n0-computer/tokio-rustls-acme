use crate::AcmeAcceptor;
use crate::acceptor::{DEFAULT_HANDSHAKE_TIMEOUT, Handshake};
use rustls::ServerConfig;
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

/// An [`axum_server`] acceptor that answers `tls-alpn-01` requests and times out handshakes.
#[derive(Clone, Debug)]
pub struct AxumAcceptor {
    acme_acceptor: AcmeAcceptor,
    config: Arc<ServerConfig>,
    handshake_timeout: Duration,
}

impl AxumAcceptor {
    /// Creates an acceptor that uses `config` for application TLS.
    pub fn new(acme_acceptor: AcmeAcceptor, config: Arc<ServerConfig>) -> Self {
        Self {
            acme_acceptor,
            config,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }

    /// Sets the time limit for the TLS handshake of each connection.
    ///
    /// The limit runs from TCP accept. When it passes, the accept future fails
    /// with [`io::ErrorKind::TimedOut`]. The default is 10 seconds. The timeout
    /// cannot be disabled, so set a large value for slow clients.
    pub fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }
}

impl<I: AsyncRead + AsyncWrite + Unpin + Send + 'static, S: Send + 'static>
    axum_server::accept::Accept<I, S> for AxumAcceptor
{
    type Stream = tokio_rustls::server::TlsStream<I>;
    type Service = S;
    type Future = AxumAccept<I, S>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let acme_accept = self.acme_acceptor.accept(stream);
        Self::Future {
            handshake: Handshake::new(acme_accept, self.config.clone(), self.handshake_timeout),
            service: Some(service),
        }
    }
}

/// Future that [`AxumAcceptor`] returns for each connection.
pub struct AxumAccept<I: AsyncRead + AsyncWrite + Unpin + Send + 'static, S: Send + 'static> {
    handshake: Handshake<I>,
    service: Option<S>,
}

impl<I: AsyncRead + AsyncWrite + Unpin + Send + 'static, S: Send + 'static> fmt::Debug
    for AxumAccept<I, S>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AxumAccept").finish_non_exhaustive()
    }
}

impl<I: AsyncRead + AsyncWrite + Unpin + Send + 'static, S: Send + 'static> Unpin
    for AxumAccept<I, S>
{
}

impl<I: AsyncRead + AsyncWrite + Unpin + Send + 'static, S: Send + 'static> Future
    for AxumAccept<I, S>
{
    type Output = io::Result<(tokio_rustls::server::TlsStream<I>, S)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let output = match ready!(Pin::new(&mut self.handshake).poll(cx)) {
            Ok(Some(tls)) => {
                let service = self
                    .service
                    .take()
                    .expect("AxumAccept polled after completion");
                Ok((tls, service))
            }
            Ok(None) => Err(io::Error::other("TLS-ALPN-01 validation request")),
            Err(err) => Err(err),
        };
        Poll::Ready(output)
    }
}
