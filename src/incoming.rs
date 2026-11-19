use crate::AcmeState;
use crate::acceptor::{AcmeAcceptor, DEFAULT_HANDSHAKE_TIMEOUT, Handshake, server_config};
use futures::Stream;
use futures::stream::{FusedStream, FuturesUnordered};
use rustls::ServerConfig;
use std::fmt::Debug;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;

/// [`Stream`] of accepted application TLS connections.
///
/// Folds ACME order and renewal work into the same poll loop, so polling
/// this stream advances both the certificate state machine and TCP accept.
pub struct Incoming<
    TCP: AsyncRead + AsyncWrite + Unpin,
    ETCP,
    ITCP: Stream<Item = Result<TCP, ETCP>> + Unpin,
    EC: Debug + 'static,
    EA: Debug + 'static,
> {
    state: AcmeState<EC, EA>,
    acceptor: AcmeAcceptor,
    rustls_config: Arc<ServerConfig>,
    tcp_incoming: Option<ITCP>,
    handshake_timeout: Duration,
    handshakes: FuturesUnordered<Handshake<TCP>>,
}

impl<
    TCP: AsyncRead + AsyncWrite + Unpin,
    ETCP,
    ITCP: Stream<Item = Result<TCP, ETCP>> + Unpin,
    EC: Debug + 'static,
    EA: Debug + 'static,
> Unpin for Incoming<TCP, ETCP, ITCP, EC, EA>
{
}

impl<
    TCP: AsyncRead + AsyncWrite + Unpin,
    ETCP,
    ITCP: Stream<Item = Result<TCP, ETCP>> + Unpin,
    EC: Debug + 'static,
    EA: Debug + 'static,
> Incoming<TCP, ETCP, ITCP, EC, EA>
{
    /// Creates an [`Incoming`] that uses `server_config` for application TLS.
    pub(crate) fn new_with_server(
        tcp_incoming: ITCP,
        state: AcmeState<EC, EA>,
        acceptor: AcmeAcceptor,
        server_config: ServerConfig,
    ) -> Self {
        Self {
            state,
            acceptor,
            rustls_config: Arc::new(server_config),
            tcp_incoming: Some(tcp_incoming),
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            handshakes: FuturesUnordered::new(),
        }
    }

    /// Creates an [`Incoming`] that offers `alpn_protocols` to application clients.
    pub(crate) fn new(
        tcp_incoming: ITCP,
        state: AcmeState<EC, EA>,
        acceptor: AcmeAcceptor,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Self {
        let mut server_config = server_config(state.crypto_provider(), state.resolver());
        server_config.alpn_protocols = alpn_protocols;
        Self::new_with_server(tcp_incoming, state, acceptor, server_config)
    }

    /// Sets the time limit for the TLS handshake of each connection.
    ///
    /// The limit runs from TCP accept. When it passes, the stream drops the
    /// connection. The default is 10 seconds. The timeout cannot be disabled,
    /// so set a large value for slow clients. It applies to connections accepted later.
    pub fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }
}

impl<
    TCP: AsyncRead + AsyncWrite + Unpin,
    ETCP,
    ITCP: Stream<Item = Result<TCP, ETCP>> + Unpin,
    EC: Debug + 'static,
    EA: Debug + 'static,
> Stream for Incoming<TCP, ETCP, ITCP, EC, EA>
{
    type Item = Result<TlsStream<TCP>, ETCP>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match Pin::new(&mut self.state).poll_next(cx) {
                Poll::Ready(Some(event)) => {
                    match event {
                        Ok(ok) => log::info!("event: {ok:?}"),
                        Err(err) => log::error!("event: {err:?}"),
                    }
                    continue;
                }
                Poll::Ready(None) => unreachable!(),
                Poll::Pending => {}
            }
            // Remote peers control how often these arms run, so they log at debug.
            match Pin::new(&mut self.handshakes).poll_next(cx) {
                Poll::Ready(Some(Ok(Some(tls)))) => return Poll::Ready(Some(Ok(tls))),
                Poll::Ready(Some(Ok(None))) => {
                    log::debug!("received TLS-ALPN-01 validation request");
                    continue;
                }
                Poll::Ready(Some(Err(err))) => {
                    log::debug!("TLS handshake failed: {err:?}");
                    continue;
                }
                Poll::Ready(None) | Poll::Pending => {}
            }
            let tcp_incoming = match &mut self.tcp_incoming {
                Some(tcp_incoming) => tcp_incoming,
                None => match self.is_terminated() {
                    true => return Poll::Ready(None),
                    false => return Poll::Pending,
                },
            };
            match Pin::new(tcp_incoming).poll_next(cx) {
                Poll::Ready(Some(Ok(tcp))) => {
                    let handshake = Handshake::new(
                        self.acceptor.accept(tcp),
                        self.rustls_config.clone(),
                        self.handshake_timeout,
                    );
                    self.handshakes.push(handshake);
                }
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Some(Err(err))),
                Poll::Ready(None) => self.tcp_incoming = None,
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<
    TCP: AsyncRead + AsyncWrite + Unpin,
    ETCP,
    ITCP: Stream<Item = Result<TCP, ETCP>> + Unpin,
    EC: Debug + 'static,
    EA: Debug + 'static,
> FusedStream for Incoming<TCP, ETCP, ITCP, EC, EA>
{
    fn is_terminated(&self) -> bool {
        self.tcp_incoming.is_none() && self.handshakes.is_terminated()
    }
}
