use crate::acme::ACME_TLS_ALPN_NAME;
use crate::ResolvesServerCertAcme;
use rustls::crypto::CryptoProvider;
use rustls::server::Acceptor;
use rustls::{ConfigBuilder, ServerConfig, WantsVerifier, DEFAULT_VERSIONS};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{Accept, LazyConfigAcceptor, StartHandshake};

#[derive(Clone)]
pub struct AcmeAcceptor {
    config: Arc<ServerConfig>,
}

impl AcmeAcceptor {
    pub(crate) fn new(resolver: Arc<ResolvesServerCertAcme>) -> Self {
        Self::new_with_config_builder(resolver, ServerConfig::builder())
    }

    pub(crate) fn new_with_crypto_provider(
        resolver: Arc<ResolvesServerCertAcme>,
        crypto_provider: Arc<CryptoProvider>,
    ) -> Self {
        let builder = ServerConfig::builder_with_provider(crypto_provider)
            // Replicates what [`ServerConfig::builder`] does.
            .with_protocol_versions(DEFAULT_VERSIONS)
            .unwrap();
        Self::new_with_config_builder(resolver, builder)
    }

    pub(crate) fn new_with_config_builder(
        resolver: Arc<ResolvesServerCertAcme>,
        builder: ConfigBuilder<ServerConfig, WantsVerifier>,
    ) -> Self {
        let mut config = builder.with_no_client_auth().with_cert_resolver(resolver);
        config.alpn_protocols.push(ACME_TLS_ALPN_NAME.to_vec());
        Self {
            config: Arc::new(config),
        }
    }
    pub fn accept<IO: AsyncRead + AsyncWrite + Unpin>(&self, io: IO) -> AcmeAccept<IO> {
        AcmeAccept::new(io, self.config.clone())
    }
}

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
