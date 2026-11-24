use clap::Parser;
use rustls::{DEFAULT_VERSIONS, ServerConfig};
use std::io;
use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio_rustls_acme::caches::DirCache;
use tokio_rustls_acme::{AcmeAcceptor, AcmeConfig};
use tokio_stream::StreamExt;
use tracing::{debug, error, info};

/// Limit for one TLS handshake, the default of axum-server.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Pause after an accept error, as in axum's `serve`.
const ACCEPT_ERROR_DELAY: Duration = Duration::from_secs(1);

#[derive(Parser, Debug)]
struct Args {
    /// Domains
    #[clap(short, required = true)]
    domains: Vec<String>,

    /// Contact info
    #[clap(short)]
    email: Vec<String>,

    /// Cache directory
    #[clap(short)]
    cache: Option<PathBuf>,

    /// Use Let's Encrypt production environment
    /// (see https://letsencrypt.org/docs/staging-environment/)
    #[clap(long)]
    prod: bool,

    #[clap(short, long, default_value = "443")]
    port: u16,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let mut state = AcmeConfig::new(args.domains)
        .contact(args.email.iter().map(|e| format!("mailto:{e}")))
        .cache_option(args.cache.clone().map(DirCache::new))
        .directory_lets_encrypt(args.prod)
        .state();
    let rustls_config = ServerConfig::builder_with_provider(state.crypto_provider())
        .with_protocol_versions(DEFAULT_VERSIONS)
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(state.resolver());
    let acceptor = state.acceptor();

    tokio::spawn(async move {
        loop {
            match state.next().await.unwrap() {
                Ok(ok) => info!(event = ?ok, "event"),
                Err(err) => error!(?err, "error"),
            }
        }
    });

    serve(acceptor, Arc::new(rustls_config), args.port).await;
}

async fn serve(acceptor: AcmeAcceptor, rustls_config: Arc<ServerConfig>, port: u16) {
    let listener = tokio::net::TcpListener::bind((Ipv6Addr::UNSPECIFIED, port))
        .await
        .unwrap();
    loop {
        let tcp = match listener.accept().await {
            Ok((tcp, _)) => tcp,
            Err(err) if is_connection_error(&err) => continue,
            Err(err) => {
                error!("TCP accept failed: {err:?}");
                // Accept fails again at once while no file descriptor is free.
                tokio::time::sleep(ACCEPT_ERROR_DELAY).await;
                continue;
            }
        };
        let rustls_config = rustls_config.clone();
        let accept_future = acceptor.accept(tcp);
        // Start the clock before spawning, so executor queueing counts.
        let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;

        tokio::spawn(async move {
            let handshake = async {
                match accept_future.await? {
                    None => Ok(None),
                    Some(start_handshake) => {
                        start_handshake.into_stream(rustls_config).await.map(Some)
                    }
                }
            };
            match tokio::time::timeout_at(deadline, handshake).await {
                Ok(Ok(Some(mut tls))) => {
                    let response = async {
                        tls.write_all(HELLO).await?;
                        tls.shutdown().await
                    };
                    if let Err(err) = response.await {
                        debug!("failed to send response: {err:?}");
                    }
                }
                Ok(Ok(None)) => info!("received TLS-ALPN-01 validation request"),
                Ok(Err(err)) => debug!("TLS handshake failed: {err:?}"),
                Err(_) => debug!("TLS handshake timed out"),
            }
        });
    }
}

/// Returns whether `err` concerns only one connection, so accepting can go on at once.
fn is_connection_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}

const HELLO: &[u8] = br#"HTTP/1.1 200 OK
Content-Length: 10
Content-Type: text/plain; charset=utf-8

Hello Tls!"#;
