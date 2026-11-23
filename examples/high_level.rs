use clap::Parser;
use std::io;
use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio_rustls_acme::AcmeConfig;
use tokio_rustls_acme::caches::DirCache;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::TcpListenerStream;

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
    simple_logger::init_with_level(log::Level::Info).unwrap();
    let args = Args::parse();

    let tcp_listener = tokio::net::TcpListener::bind((Ipv6Addr::UNSPECIFIED, args.port))
        .await
        .unwrap();
    let tcp_incoming = TcpListenerStream::new(tcp_listener);

    let mut tls_incoming = AcmeConfig::new(args.domains)
        .contact(args.email.iter().map(|e| format!("mailto:{e}")))
        .cache_option(args.cache.clone().map(DirCache::new))
        .directory_lets_encrypt(args.prod)
        .incoming(tcp_incoming, Vec::new());

    while let Some(tls) = tls_incoming.next().await {
        let mut tls = match tls {
            Ok(tls) => tls,
            Err(err) if is_connection_error(&err) => continue,
            Err(err) => {
                log::error!("TCP accept failed: {err:?}");
                // Accept fails again at once while no file descriptor is free.
                tokio::time::sleep(ACCEPT_ERROR_DELAY).await;
                continue;
            }
        };
        tokio::spawn(async move {
            tls.write_all(HELLO).await.unwrap();
            tls.shutdown().await.unwrap();
        });
    }
    unreachable!()
}

/// Pause after an accept error, as in axum's `serve`.
const ACCEPT_ERROR_DELAY: Duration = Duration::from_secs(1);

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
