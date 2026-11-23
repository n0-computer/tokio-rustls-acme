use clap::Parser;
use futures::StreamExt;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use std::io;
use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::pin::pin;
use std::time::Duration;
use tokio_rustls_acme::AcmeConfig;
use tokio_rustls_acme::caches::DirCache;
use tokio_stream::wrappers::TcpListenerStream;
use warp::Filter;

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
    simple_logger::init_with_level(log::Level::Info).unwrap();
    let args = Args::parse();

    let tcp_listener = tokio::net::TcpListener::bind((Ipv6Addr::UNSPECIFIED, args.port))
        .await
        .unwrap();
    // Log and drop accept errors here, and pause after those that would repeat at once.
    let tcp_incoming = TcpListenerStream::new(tcp_listener)
        .filter_map(|tcp| async move {
            match tcp {
                Ok(tcp) => Some(Ok::<_, io::Error>(tcp)),
                Err(err) if is_connection_error(&err) => None,
                Err(err) => {
                    log::error!("TCP accept failed: {err:?}");
                    // Accept fails again at once while no file descriptor is free.
                    tokio::time::sleep(ACCEPT_ERROR_DELAY).await;
                    None
                }
            }
        })
        .boxed();

    let tls_incoming = AcmeConfig::new(args.domains)
        .contact(args.email.iter().map(|e| format!("mailto:{e}")))
        .cache_option(args.cache.clone().map(DirCache::new))
        .directory_lets_encrypt(args.prod)
        .incoming(tcp_incoming, Vec::new());

    let route = warp::any().map(|| String::from("Hello Tls!"));
    let service = TowerToHyperService::new(warp::service(route));

    // warp 0.4 has no API for serving a stream of accepted connections, so
    // drive each TLS connection with hyper directly.
    let mut tls_incoming = pin!(tls_incoming);
    while let Some(tls) = tls_incoming.next().await {
        let tls = match tls {
            Ok(tls) => tls,
            Err(err) => {
                log::error!("accept error: {err}");
                continue;
            }
        };
        tokio::spawn(async move {
            if let Err(err) = Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(tls), service)
                .await
            {
                log::warn!("connection error: {err}");
            }
        });
    }

    unreachable!()
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
