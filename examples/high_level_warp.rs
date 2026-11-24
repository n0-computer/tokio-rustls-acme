use clap::Parser;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::pin::pin;
use tokio_rustls_acme::AcmeConfig;
use tokio_rustls_acme::caches::DirCache;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::TcpListenerStream;
use warp::Filter;

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

    let tcp_listener = tokio::net::TcpListener::bind((Ipv6Addr::UNSPECIFIED, args.port))
        .await
        .unwrap();
    let tcp_incoming = TcpListenerStream::new(tcp_listener);

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
                tracing::error!("accept error: {err}");
                continue;
            }
        };
        tokio::spawn(async move {
            if let Err(err) = Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(tls), service)
                .await
            {
                tracing::warn!("connection error: {err}");
            }
        });
    }

    unreachable!()
}
