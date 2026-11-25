//! Integration tests against a Pebble ACME test server that validates challenges.
//!
//! Pebble runs with alternate roots, so it also offers alternate chains.
//!
//! They require Pebble and `challtestsrv` from `docker-compose.pebble.yml`:
//! `docker compose -f docker-compose.pebble.yml up -d`
//!
//! Each test resolves its domains to its own loopback address, from `127.0.0.2` up, and serves
//! port 5001 there. Thus the tests can run in parallel.
//!
//! Set `PEBBLE_MINICA_CERT` to the path of Pebble's minica root cert:
//!   `docker compose -f docker-compose.pebble.yml cp pebble:/test/certs/pebble.minica.pem ./pebble.minica.pem`
//!   `export PEBBLE_MINICA_CERT=./pebble.minica.pem`
//!
//! Run with: `cargo test --test pebble -- --ignored`, or all of the above with `cargo make test`.

use std::{
    io,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use n0_future::StreamExt;
use rustls::{
    ClientConfig, DEFAULT_VERSIONS, RootCertStore, ServerConfig,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use serde_json::json;
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinSet,
};
use tokio_rustls::TlsConnector;
use tokio_rustls_acme::{
    AccountCache, AcmeAcceptor, AcmeConfig, AcmeState, CertCache, CertChainPreference, EventError,
    EventOk, OrderError,
    caches::{DirCache, NoCache},
};

const PEBBLE_DIRECTORY: &str = "https://localhost:14000/dir";
const PEBBLE_MGMT: &str = "https://localhost:15000";
/// Management API of `challtestsrv`, the DNS server that Pebble's VA queries.
const CHALLTESTSRV_MGMT: &str = "http://127.0.0.1:8055";
/// The tls-alpn-01 port, `tlsPort` in `test/pebble-config.json`.
const TLS_ALPN_PORT: u16 = 5001;
const ORDER_TIMEOUT: Duration = Duration::from_secs(30);

/// Read the Pebble minica root cert from the path in PEBBLE_MINICA_CERT.
fn load_minica_cert() -> Vec<u8> {
    let path = std::env::var("PEBBLE_MINICA_CERT").expect("PEBBLE_MINICA_CERT env var must be set");
    std::fs::read(&path).unwrap_or_else(|e| panic!("failed to read {}: {}", path, e))
}

/// Returns a fresh ring crypto provider. The pebble tests pin themselves to
/// ring (via the dev-dependency) regardless of which crate features are on,
/// so they never depend on the process-wide default provider.
fn test_crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Build a rustls ClientConfig that trusts Pebble's minica root (for ACME API calls).
fn pebble_client_config() -> Arc<ClientConfig> {
    let minica_pem = load_minica_cert();
    let pems = pem::parse_many(&minica_pem).expect("failed to parse minica PEM");
    let mut root_store = RootCertStore::empty();
    for p in pems {
        let der = CertificateDer::from(p.into_contents());
        root_store
            .add(der)
            .expect("failed to add minica cert to root store");
    }
    Arc::new(
        ClientConfig::builder_with_provider(test_crypto_provider())
            .with_protocol_versions(DEFAULT_VERSIONS)
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

/// Returns a config for `domains` against Pebble, without a cache.
fn pebble_config(domains: &[&str]) -> AcmeConfig<io::Error> {
    AcmeConfig::new_with_client_tls_config(domains, pebble_client_config())
        .directory(PEBBLE_DIRECTORY)
        .cache(NoCache::new())
}

/// Reqwest client that talks to Pebble's management API.
///
/// Installs ring as the process-wide default `CryptoProvider` so reqwest's
/// `rustls-no-provider` build path can construct its own TLS config without
/// panicking. The pebble tests pin ring for TLS (via the `rustls`
/// dev-dependency) whatever backend the crate features select, and the
/// default only affects this test binary.
fn http_client() -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

/// Fetches the roots of Pebble's ACME CA as a root store, without intermediates.
async fn pebble_acme_root_store() -> RootCertStore {
    let client = http_client();
    let mut root_store = RootCertStore::empty();

    // Index 1 only exists with PEBBLE_ALTERNATE_ROOTS, so a 404 there is expected.
    for index in 0..2 {
        let url = format!("{PEBBLE_MGMT}/roots/{index}");
        let resp = client
            .get(&url)
            .send()
            .await
            .unwrap_or_else(|e| panic!("failed to reach Pebble management API at {url}: {e}"));
        if resp.status().is_success() {
            let pem_text = resp.text().await.expect("failed to read Pebble root");
            for p in pem::parse_many(&pem_text).expect("failed to parse Pebble root PEM") {
                root_store
                    .add(CertificateDer::from(p.into_contents()))
                    .expect("failed to add Pebble root to root store");
            }
        }
    }

    assert!(
        !root_store.is_empty(),
        "failed to fetch any roots from Pebble management API"
    );
    root_store
}

/// Fetches the PEM certificate at `path` of Pebble's management API.
async fn fetch_pebble_cert(path: &str) -> CertificateDer<'static> {
    let url = format!("{PEBBLE_MGMT}/{path}");
    let pem_text = http_client()
        .get(&url)
        .send()
        .await
        .and_then(|resp| resp.error_for_status())
        .unwrap_or_else(|e| panic!("failed to fetch {url}: {e}"))
        .text()
        .await
        .unwrap_or_else(|e| panic!("failed to read {url}: {e}"));
    let pems = pem::parse_many(&pem_text).expect("failed to parse PEM");
    CertificateDer::from(pems[0].contents().to_vec())
}

/// Fetches the subject CN of Pebble's root `index`.
///
/// Index 0 is the root of the default chain, 1 the root of the alternate.
async fn fetch_root_cn(index: usize) -> String {
    let der = fetch_pebble_cert(&format!("roots/{index}")).await;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).expect("failed to parse root");
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .expect("root has no CN")
        .to_owned()
}

/// Fetches Pebble's intermediate for chain `index`.
///
/// Index 0 is the default chain, 1 the alternate.
///
/// With alternate roots, every chain has the same intermediate key, signed by a different root,
/// so the DER identifies the chain exactly.
async fn fetch_intermediate(index: usize) -> CertificateDer<'static> {
    fetch_pebble_cert(&format!("intermediates/{index}")).await
}

/// Makes the DNS server of Pebble's VA resolve `domain` to `addr` only.
async fn set_dns_record(domain: &str, addr: IpAddr) {
    let kind = match addr {
        IpAddr::V4(_) => "a",
        IpAddr::V6(_) => "aaaa",
    };
    let host = format!("{domain}.");
    let client = http_client();
    // `add-a` appends to the records of earlier runs, so clear them first.
    post_challtestsrv(&client, &format!("clear-{kind}"), json!({ "host": host })).await;
    let body = json!({ "host": host, "addresses": [addr.to_string()] });
    post_challtestsrv(&client, &format!("add-{kind}"), body).await;
}

/// Posts `body` to the `challtestsrv` management endpoint `path`.
async fn post_challtestsrv(client: &reqwest::Client, path: &str, body: serde_json::Value) {
    let url = format!("{CHALLTESTSRV_MGMT}/{path}");
    let resp = client
        .post(&url)
        .body(body.to_string())
        .send()
        .await
        .unwrap_or_else(|e| panic!("failed to reach challtestsrv at {url}: {e}"));
    assert!(
        resp.status().is_success(),
        "{url} returned {}",
        resp.status()
    );
}

/// An ACME state machine whose own [`AcmeAcceptor`] answers Pebble's tls-alpn-01 validation.
struct Site {
    state: AcmeState<io::Error>,
    listeners: JoinSet<()>,
}

impl Site {
    /// Starts the state machine and serves its acceptor on [`TLS_ALPN_PORT`] of each of `addrs`.
    async fn bind(config: AcmeConfig<io::Error>, addrs: &[IpAddr]) -> Self {
        let state = config.state();
        let acceptor = state.acceptor();
        let server_config = Arc::new(
            ServerConfig::builder_with_provider(state.crypto_provider())
                .with_protocol_versions(DEFAULT_VERSIONS)
                .expect("provider should support the default protocol versions")
                .with_no_client_auth()
                .with_cert_resolver(state.resolver()),
        );
        let mut listeners = JoinSet::new();
        for &addr in addrs {
            let listener = TcpListener::bind((addr, TLS_ALPN_PORT))
                .await
                .unwrap_or_else(|e| panic!("failed to bind {addr}:{TLS_ALPN_PORT}: {e}"));
            listeners.spawn(serve(listener, acceptor.clone(), server_config.clone()));
        }
        Self { state, listeners }
    }

    /// Polls the state machine until it deploys a new certificate or an order fails.
    ///
    /// # Panics
    ///
    /// Panics on other errors and after [`ORDER_TIMEOUT`].
    // The crate returns `OrderError` by value in its events too.
    #[allow(clippy::result_large_err)]
    async fn deploy(&mut self) -> Result<(), OrderError> {
        tokio::time::timeout(ORDER_TIMEOUT, async {
            loop {
                match self.state.next().await {
                    Some(Ok(EventOk::DeployedNewCert)) => return Ok(()),
                    Some(Ok(_)) => {}
                    Some(Err(EventError::Order(err))) => return Err(err),
                    Some(Err(err)) => panic!("ACME error: {err:?}"),
                    None => panic!("state stream ended unexpectedly"),
                }
            }
        })
        .await
        .expect("timed out waiting for certificate deployment")
    }

    /// Closes the listeners and waits until their ports are free.
    async fn close(mut self) {
        self.listeners.shutdown().await;
    }
}

/// Accepts connections on `listener` and answers each with `acceptor`.
async fn serve(listener: TcpListener, acceptor: AcmeAcceptor, server_config: Arc<ServerConfig>) {
    let mut connections = JoinSet::new();
    loop {
        let (tcp, peer) = listener.accept().await.expect("accept failed");
        while connections.try_join_next().is_some() {}
        let acceptor = acceptor.clone();
        let server_config = server_config.clone();
        connections.spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(None) => eprintln!("served tls-alpn-01 challenge to {peer}"),
                Ok(Some(start)) => {
                    if let Err(err) = start.into_stream(server_config).await {
                        eprintln!("TLS handshake with {peer} failed: {err}");
                    }
                }
                Err(err) => eprintln!("TLS accept from {peer} failed: {err}"),
            }
        });
    }
}

/// Connects to `addr` on the tls-alpn-01 port and returns the verified chain served for `name`.
async fn fetch_chain(addr: IpAddr, name: ServerName<'static>) -> Vec<CertificateDer<'static>> {
    let connector = TlsConnector::from(Arc::new(
        ClientConfig::builder_with_provider(test_crypto_provider())
            .with_protocol_versions(DEFAULT_VERSIONS)
            .expect("provider should support the default protocol versions")
            .with_root_certificates(pebble_acme_root_store().await)
            .with_no_client_auth(),
    ));
    let tcp = TcpStream::connect((addr, TLS_ALPN_PORT))
        .await
        .unwrap_or_else(|e| panic!("failed to connect to {addr}:{TLS_ALPN_PORT}: {e}"));
    let tls = connector
        .connect(name.clone(), tcp)
        .await
        .unwrap_or_else(|e| panic!("TLS handshake with {addr} as {name:?} failed: {e}"));
    let chain = tls
        .get_ref()
        .1
        .peer_certificates()
        .expect("no peer certificates");
    assert!(!chain.is_empty(), "should have received certificates");
    chain.to_vec()
}

/// Like [`fetch_chain`], with `domain` as server name.
async fn fetch_chain_for(addr: IpAddr, domain: &str) -> Vec<CertificateDer<'static>> {
    let name = ServerName::try_from(domain.to_owned()).expect("invalid domain");
    fetch_chain(addr, name).await
}

/// Asserts that `chain` verifies for `domain` against Pebble's roots only with its intermediates.
async fn assert_needs_intermediates(chain: &[CertificateDer<'static>], domain: &str) {
    let roots = Arc::new(pebble_acme_root_store().await);
    let verifier = WebPkiServerVerifier::builder_with_provider(roots, test_crypto_provider())
        .build()
        .expect("failed to build verifier");
    let name = ServerName::try_from(domain.to_owned()).expect("invalid domain");
    let now = UnixTime::now();
    let (leaf, intermediates) = chain.split_first().expect("empty chain");
    verifier
        .verify_server_cert(leaf, intermediates, &name, &[], now)
        .expect("chain should verify against Pebble's roots");
    assert!(
        verifier
            .verify_server_cert(leaf, &[], &name, &[], now)
            .is_err(),
        "leaf without intermediates should not verify against Pebble's roots"
    );
}

/// Returns the path of the only file in `dir` whose name starts with `prefix`.
fn cache_file(dir: &Path, prefix: &str) -> PathBuf {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("failed to read cache dir")
        .map(|entry| entry.expect("failed to read cache dir entry"))
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(prefix))
        })
        .map(|entry| entry.path())
        .collect();
    assert_eq!(
        files.len(),
        1,
        "expected one {prefix}* file in {}",
        dir.display()
    );
    files.remove(0)
}

/// Collected events from a single ACME state machine run.
#[derive(Default, Debug)]
struct AcmeEvents {
    deployed_cached: bool,
    deployed_new: bool,
    cert_cache_store: bool,
    account_cache_store: bool,
    cached_cert_parse_error: bool,
}

/// Runs a [`Site`] with `cache` until it deploys a certificate, collecting events.
async fn acquire_cert_with_cache<C>(
    domain: &str,
    addr: IpAddr,
    cert_chain: CertChainPreference,
    cache: C,
) -> (Site, AcmeEvents)
where
    C: CertCache<EC = io::Error> + AccountCache<EA = io::Error> + Send + Sync + 'static,
{
    let config = AcmeConfig::new_with_client_tls_config([domain], pebble_client_config())
        .directory(PEBBLE_DIRECTORY)
        .cert_chain(cert_chain)
        .cache(cache);
    let mut site = Site::bind(config, &[addr]).await;
    let mut events = AcmeEvents::default();

    tokio::time::timeout(ORDER_TIMEOUT, async {
        loop {
            match site.state.next().await {
                Some(Ok(EventOk::DeployedCachedCert)) => {
                    eprintln!("event: DeployedCachedCert");
                    events.deployed_cached = true;
                    return;
                }
                Some(Ok(EventOk::DeployedNewCert)) => {
                    eprintln!("event: DeployedNewCert");
                    events.deployed_new = true;
                    // Continue to collect the CertCacheStore event that follows.
                    // Event order: AccountCacheStore, DeployedNewCert, CertCacheStore.
                }
                Some(Ok(EventOk::CertCacheStore)) => {
                    eprintln!("event: CertCacheStore");
                    events.cert_cache_store = true;
                    return;
                }
                Some(Ok(EventOk::AccountCacheStore)) => {
                    eprintln!("event: AccountCacheStore");
                    events.account_cache_store = true;
                }
                Some(Ok(event)) => eprintln!("event: {event:?}"),
                Some(Err(EventError::CachedCertParse(err))) => {
                    eprintln!("event: CachedCertParse: {err}");
                    events.cached_cert_parse_error = true;
                }
                Some(Err(err)) => panic!("ACME error: {:?}", err),
                None => panic!("state stream ended unexpectedly"),
            }
        }
    })
    .await
    .expect("timed out waiting for certificate deployment");

    (site, events)
}

/// Obtain a cert with the default chain and verify it can serve TLS.
///
/// This is the baseline test: a fresh ACME order with no cache and no chain
/// preference should produce a valid certificate that passes a TLS handshake.
#[tokio::test]
#[ignore]
async fn test_default_chain() {
    let _ = tracing_subscriber::fmt::try_init();

    let domain = "default-chain.example.com";
    let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    set_dns_record(domain, addr).await;

    let mut site = Site::bind(pebble_config(&[domain]), &[addr]).await;
    site.deploy().await.expect("order failed");

    let peer_certs = fetch_chain_for(addr, domain).await;
    eprintln!("default chain: received {} certificates", peer_certs.len());
    assert_needs_intermediates(&peer_certs, domain).await;
}

/// Verify that DirCache persists certs and a second run loads from cache.
///
/// The first run should issue a fresh certificate (DeployedNewCert + CertCacheStore).
/// The second run, using the same cache directory, should skip the ACME order
/// entirely and deploy the cached cert (DeployedCachedCert).
#[tokio::test]
#[ignore]
async fn test_dir_cache_stores_and_reloads() {
    let _ = tracing_subscriber::fmt::try_init();

    let domain = "dir-cache.example.com";
    let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3));
    set_dns_record(domain, addr).await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache_path: PathBuf = cache_dir.path().into();

    // First run: fresh order, should store to cache.
    let (site, events) = acquire_cert_with_cache(
        domain,
        addr,
        CertChainPreference::Default,
        DirCache::new(cache_path.clone()),
    )
    .await;
    assert!(events.deployed_new, "first run should deploy a new cert");
    assert!(
        events.cert_cache_store,
        "first run should store cert to cache"
    );

    // Verify the cert works.
    fetch_chain_for(addr, domain).await;
    site.close().await;

    // Second run: same cache dir, should load from cache without ordering.
    let (_site, events2) = acquire_cert_with_cache(
        domain,
        addr,
        CertChainPreference::Default,
        DirCache::new(cache_path),
    )
    .await;
    assert!(
        events2.deployed_cached,
        "second run should deploy cached cert"
    );
    assert!(
        !events2.deployed_new,
        "second run should not issue a new cert"
    );

    // Verify the cached cert also works.
    fetch_chain_for(addr, domain).await;
}

/// A cached cert that cannot be parsed triggers re-issuance with the cached account key.
#[tokio::test]
#[ignore]
async fn test_corrupted_cache_reissues_with_cached_account() {
    let _ = tracing_subscriber::fmt::try_init();

    let domain = "corrupted-cache.example.com";
    let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5));
    set_dns_record(domain, addr).await;
    let cache_dir = tempfile::tempdir().expect("failed to create temp dir");
    let cache_path: PathBuf = cache_dir.path().into();

    let (site, events) = acquire_cert_with_cache(
        domain,
        addr,
        CertChainPreference::Default,
        DirCache::new(cache_path.clone()),
    )
    .await;
    assert!(
        events.deployed_new && events.account_cache_store,
        "first run should issue a cert and store the account, got {events:?}"
    );
    site.close().await;

    let account_file = cache_file(&cache_path, "cached_account_");
    let account_key = std::fs::read(&account_file).expect("failed to read cached account");
    std::fs::write(cache_file(&cache_path, "cached_cert_"), b"not a valid PEM")
        .expect("failed to corrupt cached cert");

    let (_site, events) = acquire_cert_with_cache(
        domain,
        addr,
        CertChainPreference::Default,
        DirCache::new(cache_path),
    )
    .await;
    assert!(
        events.cached_cert_parse_error && events.deployed_new && !events.deployed_cached,
        "second run should reject the cached cert and issue a new one, got {events:?}"
    );
    assert!(
        !events.account_cache_store,
        "second run should load cached account, not store a new one"
    );
    assert_eq!(
        std::fs::read(&account_file).expect("failed to read cached account"),
        account_key,
        "second run should not replace the cached account key"
    );
    fetch_chain_for(addr, domain).await;
}

/// Verify that the state machine automatically renews an expiring certificate.
///
/// Pebble picks a random profile from `test/pebble-config.json`, so every profile there must
/// keep the validity short enough to renew within [`ORDER_TIMEOUT`].
#[tokio::test]
#[ignore]
async fn test_automatic_renewal() {
    let _ = tracing_subscriber::fmt::try_init();

    let domain = "renewal.example.com";
    let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 6));
    set_dns_record(domain, addr).await;

    let mut site = Site::bind(pebble_config(&[domain]), &[addr]).await;
    site.deploy().await.expect("initial order failed");
    site.deploy().await.expect("renewal order failed");

    fetch_chain_for(addr, domain).await;
}

/// Issue a certificate with multiple SAN domains and verify all are present.
#[tokio::test]
#[ignore]
async fn test_multi_domain_san() {
    let _ = tracing_subscriber::fmt::try_init();

    let hosts = [
        ("multi-1.example.com", Ipv4Addr::new(127, 0, 0, 7)),
        ("multi-2.example.com", Ipv4Addr::new(127, 0, 0, 8)),
        ("multi-3.example.com", Ipv4Addr::new(127, 0, 0, 9)),
    ]
    .map(|(domain, addr)| (domain, IpAddr::V4(addr)));
    for (domain, addr) in hosts {
        set_dns_record(domain, addr).await;
    }
    let domains = hosts.map(|(domain, _)| domain);
    let addrs = hosts.map(|(_, addr)| addr);

    let mut site = Site::bind(pebble_config(&domains), &addrs).await;
    site.deploy().await.expect("order failed");

    for (domain, addr) in hosts {
        let peer_certs = fetch_chain_for(addr, domain).await;

        let (_, leaf) = x509_parser::parse_x509_certificate(peer_certs[0].as_ref())
            .expect("failed to parse leaf certificate");
        let sans: Vec<String> = leaf
            .subject_alternative_name()
            .expect("SAN extension missing")
            .expect("SAN extension empty")
            .value
            .general_names
            .iter()
            .filter_map(|name| match name {
                x509_parser::extensions::GeneralName::DNSName(dns) => Some(dns.to_string()),
                _ => None,
            })
            .collect();

        for domain in domains {
            assert!(
                sans.contains(&domain.to_string()),
                "SAN should contain {}, got: {:?}",
                domain,
                sans
            );
        }
        eprintln!("multi-domain SANs served on {addr}: {sans:?}");
    }
}

/// PreferredChain serves the alternate chain whose root matches the issuer.
#[tokio::test]
#[ignore]
async fn test_preferred_chain() {
    let _ = tracing_subscriber::fmt::try_init();

    let domain = "preferred-chain.example.com";
    let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10));
    set_dns_record(domain, addr).await;
    let alt_root_cn = fetch_root_cn(1).await;

    let config =
        pebble_config(&[domain]).cert_chain(CertChainPreference::PreferredChain(alt_root_cn));
    let mut site = Site::bind(config, &[addr]).await;
    site.deploy().await.expect("order failed");

    let chain = fetch_chain_for(addr, domain).await;
    assert_eq!(
        chain.last(),
        Some(&fetch_intermediate(1).await),
        "should serve the alternate chain"
    );
}

/// DualChain serves the default chain to a client that verifies it.
#[tokio::test]
#[ignore]
async fn test_dual_chain() {
    let _ = tracing_subscriber::fmt::try_init();

    let domain = "dual-chain.example.com";
    let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 11));
    set_dns_record(domain, addr).await;
    let alt_root_cn = fetch_root_cn(1).await;

    let config = pebble_config(&[domain]).cert_chain(CertChainPreference::DualChain(alt_root_cn));
    let mut site = Site::bind(config, &[addr]).await;
    site.deploy().await.expect("order failed");

    let chain = fetch_chain_for(addr, domain).await;
    assert_eq!(
        chain.last(),
        Some(&fetch_intermediate(0).await),
        "a client that verifies the default chain should get it"
    );
}

/// A PreferredChain that no offered chain matches falls back to the default.
#[tokio::test]
#[ignore]
async fn test_preferred_chain_falls_back_to_default() {
    let _ = tracing_subscriber::fmt::try_init();

    let domain = "preferred-fallback.example.com";
    let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 12));
    set_dns_record(domain, addr).await;

    let config = pebble_config(&[domain])
        .cert_chain(CertChainPreference::PreferredChain("No Such Root".into()));
    let mut site = Site::bind(config, &[addr]).await;
    site.deploy().await.expect("order failed");

    let chain = fetch_chain_for(addr, domain).await;
    assert_eq!(
        chain.last(),
        Some(&fetch_intermediate(0).await),
        "should serve the default chain"
    );
}

/// DualChain stores the alternate chain in its own cache file and loads it on the next run.
#[tokio::test]
#[ignore]
async fn test_dual_chain_cache() {
    let _ = tracing_subscriber::fmt::try_init();

    let domain = "dual-chain-cache.example.com";
    let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 13));
    set_dns_record(domain, addr).await;
    let cache_dir = tempfile::tempdir().expect("failed to create temp dir");
    let cache_path: PathBuf = cache_dir.path().into();
    let alt_root_cn = fetch_root_cn(1).await;

    let (site, events) = acquire_cert_with_cache(
        domain,
        addr,
        CertChainPreference::DualChain(alt_root_cn.clone()),
        DirCache::new(cache_path.clone()),
    )
    .await;
    assert!(
        events.deployed_new && events.cert_cache_store,
        "first run should issue and store a cert, got {events:?}"
    );
    site.close().await;

    let alt_file = std::fs::read_dir(&cache_path)
        .expect("failed to read cache dir")
        .map(|entry| entry.expect("failed to read cache dir entry").path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("cached_cert_") && name.ends_with("_alt"))
        })
        .expect("should have an alternate cert cache file");
    let alt_pems = pem::parse_many(std::fs::read(&alt_file).expect("failed to read alt cache"))
        .expect("failed to parse alt cache");
    assert_eq!(
        alt_pems.last().map(|p| p.contents()),
        Some(fetch_intermediate(1).await.as_ref()),
        "the alternate cache file should hold the alternate chain"
    );

    let (_site, events) = acquire_cert_with_cache(
        domain,
        addr,
        CertChainPreference::DualChain(alt_root_cn),
        DirCache::new(cache_path),
    )
    .await;
    assert!(
        events.deployed_cached && !events.deployed_new,
        "second run should deploy the cached cert, got {events:?}"
    );
    let chain = fetch_chain_for(addr, domain).await;
    assert_eq!(chain.last(), Some(&fetch_intermediate(0).await));
}
