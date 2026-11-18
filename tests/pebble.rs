//! Integration tests against a Pebble ACME test server that validates challenges.
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
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use futures::StreamExt;
use rustls::{
    ClientConfig, DEFAULT_VERSIONS, RootCertStore, ServerConfig,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinSet,
};
use tokio_rustls::TlsConnector;
use tokio_rustls_acme::{
    AccountCache, AcmeAcceptor, AcmeConfig, AcmeState, CertCache, EventError, EventOk, OrderError,
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
            let pem_text = resp.text().await.unwrap();
            for p in pem::parse_many(&pem_text).unwrap() {
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

/// Makes the DNS server of Pebble's VA resolve `domain` to `addr` only.
async fn set_dns_record(domain: &str, addr: IpAddr) {
    let kind = match addr {
        IpAddr::V4(_) => "a",
        IpAddr::V6(_) => "aaaa",
    };
    let host = format!("{domain}.");
    let client = http_client();
    // `add-a` appends to the records of earlier runs, so clear them first.
    for (path, body) in [
        (format!("clear-{kind}"), serde_json::json!({ "host": host })),
        (
            format!("add-{kind}"),
            serde_json::json!({ "host": host, "addresses": [addr.to_string()] }),
        ),
    ] {
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
}

/// An ACME state machine whose own [`AcmeAcceptor`] answers Pebble's tls-alpn-01 validation.
struct Site {
    state: AcmeState<io::Error>,
    listeners: JoinSet<()>,
}

impl Site {
    async fn bind(config: AcmeConfig<io::Error>, addrs: &[IpAddr]) -> Self {
        let state = config.state();
        let acceptor = state.acceptor();
        let server_config = Arc::new(
            ServerConfig::builder_with_provider(state.crypto_provider())
                .with_protocol_versions(DEFAULT_VERSIONS)
                .unwrap()
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
            .unwrap()
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

async fn fetch_chain_for(addr: IpAddr, domain: &str) -> Vec<CertificateDer<'static>> {
    fetch_chain(addr, ServerName::try_from(domain.to_owned()).unwrap()).await
}

/// Asserts that `chain` verifies for `domain` against Pebble's roots only with its intermediates.
async fn assert_needs_intermediates(chain: &[CertificateDer<'static>], domain: &str) {
    let roots = Arc::new(pebble_acme_root_store().await);
    let verifier = WebPkiServerVerifier::builder_with_provider(roots, test_crypto_provider())
        .build()
        .unwrap();
    let name = ServerName::try_from(domain.to_owned()).unwrap();
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
        .unwrap()
        .map(|entry| entry.unwrap())
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

async fn acquire_cert_with_cache<C>(domain: &str, addr: IpAddr, cache: C) -> (Site, AcmeEvents)
where
    C: CertCache<EC = io::Error> + AccountCache<EA = io::Error> + Send + Sync + 'static,
{
    let config = AcmeConfig::new_with_client_tls_config([domain], pebble_client_config())
        .directory(PEBBLE_DIRECTORY)
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
    let _ = simple_logger::init_with_level(log::Level::Info);

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
    let _ = simple_logger::init_with_level(log::Level::Info);

    let domain = "dir-cache.example.com";
    let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3));
    set_dns_record(domain, addr).await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache_path: PathBuf = cache_dir.path().into();

    // First run: fresh order, should store to cache.
    let (site, events) =
        acquire_cert_with_cache(domain, addr, DirCache::new(cache_path.clone())).await;
    assert!(events.deployed_new, "first run should deploy a new cert");
    assert!(
        events.cert_cache_store,
        "first run should store cert to cache"
    );

    // Verify the cert works.
    fetch_chain_for(addr, domain).await;
    site.close().await;

    // Second run: same cache dir, should load from cache without ordering.
    let (_site, events2) = acquire_cert_with_cache(domain, addr, DirCache::new(cache_path)).await;
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
    let _ = simple_logger::init_with_level(log::Level::Info);

    let domain = "corrupted-cache.example.com";
    let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5));
    set_dns_record(domain, addr).await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache_path: PathBuf = cache_dir.path().into();

    let (site, events) =
        acquire_cert_with_cache(domain, addr, DirCache::new(cache_path.clone())).await;
    assert!(
        events.deployed_new && events.account_cache_store,
        "first run should issue a cert and store the account, got {events:?}"
    );
    site.close().await;

    let account_file = cache_file(&cache_path, "cached_account_");
    let account_key = std::fs::read(&account_file).unwrap();
    std::fs::write(cache_file(&cache_path, "cached_cert_"), b"not a valid PEM").unwrap();

    let (_site, events) = acquire_cert_with_cache(domain, addr, DirCache::new(cache_path)).await;
    assert!(
        events.cached_cert_parse_error && events.deployed_new && !events.deployed_cached,
        "second run should reject the cached cert and issue a new one, got {events:?}"
    );
    assert!(
        !events.account_cache_store,
        "second run should load cached account, not store a new one"
    );
    assert_eq!(
        std::fs::read(&account_file).unwrap(),
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
    let _ = simple_logger::init_with_level(log::Level::Info);

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
    let _ = simple_logger::init_with_level(log::Level::Info);

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

        let (_, leaf) = x509_parser::parse_x509_certificate(peer_certs[0].as_ref()).unwrap();
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

/// Collects the IP address SANs of a DER certificate.
fn ip_sans(cert: &CertificateDer<'_>) -> Vec<IpAddr> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert.as_ref()).unwrap();
    let san = cert
        .subject_alternative_name()
        .expect("SAN extension malformed")
        .expect("SAN extension missing");
    san.value
        .general_names
        .iter()
        .filter_map(|name| match name {
            x509_parser::extensions::GeneralName::IPAddress(bytes) => match bytes.len() {
                4 => Some(IpAddr::from(<[u8; 4]>::try_from(*bytes).unwrap())),
                16 => Some(IpAddr::from(<[u8; 16]>::try_from(*bytes).unwrap())),
                n => panic!("IP SAN with {n} bytes"),
            },
            _ => None,
        })
        .collect()
}

/// Serializes the tests that listen on `127.0.0.1` or `::1`.
///
/// The tests with IP identifiers share these addresses. Pebble's VA connects to the address in
/// the identifier, and `::1` is the only IPv6 loopback address.
static LOOPBACK_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Orders a certificate for the IP addresses `ips`, with `profile` if set.
///
/// Serves tls-alpn-01 on each address of `ips`, and after deployment connects to each of them
/// with the address as server name. Returns the chain served on the first address, or the
/// error of the order.
// The crate returns `OrderError` by value in its events too.
#[allow(clippy::result_large_err)]
async fn acquire_ip_cert(
    ips: &[IpAddr],
    profile: Option<&str>,
) -> Result<Vec<CertificateDer<'static>>, OrderError> {
    let _guard = LOOPBACK_LOCK.lock().await;

    let identifiers: Vec<String> = ips.iter().map(IpAddr::to_string).collect();
    let identifiers: Vec<&str> = identifiers.iter().map(String::as_str).collect();
    let mut config = pebble_config(&identifiers);
    if let Some(profile) = profile {
        config = config.profile(profile);
    }
    let mut site = Site::bind(config, ips).await;
    let result = site.deploy().await;
    let mut chains = Vec::new();
    if result.is_ok() {
        for &ip in ips {
            chains.push(fetch_chain(ip, ServerName::from(ip)).await);
        }
    }
    site.close().await;
    result.map(|()| chains.swap_remove(0))
}

/// Issue a certificate for an IPv4 address through real tls-alpn-01 validation.
///
/// The CA sends the reverse-DNS name `1.0.0.127.in-addr.arpa` as SNI (RFC 8738 section 6), so
/// this fails unless the resolver serves the challenge certificate under that name.
#[tokio::test]
#[ignore]
async fn test_validated_ipv4_certificate() {
    let _ = simple_logger::init_with_level(log::Level::Info);

    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let chain = acquire_ip_cert(&[ip], None).await.expect("order failed");
    assert_eq!(ip_sans(&chain[0]), [ip]);
}

/// Issue a certificate for an IPv6 address through real tls-alpn-01 validation, with the
/// nibble-format reverse name under `ip6.arpa` as SNI.
#[tokio::test]
#[ignore]
async fn test_validated_ipv6_certificate() {
    let _ = simple_logger::init_with_level(log::Level::Info);

    let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let chain = acquire_ip_cert(&[ip], None).await.expect("order failed");
    assert_eq!(ip_sans(&chain[0]), [ip]);
}

/// Issue one certificate for both an IPv4 and an IPv6 address.
#[tokio::test]
#[ignore]
async fn test_validated_dual_stack_certificate() {
    let _ = simple_logger::init_with_level(log::Level::Info);

    let ips = [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ];
    let chain = acquire_ip_cert(&ips, None).await.expect("order failed");
    assert_eq!(ip_sans(&chain[0]), ips);
}

/// Issue one certificate for an IP address and a domain.
///
/// Pebble validates the IP identifier on `127.0.0.1` with the reverse-DNS name as SNI, and the
/// domain on the address that `challtestsrv` resolves it to, with the domain as SNI.
#[tokio::test]
#[ignore]
async fn test_validated_mixed_ip_and_domain_certificate() {
    let _ = simple_logger::init_with_level(log::Level::Info);

    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let domain = "mixed.example.com";
    let domain_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10));
    set_dns_record(domain, domain_addr).await;

    let _guard = LOOPBACK_LOCK.lock().await;
    let ip_identifier = ip.to_string();
    let config = pebble_config(&[&ip_identifier, domain]);
    let mut site = Site::bind(config, &[ip, domain_addr]).await;
    site.deploy().await.expect("order failed");

    let chain = fetch_chain(ip, ServerName::from(ip)).await;
    fetch_chain_for(domain_addr, domain).await;
    site.close().await;

    assert_eq!(ip_sans(&chain[0]), [ip]);
    let (_, leaf) = x509_parser::parse_x509_certificate(chain[0].as_ref()).unwrap();
    let has_dns = leaf
        .subject_alternative_name()
        .expect("SAN extension malformed")
        .expect("SAN extension missing")
        .value
        .general_names
        .iter()
        .any(
            |name| matches!(name, x509_parser::extensions::GeneralName::DNSName(d) if *d == domain),
        );
    assert!(has_dns, "certificate should contain a DNS SAN for {domain}");
}

/// Lifetime of a DER certificate (`notAfter - notBefore`) in seconds.
fn lifetime_secs(cert: &CertificateDer<'_>) -> i64 {
    let (_, cert) = x509_parser::parse_x509_certificate(cert.as_ref()).unwrap();
    let validity = cert.validity();
    validity.not_after.timestamp() - validity.not_before.timestamp()
}

/// Request certificates under specific ACME profiles and check that the CA applied them.
///
/// `test/pebble-config.json` gives the profiles distinct validity periods. Pebble issues
/// certificates valid for `validityPeriod - 1` seconds.
#[tokio::test]
#[ignore]
async fn test_profile_selects_lifetime() {
    let _ = simple_logger::init_with_level(log::Level::Info);

    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    for (profile, validity_period) in [("shortlived", 10), ("default", 20)] {
        let chain = acquire_ip_cert(&[ip], Some(profile))
            .await
            .unwrap_or_else(|e| panic!("order with profile {profile} failed: {e}"));
        assert_eq!(
            lifetime_secs(&chain[0]),
            validity_period - 1,
            "lifetime for profile {profile}"
        );
    }
}

/// Requesting a profile the CA doesn't offer fails the order.
///
/// Pebble rejects the order before it validates anything, so the test does not listen.
#[tokio::test]
#[ignore]
async fn test_unknown_profile_is_rejected() {
    let _ = simple_logger::init_with_level(log::Level::Info);

    let config = pebble_config(&["127.0.0.1"]).profile("no-such-profile");
    let mut site = Site::bind(config, &[]).await;
    let err = site
        .deploy()
        .await
        .expect_err("order with an unknown profile should fail")
        .to_string();
    assert!(
        err.contains("invalidProfile"),
        "expected an invalidProfile error, got: {err}"
    );
}
