//! Integration tests against a Pebble ACME test server that validates challenges.
//!
//! Each test starts its own Pebble and `challtestsrv` on free ports, see [`server`], so the tests
//! can run in parallel, also with other runs of them.
//!
//! Install the Pebble binaries with `cargo make pebble-install`, then run the tests with
//! `cargo test --test pebble -- --ignored`, or both with `cargo make test-pebble`.

mod server;

use std::{
    collections::BTreeSet,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use n0_future::StreamExt;
use rustls::{
    ClientConfig, DEFAULT_VERSIONS, ServerConfig,
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
    caches::DirCache,
};
use x509_parser::extensions::GeneralName;

use crate::server::Pebble;

/// The address that Pebble's validation authority resolves every name to.
const LOCALHOST: Ipv4Addr = Ipv4Addr::LOCALHOST;
const ORDER_TIMEOUT: Duration = Duration::from_secs(30);

/// Returns a fresh ring crypto provider. The pebble tests pin themselves to
/// ring (via the dev-dependency) regardless of which crate features are on,
/// so they never depend on the process-wide default provider.
fn test_crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// An ACME state machine whose own [`AcmeAcceptor`] answers Pebble's tls-alpn-01 validation.
struct Site {
    state: AcmeState<io::Error>,
    server: JoinSet<()>,
}

impl Site {
    /// Starts the state machine and serves its acceptor on the tls-alpn-01 listener of `pebble`.
    fn start(config: AcmeConfig<io::Error>, pebble: &Pebble) -> Self {
        let state = config.state();
        let acceptor = state.acceptor();
        let server_config = Arc::new(
            ServerConfig::builder_with_provider(state.crypto_provider())
                .with_protocol_versions(DEFAULT_VERSIONS)
                .expect("provider should support the default protocol versions")
                .with_no_client_auth()
                .with_cert_resolver(state.resolver()),
        );
        let mut server = JoinSet::new();
        for listener in pebble.tls_alpn_listeners() {
            server.spawn(serve(listener, acceptor.clone(), server_config.clone()));
        }
        Self { state, server }
    }

    /// Polls the state machine until it deploys a new certificate or an order fails.
    ///
    /// # Panics
    ///
    /// Panics on other errors and after [`ORDER_TIMEOUT`].
    #[allow(
        clippy::result_large_err,
        reason = "the crate returns `OrderError` by value in its events too"
    )]
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

    /// Closes the listener and waits until its port is free.
    async fn close(mut self) {
        self.server.shutdown().await;
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

/// Connects to the tls-alpn-01 port of `pebble` on `addr`, and returns the verified chain served
/// for `name`.
async fn fetch_chain(
    pebble: &Pebble,
    addr: IpAddr,
    name: ServerName<'static>,
) -> Vec<CertificateDer<'static>> {
    let connector = TlsConnector::from(Arc::new(
        ClientConfig::builder_with_provider(test_crypto_provider())
            .with_protocol_versions(DEFAULT_VERSIONS)
            .expect("provider should support the default protocol versions")
            .with_root_certificates(pebble.acme_root_store().await)
            .with_no_client_auth(),
    ));
    let port = pebble.tls_alpn_port();
    let tcp = TcpStream::connect((addr, port))
        .await
        .unwrap_or_else(|e| panic!("failed to connect to {addr} on port {port}: {e}"));
    let tls = connector
        .connect(name.clone(), tcp)
        .await
        .unwrap_or_else(|e| panic!("TLS handshake as {name:?} failed: {e}"));
    let chain = tls
        .get_ref()
        .1
        .peer_certificates()
        .expect("no peer certificates");
    assert!(!chain.is_empty(), "should have received certificates");
    chain.to_vec()
}

/// Like [`fetch_chain`], with `domain` as server name on the address it resolves to.
async fn fetch_chain_for(pebble: &Pebble, domain: &str) -> Vec<CertificateDer<'static>> {
    let name = ServerName::try_from(domain.to_owned()).expect("invalid domain");
    fetch_chain(pebble, LOCALHOST.into(), name).await
}

/// Asserts that `chain` verifies for `domain` against Pebble's roots only with its intermediates.
async fn assert_needs_intermediates(
    pebble: &Pebble,
    chain: &[CertificateDer<'static>],
    domain: &str,
) {
    let roots = Arc::new(pebble.acme_root_store().await);
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
async fn acquire_cert_with_cache<C>(pebble: &Pebble, domain: &str, cache: C) -> (Site, AcmeEvents)
where
    C: CertCache<EC = io::Error> + AccountCache<EA = io::Error> + Send + Sync + 'static,
{
    let config = pebble.config(&[domain]).cache(cache);
    let mut site = Site::start(config, pebble);
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

    let pebble = Pebble::start().await;
    let domain = "default-chain.example.com";

    let mut site = Site::start(pebble.config(&[domain]), &pebble);
    site.deploy().await.expect("order failed");

    let peer_certs = fetch_chain_for(&pebble, domain).await;
    eprintln!("default chain: received {} certificates", peer_certs.len());
    assert_needs_intermediates(&pebble, &peer_certs, domain).await;
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

    let pebble = Pebble::start().await;
    let domain = "dir-cache.example.com";
    let cache_dir = tempfile::tempdir().unwrap();
    let cache_path: PathBuf = cache_dir.path().into();

    // First run: fresh order, should store to cache.
    let (site, events) =
        acquire_cert_with_cache(&pebble, domain, DirCache::new(cache_path.clone())).await;
    assert!(events.deployed_new, "first run should deploy a new cert");
    assert!(
        events.cert_cache_store,
        "first run should store cert to cache"
    );

    // Verify the cert works.
    fetch_chain_for(&pebble, domain).await;
    site.close().await;

    // Second run: same cache dir, should load from cache without ordering.
    let (_site, events2) =
        acquire_cert_with_cache(&pebble, domain, DirCache::new(cache_path)).await;
    assert!(
        events2.deployed_cached,
        "second run should deploy cached cert"
    );
    assert!(
        !events2.deployed_new,
        "second run should not issue a new cert"
    );

    // Verify the cached cert also works.
    fetch_chain_for(&pebble, domain).await;
}

/// A cached cert that cannot be parsed triggers re-issuance with the cached account key.
#[tokio::test]
#[ignore]
async fn test_corrupted_cache_reissues_with_cached_account() {
    let _ = tracing_subscriber::fmt::try_init();

    let pebble = Pebble::start().await;
    let domain = "corrupted-cache.example.com";
    let cache_dir = tempfile::tempdir().expect("failed to create temp dir");
    let cache_path: PathBuf = cache_dir.path().into();

    let (site, events) =
        acquire_cert_with_cache(&pebble, domain, DirCache::new(cache_path.clone())).await;
    assert!(
        events.deployed_new && events.account_cache_store,
        "first run should issue a cert and store the account, got {events:?}"
    );
    site.close().await;

    let account_file = cache_file(&cache_path, "cached_account_");
    let account_key = std::fs::read(&account_file).expect("failed to read cached account");
    std::fs::write(cache_file(&cache_path, "cached_cert_"), b"not a valid PEM")
        .expect("failed to corrupt cached cert");

    let (_site, events) = acquire_cert_with_cache(&pebble, domain, DirCache::new(cache_path)).await;
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
    fetch_chain_for(&pebble, domain).await;
}

/// Verify that the state machine automatically renews an expiring certificate.
///
/// Pebble picks a random profile, so every profile in [`server`] must keep the validity short
/// enough to renew within [`ORDER_TIMEOUT`].
#[tokio::test]
#[ignore]
async fn test_automatic_renewal() {
    let _ = tracing_subscriber::fmt::try_init();

    let pebble = Pebble::start().await;
    let domain = "renewal.example.com";

    let mut site = Site::start(pebble.config(&[domain]), &pebble);
    site.deploy().await.expect("initial order failed");
    site.deploy().await.expect("renewal order failed");

    fetch_chain_for(&pebble, domain).await;
}

/// Issue a certificate with multiple SAN domains and verify all are present.
#[tokio::test]
#[ignore]
async fn test_multi_domain_san() {
    let _ = tracing_subscriber::fmt::try_init();

    let pebble = Pebble::start().await;
    let domains = [
        "multi-1.example.com",
        "multi-2.example.com",
        "multi-3.example.com",
    ];

    let mut site = Site::start(pebble.config(&domains), &pebble);
    site.deploy().await.expect("order failed");

    for domain in domains {
        let peer_certs = fetch_chain_for(&pebble, domain).await;

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

        for name in domains {
            assert!(
                sans.contains(&name.to_string()),
                "SAN should contain {}, got: {:?}",
                name,
                sans
            );
        }
        eprintln!("multi-domain SANs served for {domain}: {sans:?}");
    }
}

/// Collects the IP address SANs of a DER certificate, sorted.
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
            GeneralName::IPAddress(bytes) => match bytes.len() {
                4 => Some(IpAddr::from(<[u8; 4]>::try_from(*bytes).unwrap())),
                16 => Some(IpAddr::from(<[u8; 16]>::try_from(*bytes).unwrap())),
                n => panic!("IP SAN with {n} bytes"),
            },
            _ => None,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Orders a certificate for the IP addresses `ips`, with `profile` if set.
///
/// Starts its own Pebble, and after deployment connects to each address of `ips` with the address
/// as server name. Returns the chain served on the first address, or the error of the order.
#[allow(
    clippy::result_large_err,
    reason = "the crate returns `OrderError` by value in its events too"
)]
async fn acquire_ip_cert(
    ips: &[IpAddr],
    profile: Option<&str>,
) -> Result<Vec<CertificateDer<'static>>, OrderError> {
    let pebble = Pebble::start().await;
    assert!(
        ips.iter().all(IpAddr::is_ipv4) || pebble.serves_ipv6(),
        "the test needs IPv6 on ::1"
    );
    let identifiers: Vec<String> = ips.iter().map(IpAddr::to_string).collect();
    let identifiers: Vec<&str> = identifiers.iter().map(String::as_str).collect();
    let mut config = pebble.config(&identifiers);
    if let Some(profile) = profile {
        config = config.profile(profile);
    }
    let mut site = Site::start(config, &pebble);
    let result = site.deploy().await;
    let mut chains = Vec::new();
    if result.is_ok() {
        for &ip in ips {
            chains.push(fetch_chain(&pebble, ip, ServerName::from(ip)).await);
        }
    }
    site.close().await;
    result.map(|()| chains.swap_remove(0))
}

/// Issues a certificate for an IPv4 address through real tls-alpn-01 validation.
///
/// The CA sends the reverse-DNS name `1.0.0.127.in-addr.arpa` as SNI (RFC 8738 section 6), so
/// this fails unless the resolver serves the challenge certificate under that name.
#[tokio::test]
#[ignore]
async fn test_validated_ipv4_certificate() {
    let _ = tracing_subscriber::fmt::try_init();

    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let chain = acquire_ip_cert(&[ip], None).await.expect("order failed");
    assert_eq!(ip_sans(&chain[0]), [ip]);
}

/// Issues a certificate for an IPv6 address through real tls-alpn-01 validation.
///
/// The CA sends the nibble-format reverse name under `ip6.arpa` as SNI.
#[tokio::test]
#[ignore]
async fn test_validated_ipv6_certificate() {
    let _ = tracing_subscriber::fmt::try_init();

    let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let chain = acquire_ip_cert(&[ip], None).await.expect("order failed");
    assert_eq!(ip_sans(&chain[0]), [ip]);
}

/// Issues one certificate for both an IPv4 and an IPv6 address.
#[tokio::test]
#[ignore]
async fn test_validated_dual_stack_certificate() {
    let _ = tracing_subscriber::fmt::try_init();

    let ips = [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ];
    let chain = acquire_ip_cert(&ips, None).await.expect("order failed");
    assert_eq!(ip_sans(&chain[0]), ips);
}

/// Issues one certificate for an IP address and a domain.
///
/// Pebble validates both on `127.0.0.1`: the IP identifier with its reverse-DNS name as SNI, and
/// the domain, which `challtestsrv` resolves there, with the domain as SNI.
#[tokio::test]
#[ignore]
async fn test_validated_mixed_ip_and_domain_certificate() {
    let _ = tracing_subscriber::fmt::try_init();

    let pebble = Pebble::start().await;
    let ip = IpAddr::V4(LOCALHOST);
    let domain = "mixed.example.com";
    let ip_identifier = ip.to_string();
    let mut site = Site::start(pebble.config(&[&ip_identifier, domain]), &pebble);
    site.deploy().await.expect("order failed");

    let chain = fetch_chain(&pebble, ip, ServerName::from(ip)).await;
    fetch_chain_for(&pebble, domain).await;
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
        .any(|name| matches!(name, GeneralName::DNSName(d) if *d == domain));
    assert!(has_dns, "certificate should contain a DNS SAN for {domain}");
}

/// Returns the lifetime of a DER certificate (`notAfter - notBefore`) in seconds.
fn lifetime_secs(cert: &CertificateDer<'_>) -> i64 {
    let (_, cert) = x509_parser::parse_x509_certificate(cert.as_ref()).unwrap();
    let validity = cert.validity();
    validity.not_after.timestamp() - validity.not_before.timestamp()
}

/// Requests certificates under specific ACME profiles and checks that the CA applied them.
///
/// The harness gives the profiles distinct validity periods, see [`server`]. Pebble issues
/// certificates valid for `validityPeriod - 1` seconds.
#[tokio::test]
#[ignore]
async fn test_profile_selects_lifetime() {
    let _ = tracing_subscriber::fmt::try_init();

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

/// Checks that the CA rejects an order for a profile it doesn't offer.
///
/// Pebble rejects the order before it validates anything. The identifier is a documentation
/// address, so a regression that validates hits no listener.
#[tokio::test]
#[ignore]
async fn test_unknown_profile_is_rejected() {
    let _ = tracing_subscriber::fmt::try_init();

    let pebble = Pebble::start().await;
    let config = pebble.config(&["192.0.2.1"]).profile("no-such-profile");
    let mut site = Site::start(config, &pebble);
    let err = site
        .deploy()
        .await
        .expect_err("order with an unknown profile should fail");
    assert!(
        matches!(err, OrderError::Acme(_)) && err.to_string().contains("invalidProfile"),
        "expected Pebble's invalidProfile error, got {err:?}"
    );
}
