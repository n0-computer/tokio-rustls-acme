//! Integration tests against Pebble ACME test servers.
//!
//! These tests require two running Pebble instances, see `docker-compose.pebble.yml`:
//! - `pebble` (port 14000) runs with `PEBBLE_VA_ALWAYS_VALID=1`, so challenges are never checked.
//! - `pebble-validating` (port 14001) validates challenges for real. Its VA connects to
//!   tls-alpn-01 port 5001 on the identifier's address, so the tests using it serve challenges
//!   from a listener on `127.0.0.1:5001` and `[::1]:5001`. That requires the instance to share
//!   the host's network namespace.
//!
//! Start them with: `docker compose -f docker-compose.pebble.yml up -d`
//!
//! Set `PEBBLE_MINICA_CERT` to the path of Pebble's minica root cert (the same for both):
//!   `docker compose -f docker-compose.pebble.yml cp pebble:/test/certs/pebble.minica.pem ./pebble.minica.pem`
//!   `export PEBBLE_MINICA_CERT=./pebble.minica.pem`
//!
//! Run with: `cargo test --test pebble -- --ignored`, or all of the above with `cargo make test`.

use std::{
    convert::TryFrom,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use futures::StreamExt;
use rustls::{
    ClientConfig, DEFAULT_VERSIONS, RootCertStore, ServerConfig,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName},
};
use tokio::{net::TcpListener, task::JoinSet};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_rustls_acme::{
    AccountCache, AcmeConfig, CertCache, EventError, EventOk, ResolvesServerCertAcme,
    caches::{DirCache, NoCache},
};

const PEBBLE_DIRECTORY: &str = "https://localhost:14000/dir";
const PEBBLE_MGMT: &str = "https://localhost:15000";
const VALIDATING_DIRECTORY: &str = "https://localhost:14001/dir";
const VALIDATING_MGMT: &str = "https://localhost:15001";
/// `tlsPort` of the validating instance: where its VA connects for tls-alpn-01.
const VALIDATING_TLS_PORT: u16 = 5001;
const TEST_DOMAIN: &str = "pebble-test.example.com";
const TEST_DOMAINS: &[&str] = &[
    "pebble-multi-1.example.com",
    "pebble-multi-2.example.com",
    "pebble-multi-3.example.com",
];

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

/// Fetch Pebble's ACME-issued root + intermediate certs and build a root store
/// for verifying certs issued by Pebble's CA.
async fn pebble_acme_root_store() -> RootCertStore {
    pebble_acme_root_store_at(PEBBLE_MGMT).await
}

/// Like [`pebble_acme_root_store`], for the instance with management API at `mgmt`.
async fn pebble_acme_root_store_at(mgmt: &str) -> RootCertStore {
    let client = http_client();
    let mut root_store = RootCertStore::empty();

    // Fetch up to 2 roots and intermediates (index 1 only exists when
    // PEBBLE_ALTERNATE_ROOTS is enabled). 404s are expected and skipped.
    for kind in &["roots", "intermediates"] {
        for index in 0..2 {
            let url = format!("{mgmt}/{kind}/{index}");
            let resp = client.get(&url).send().await.unwrap_or_else(|e| {
                panic!("failed to reach Pebble management API at {}: {}", url, e)
            });
            if resp.status().is_success() {
                let pem_text = resp.text().await.unwrap();
                for p in pem::parse_many(&pem_text).unwrap() {
                    let der = CertificateDer::from(p.into_contents());
                    let _ = root_store.add(der);
                }
            }
        }
    }

    assert!(
        !root_store.is_empty(),
        "failed to fetch any roots from Pebble management API"
    );
    root_store
}

/// Collected events from a single ACME state machine run.
#[derive(Default, Debug)]
struct AcmeEvents {
    deployed_cached: bool,
    deployed_new: bool,
    cert_cache_store: bool,
    account_cache_store: bool,
}

/// Run the ACME state machine until a certificate is deployed, collecting events.
async fn acquire_cert_with_cache<C>(
    client_config: Arc<ClientConfig>,
    cache: C,
) -> (Arc<ResolvesServerCertAcme>, AcmeEvents)
where
    C: CertCache<EC = io::Error> + AccountCache<EA = io::Error> + Send + Sync + 'static,
{
    let config: AcmeConfig<io::Error> =
        AcmeConfig::new_with_client_tls_config([TEST_DOMAIN], client_config)
            .directory(PEBBLE_DIRECTORY)
            .cache(cache);

    let mut state = config.state();
    let resolver = state.resolver();
    let mut events = AcmeEvents::default();

    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match state.next().await {
                Some(Ok(EventOk::DeployedCachedCert)) => {
                    eprintln!("event: DeployedCachedCert");
                    events.deployed_cached = true;
                    return;
                }
                Some(Ok(EventOk::DeployedNewCert)) => {
                    eprintln!("event: DeployedNewCert");
                    events.deployed_new = true;
                    // Continue to collect the CertCacheStore event that follows.
                    // Event ordering: AccountCacheStore → DeployedNewCert → CertCacheStore.
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
                Some(Err(err)) => panic!("ACME error: {:?}", err),
                None => panic!("state stream ended unexpectedly"),
            }
        }
    })
    .await
    .expect("timed out waiting for certificate deployment");

    (resolver, events)
}

/// Run the ACME state machine with NoCache until a certificate is deployed.
async fn acquire_cert(client_config: Arc<ClientConfig>) -> Arc<ResolvesServerCertAcme> {
    let (resolver, _) = acquire_cert_with_cache(client_config, NoCache::new()).await;
    resolver
}

/// Do an in-process TLS handshake using the resolver and verify it succeeds.
async fn verify_tls_handshake(
    resolver: Arc<ResolvesServerCertAcme>,
    root_store: RootCertStore,
) -> Vec<CertificateDer<'static>> {
    verify_tls_handshake_for(resolver, root_store, TEST_DOMAIN).await
}

/// Do an in-process TLS handshake against a specific domain name.
async fn verify_tls_handshake_for(
    resolver: Arc<ResolvesServerCertAcme>,
    root_store: RootCertStore,
    domain: &str,
) -> Vec<CertificateDer<'static>> {
    let server_config = Arc::new(
        ServerConfig::builder_with_provider(test_crypto_provider())
            .with_protocol_versions(DEFAULT_VERSIONS)
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(resolver),
    );
    let acceptor = TlsAcceptor::from(server_config);

    let client_config = Arc::new(
        ClientConfig::builder_with_provider(test_crypto_provider())
            .with_protocol_versions(DEFAULT_VERSIONS)
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );
    let connector = tokio_rustls::TlsConnector::from(client_config);

    let (client_io, server_io) = tokio::io::duplex(4096);
    let server_name = ServerName::try_from(domain).unwrap().to_owned();

    let (client_result, server_result) = tokio::join!(
        connector.connect(server_name, client_io),
        acceptor.accept(server_io),
    );

    let _ = server_result.expect("TLS server handshake failed");
    let client_tls = client_result.expect("TLS client handshake failed");
    let (_, conn) = client_tls.get_ref();
    conn.peer_certificates()
        .expect("no peer certificates")
        .to_vec()
}

/// Obtain a cert with the default chain and verify it can serve TLS.
///
/// This is the baseline test: a fresh ACME order with no cache and no chain
/// preference should produce a valid certificate that passes a TLS handshake.
#[tokio::test]
#[ignore]
async fn test_default_chain() {
    let _ = simple_logger::init_with_level(log::Level::Info);

    let client_config = pebble_client_config();
    let resolver = acquire_cert(client_config).await;

    let root_store = pebble_acme_root_store().await;
    let peer_certs = verify_tls_handshake(resolver, root_store).await;
    assert!(!peer_certs.is_empty(), "should have received certificates");
    eprintln!("default chain: received {} certificates", peer_certs.len());
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

    let cache_dir = tempfile::tempdir().unwrap();
    let cache_path: PathBuf = cache_dir.path().into();

    // First run: fresh order, should store to cache.
    let client_config = pebble_client_config();
    let (resolver, events) =
        acquire_cert_with_cache(client_config.clone(), DirCache::new(cache_path.clone())).await;
    assert!(events.deployed_new, "first run should deploy a new cert");
    assert!(
        events.cert_cache_store,
        "first run should store cert to cache"
    );

    // Verify the cert works.
    let root_store = pebble_acme_root_store().await;
    let peer_certs = verify_tls_handshake(resolver, root_store).await;
    assert!(!peer_certs.is_empty());

    // Second run: same cache dir, should load from cache without ordering.
    let (resolver2, events2) =
        acquire_cert_with_cache(client_config, DirCache::new(cache_path)).await;
    assert!(
        events2.deployed_cached,
        "second run should deploy cached cert"
    );
    assert!(
        !events2.deployed_new,
        "second run should not issue a new cert"
    );

    // Verify the cached cert also works.
    let root_store = pebble_acme_root_store().await;
    let peer_certs = verify_tls_handshake(resolver2, root_store).await;
    assert!(!peer_certs.is_empty());
}

/// Verify that the account key is cached and reused across runs.
///
/// Without account caching, every run generates a new ACME account. With
/// DirCache, the account key should be stored on first run and loaded on
/// subsequent runs, avoiding unnecessary account registrations.
#[tokio::test]
#[ignore]
async fn test_account_cache_reuse() {
    let _ = simple_logger::init_with_level(log::Level::Info);

    let cache_dir = tempfile::tempdir().unwrap();
    let cache_path: PathBuf = cache_dir.path().into();

    // First run: registers a new account, stores it.
    let client_config = pebble_client_config();
    let (_, events) =
        acquire_cert_with_cache(client_config.clone(), DirCache::new(cache_path.clone())).await;
    assert!(
        events.account_cache_store,
        "first run should store account to cache"
    );

    // Check that account file was written.
    let entries: Vec<_> = std::fs::read_dir(&cache_path)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("cached_account_"))
        })
        .collect();
    assert_eq!(entries.len(), 1, "should have exactly one cached account");

    // Second run: should load the cached account (no AccountCacheStore event).
    let (_, events2) = acquire_cert_with_cache(client_config, DirCache::new(cache_path)).await;
    assert!(
        !events2.account_cache_store,
        "second run should load cached account, not store a new one"
    );
}

/// Verify that a corrupted cache file triggers re-issuance instead of crashing.
///
/// If a cached cert PEM is truncated or invalid, the state machine should
/// emit a CachedCertParse error but recover by placing a new ACME order,
/// ultimately deploying a fresh certificate.
#[tokio::test]
#[ignore]
async fn test_corrupted_cache_triggers_reissue() {
    let _ = simple_logger::init_with_level(log::Level::Info);

    let cache_dir = tempfile::tempdir().unwrap();
    let cache_path: PathBuf = cache_dir.path().into();

    // First run: obtain and cache a valid cert.
    let client_config = pebble_client_config();
    let (_, events) =
        acquire_cert_with_cache(client_config.clone(), DirCache::new(cache_path.clone())).await;
    assert!(events.deployed_new);

    // Corrupt the cached cert file.
    let cert_file = std::fs::read_dir(&cache_path)
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("cached_cert_"))
        })
        .expect("should have a cached cert file");
    std::fs::write(cert_file.path(), b"not a valid PEM").unwrap();

    // Second run: should detect corruption, fall back to new order.
    let config: AcmeConfig<io::Error> =
        AcmeConfig::new_with_client_tls_config([TEST_DOMAIN], client_config)
            .directory(PEBBLE_DIRECTORY)
            .cache(DirCache::new(cache_path));

    let mut state = config.state();
    let resolver = state.resolver();

    let mut saw_parse_error = false;
    let mut deployed_new = false;

    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match state.next().await {
                Some(Ok(EventOk::DeployedNewCert)) => {
                    deployed_new = true;
                }
                Some(Ok(EventOk::CertCacheStore)) => {
                    return;
                }
                Some(Ok(_)) => {}
                Some(Err(err)) => {
                    let msg = format!("{:?}", err);
                    if msg.contains("CachedCertParse") {
                        eprintln!("got expected CachedCertParse error");
                        saw_parse_error = true;
                    } else {
                        panic!("unexpected ACME error: {:?}", err);
                    }
                }
                None => panic!("state stream ended unexpectedly"),
            }
        }
    })
    .await
    .expect("timed out waiting for recovery from corrupted cache");

    assert!(
        saw_parse_error,
        "should have seen CachedCertParse error for corrupted file"
    );
    assert!(deployed_new, "should have recovered by issuing a new cert");

    // Verify the fresh cert works.
    let root_store = pebble_acme_root_store().await;
    let peer_certs = verify_tls_handshake(resolver, root_store).await;
    assert!(!peer_certs.is_empty());
}

/// Verify that the state machine automatically renews an expiring certificate.
///
/// Pebble is configured with a 10-second certificate validity period. The
/// renewal timer fires at 2/3 of the validity window (~6.7s), so within
/// about 10 seconds the state machine should issue a second certificate
/// without any external prompting.
#[tokio::test]
#[ignore]
async fn test_automatic_renewal() {
    let _ = simple_logger::init_with_level(log::Level::Info);

    let cache_dir = tempfile::tempdir().unwrap();
    let client_config = pebble_client_config();
    let config: AcmeConfig<io::Error> =
        AcmeConfig::new_with_client_tls_config([TEST_DOMAIN], client_config)
            .directory(PEBBLE_DIRECTORY)
            .cache(DirCache::new(cache_dir.path().to_path_buf()));

    let mut state = config.state();
    let resolver = state.resolver();

    let mut deploy_count = 0u32;

    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match state.next().await {
                Some(Ok(EventOk::DeployedNewCert)) => {
                    deploy_count += 1;
                    eprintln!("deployed new cert #{deploy_count}");
                    if deploy_count >= 2 {
                        return;
                    }
                }
                Some(Ok(event)) => eprintln!("event: {event:?}"),
                Some(Err(err)) => {
                    eprintln!("ACME error (continuing): {:?}", err);
                }
                None => panic!("state stream ended unexpectedly"),
            }
        }
    })
    .await
    .expect("timed out waiting for automatic renewal");

    assert!(
        deploy_count >= 2,
        "should have deployed at least 2 certs (initial + renewal), got {}",
        deploy_count
    );

    // Verify the renewed cert works.
    let root_store = pebble_acme_root_store().await;
    let peer_certs = verify_tls_handshake(resolver, root_store).await;
    assert!(!peer_certs.is_empty());
}

/// Issue a certificate with multiple SAN domains and verify all are present.
///
/// Exercises the multi-domain code path in `new_order`, where the order
/// contains multiple identifiers. The resulting certificate should list
/// all requested domains as Subject Alternative Names.
#[tokio::test]
#[ignore]
async fn test_multi_domain_san() {
    let _ = simple_logger::init_with_level(log::Level::Info);

    let client_config = pebble_client_config();
    let config: AcmeConfig<io::Error> =
        AcmeConfig::new_with_client_tls_config(TEST_DOMAINS, client_config)
            .directory(PEBBLE_DIRECTORY)
            .cache(NoCache::new());

    let mut state = config.state();
    let resolver = state.resolver();

    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match state.next().await {
                Some(Ok(EventOk::DeployedNewCert)) => return,
                Some(Ok(_)) => {}
                Some(Err(err)) => panic!("ACME error: {:?}", err),
                None => panic!("state stream ended unexpectedly"),
            }
        }
    })
    .await
    .expect("timed out waiting for multi-domain cert");

    let root_store = pebble_acme_root_store().await;
    let peer_certs = verify_tls_handshake_for(resolver, root_store, TEST_DOMAINS[0]).await;
    assert!(!peer_certs.is_empty());

    // Parse the leaf certificate and check SANs.
    let leaf_der = &peer_certs[0];
    let (_, leaf) = x509_parser::parse_x509_certificate(leaf_der.as_ref()).unwrap();
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

    for domain in TEST_DOMAINS {
        assert!(
            sans.contains(&domain.to_string()),
            "SAN should contain {}, got: {:?}",
            domain,
            sans
        );
    }
    eprintln!("multi-domain SANs: {sans:?}");
}

const TEST_IP: &str = "10.30.50.1";

/// Helper: run ACME state machine for given identifiers until cert is deployed.
async fn acquire_cert_for(
    client_config: Arc<ClientConfig>,
    identifiers: &[&str],
) -> Arc<ResolvesServerCertAcme> {
    let config: AcmeConfig<io::Error> =
        AcmeConfig::new_with_client_tls_config(identifiers, client_config)
            .directory(PEBBLE_DIRECTORY)
            .cache(NoCache::new());

    let mut state = config.state();
    let resolver = state.resolver();

    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match state.next().await {
                Some(Ok(EventOk::DeployedNewCert)) => return,
                Some(Ok(_)) => {}
                Some(Err(err)) => panic!("ACME error: {:?}", err),
                None => panic!("state stream ended unexpectedly"),
            }
        }
    })
    .await
    .expect("timed out waiting for certificate deployment");

    resolver
}

/// Do an in-process TLS handshake using an IP address as the server name.
async fn verify_tls_handshake_ip(
    resolver: Arc<ResolvesServerCertAcme>,
    root_store: RootCertStore,
    ip: IpAddr,
) -> Vec<CertificateDer<'static>> {
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver),
    );
    let acceptor = TlsAcceptor::from(server_config);

    let client_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );
    let connector = tokio_rustls::TlsConnector::from(client_config);

    let (client_io, server_io) = tokio::io::duplex(4096);
    let server_name = ServerName::from(ip);

    let (client_result, server_result) = tokio::join!(
        connector.connect(server_name, client_io),
        acceptor.accept(server_io),
    );

    let _ = server_result.expect("TLS server handshake failed");
    let client_tls = client_result.expect("TLS client handshake failed");
    let (_, conn) = client_tls.get_ref();
    conn.peer_certificates()
        .expect("no peer certificates")
        .to_vec()
}

/// Issue a certificate for an IP address and verify TLS works with an IP SAN.
#[tokio::test]
#[ignore]
async fn test_ip_certificate() {
    let _ = simple_logger::init_with_level(log::Level::Info);

    let client_config = pebble_client_config();
    let resolver = acquire_cert_for(client_config, &[TEST_IP]).await;

    let root_store = pebble_acme_root_store().await;
    let ip: IpAddr = TEST_IP.parse().unwrap();
    let peer_certs = verify_tls_handshake_ip(resolver, root_store, ip).await;
    assert!(!peer_certs.is_empty(), "should have received certificates");

    // Verify the leaf certificate contains exactly the requested IP SAN.
    assert_eq!(ip_sans(&peer_certs[0]), [ip]);
    eprintln!("IP certificate issued successfully for {TEST_IP}");
}

/// Issue a certificate with both IP and DNS identifiers in a single order.
#[tokio::test]
#[ignore]
async fn test_mixed_ip_and_domain() {
    let _ = simple_logger::init_with_level(log::Level::Info);

    let mixed_ip = "10.30.50.2";
    let mixed_domain = "mixed.example.com";

    let client_config = pebble_client_config();
    let resolver = acquire_cert_for(client_config, &[mixed_ip, mixed_domain]).await;

    let root_store = pebble_acme_root_store().await;

    // Verify TLS handshake using the IP address.
    let ip: IpAddr = mixed_ip.parse().unwrap();
    let peer_certs = verify_tls_handshake_ip(resolver.clone(), root_store, ip).await;
    assert!(!peer_certs.is_empty());

    // Verify TLS handshake using the domain name.
    let root_store = pebble_acme_root_store().await;
    let peer_certs = verify_tls_handshake_for(resolver, root_store, mixed_domain).await;
    assert!(!peer_certs.is_empty());

    // Parse leaf and check both SANs are present.
    let (_, leaf) = x509_parser::parse_x509_certificate(peer_certs[0].as_ref()).unwrap();
    let san = leaf
        .subject_alternative_name()
        .expect("SAN extension missing")
        .expect("SAN extension empty");

    let has_dns = san.value.general_names.iter().any(|name| {
        matches!(name, x509_parser::extensions::GeneralName::DNSName(d) if *d == mixed_domain)
    });
    assert_eq!(ip_sans(&peer_certs[0]), [ip]);
    assert!(
        has_dns,
        "certificate should contain a DNS SAN for {}",
        mixed_domain
    );
    eprintln!("mixed IP+domain certificate issued successfully");
}

/// Collect the IP address SANs of a DER certificate.
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

/// Serializes the tests using the validating instance: they all listen on its `tlsPort`.
static VALIDATING_TLS_PORT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Order a certificate for `ips` from the validating Pebble instance, answering its
/// tls-alpn-01 challenges from a real listener, then fetch the deployed certificate chain over
/// TCP from each IP.
///
/// Returns the order error if the order fails, and the chain served on the first IP otherwise.
async fn acquire_validated_cert(
    ips: &[IpAddr],
    profile: Option<&str>,
) -> Result<Vec<CertificateDer<'static>>, String> {
    let _guard = VALIDATING_TLS_PORT_LOCK.lock().await;

    let identifiers: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
    let mut config: AcmeConfig<io::Error> =
        AcmeConfig::new_with_client_tls_config(&identifiers, pebble_client_config())
            .directory(VALIDATING_DIRECTORY)
            .cache(NoCache::new());
    if let Some(profile) = profile {
        config = config.profile(profile);
    }
    let mut state = config.state();

    // Serve on both loopback addresses: Pebble's VA connects to the identifier's address.
    let acceptor = state.acceptor();
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(state.resolver()),
    );
    let mut servers = JoinSet::new();
    for addr in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        let listener = TcpListener::bind((addr, VALIDATING_TLS_PORT))
            .await
            .unwrap_or_else(|e| panic!("failed to bind {addr}:{VALIDATING_TLS_PORT}: {e}"));
        let acceptor = acceptor.clone();
        let server_config = server_config.clone();
        servers.spawn(async move {
            loop {
                let (tcp, peer) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                let server_config = server_config.clone();
                tokio::spawn(async move {
                    match acceptor.accept(tcp).await {
                        Ok(None) => eprintln!("served tls-alpn-01 challenge to {peer}"),
                        Ok(Some(start)) => {
                            let _ = start.into_stream(server_config).await;
                        }
                        Err(err) => eprintln!("TLS accept from {peer} failed: {err}"),
                    }
                });
            }
        });
    }

    let result = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            match state.next().await {
                Some(Ok(EventOk::DeployedNewCert)) => return Ok(()),
                Some(Ok(_)) => {}
                Some(Err(EventError::Order(err))) => return Err(err.to_string()),
                Some(Err(err)) => panic!("ACME error: {:?}", err),
                None => panic!("state stream ended unexpectedly"),
            }
        }
    })
    .await
    .expect("timed out waiting for certificate deployment");

    let chain = match result {
        Ok(()) => {
            let root_store = pebble_acme_root_store_at(VALIDATING_MGMT).await;
            let connector = TlsConnector::from(Arc::new(
                ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth(),
            ));
            let mut chains = Vec::new();
            for &ip in ips {
                let tcp = tokio::net::TcpStream::connect((ip, VALIDATING_TLS_PORT))
                    .await
                    .unwrap();
                let tls = connector
                    .connect(ServerName::from(ip), tcp)
                    .await
                    .unwrap_or_else(|e| panic!("TLS handshake with {ip} failed: {e}"));
                chains.push(tls.get_ref().1.peer_certificates().unwrap().to_vec());
            }
            Ok(chains.swap_remove(0))
        }
        Err(err) => Err(err),
    };
    servers.shutdown().await;
    chain
}

/// Issue a certificate for an IPv4 address through real tls-alpn-01 validation.
///
/// The CA sends the reverse-DNS name `1.0.0.127.in-addr.arpa` as SNI (RFC 8738 §6), so this
/// fails unless the resolver serves the challenge certificate under that name.
#[tokio::test]
#[ignore]
async fn test_validated_ipv4_certificate() {
    let _ = simple_logger::init_with_level(log::Level::Info);

    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let chain = acquire_validated_cert(&[ip], None)
        .await
        .expect("order failed");
    assert_eq!(ip_sans(&chain[0]), [ip]);
}

/// Issue a certificate for an IPv6 address through real tls-alpn-01 validation, with the
/// nibble-format reverse name under `ip6.arpa` as SNI.
#[tokio::test]
#[ignore]
async fn test_validated_ipv6_certificate() {
    let _ = simple_logger::init_with_level(log::Level::Info);

    let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let chain = acquire_validated_cert(&[ip], None)
        .await
        .expect("order failed");
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
    let chain = acquire_validated_cert(&ips, None)
        .await
        .expect("order failed");
    assert_eq!(ip_sans(&chain[0]), ips);
}

/// Lifetime of a DER certificate (`notAfter - notBefore`) in seconds.
fn lifetime_secs(cert: &CertificateDer<'_>) -> i64 {
    let (_, cert) = x509_parser::parse_x509_certificate(cert.as_ref()).unwrap();
    let validity = cert.validity();
    validity.not_after.timestamp() - validity.not_before.timestamp()
}

/// Request certificates under specific ACME profiles and check that the CA applied them.
///
/// `test/pebble-validating-config.json` gives the profiles distinct validity periods. Pebble
/// issues certificates valid for `validityPeriod - 1` seconds.
#[tokio::test]
#[ignore]
async fn test_profile_selects_lifetime() {
    let _ = simple_logger::init_with_level(log::Level::Info);

    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    for (profile, validity_period) in [("shortlived", 600), ("default", 7200)] {
        let chain = acquire_validated_cert(&[ip], Some(profile))
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
#[tokio::test]
#[ignore]
async fn test_unknown_profile_is_rejected() {
    let _ = simple_logger::init_with_level(log::Level::Info);

    let err = acquire_validated_cert(&[IpAddr::V4(Ipv4Addr::LOCALHOST)], Some("no-such-profile"))
        .await
        .expect_err("order with an unknown profile should fail");
    assert!(
        err.contains("invalidProfile"),
        "expected an invalidProfile error, got: {err}"
    );
}
