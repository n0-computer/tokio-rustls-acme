//! Integration tests against a Pebble ACME test server.
//!
//! These tests require a running Pebble instance with alternate roots enabled.
//! Start it with: `docker compose -f docker-compose.pebble.yml up -d`
//!
//! Set `PEBBLE_MINICA_CERT` to the path of Pebble's minica root cert:
//!   `docker compose -f docker-compose.pebble.yml cp pebble:/test/certs/pebble.minica.pem ./pebble.minica.pem`
//!   `export PEBBLE_MINICA_CERT=./pebble.minica.pem`
//!
//! Run with: `cargo test --test pebble -- --ignored`

use std::{convert::TryFrom, io, path::PathBuf, sync::Arc, time::Duration};

use futures::StreamExt;
use rustls::{
    pki_types::{CertificateDer, ServerName},
    ClientConfig, RootCertStore, ServerConfig,
};
use tokio_rustls::TlsAcceptor;
use tokio_rustls_acme::{
    caches::{DirCache, NoCache},
    AccountCache, AcmeConfig, CertCache, CertChainPreference, EventOk, ResolvesServerCertAcme,
};

const PEBBLE_DIRECTORY: &str = "https://localhost:14000/dir";
const PEBBLE_MGMT: &str = "https://localhost:15000";
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
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

/// Insecure reqwest client for Pebble management API calls.
fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

/// Fetch the subject CN of a Pebble root by index (e.g., 0 = primary, 1 = first alternate).
async fn fetch_root_cn(index: usize) -> String {
    let url = format!("{PEBBLE_MGMT}/roots/{index}");
    let pem_text = http_client()
        .get(&url)
        .send()
        .await
        .unwrap_or_else(|e| panic!("failed to fetch {}: {}", url, e))
        .text()
        .await
        .unwrap();
    let pems = pem::parse_many(&pem_text).expect("failed to parse root PEM");
    let der = pems[0].contents().to_vec();
    let (_, cert) = x509_parser::parse_x509_certificate(&der).expect("failed to parse root X509");
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string());
    cn.expect("root cert has no CN")
}

/// Fetch Pebble's ACME-issued root + intermediate certs and build a root store
/// for verifying certs issued by Pebble's CA.
async fn pebble_acme_root_store() -> RootCertStore {
    let client = http_client();
    let mut root_store = RootCertStore::empty();

    // Fetch up to 2 roots and intermediates (index 1 only exists when
    // PEBBLE_ALTERNATE_ROOTS is enabled). 404s are expected and skipped.
    for kind in &["roots", "intermediates"] {
        for index in 0..2 {
            let url = format!("{PEBBLE_MGMT}/{kind}/{index}");
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
    cert_chain: CertChainPreference,
    cache: C,
) -> (Arc<ResolvesServerCertAcme>, AcmeEvents)
where
    C: CertCache<EC = io::Error> + AccountCache<EA = io::Error> + Send + Sync + 'static,
{
    let config: AcmeConfig<io::Error> =
        AcmeConfig::new_with_client_tls_config([TEST_DOMAIN], client_config)
            .directory(PEBBLE_DIRECTORY)
            .cert_chain(cert_chain)
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
async fn acquire_cert(
    client_config: Arc<ClientConfig>,
    cert_chain: CertChainPreference,
) -> Arc<ResolvesServerCertAcme> {
    let (resolver, _) = acquire_cert_with_cache(client_config, cert_chain, NoCache::new()).await;
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
    let resolver = acquire_cert(client_config, CertChainPreference::Default).await;

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
    let (resolver, events) = acquire_cert_with_cache(
        client_config.clone(),
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
    let root_store = pebble_acme_root_store().await;
    let peer_certs = verify_tls_handshake(resolver, root_store).await;
    assert!(!peer_certs.is_empty());

    // Second run: same cache dir, should load from cache without ordering.
    let (resolver2, events2) = acquire_cert_with_cache(
        client_config,
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
    let (_, events) = acquire_cert_with_cache(
        client_config.clone(),
        CertChainPreference::Default,
        DirCache::new(cache_path.clone()),
    )
    .await;
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
    let (_, events2) = acquire_cert_with_cache(
        client_config,
        CertChainPreference::Default,
        DirCache::new(cache_path),
    )
    .await;
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
    let (_, events) = acquire_cert_with_cache(
        client_config.clone(),
        CertChainPreference::Default,
        DirCache::new(cache_path.clone()),
    )
    .await;
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
            .cert_chain(CertChainPreference::Default)
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
            .cert_chain(CertChainPreference::Default)
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

/// Select the alternate chain via PreferredChain and verify the issuer matches.
///
/// Pebble generates two independent CA hierarchies when PEBBLE_ALTERNATE_ROOTS=1.
/// This test fetches the alternate root's CN from the management API, requests
/// that chain via PreferredChain, and checks that the served intermediate was
/// actually signed by the alternate root.
#[tokio::test]
#[ignore]
async fn test_preferred_chain() {
    let _ = simple_logger::init_with_level(log::Level::Info);

    let alt_root_cn = fetch_root_cn(1).await;
    eprintln!("alternate root CN: {alt_root_cn}");

    let client_config = pebble_client_config();
    let resolver = acquire_cert(
        client_config,
        CertChainPreference::PreferredChain(alt_root_cn.clone()),
    )
    .await;

    let root_store = pebble_acme_root_store().await;
    let peer_certs = verify_tls_handshake(resolver, root_store).await;
    assert!(!peer_certs.is_empty(), "should have received certificates");

    let last_cert_der = peer_certs.last().unwrap();
    let (_, last_cert) = x509_parser::parse_x509_certificate(last_cert_der.as_ref()).unwrap();
    let issuer_cn = last_cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("");
    eprintln!("preferred chain root issuer: {issuer_cn}");
    assert_eq!(
        issuer_cn, alt_root_cn,
        "chain should be issued by the preferred alternate root"
    );
}

/// Fetch both chains with DualChain and verify TLS works with the primary.
///
/// DualChain stores both the default and an alternate chain, serving the
/// alternate to clients that cannot verify the primary's signature schemes.
/// This test verifies the basic DualChain flow completes and the primary
/// chain is usable in a TLS handshake.
#[tokio::test]
#[ignore]
async fn test_dual_chain() {
    let _ = simple_logger::init_with_level(log::Level::Info);

    let alt_root_cn = fetch_root_cn(1).await;
    eprintln!("alternate root CN: {alt_root_cn}");

    let client_config = pebble_client_config();
    let resolver = acquire_cert(client_config, CertChainPreference::DualChain(alt_root_cn)).await;

    let root_store = pebble_acme_root_store().await;
    let peer_certs = verify_tls_handshake(resolver, root_store).await;
    assert!(!peer_certs.is_empty(), "should have received certificates");
    eprintln!(
        "dual chain: received {} certificates from primary",
        peer_certs.len()
    );
}

/// Verify that DualChain mode caches the alternate chain separately.
///
/// When using DualChain with DirCache, both the default and alternate cert
/// PEM bundles should be written to disk as separate files. A second run
/// should load both from cache without contacting the ACME server.
#[tokio::test]
#[ignore]
async fn test_dual_chain_cache() {
    let _ = simple_logger::init_with_level(log::Level::Info);

    let cache_dir = tempfile::tempdir().unwrap();
    let cache_path: PathBuf = cache_dir.path().into();
    let alt_root_cn = fetch_root_cn(1).await;

    // First run: orders cert with DualChain, caches both chains.
    let client_config = pebble_client_config();
    let (_, events) = acquire_cert_with_cache(
        client_config.clone(),
        CertChainPreference::DualChain(alt_root_cn.clone()),
        DirCache::new(cache_path.clone()),
    )
    .await;
    assert!(events.deployed_new);
    assert!(events.cert_cache_store);

    // Should have both a default and an alternate cert file.
    let cert_files: Vec<_> = std::fs::read_dir(&cache_path)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("cached_cert_"))
        })
        .collect();
    assert!(
        cert_files.len() >= 2,
        "should have at least 2 cached cert files (default + alt), got {}",
        cert_files.len()
    );
    let has_alt = cert_files
        .iter()
        .any(|e| e.file_name().to_str().is_some_and(|n| n.ends_with("_alt")));
    assert!(has_alt, "should have an alternate cert cache file");

    // Give the background alt cert cache task time to complete.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Second run: should load both chains from cache.
    let (resolver, events2) = acquire_cert_with_cache(
        client_config,
        CertChainPreference::DualChain(alt_root_cn),
        DirCache::new(cache_path),
    )
    .await;
    assert!(
        events2.deployed_cached,
        "second run should deploy cached cert"
    );

    // Verify the cached cert still works in a TLS handshake.
    let root_store = pebble_acme_root_store().await;
    let peer_certs = verify_tls_handshake(resolver, root_store).await;
    assert!(!peer_certs.is_empty());
}
