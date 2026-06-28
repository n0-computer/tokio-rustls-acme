//! Integration tests against a Pebble ACME test server.
//!
//! These tests require a running Pebble instance.
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
    acme::{
        dns_persist_01_record_name, dns_persist_01_record_value, Account, AuthStatus,
        ChallengeType, Directory,
    },
    caches::{DirCache, NoCache},
    AccountCache, AcmeConfig, CertCache, EventOk, ResolvesServerCertAcme,
};

const PEBBLE_DIRECTORY: &str = "https://localhost:14000/dir";
const PEBBLE_MGMT: &str = "https://localhost:15000";
/// Directory of the second Pebble instance, which performs real validation
/// against challtestsrv. Used by the dns-persist-01 tests.
const PEBBLE_DNS_DIRECTORY: &str = "https://localhost:14001/dir";
const PEBBLE_DNS_MGMT: &str = "https://localhost:15001";
/// Management API of the mock DNS server (pebble-challtestsrv).
const CHALLTESTSRV: &str = "http://localhost:8055";
/// Issuer domain name advertised by Pebble (its `caaIdentities`), which must
/// lead the dns-persist-01 TXT record value.
const PEBBLE_ISSUER_DOMAIN: &str = "pebble.letsencrypt.org";
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

/// Fetch Pebble's ACME-issued root + intermediate certs and build a root store
/// for verifying certs issued by Pebble's CA.
async fn pebble_acme_root_store() -> RootCertStore {
    pebble_acme_root_store_at(PEBBLE_MGMT).await
}

/// Like [`pebble_acme_root_store`] but for a specific management API endpoint.
///
/// Each Pebble instance generates its own CA at startup, so certs issued by
/// `pebble-dns` must be verified against roots fetched from its own management
/// API (port 15001), not the default instance's.
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

// --- dns-persist-01 -------------------------------------------------------
//
// These tests run against the `pebble-dns` instance, which performs real
// validation (PEBBLE_VA_ALWAYS_VALID is not set) and resolves DNS through
// challtestsrv. We publish the `_validation-persist` TXT record via
// challtestsrv's management API and let the VA verify it.

/// Publish a TXT record at `host` (with trailing dot) via challtestsrv.
async fn set_txt(host: &str, value: &str) {
    let client = http_client();
    let body = serde_json::json!({ "host": host, "value": value }).to_string();
    let resp = client
        .post(format!("{CHALLTESTSRV}/set-txt"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("challtestsrv set-txt request failed");
    assert!(
        resp.status().is_success(),
        "challtestsrv set-txt returned {}",
        resp.status()
    );
}

/// Remove the TXT record at `host` (with trailing dot) via challtestsrv.
async fn clear_txt(host: &str) {
    let client = http_client();
    let body = serde_json::json!({ "host": host }).to_string();
    let _ = client
        .post(format!("{CHALLTESTSRV}/clear-txt"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await;
}

/// Register a fresh ACME account against `pebble-dns` and return it.
async fn new_dns_account(client_config: &Arc<ClientConfig>) -> Account {
    let directory = Directory::discover(client_config, PEBBLE_DNS_DIRECTORY)
        .await
        .expect("directory discovery failed");
    let key_pair = Account::generate_key_pair();
    Account::create_with_keypair(
        client_config,
        directory,
        &Vec::<String>::new(),
        &key_pair,
        &None,
    )
    .await
    .expect("account creation failed")
}

/// Poll an authorization until it leaves the pending state, returning the
/// terminal status.
async fn poll_auth_status(
    client_config: &Arc<ClientConfig>,
    account: &Account,
    auth_url: &str,
) -> AuthStatus {
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let auth = account
            .auth(client_config, auth_url)
            .await
            .expect("auth fetch failed");
        match auth.status {
            AuthStatus::Pending => continue,
            other => return other,
        }
    }
    panic!("authorization did not reach a terminal state in time");
}

/// A correctly provisioned `_validation-persist` record satisfies the challenge.
///
/// Drives the low-level `acme` module: order, read the dns-persist-01 challenge,
/// publish the matching TXT record, respond, and confirm the VA marks the
/// authorization valid. This exercises the real wire format end to end.
#[tokio::test]
#[ignore]
async fn test_dns_persist_01_validates() {
    let _ = simple_logger::init_with_level(log::Level::Info);
    let domain = "dns-persist-ok.example.com";

    let client_config = pebble_client_config();
    let account = new_dns_account(&client_config).await;
    let (_order_url, order) = account
        .new_order(&client_config, vec![domain.to_string()])
        .await
        .expect("new_order failed");

    let auth_url = &order.authorizations[0];
    let auth = account
        .auth(&client_config, auth_url)
        .await
        .expect("auth fetch failed");

    let challenge = account
        .dns_persist_01(&auth.challenges)
        .expect("no dns-persist-01 challenge offered");

    // The challenge advertises the accepted issuer domains. The accounturi field
    // is informational and may be empty; when present it must equal our kid.
    assert!(
        challenge
            .issuer_domain_names
            .contains(&PEBBLE_ISSUER_DOMAIN.to_string()),
        "expected issuer {} in {:?}",
        PEBBLE_ISSUER_DOMAIN,
        challenge.issuer_domain_names
    );
    assert!(
        challenge.account_uri.is_empty() || challenge.account_uri == account.kid,
        "challenge accounturi {:?} should be empty or equal the account kid {:?}",
        challenge.account_uri,
        account.kid
    );

    let record_name = format!("{}.", dns_persist_01_record_name(domain));
    let record_value = dns_persist_01_record_value(PEBBLE_ISSUER_DOMAIN, &account.kid, false);
    set_txt(&record_name, &record_value).await;

    account
        .challenge(&client_config, &challenge.url)
        .await
        .expect("challenge response failed");

    let status = poll_auth_status(&client_config, &account, auth_url).await;
    clear_txt(&record_name).await;
    assert!(
        matches!(status, AuthStatus::Valid),
        "authorization should be valid, got {:?}",
        status
    );
}

/// A missing `_validation-persist` record fails validation.
///
/// The mirror of [`test_dns_persist_01_validates`] without publishing the
/// record, confirming the VA actually checks DNS rather than rubber-stamping.
#[tokio::test]
#[ignore]
async fn test_dns_persist_01_missing_record_fails() {
    let _ = simple_logger::init_with_level(log::Level::Info);
    let domain = "dns-persist-missing.example.com";

    let client_config = pebble_client_config();
    let account = new_dns_account(&client_config).await;

    // Make sure no stale record lingers from a previous run.
    clear_txt(&format!("{}.", dns_persist_01_record_name(domain))).await;

    let (_order_url, order) = account
        .new_order(&client_config, vec![domain.to_string()])
        .await
        .expect("new_order failed");
    let auth_url = &order.authorizations[0];
    let auth = account
        .auth(&client_config, auth_url)
        .await
        .expect("auth fetch failed");
    let challenge = account
        .dns_persist_01(&auth.challenges)
        .expect("no dns-persist-01 challenge offered");

    account
        .challenge(&client_config, &challenge.url)
        .await
        .expect("challenge response failed");

    let status = poll_auth_status(&client_config, &account, auth_url).await;
    assert!(
        matches!(status, AuthStatus::Invalid),
        "authorization should be invalid without a record, got {:?}",
        status
    );
}

/// The high-level state machine issues a certificate via dns-persist-01.
///
/// Registers the account up front to learn its kid, publishes the matching
/// record, seeds the account into a cache so the state machine reuses it, then
/// runs `AcmeConfig` with `ChallengeType::DnsPersist01` and verifies the
/// resulting certificate serves a TLS handshake.
#[tokio::test]
#[ignore]
async fn test_dns_persist_01_state_machine() {
    let _ = simple_logger::init_with_level(log::Level::Info);
    let domain = "dns-persist-hl.example.com";

    let client_config = pebble_client_config();

    // Register the account first so we know its kid, then publish the record.
    // We keep the raw key bytes so the same account can be seeded into the cache
    // and reused by the state machine.
    let key_pair = Account::generate_key_pair();
    let directory = Directory::discover(&client_config, PEBBLE_DNS_DIRECTORY)
        .await
        .expect("directory discovery failed");
    let account = Account::create_with_keypair(
        &client_config,
        directory,
        &Vec::<String>::new(),
        &key_pair,
        &None,
    )
    .await
    .expect("account creation failed");

    let record_name = format!("{}.", dns_persist_01_record_name(domain));
    let record_value = dns_persist_01_record_value(PEBBLE_ISSUER_DOMAIN, &account.kid, false);
    set_txt(&record_name, &record_value).await;

    // Seed the account key into a cache so the state machine reuses the same
    // account (and therefore the same kid the record is bound to).
    let cache_dir = tempfile::tempdir().unwrap();
    let cache_path: PathBuf = cache_dir.path().into();
    DirCache::new(cache_path.clone())
        .store_account(&[], PEBBLE_DNS_DIRECTORY, &key_pair)
        .await
        .expect("seeding account cache failed");

    let config: AcmeConfig<io::Error> =
        AcmeConfig::new_with_client_tls_config([domain], client_config)
            .directory(PEBBLE_DNS_DIRECTORY)
            .challenge_type(ChallengeType::DnsPersist01)
            .cache(DirCache::new(cache_path));

    let mut state = config.state();
    let resolver = state.resolver();

    let deploy = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match state.next().await {
                Some(Ok(EventOk::DeployedNewCert)) => return,
                Some(Ok(event)) => eprintln!("event: {event:?}"),
                Some(Err(err)) => panic!("ACME error: {:?}", err),
                None => panic!("state stream ended unexpectedly"),
            }
        }
    })
    .await;
    clear_txt(&record_name).await;
    deploy.expect("timed out waiting for dns-persist-01 certificate");

    let root_store = pebble_acme_root_store_at(PEBBLE_DNS_MGMT).await;
    let peer_certs = verify_tls_handshake_for(resolver, root_store, domain).await;
    assert!(!peer_certs.is_empty(), "should have received certificates");
}
