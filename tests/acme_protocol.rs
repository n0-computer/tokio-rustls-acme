//! Protocol conformance tests against a scripted ACME server.
//!
//! The CA runs in-process, so the tests can inspect every request. Pebble
//! does not allow that.

mod support;

use std::{
    convert::{Infallible, TryFrom},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use n0_future::StreamExt;
use rustls::{
    ClientConfig, DEFAULT_VERSIONS, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, ServerName},
};
use serde_json::json;
use support::{ACME_IDENTIFIER_OID, ACME_TLS_ALPN, AcceptAnyCert, MockAcme};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls_acme::{
    AcmeAcceptor, AcmeConfig, AcmeState, CertCache, EventError, EventOk, OrderError,
    ResolvesServerCertAcme,
    acme::Identifier,
    caches::{NoCache, TestCache},
};
use x509_parser::{
    certificate::X509Certificate, extensions::GeneralName, oid_registry::Oid, prelude::FromDer,
};

const DOMAIN: &str = "invariants.example.com";
const LIMIT: Duration = Duration::from_secs(30);

/// Sets the identifiers of a config.
type Configure = fn(AcmeConfig<Infallible>) -> AcmeConfig<Infallible>;

/// An ACME order that waits for the CA to validate its tls-alpn-01 challenge.
struct PendingChallenge {
    mock: MockAcme,
    acceptor: AcmeAcceptor,
    resolver: Arc<ResolvesServerCertAcme>,
    events: tokio::sync::mpsc::Receiver<Result<EventOk, String>>,
    driver: JoinHandle<()>,
}

impl Drop for PendingChallenge {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

/// Starts an order for [`DOMAIN`] and returns once the client triggered the challenge.
///
/// The authorization names the identifier `authz_value`, or [`DOMAIN`] if it is `None`.
async fn pending_challenge(authz_value: Option<&str>) -> PendingChallenge {
    let mock = MockAcme::start().await;
    mock.state().authz_status = "pending";
    mock.state().authz_value = authz_value.map(str::to_owned);
    let mut state = AcmeConfig::new_with_client_tls_config([DOMAIN], mock.client_config.clone())
        .directory(&mock.directory_url)
        .state();
    let acceptor = state.acceptor();
    let resolver = state.resolver();
    let (sender, events) = tokio::sync::mpsc::channel(16);
    let driver = tokio::spawn(async move {
        while let Some(event) = state.next().await {
            let event = event.map_err(|err| format!("{err:?}"));
            if sender.send(event).await.is_err() {
                return;
            }
        }
    });
    mock.wait_for_hits("POST /chall/1", 1, LIMIT).await;
    PendingChallenge {
        mock,
        acceptor,
        resolver,
        events,
        driver,
    }
}

struct Handshake {
    handled_as_validation: bool,
    /// Leaf certificate and negotiated ALPN protocol, if the client finished.
    client: Option<(CertificateDer<'static>, Option<Vec<u8>>)>,
}

/// Connects to `challenge` with `sni` and `alpn`, and accepts any certificate without `roots`.
async fn handshake(
    challenge: &PendingChallenge,
    sni: &str,
    alpn: &[&[u8]],
    roots: Option<RootCertStore>,
) -> Handshake {
    let provider = support::provider();
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(DEFAULT_VERSIONS)
        .unwrap();
    let mut client_config = match roots {
        Some(roots) => builder.with_root_certificates(roots),
        None => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider.clone()))),
    }
    .with_no_client_auth();
    client_config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_config = Arc::new(
        ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(DEFAULT_VERSIONS)
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(challenge.resolver.clone()),
    );

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server_name = ServerName::try_from(sni.to_string()).unwrap();
    let server = async {
        match challenge.acceptor.accept(server_io).await {
            Ok(None) => true,
            Ok(Some(start)) => {
                let _ = start.into_stream(server_config).await;
                false
            }
            Err(_) => false,
        }
    };
    let (client, handled_as_validation) = tokio::time::timeout(LIMIT, async {
        tokio::join!(connector.connect(server_name, client_io), server)
    })
    .await
    .expect("the handshake stalled");
    let client = client.ok().map(|stream| {
        let (_, connection) = stream.get_ref();
        let leaf = connection.peer_certificates().unwrap()[0]
            .clone()
            .into_owned();
        (leaf, connection.alpn_protocol().map(<[u8]>::to_vec))
    });
    Handshake {
        handled_as_validation,
        client,
    }
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .expect("a TLS 1.3 suite");
    suite.common.hash_provider.hash(data).as_ref().to_vec()
}

/// Computes the `acmeIdentifier` value the CA expects, per RFC 8737 and RFC 7638.
fn expected_acme_identifier(mock: &MockAcme) -> Vec<u8> {
    let state = mock.state();
    let jwk = state.account_jwk.as_ref().expect("account was created");
    let field = |name: &str| jwk[name].as_str().expect("JWK field").to_string();
    let thumbprint_input = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
        field("crv"),
        field("kty"),
        field("x"),
        field("y"),
    );
    let thumbprint = URL_SAFE_NO_PAD.encode(sha256(thumbprint_input.as_bytes()));
    let key_authorization = format!("{}.{}", state.token, thumbprint);
    sha256(key_authorization.as_bytes())
}

#[tokio::test]
async fn tls_alpn_01_response_conforms_to_rfc_8737() {
    // A CA may spell the identifier of the authorization otherwise.
    for authz_value in [None, Some("Invariants.Example.COM.")] {
        let challenge = pending_challenge(authz_value).await;

        let result = handshake(&challenge, DOMAIN, &[ACME_TLS_ALPN], None).await;

        assert!(
            result.handled_as_validation,
            "the acceptor must end a validation handshake itself, {authz_value:?}"
        );
        let (leaf, alpn) = result.client.expect("validation handshake completes");
        assert_eq!(alpn.as_deref(), Some(ACME_TLS_ALPN));

        let (_, cert) = X509Certificate::from_der(&leaf).unwrap();
        assert_eq!(cert.subject(), cert.issuer(), "must be self-issued");
        cert.verify_signature(None)
            .expect("must be signed with its own public key");
        let san = cert.subject_alternative_name().unwrap().expect("has a SAN");
        let names = &san.value.general_names;
        assert!(
            matches!(names.as_slice(), [GeneralName::DNSName(name)] if *name == DOMAIN),
            "the SAN must hold the validated domain and nothing else: {names:?}",
        );
        let oid = Oid::from(ACME_IDENTIFIER_OID).unwrap();
        let extension = cert
            .get_extension_unique(&oid)
            .unwrap()
            .expect("has an acmeIdentifier extension");
        assert!(extension.critical, "acmeIdentifier must be critical");
        // The extension value is a DER OCTET STRING with the 32-byte digest.
        let mut expected = vec![0x04, 0x20];
        expected.extend(expected_acme_identifier(&challenge.mock));
        assert_eq!(extension.value, expected);
    }
}

#[tokio::test]
async fn challenge_certificate_requires_exact_acme_alpn_and_matching_sni() {
    let challenge = pending_challenge(None).await;

    let cases: [(&str, &[&[u8]]); 4] = [
        (DOMAIN, &[]),
        (DOMAIN, &[b"h2"]),
        (DOMAIN, &[ACME_TLS_ALPN, b"h2"]),
        ("other.example.com", &[ACME_TLS_ALPN]),
    ];
    for (sni, alpn) in cases {
        let result = handshake(&challenge, sni, alpn, None).await;
        assert!(!result.handled_as_validation, "sni {sni}, alpn {alpn:?}");
        assert!(
            result.client.is_none(),
            "a client with sni {sni} and alpn {alpn:?} got a certificate before one was issued"
        );
    }
}

#[tokio::test]
async fn validated_order_follows_jws_rules_and_deploys_own_key() {
    let mut challenge = pending_challenge(None).await;
    challenge.mock.state().authz_status = "valid";

    tokio::time::timeout(LIMIT, async {
        while let Some(event) = challenge.events.recv().await {
            match event {
                Ok(EventOk::DeployedNewCert) => return,
                Ok(_) => {}
                Err(err) => panic!("order failed: {err}"),
            }
        }
        panic!("the state machine stopped before it deployed a certificate");
    })
    .await
    .expect("certificate deployed in time");

    {
        let state = challenge.mock.state();
        assert!(
            state.jws_violations.is_empty(),
            "{:#?}",
            state.jws_violations
        );
        for route in [
            "POST /acct",
            "POST /order",
            "POST /authz/1",
            "POST /chall/1",
            "POST /order/1",
            "POST /finalize/1",
            "POST /cert/1",
        ] {
            assert!(state.hits(route) > 0, "no request to {route}");
        }
    }

    // The handshake signature proves that the resolver holds the leaf key.
    let roots = challenge.mock.issued_roots.clone();
    let result = handshake(&challenge, DOMAIN, &[b"h2"], Some(roots)).await;
    assert!(
        result.client.is_some(),
        "the deployed certificate does not verify for {DOMAIN}"
    );
}

/// Fails invalid identifiers before any request to the CA, and without a cached certificate.
#[tokio::test]
async fn invalid_identifiers_fail_before_the_cache_and_the_ca() {
    let cases: [Configure; 6] = [
        |config| config.domains(["foo bar"]),
        |config| config.domains(["example.org.."]),
        |config| config.domains(["b\u{fc}cher.example"]),
        // Both identifiers would need the same challenge SNI.
        |config| config.domains(["192.0.2.1", "1.2.0.192.in-addr.arpa"]),
        |config| config.identifiers([Identifier::Dns("192.0.2.1".into())]),
        |config| config.domains([""; 0]),
    ];
    let mock = MockAcme::start().await;
    for (case, configure) in cases.into_iter().enumerate() {
        let config = || configure(mock_config(&mock));
        // TestCache holds a certificate for any identifiers, like a cache of an earlier version.
        let cold = config().state();
        let warm = config()
            .cache(TestCache::<Infallible, Infallible>::new())
            .state();
        for (start, mut state) in [("cold", cold), ("warm", warm)] {
            let event = tokio::time::timeout(LIMIT, state.next()).await;
            assert!(
                matches!(
                    event,
                    Ok(Some(Err(EventError::Order(OrderError::InvalidIdentifier(
                        _
                    )))))
                ),
                "case {case}, {start} start: {event:?}"
            );
        }
    }
    assert_eq!(
        mock.state().hits("GET /dir"),
        0,
        "the client contacted the CA"
    );
}

/// Keys the cache by strings as given, and by the canonical text of typed identifiers.
#[tokio::test]
async fn cache_keys_follow_the_builder() {
    let cases: [(Configure, &str); 2] = [
        (
            |config| config.domains(["Invariants.Example.COM."]),
            "Invariants.Example.COM.",
        ),
        (
            |config| config.identifiers([Identifier::Dns("Invariants.Example.COM.".into())]),
            DOMAIN,
        ),
    ];
    for (configure, key) in cases {
        let mock = MockAcme::start().await;
        let cache = KeyRecorder::default();
        let keys = cache.keys.clone();
        let state = configure(mock_config(&mock))
            .cache_compose(cache, NoCache::<Infallible>::new())
            .state();
        deploy(state).await.expect("order failed");
        let expected = [format!("load {key}"), format!("store {key}")];
        assert_eq!(*keys.lock().expect("poisoned"), expected);
    }
}

/// Fails an order whose profile the CA does not confirm, before finalizing it.
#[tokio::test]
async fn unconfirmed_profile_fails_the_order() {
    for selected in [None, Some("classic")] {
        let mock = MockAcme::start().await;
        mock.state().profile = selected.map(|name| json!(name));
        let mut state =
            AcmeConfig::new_with_client_tls_config([DOMAIN], mock.client_config.clone())
                .directory(&mock.directory_url)
                .profile("shortlived")
                .state();
        match first_order_error(&mut state).await {
            OrderError::ProfileMismatch {
                requested,
                selected: actual,
            } => {
                assert_eq!(requested, "shortlived");
                assert_eq!(actual.as_deref(), selected);
            }
            err => panic!("{selected:?}: expected a profile mismatch, got {err:?}"),
        }
        assert_eq!(
            mock.state().hits("POST /finalize/1"),
            0,
            "{selected:?}: the client finalized the order"
        );
    }
}

/// Deploys a certificate whose profile the CA confirms.
#[tokio::test]
async fn confirmed_profile_deploys() {
    let mock = MockAcme::start().await;
    mock.state().profile = Some(json!("shortlived"));
    let state = AcmeConfig::new_with_client_tls_config([DOMAIN], mock.client_config.clone())
        .directory(&mock.directory_url)
        .profile("shortlived")
        .state();
    deploy(state)
        .await
        .expect("order with a confirmed profile failed");
}

/// Ignores a malformed `profile` in the order when no profile is configured.
#[tokio::test]
async fn malformed_profile_is_ignored_without_a_configured_profile() {
    let mock = MockAcme::start().await;
    mock.state().profile = Some(json!({"name": 42}));
    let state = AcmeConfig::new_with_client_tls_config([DOMAIN], mock.client_config.clone())
        .directory(&mock.directory_url)
        .state();
    deploy(state)
        .await
        .expect("order with a malformed profile failed");
}

/// Returns a config for the CA of `mock`, without identifiers.
fn mock_config(mock: &MockAcme) -> AcmeConfig<Infallible> {
    AcmeConfig::new_with_client_tls_config([""; 0], mock.client_config.clone())
        .directory(&mock.directory_url)
}

/// A cert cache that stays empty and records the keys of its loads and stores.
#[derive(Debug, Default)]
struct KeyRecorder {
    /// Each load and store, like `load example.com,example.org`.
    keys: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl CertCache for KeyRecorder {
    type EC = Infallible;

    async fn load_cert(&self, domains: &[String], _: &str) -> Result<Option<Vec<u8>>, Infallible> {
        let mut keys = self.keys.lock().expect("poisoned");
        keys.push(format!("load {}", domains.join(",")));
        Ok(None)
    }

    async fn store_cert(&self, domains: &[String], _: &str, _: &[u8]) -> Result<(), Infallible> {
        let mut keys = self.keys.lock().expect("poisoned");
        keys.push(format!("store {}", domains.join(",")));
        Ok(())
    }
}

/// Drives `state` until it stores a new certificate, or returns the first order error.
#[allow(
    clippy::result_large_err,
    reason = "the crate returns `OrderError` by value in its events too"
)]
async fn deploy(mut state: AcmeState) -> Result<(), OrderError> {
    tokio::time::timeout(LIMIT, async {
        loop {
            match state.next().await.expect("state stream ended") {
                Ok(EventOk::CertCacheStore) => return Ok(()),
                Ok(_) => {}
                Err(EventError::Order(err)) => return Err(err),
                Err(err) => panic!("expected an order error, got {err:?}"),
            }
        }
    })
    .await
    .expect("timed out waiting for the order")
}

/// Drives `state` until its first error, which must be an order error.
async fn first_order_error(state: &mut AcmeState) -> OrderError {
    // The account key is stored first, then the order fails.
    tokio::time::timeout(LIMIT, async {
        loop {
            match state.next().await.expect("state stream ended") {
                Ok(_) => {}
                Err(EventError::Order(err)) => return err,
                Err(err) => panic!("expected an order error, got {err:?}"),
            }
        }
    })
    .await
    .expect("timed out waiting for the order")
}
