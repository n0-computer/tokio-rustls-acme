//! Protocol conformance tests against a scripted ACME server.
//!
//! The CA runs in-process, so the tests can inspect every request. Pebble
//! does not allow that.

mod support;

use std::{convert::TryFrom, sync::Arc, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use n0_future::StreamExt;
use rustls::{
    ClientConfig, DEFAULT_VERSIONS, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, ServerName},
};
use support::{ACME_IDENTIFIER_OID, ACME_TLS_ALPN, AcceptAnyCert, MockAcme};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls_acme::{
    AcmeAcceptor, AcmeConfig, EventError, EventOk, OrderError, ResolvesServerCertAcme,
};
use x509_parser::{
    certificate::X509Certificate, extensions::GeneralName, oid_registry::Oid, prelude::FromDer,
};

const DOMAIN: &str = "invariants.example.com";
const LIMIT: Duration = Duration::from_secs(30);

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
async fn pending_challenge() -> PendingChallenge {
    let mock = MockAcme::start().await;
    mock.state().authz_status = "pending";
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
    let challenge = pending_challenge().await;

    let result = handshake(&challenge, DOMAIN, &[ACME_TLS_ALPN], None).await;

    assert!(
        result.handled_as_validation,
        "the acceptor must end a validation handshake itself"
    );
    let (leaf, alpn) = result.client.expect("validation handshake completes");
    assert_eq!(alpn.as_deref(), Some(ACME_TLS_ALPN));

    let (_, cert) = X509Certificate::from_der(&leaf).unwrap();
    assert_eq!(cert.subject(), cert.issuer(), "must be self-issued");
    cert.verify_signature(None)
        .expect("must be signed with its own public key");
    let san = cert.subject_alternative_name().unwrap().expect("has a SAN");
    assert!(
        matches!(san.value.general_names.as_slice(), [GeneralName::DNSName(name)] if *name == DOMAIN),
        "the SAN must hold the validated domain and nothing else: {:?}",
        san.value.general_names
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

#[tokio::test]
async fn challenge_certificate_requires_exact_acme_alpn_and_matching_sni() {
    let challenge = pending_challenge().await;

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
    let mut challenge = pending_challenge().await;
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

/// Fails the order of an invalid identifier before any request to the CA.
#[tokio::test]
async fn invalid_identifier_fails_before_contacting_the_ca() {
    let mock = MockAcme::start().await;
    let mut state = AcmeConfig::new_with_client_tls_config(["foo bar"], mock.client_config.clone())
        .directory(&mock.directory_url)
        .state();
    // The account key is stored first, then the order fails.
    let err = tokio::time::timeout(LIMIT, async {
        loop {
            match state.next().await.expect("state stream ended") {
                Ok(_) => {}
                Err(err) => return err,
            }
        }
    })
    .await
    .expect("timed out waiting for the order");
    assert!(
        matches!(err, EventError::Order(OrderError::InvalidIdentifier(_))),
        "expected an invalid identifier error, got {err:?}"
    );
    assert_eq!(
        mock.state().hits("GET /dir"),
        0,
        "the client contacted the CA"
    );
}
