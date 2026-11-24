//! Protocol conformance tests against a scripted ACME server.
//!
//! The CA runs in-process, so the tests can inspect every request. Pebble
//! does not allow that.

mod support;

use std::{convert::TryFrom, sync::Arc, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use n0_future::StreamExt;
use rustls::{
    ClientConfig, DEFAULT_VERSIONS, DigitallySignedStruct, RootCertStore, ServerConfig,
    SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use support::MockAcme;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls_acme::{AcmeAcceptor, AcmeConfig, EventOk, ResolvesServerCertAcme};
use x509_parser::{
    certificate::X509Certificate, extensions::GeneralName, oid_registry::Oid, prelude::FromDer,
};

const DOMAIN: &str = "invariants.example.com";
const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";
/// OID of the `acmeIdentifier` extension, RFC 8737 section 6.1.
const ACME_IDENTIFIER_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];
const LIMIT: Duration = Duration::from_secs(30);

/// Accepts any certificate, but still checks the handshake signature.
///
/// It reads the public key with x509-parser because webpki rejects the
/// critical `acmeIdentifier` extension.
#[derive(Debug)]
struct AcceptAnyCert(Arc<CryptoProvider>);

impl AcceptAnyCert {
    fn verify_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let (_, cert) = X509Certificate::from_der(cert)
            .map_err(|err| rustls::Error::General(format!("unparsable certificate: {err}")))?;
        let public_key = &cert.public_key().subject_public_key.data;
        let valid = self
            .0
            .signature_verification_algorithms
            .mapping
            .iter()
            .filter(|(scheme, _)| *scheme == dss.scheme)
            .flat_map(|(_, algorithms)| algorithms.iter())
            .any(|algorithm| {
                algorithm
                    .verify_signature(public_key, message, dss.signature())
                    .is_ok()
            });
        match valid {
            true => Ok(HandshakeSignatureValid::assertion()),
            false => Err(rustls::Error::General("bad handshake signature".into())),
        }
    }
}

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

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
