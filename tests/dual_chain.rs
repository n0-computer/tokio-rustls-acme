//! Chain preferences end to end: an order at the mock CA, then handshakes through `Incoming`.

mod support;

use std::{io, sync::Arc, time::Duration};

use n0_future::StreamExt;
use rustls::{
    ClientConfig, DEFAULT_VERSIONS, RootCertStore, SignatureScheme,
    crypto::{CryptoProvider, ring},
    pki_types::{CertificateDer, ServerName, alg_id::ED25519},
};
use support::{CROSS_SIGNING_ROOT_CN, MOCK_CA_CN, MockAcme};
use tokio::{io::DuplexStream, sync::mpsc};
use tokio_rustls::TlsConnector;
use tokio_rustls_acme::{AcmeConfig, CertChainPreference, EventOk, ResolvesServerCertAcme};
use tokio_stream::wrappers::ReceiverStream;
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

const DOMAIN: &str = "dual-chain.example.com";
const LIMIT: Duration = Duration::from_secs(30);
/// How often a test checks whether the alternate chain is served.
const POLL_INTERVAL: Duration = Duration::from_millis(10);
/// Buffer size of the in-memory connections.
const DUPLEX_BUFFER: usize = 64 * 1024;

/// The default chain needs Ed25519 for the cross-signature, the alternate to the CA doesn't.
#[tokio::test]
async fn dual_chain_serves_each_client_a_chain_it_verifies() {
    let mock = MockAcme::start().await;
    mock.state().alternate_chain = true;
    let (connections, resolver) = serve(&mock, CertChainPreference::dual_chain(MOCK_CA_CN)).await;
    tokio::time::timeout(LIMIT, async {
        while !resolver.serves_alternate_chain() {
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("no alternate chain served");

    let client = config(ring::default_provider(), mock.cross_signing_root.clone());
    let chain = connect(&connections, client).await;
    assert_eq!(top_issuer(&chain), CROSS_SIGNING_ROOT_CN);

    let client = config(without_ed25519(), mock.issued_roots.clone());
    let chain = connect(&connections, client).await;
    assert_eq!(top_issuer(&chain), MOCK_CA_CN);
    // The first alternate ends at the wrong root, so the client also fetched the second.
    let state = mock.state();
    assert_eq!(state.hits("POST /cert/1/other"), 1);
    assert_eq!(state.hits("POST /cert/1/alt"), 1);
    assert_eq!(state.jws_violations, Vec::<String>::new());
}

/// Without DualChain, every client gets the default chain, and no alternate is fetched.
#[tokio::test]
async fn default_preference_serves_the_default_chain() {
    let mock = MockAcme::start().await;
    mock.state().alternate_chain = true;
    let (connections, resolver) = serve(&mock, CertChainPreference::Default).await;

    let client = config(without_ed25519(), mock.issued_roots.clone());
    let chain = connect(&connections, client).await;
    assert_eq!(top_issuer(&chain), CROSS_SIGNING_ROOT_CN);
    assert!(!resolver.serves_alternate_chain());
    let state = mock.state();
    assert_eq!(
        state.hits("POST /cert/1/other") + state.hits("POST /cert/1/alt"),
        0
    );
}

/// Orders a certificate from `mock` with `preference`, then serves it through `Incoming`.
///
/// Returns the sender of the server side of connections, and the resolver.
async fn serve(
    mock: &MockAcme,
    preference: CertChainPreference,
) -> (
    mpsc::Sender<io::Result<DuplexStream>>,
    Arc<ResolvesServerCertAcme>,
) {
    let mut state = AcmeConfig::new_with_client_tls_config([DOMAIN], mock.client_config.clone())
        .directory(&mock.directory_url)
        .cert_chain(preference)
        .state();
    let stored = tokio::time::timeout(LIMIT, async {
        while !matches!(state.next().await, Some(Ok(EventOk::CertCacheStore))) {}
    });
    stored.await.expect("no certificate stored");
    let resolver = state.resolver();
    let (connections, tcp) = mpsc::channel(1);
    let mut incoming = state.incoming(ReceiverStream::new(tcp), Vec::new());
    // Runs the server side of the handshakes, and the rest of the state machine.
    tokio::spawn(async move { while incoming.next().await.is_some() {} });
    (connections, resolver)
}

/// Returns a client config with `provider` that trusts `roots`.
fn config(provider: CryptoProvider, roots: RootCertStore) -> ClientConfig {
    ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(DEFAULT_VERSIONS)
        .expect("ring supports the default versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Returns ring's provider without Ed25519, which clients then neither verify nor offer.
fn without_ed25519() -> CryptoProvider {
    let mut provider = ring::default_provider();
    let algorithms = &mut provider.signature_verification_algorithms;
    let all: Vec<_> = algorithms
        .all
        .iter()
        .filter(|algorithm| algorithm.public_key_alg_id() != ED25519)
        .copied()
        .collect();
    let mapping: Vec<_> = algorithms
        .mapping
        .iter()
        .filter(|(scheme, _)| *scheme != SignatureScheme::ED25519)
        .copied()
        .collect();
    algorithms.all = Vec::leak(all);
    algorithms.mapping = Vec::leak(mapping);
    provider
}

/// Connects with `client` through `connections`, and returns the chain the client verified.
async fn connect(
    connections: &mpsc::Sender<io::Result<DuplexStream>>,
    client: ClientConfig,
) -> Vec<CertificateDer<'static>> {
    let (client_io, server_io) = tokio::io::duplex(DUPLEX_BUFFER);
    connections
        .send(Ok(server_io))
        .await
        .expect("Incoming runs");
    let name = ServerName::try_from(DOMAIN).expect("valid name");
    let connect = TlsConnector::from(Arc::new(client)).connect(name, client_io);
    let tls = tokio::time::timeout(LIMIT, connect)
        .await
        .expect("the handshake stalled")
        .expect("the client verifies the chain");
    let chain = tls.get_ref().1.peer_certificates();
    chain.expect("the server sent a chain").to_vec()
}

/// Returns the issuer common name of the topmost certificate of `chain`, which names its root.
fn top_issuer(chain: &[CertificateDer<'_>]) -> String {
    let top = chain.last().expect("a non-empty chain");
    let (_, top) = X509Certificate::from_der(top).expect("valid certificate");
    let name = top.issuer().iter_common_name().next();
    name.and_then(|name| name.as_str().ok())
        .expect("an issuer common name")
        .to_owned()
}
