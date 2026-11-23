//! Tests the handshake timeouts and tls-alpn-01 answers of `Incoming` and `AxumAcceptor`.

mod support;

use std::{convert::Infallible, convert::TryFrom, io, sync::Arc, time::Duration};

use futures::{StreamExt, stream::BoxStream};
use rustls::{
    ClientConfig, DEFAULT_VERSIONS, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use support::{ACME_IDENTIFIER_OID, ACME_TLS_ALPN, AcceptAnyCert, MockAcme};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    task::JoinHandle,
    time::Instant,
};
use tokio_rustls::{TlsConnector, client::TlsStream as ClientTls, server::TlsStream as ServerTls};
use tokio_rustls_acme::{AcmeConfig, Incoming, caches::TestCache};
use tokio_stream::wrappers::ReceiverStream;
use x509_parser::{certificate::X509Certificate, oid_registry::Oid, prelude::FromDer};

const DOMAIN: &str = "example.com";

/// Handshake timeout far above the duration of any test.
const STALL_LIMIT: Duration = Duration::from_secs(3600);

/// Upper bound for a complete handshake, which takes no time on the paused clock.
const HANDSHAKE_LIMIT: Duration = Duration::from_secs(1);

/// Handshake timeout below the default.
const CONFIGURED_TIMEOUT: Duration = Duration::from_secs(1);

/// Handshake timeout that applies when none is configured.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Handshake timeout above the default.
const LONG_TIMEOUT: Duration = Duration::from_secs(30);

/// Configured handshake timeouts and the timeouts they result in.
const TIMEOUT_CASES: [TimeoutCase; 3] = [
    TimeoutCase {
        configured: None,
        expected: DEFAULT_TIMEOUT,
    },
    TimeoutCase {
        configured: Some(CONFIGURED_TIMEOUT),
        expected: CONFIGURED_TIMEOUT,
    },
    TimeoutCase {
        configured: Some(LONG_TIMEOUT),
        expected: LONG_TIMEOUT,
    },
];

/// Allowed difference between the configured and the observed timeout.
const MARGIN: Duration = Duration::from_millis(100);

/// Upper bound for each step against the mock ACME server, which needs the real clock.
const MOCK_LIMIT: Duration = Duration::from_secs(5);

/// Upper bound for the server's answer to a ClientHello.
const ANSWER_LIMIT: Duration = Duration::from_secs(1);

/// Paused-clock step that lets `Incoming` take the connections.
const SETTLE: Duration = Duration::from_millis(1);

/// A handshake timeout to configure and the timeout it results in.
#[derive(Debug, Clone, Copy)]
struct TimeoutCase {
    /// Timeout passed to `handshake_timeout`, or `None` to keep the default.
    configured: Option<Duration>,
    expected: Duration,
}

type Cache = TestCache<io::Error, io::Error>;

type TestIncoming = Incoming<
    DuplexStream,
    io::Error,
    BoxStream<'static, io::Result<DuplexStream>>,
    io::Error,
    io::Error,
>;

fn incoming(cache: Cache, connections: impl IntoIterator<Item = DuplexStream>) -> TestIncoming {
    let connections: Vec<_> = connections.into_iter().map(io::Result::Ok).collect();
    let tcp = futures::stream::iter(connections)
        .chain(futures::stream::pending())
        .boxed();
    AcmeConfig::new_with_client_tls_config([DOMAIN], support::client_config_without_roots())
        .cache(cache)
        .incoming(tcp, Vec::new())
}

/// Polls `incoming` in a new task and drops the connections it yields.
fn serve(mut incoming: TestIncoming) -> JoinHandle<()> {
    tokio::spawn(async move { while incoming.next().await.is_some() {} })
}

#[cfg(feature = "axum")]
fn axum_acceptor_of<EC: std::fmt::Debug + 'static, EA: std::fmt::Debug + 'static>(
    state: &tokio_rustls_acme::AcmeState<EC, EA>,
) -> tokio_rustls_acme::axum::AxumAcceptor {
    let server_config = rustls::ServerConfig::builder_with_provider(state.crypto_provider())
        .with_protocol_versions(DEFAULT_VERSIONS)
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(state.resolver());
    state.axum_acceptor(Arc::new(server_config))
}

#[cfg(feature = "axum")]
async fn axum_acceptor(cache: Cache) -> tokio_rustls_acme::axum::AxumAcceptor {
    let mut state =
        AcmeConfig::new_with_client_tls_config([DOMAIN], support::client_config_without_roots())
            .cache(cache)
            .state();
    let acceptor = axum_acceptor_of(&state);
    // The resolver has no certificate until the state loads it from the cache.
    loop {
        match state.next().await {
            Some(Ok(tokio_rustls_acme::EventOk::DeployedCachedCert)) => return acceptor,
            Some(Ok(_)) => {}
            event => panic!("the state did not deploy the cached certificate: {event:?}"),
        }
    }
}

/// Checks that the server closes `client` within [`MARGIN`] of `timeout` after `start`.
async fn assert_closed_after(client: &mut DuplexStream, start: Instant, timeout: Duration) {
    let mut received = Vec::new();
    let early =
        tokio::time::timeout_at(start + timeout - MARGIN, client.read_to_end(&mut received));
    assert!(
        early.await.is_err(),
        "the server closed the connection before {:?}",
        timeout - MARGIN
    );
    let in_time =
        tokio::time::timeout_at(start + timeout + MARGIN, client.read_to_end(&mut received));
    assert!(
        in_time.await.is_ok(),
        "the server held the connection open past {:?}",
        timeout + MARGIN
    );
}

async fn assert_incoming_drops_silent_connection(case: TimeoutCase) {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let start = Instant::now();
    let mut incoming = incoming(Cache::new(), [server]);
    if let Some(configured) = case.configured {
        incoming = incoming.handshake_timeout(configured);
    }
    let incoming = serve(incoming);

    assert_closed_after(&mut client, start, case.expected).await;
    incoming.abort();
}

#[cfg(feature = "axum")]
async fn assert_axum_acceptor_gives_up_on_silent_connection(case: TimeoutCase) {
    let mut acceptor = axum_acceptor(Cache::new()).await;
    if let Some(configured) = case.configured {
        acceptor = acceptor.handshake_timeout(configured);
    }

    let (_client, server) = tokio::io::duplex(64 * 1024);
    assert_axum_accept_times_out(&acceptor, server, case.expected).await;
}

#[cfg(feature = "axum")]
async fn assert_axum_accept_times_out(
    acceptor: &tokio_rustls_acme::axum::AxumAcceptor,
    server: DuplexStream,
    timeout: Duration,
) {
    let start = Instant::now();
    let mut accept = axum_server::accept::Accept::accept(acceptor, server, ());
    let early = tokio::time::timeout_at(start + timeout - MARGIN, &mut accept).await;
    assert!(
        early.is_err(),
        "the accept future finished before {:?}",
        timeout - MARGIN
    );
    match tokio::time::timeout_at(start + timeout + MARGIN, accept).await {
        Ok(Err(err)) => assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}"),
        Ok(Ok(_)) => panic!("the accept future succeeded without a complete handshake"),
        Err(_) => panic!(
            "the accept future was still pending after {:?}",
            timeout + MARGIN
        ),
    }
}

/// Starts a mock ACME server that keeps the challenge certificate for [`DOMAIN`] deployed.
async fn pending_mock() -> MockAcme {
    let mock = MockAcme::start().await;
    mock.state().authz_status = "pending";
    mock
}

fn mock_config(mock: &MockAcme) -> AcmeConfig<Infallible> {
    AcmeConfig::new_with_client_tls_config([DOMAIN], mock.client_config.clone())
        .directory(&mock.directory_url)
}

/// Runs a tls-alpn-01 validation on `io` and returns the open connection for the server's session tickets.
async fn validate(io: DuplexStream) -> ClientTls<DuplexStream> {
    let provider = support::provider();
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(DEFAULT_VERSIONS)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
        .with_no_client_auth();
    config.alpn_protocols = vec![ACME_TLS_ALPN.to_vec()];
    let connect =
        TlsConnector::from(Arc::new(config)).connect(ServerName::try_from(DOMAIN).unwrap(), io);
    let tls = tokio::time::timeout(MOCK_LIMIT, connect)
        .await
        .unwrap_or_else(|_| panic!("the validation handshake stalled for {MOCK_LIMIT:?}"))
        .expect("the validation handshake failed");

    let (_, connection) = tls.get_ref();
    let certificates = connection
        .peer_certificates()
        .expect("the server sent no certificate");
    let (_, leaf) = X509Certificate::from_der(&certificates[0]).unwrap();
    let oid = Oid::from(ACME_IDENTIFIER_OID).unwrap();
    assert!(
        leaf.get_extension_unique(&oid).unwrap().is_some(),
        "the certificate has no acmeIdentifier extension"
    );
    tls
}

fn client_hello(alpn_protocols: Vec<Vec<u8>>) -> Vec<u8> {
    let mut config = (*support::client_config_without_roots()).clone();
    config.alpn_protocols = alpn_protocols;
    let mut tls =
        rustls::ClientConnection::new(Arc::new(config), ServerName::try_from(DOMAIN).unwrap())
            .unwrap();
    let mut client_hello = Vec::new();
    tls.write_tls(&mut client_hello).unwrap();
    client_hello
}

async fn connect(ca_pem: &str, io: DuplexStream) -> io::Result<ClientTls<DuplexStream>> {
    let mut roots = RootCertStore::empty();
    for pem in pem::parse_many(ca_pem).unwrap() {
        roots
            .add(CertificateDer::from(pem.into_contents()))
            .unwrap();
    }
    TlsConnector::from(support::client_config(roots))
        .connect(ServerName::try_from(DOMAIN).unwrap(), io)
        .await
}

async fn assert_connected(
    mut server: ServerTls<DuplexStream>,
    mut client: ClientTls<DuplexStream>,
) {
    server.write_all(b"hello").await.unwrap();
    server.shutdown().await.unwrap();
    let mut received = Vec::new();
    client.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, b"hello");
}

#[tokio::test(start_paused = true)]
async fn incoming_yields_connection_after_handshake() {
    let cache = Cache::new();
    let ca_pem = cache.ca_pem().to_owned();
    let (client, server) = tokio::io::duplex(64 * 1024);
    let mut incoming = incoming(cache, [server]);

    let handshake = async { tokio::join!(incoming.next(), connect(&ca_pem, client)) };
    let (server, client) = tokio::time::timeout(HANDSHAKE_LIMIT, handshake)
        .await
        .unwrap_or_else(|_| panic!("the handshake did not complete in {HANDSHAKE_LIMIT:?}"));

    let server = server
        .expect("the stream ended")
        .expect("the stream failed");
    let client = client.expect("the client handshake failed");
    assert_connected(server, client).await;
}

#[tokio::test(start_paused = true)]
async fn incoming_drops_silent_connection_after_handshake_timeout() {
    for case in TIMEOUT_CASES {
        assert_incoming_drops_silent_connection(case).await;
    }
}

#[tokio::test(start_paused = true)]
async fn incoming_applies_one_deadline_to_whole_handshake() {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let start = Instant::now();
    let incoming = serve(incoming(Cache::new(), [server]).handshake_timeout(CONFIGURED_TIMEOUT));

    let client_hello = client_hello(Vec::new());
    let (first, rest) = client_hello.split_at(client_hello.len() / 2);
    client.write_all(first).await.unwrap();
    tokio::time::sleep(CONFIGURED_TIMEOUT.mul_f64(0.6)).await;
    client.write_all(rest).await.unwrap();
    // The answer shows that the handshake left its first stage.
    let mut byte = [0u8; 1];
    assert!(
        matches!(client.read(&mut byte).await, Ok(1)),
        "the server did not answer the ClientHello"
    );

    assert_closed_after(&mut client, start, CONFIGURED_TIMEOUT).await;
    incoming.abort();
}

#[tokio::test]
async fn incoming_answers_tls_alpn_01_validation() {
    let mock = pending_mock().await;
    let (connections, tcp) = tokio::sync::mpsc::channel::<DuplexStream>(1);
    let incoming = mock_config(&mock)
        .incoming(ReceiverStream::new(tcp).map(Ok::<_, io::Error>), Vec::new())
        .handshake_timeout(STALL_LIMIT);
    let served = tokio::spawn(async move { incoming.count().await });
    mock.wait_for_hits("POST /chall/1", 1, MOCK_LIMIT).await;

    // The second validation shows that `Incoming` still accepts connections.
    let mut clients = Vec::new();
    for _ in 0..2 {
        let (client, server) = tokio::io::duplex(64 * 1024);
        connections.send(server).await.unwrap();
        clients.push(validate(client).await);
    }

    // `Incoming` ends with the TCP stream once no handshake is left.
    drop(connections);
    let yielded = tokio::time::timeout(MOCK_LIMIT, served)
        .await
        .unwrap_or_else(|_| panic!("`Incoming` did not end in {MOCK_LIMIT:?}"))
        .unwrap();
    assert_eq!(
        yielded, 0,
        "`Incoming` yielded an item for a validation request"
    );
}

#[tokio::test(start_paused = true)]
async fn incoming_answers_all_client_hellos_of_one_wakeup() {
    // Two connections are not enough to show the fault: `FuturesUnordered`
    // wakes its task once more when it polled all of its futures.
    let (mut clients, servers): (Vec<_>, Vec<_>) =
        (0..3).map(|_| tokio::io::duplex(64 * 1024)).unzip();
    let incoming = serve(incoming(Cache::new(), servers));
    // Let `Incoming` take the connections and wait for their ClientHellos.
    tokio::time::sleep(SETTLE).await;

    // All writes finish before the task of `Incoming` runs again. No client
    // answers the server flight, so no later event wakes that task.
    let client_hello = client_hello(Vec::new());
    for client in &mut clients {
        client.write_all(&client_hello).await.unwrap();
    }

    for (index, client) in clients.iter_mut().enumerate() {
        let mut byte = [0u8; 1];
        let answered = tokio::time::timeout(ANSWER_LIMIT, client.read(&mut byte)).await;
        assert!(
            matches!(answered, Ok(Ok(1))),
            "connection {index} got no answer to its ClientHello in {ANSWER_LIMIT:?}"
        );
    }
    incoming.abort();
}

#[cfg(feature = "axum")]
#[tokio::test(start_paused = true)]
async fn axum_acceptor_returns_connection_after_handshake() {
    let cache = Cache::new();
    let ca_pem = cache.ca_pem().to_owned();
    let acceptor = axum_acceptor(cache).await;
    let (client, server) = tokio::io::duplex(64 * 1024);

    let accept = axum_server::accept::Accept::accept(&acceptor, server, ());
    let handshake = async { tokio::join!(accept, connect(&ca_pem, client)) };
    let (accepted, client) = tokio::time::timeout(HANDSHAKE_LIMIT, handshake)
        .await
        .unwrap_or_else(|_| panic!("the handshake did not complete in {HANDSHAKE_LIMIT:?}"));

    let (server, ()) = accepted.expect("the accept future failed");
    let client = client.expect("the client handshake failed");
    assert_connected(server, client).await;
}

#[cfg(feature = "axum")]
#[tokio::test(start_paused = true)]
async fn axum_acceptor_gives_up_on_silent_connection_after_handshake_timeout() {
    for case in TIMEOUT_CASES {
        assert_axum_acceptor_gives_up_on_silent_connection(case).await;
    }
}

#[cfg(feature = "axum")]
#[tokio::test]
async fn axum_acceptor_answers_tls_alpn_01_validation() {
    let mock = pending_mock().await;
    let mut state = mock_config(&mock).state();
    let acceptor = axum_acceptor_of(&state).handshake_timeout(STALL_LIMIT);
    let driver = tokio::spawn(async move { while state.next().await.is_some() {} });
    mock.wait_for_hits("POST /chall/1", 1, MOCK_LIMIT).await;

    let (client, server) = tokio::io::duplex(64 * 1024);
    let accept = axum_server::accept::Accept::accept(&acceptor, server, ());
    let (accepted, _client) =
        tokio::join!(tokio::time::timeout(MOCK_LIMIT, accept), validate(client));
    driver.abort();

    match accepted {
        Ok(Err(err)) => assert_eq!(err.to_string(), "TLS-ALPN-01 validation request"),
        Ok(Ok(_)) => panic!("the accept future returned a validation connection"),
        Err(_) => panic!("the accept future was still pending after {MOCK_LIMIT:?}"),
    }
}

#[cfg(feature = "axum")]
#[tokio::test]
async fn axum_acceptor_gives_up_on_stalled_validation() {
    let mock = pending_mock().await;
    let mut state = mock_config(&mock).state();
    let acceptor = axum_acceptor_of(&state).handshake_timeout(CONFIGURED_TIMEOUT);
    let driver = tokio::spawn(async move { while state.next().await.is_some() {} });
    mock.wait_for_hits("POST /chall/1", 1, MOCK_LIMIT).await;
    // The ACME client would time out on the paused clock. The resolver keeps
    // the challenge certificate without it.
    driver.abort();
    tokio::time::pause();

    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let client_hello = client_hello(vec![ACME_TLS_ALPN.to_vec()]);
    client.write_all(&client_hello).await.unwrap();
    assert_axum_accept_times_out(&acceptor, server, CONFIGURED_TIMEOUT).await;
    // The answer shows that the handshake reached the validation stage.
    let mut byte = [0u8; 1];
    assert!(
        matches!(client.read(&mut byte).await, Ok(1)),
        "the server did not answer the ClientHello"
    );
}
