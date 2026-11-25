//! In-process HTTP(S) and scripted ACME servers on `127.0.0.1` for tests.

#![allow(
    dead_code,
    reason = "each test binary uses a different subset of these helpers"
)]

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    PKCS_ECDSA_P256_SHA256, PublicKeyData, SignatureAlgorithm,
};
use rustls::{
    ClientConfig, DEFAULT_VERSIONS, DigitallySignedStruct, RootCertStore, ServerConfig,
    SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::TlsAcceptor;
use x509_parser::{
    certificate::X509Certificate, certification_request::X509CertificationRequest, prelude::FromDer,
};

/// ALPN protocol of the tls-alpn-01 challenge, RFC 8737 section 6.2.
pub(crate) const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

/// How often `wait_for_hits` checks the request count.
const HIT_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// OID of the `acmeIdentifier` extension, RFC 8737 section 6.1.
pub(crate) const ACME_IDENTIFIER_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];

/// Returns the provider all tests use for TLS, whatever the crate features select.
pub(crate) fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub(crate) fn client_config(roots: RootCertStore) -> Arc<ClientConfig> {
    Arc::new(
        ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(DEFAULT_VERSIONS)
            .expect("ring supports the default versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Builds a client config for tests that never reach an ACME server.
pub(crate) fn client_config_without_roots() -> Arc<ClientConfig> {
    client_config(RootCertStore::empty())
}

/// Accepts any certificate, but still checks the handshake signature.
///
/// It reads the public key with x509-parser because webpki rejects the
/// critical `acmeIdentifier` extension.
#[derive(Debug)]
pub(crate) struct AcceptAnyCert(pub(crate) Arc<CryptoProvider>);

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

/// A TLS identity for `127.0.0.1` and a client config that trusts it.
pub(crate) struct LocalTls {
    pub acceptor: TlsAcceptor,
    pub client_config: Arc<ClientConfig>,
}

pub(crate) fn local_tls() -> LocalTls {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate key");
    let cert = CertificateParams::new(vec!["127.0.0.1".to_string()])
        .expect("valid params")
        .self_signed(&key)
        .expect("self-sign");
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).expect("add root");
    let key: PrivateKeyDer<'static> = PrivatePkcs8KeyDer::from(key.serialize_der()).into();
    let server_config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(DEFAULT_VERSIONS)
        .expect("ring supports the default versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key)
        .expect("valid server identity");
    LocalTls {
        acceptor: TlsAcceptor::from(Arc::new(server_config)),
        client_config: client_config(roots),
    }
}

/// A byte stream of an accepted connection, with or without TLS.
pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

type ConnFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

#[derive(Debug, Clone)]
pub(crate) struct Request {
    pub method: String,
    pub path: String,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(crate) struct Response {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub(crate) fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub(crate) fn json(status: u16, body: &Value) -> Self {
        Self::new(status)
            .header("content-type", "application/json")
            .body(body.to_string())
    }

    pub(crate) fn header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    pub(crate) fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }
}

/// A server on `127.0.0.1` that stops when dropped.
pub(crate) struct Server {
    pub addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    pub(crate) async fn bind() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        (listener, addr)
    }

    /// Serves one request per connection with `handler`.
    pub(crate) fn start(
        listener: TcpListener,
        tls: Option<TlsAcceptor>,
        handler: impl Fn(Request) -> Response + Send + Sync + 'static,
    ) -> Self {
        let handler = Arc::new(handler);
        Self::start_raw(listener, tls, move |mut stream| {
            let handler = handler.clone();
            Box::pin(async move {
                let Ok(request) = read_request(&mut stream).await else {
                    return;
                };
                let response = handler(request);
                let _ = write_response(&mut stream, &response).await;
            })
        })
    }

    pub(crate) fn start_raw(
        listener: TcpListener,
        tls: Option<TlsAcceptor>,
        serve: impl Fn(Box<dyn Io>) -> ConnFuture + Send + Sync + 'static,
    ) -> Self {
        let addr = listener.local_addr().expect("local addr");
        let serve = Arc::new(serve);
        let task = tokio::spawn(async move {
            // Owns the connection tasks, so they stop with the server.
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((tcp, _)) = accepted else { continue };
                        let tls = tls.clone();
                        let serve = serve.clone();
                        connections.spawn(async move {
                            let stream: Box<dyn Io> = match tls {
                                None => Box::new(tcp),
                                Some(tls) => match tls.accept(tcp).await {
                                    Ok(stream) => Box::new(stream),
                                    Err(_) => return,
                                },
                            };
                            serve(stream).await;
                        });
                    }
                    Some(_) = connections.join_next() => {}
                }
            }
        });
        Self { addr, task }
    }
}

/// Reads one HTTP/1.1 request, with its body if it has a `content-length`.
pub(crate) async fn read_request(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Request> {
    let mut buf = Vec::new();
    let head_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split(' ');
    let method = request_line.next().unwrap_or_default().to_string();
    let path = request_line.next().unwrap_or_default().to_string();
    let headers: Vec<(&str, &str)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name, value.trim()))
        .collect();
    let header = |wanted: &str| {
        headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
            .map(|(_, value)| value.to_string())
    };
    let content_length = header("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let content_type = header("content-type");
    let mut body = buf[head_end..].to_vec();
    while body.len() < content_length {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Ok(Request {
        method,
        path,
        content_type,
        body,
    })
}

async fn write_response(
    stream: &mut (impl AsyncWrite + Unpin),
    response: &Response,
) -> io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} Mock\r\ncontent-length: {}\r\nconnection: close\r\n",
        response.status,
        response.body.len()
    );
    for (name, value) in &response.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&response.body).await?;
    stream.shutdown().await
}

/// Decodes a flattened JWS into its protected header and payload.
pub(crate) fn decode_jws(body: &[u8]) -> Option<(Value, Vec<u8>)> {
    let jws: Value = serde_json::from_slice(body).ok()?;
    let protected = URL_SAFE_NO_PAD
        .decode(jws.get("protected")?.as_str()?)
        .ok()?;
    let payload = URL_SAFE_NO_PAD.decode(jws.get("payload")?.as_str()?).ok()?;
    Some((serde_json::from_slice(&protected).ok()?, payload))
}

/// Returns the uncompressed public point of the P-256 key in `jwk`.
pub(crate) fn jwk_public_point(jwk: &Value) -> [u8; 65] {
    let coordinate = |name: &str| {
        let value = jwk[name].as_str().expect("JWK coordinate");
        URL_SAFE_NO_PAD.decode(value).expect("base64url coordinate")
    };
    [vec![0x04], coordinate("x"), coordinate("y")]
        .concat()
        .try_into()
        .expect("P-256 point")
}

fn unauthorized() -> Response {
    Response::json(
        403,
        &json!({"type": "urn:ietf:params:acme:error:unauthorized"}),
    )
    .header("content-type", "application/problem+json")
}

/// How the mock ACME server reports the order status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OrderScript {
    /// Follows RFC 8555: pending, ready, then valid after finalization.
    Normal,
    /// Reports `pending` forever, even when all authorizations are valid.
    AlwaysPending,
    /// Reports `ready`, but answers each finalization with `pending`.
    RevertsOnFinalize,
}

/// The mutable part of [`MockAcme`], open to the tests.
pub(crate) struct MockAcmeState {
    pub authz_status: &'static str,
    pub order_script: OrderScript,
    /// Validity of the certificates that the server issues.
    pub issue_validity: Validity,
    /// Token of the tls-alpn-01 challenge.
    pub token: String,
    /// Domain of the most recent order.
    pub domain: String,
    /// JWK of the most recent `newAccount` request.
    pub account_jwk: Option<Value>,
    /// Public point of an account key whose `newAccount` requests fail with `unauthorized`.
    pub deactivated_key: Option<[u8; 65]>,
    /// Answers the next finalization with `unauthorized`, then resets.
    pub reject_finalize: bool,
    /// Number of requests per `"METHOD /path"`.
    pub hits: HashMap<String, usize>,
    /// Arrival times of the requests per `"METHOD /path"`, on the real clock.
    pub arrivals: HashMap<String, Vec<Instant>>,
    /// JWS requests that break the RFC 8555 section 6 rules.
    pub jws_violations: Vec<String>,
    issued: Option<String>,
    nonce_counter: u64,
    issued_nonces: HashSet<String>,
    used_nonces: HashSet<String>,
}

impl MockAcmeState {
    pub(crate) fn hits(&self, route: &str) -> usize {
        self.hits.get(route).copied().unwrap_or(0)
    }

    /// Returns the arrival times of the requests to `route`, oldest first.
    pub(crate) fn arrivals(&self, route: &str) -> &[Instant] {
        self.arrivals.get(route).map_or(&[], Vec::as_slice)
    }
}

/// A scripted ACME server with its own CA.
///
/// It serves one account and one order at a time. It does not verify JWS
/// signatures.
pub(crate) struct MockAcme {
    pub directory_url: String,
    /// Client config that trusts the API endpoint of this server.
    pub client_config: Arc<ClientConfig>,
    /// Root store with the CA that signs the issued certificates.
    pub issued_roots: RootCertStore,
    pub state: Arc<Mutex<MockAcmeState>>,
    _server: Server,
}

impl MockAcme {
    pub(crate) async fn start() -> Self {
        let tls = local_tls();
        let (listener, addr) = Server::bind().await;
        let base = format!("https://{addr}");
        let ca = MockCa::new();
        let mut issued_roots = RootCertStore::empty();
        issued_roots
            .add(ca.cert_der.clone())
            .expect("add mock CA root");
        let state = Arc::new(Mutex::new(MockAcmeState {
            authz_status: "valid",
            order_script: OrderScript::Normal,
            issue_validity: Validity::Fresh,
            token: "bW9jay1hY21lLXRva2Vu".to_string(),
            domain: String::new(),
            account_jwk: None,
            deactivated_key: None,
            reject_finalize: false,
            hits: HashMap::new(),
            arrivals: HashMap::new(),
            jws_violations: Vec::new(),
            issued: None,
            nonce_counter: 0,
            issued_nonces: HashSet::new(),
            used_nonces: HashSet::new(),
        }));
        let server = Server::start(listener, Some(tls.acceptor), {
            let state = state.clone();
            let base = base.clone();
            move |request| handle_acme(&base, &ca, &state, request)
        });
        Self {
            directory_url: format!("{base}/dir"),
            client_config: tls.client_config,
            issued_roots,
            state,
            _server: server,
        }
    }

    pub(crate) fn state(&self) -> std::sync::MutexGuard<'_, MockAcmeState> {
        self.state.lock().expect("poisoned")
    }

    pub(crate) async fn wait_for_hits(&self, route: &str, count: usize, limit: Duration) {
        let reached = tokio::time::timeout(limit, async {
            while self.state().hits(route) < count {
                tokio::time::sleep(HIT_POLL_INTERVAL).await;
            }
        })
        .await;
        assert!(
            reached.is_ok(),
            "no {count} requests to {route} in {limit:?}"
        );
    }
}

fn handle_acme(
    base: &str,
    ca: &MockCa,
    state: &Mutex<MockAcmeState>,
    request: Request,
) -> Response {
    let mut state = state.lock().expect("poisoned");
    let route = format!("{} {}", request.method, request.path);
    *state.hits.entry(route.clone()).or_default() += 1;
    state
        .arrivals
        .entry(route.clone())
        .or_default()
        .push(Instant::now());

    let mut payload = Vec::new();
    if request.method == "POST" {
        let Some((protected, decoded)) = decode_jws(&request.body) else {
            state.jws_violations.push(format!("{route}: not a JWS"));
            return Response::new(400);
        };
        if request.content_type.as_deref() != Some("application/jose+json") {
            state.jws_violations.push(format!(
                "POST {}: content type is {:?}, not application/jose+json",
                request.path, request.content_type
            ));
        }
        check_jws_header(&mut state, base, &request.path, &protected);
        if POST_AS_GET.contains(&request.path.as_str()) && !decoded.is_empty() {
            state.jws_violations.push(format!(
                "POST {}: POST-as-GET payload is not empty",
                request.path
            ));
        }
        if request.path == "/acct" {
            state.account_jwk = protected.get("jwk").cloned();
        }
        payload = decoded;
    }

    match route.as_str() {
        "GET /dir" => Response::json(
            200,
            &json!({
                "newNonce": format!("{base}/nonce"),
                "newAccount": format!("{base}/acct"),
                "newOrder": format!("{base}/order"),
            }),
        ),
        "HEAD /nonce" => {
            state.nonce_counter += 1;
            let nonce = URL_SAFE_NO_PAD.encode(state.nonce_counter.to_be_bytes());
            state.issued_nonces.insert(nonce.clone());
            Response::new(200).header("replay-nonce", nonce)
        }
        "POST /acct"
            if state.deactivated_key.is_some()
                && state.account_jwk.as_ref().map(jwk_public_point) == state.deactivated_key =>
        {
            unauthorized()
        }
        "POST /acct" => Response::json(201, &json!({"status": "valid"}))
            .header("location", format!("{base}/acct/1")),
        "POST /order" => {
            let order: Value = serde_json::from_slice(&payload).unwrap_or_default();
            state.domain = order["identifiers"][0]["value"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            state.issued = None;
            Response::json(201, &order_json(base, &state))
                .header("location", format!("{base}/order/1"))
        }
        "POST /order/1" => Response::json(200, &order_json(base, &state)),
        "POST /authz/1" => Response::json(
            200,
            &json!({
                "status": state.authz_status,
                "identifier": {"type": "dns", "value": state.domain},
                "challenges": [{
                    "type": "tls-alpn-01",
                    "url": format!("{base}/chall/1"),
                    "token": state.token,
                    "status": "pending",
                }],
            }),
        ),
        "POST /chall/1" => Response::json(200, &json!({})),
        "POST /finalize/1" if state.reject_finalize => {
            state.reject_finalize = false;
            unauthorized()
        }
        "POST /finalize/1" if state.order_script == OrderScript::RevertsOnFinalize => {
            let mut order = order_json(base, &state);
            order["status"] = json!("pending");
            Response::json(200, &order)
        }
        "POST /finalize/1" => {
            let csr: Value = serde_json::from_slice(&payload).unwrap_or_default();
            let csr = URL_SAFE_NO_PAD
                .decode(csr["csr"].as_str().unwrap_or_default())
                .unwrap_or_default();
            state.issued = Some(ca.issue_for_csr(&csr, &state.domain, state.issue_validity));
            Response::json(200, &order_json(base, &state))
        }
        "POST /cert/1" => {
            let chain = state.issued.clone().unwrap_or_default();
            Response::new(200)
                .header("content-type", "application/pem-certificate-chain")
                .body(chain)
        }
        _ => Response::new(404),
    }
}

/// Paths that must receive a POST-as-GET request, RFC 8555 section 6.3.
const POST_AS_GET: [&str; 3] = ["/authz/1", "/order/1", "/cert/1"];

/// Records how `protected` deviates from RFC 8555 section 6.
fn check_jws_header(state: &mut MockAcmeState, base: &str, path: &str, protected: &Value) {
    let mut violation = |what: &str| {
        state
            .jws_violations
            .push(format!("POST {path}: {what}: {protected}"));
    };
    if protected["alg"] != "ES256" {
        violation("alg is not ES256");
    }
    if protected["url"] != format!("{base}{path}") {
        violation("url does not match the request URL");
    }
    match protected["nonce"]
        .as_str()
        .filter(|nonce| !nonce.is_empty())
    {
        None => violation("nonce is missing"),
        Some(nonce) if state.used_nonces.contains(nonce) => violation("nonce was used before"),
        Some(nonce) if !state.issued_nonces.contains(nonce) => violation("nonce was not issued"),
        Some(nonce) => {
            state.used_nonces.insert(nonce.to_string());
        }
    }
    let has_jwk = protected.get("jwk").is_some();
    let has_kid = protected.get("kid").is_some();
    if path == "/acct" && (!has_jwk || has_kid) {
        violation("newAccount must use jwk and no kid");
    }
    if path != "/acct" && (has_jwk || protected["kid"] != format!("{base}/acct/1")) {
        violation("request must use the account kid and no jwk");
    }
}

fn order_json(base: &str, state: &MockAcmeState) -> Value {
    let mut order = json!({
        "authorizations": [format!("{base}/authz/1")],
        "finalize": format!("{base}/finalize/1"),
    });
    let status = match state.order_script {
        OrderScript::AlwaysPending => "pending",
        OrderScript::RevertsOnFinalize => "ready",
        OrderScript::Normal if state.issued.is_some() => {
            order["certificate"] = json!(format!("{base}/cert/1"));
            "valid"
        }
        OrderScript::Normal if state.authz_status == "valid" => "ready",
        OrderScript::Normal => "pending",
    };
    order["status"] = json!(status);
    order
}

/// The validity period of a certificate that [`MockCa`] issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Validity {
    /// Valid from one day ago for 90 days.
    Fresh,
    /// Valid for one more day out of 90, so past the renewal time of the client.
    Due,
    /// Expired one day ago.
    Expired,
}

pub(crate) struct MockCa {
    issuer: Issuer<'static, KeyPair>,
    cert_pem: String,
    pub cert_der: CertificateDer<'static>,
}

/// The public key of a CSR, in the form rcgen needs to sign for it.
struct CsrPublicKey(Vec<u8>);

impl PublicKeyData for CsrPublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

impl MockCa {
    pub(crate) fn new() -> Self {
        let mut params = CertificateParams::default();
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "Mock ACME CA");
        params.distinguished_name = name;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate key");
        let cert = params.self_signed(&key).expect("self-sign");
        Self {
            cert_pem: cert.pem(),
            cert_der: cert.der().clone(),
            issuer: Issuer::new(params, key),
        }
    }

    pub(crate) fn issue_for_csr(&self, csr_der: &[u8], domain: &str, validity: Validity) -> String {
        let (_, csr) = X509CertificationRequest::from_der(csr_der).expect("parse CSR");
        let public_key = csr
            .certification_request_info
            .subject_pki
            .subject_public_key
            .data
            .to_vec();
        self.issue(&CsrPublicKey(public_key), domain, validity)
    }

    /// Issues a new key and chain for `domain` as cache PEM.
    pub(crate) fn issue_with_key(&self, domain: &str, validity: Validity) -> Vec<u8> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate key");
        let chain = self.issue(&key, domain, validity);
        format!("{}\n{chain}", key.serialize_pem()).into_bytes()
    }

    fn issue(&self, public_key: &impl PublicKeyData, domain: &str, validity: Validity) -> String {
        let mut params = CertificateParams::new(vec![domain.to_string()]).expect("valid domain");
        params.distinguished_name = DistinguishedName::new();
        let now = OffsetDateTime::now_utc();
        let day = time::Duration::days(1);
        (params.not_before, params.not_after) = match validity {
            Validity::Fresh => (now - day, now + 90 * day),
            Validity::Due => (now - 89 * day, now + day),
            Validity::Expired => (now - 2 * day, now - day),
        };
        let leaf = params
            .signed_by(public_key, &self.issuer)
            .expect("sign leaf");
        format!("{}\n{}", leaf.pem(), self.cert_pem)
    }
}
