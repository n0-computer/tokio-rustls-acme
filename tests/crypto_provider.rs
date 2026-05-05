//! End-to-end TLS handshake tests against `AcmeConfig::crypto_provider`.
//!
//! Each test installs a specific `CryptoProvider` on the config, drives the
//! state machine until `TestCache` yields a self-signed chain, and verifies a
//! TLS handshake succeeds against the resolver. This exercises both the
//! `parse_cert` path (which uses `provider.key_provider.load_private_key`)
//! and the runtime handshake.
//!
//! `rustls` is also a dev-dependency with the `ring` feature on, so tests
//! can construct a provider even when the crate is built without either of
//! the `ring`/`aws-lc-rs` crate features. That mirrors how a downstream
//! user would integrate a third-party provider.

#![cfg(feature = "rustls-tls-webpki-roots")]

use std::{convert::TryFrom, io, sync::Arc, time::Duration};

use futures::StreamExt;
use rustls::{
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName},
    ClientConfig, RootCertStore, DEFAULT_VERSIONS,
};
use tokio_rustls_acme::{caches::TestCache, AcmeConfig, EventOk, ResolvesServerCertAcme};

const DOMAIN: &str = "example.com";

fn client_config_with_roots(provider: Arc<CryptoProvider>, ca_pem: &[u8]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for p in pem::parse_many(ca_pem).expect("parse CA PEM") {
        roots
            .add(CertificateDer::from(p.into_contents()))
            .expect("add CA to root store");
    }
    Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(DEFAULT_VERSIONS)
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Run the state machine against `TestCache` until a cached cert is deployed.
async fn deploy_test_cert(provider: Arc<CryptoProvider>) -> (Arc<ResolvesServerCertAcme>, String) {
    let test_cache = TestCache::<io::Error, io::Error>::new();
    let ca_pem = test_cache.ca_pem().to_string();

    let mut state = AcmeConfig::new_with_crypto_provider([DOMAIN], provider)
        .cache(test_cache)
        .state();
    let resolver = state.resolver();

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match state.next().await {
                Some(Ok(EventOk::DeployedCachedCert)) => return,
                Some(Ok(_)) => {}
                Some(Err(err)) => panic!("state error: {:?}", err),
                None => panic!("state stream ended"),
            }
        }
    })
    .await
    .expect("timed out waiting for cached cert deploy");

    (resolver, ca_pem)
}

/// In-process TLS handshake against the resolver. Returns the leaf cert.
async fn tls_handshake(
    resolver: Arc<ResolvesServerCertAcme>,
    server_provider: Arc<CryptoProvider>,
    client_provider: Arc<CryptoProvider>,
    ca_pem: &str,
) -> CertificateDer<'static> {
    let server_config = Arc::new(
        rustls::ServerConfig::builder_with_provider(server_provider)
            .with_protocol_versions(DEFAULT_VERSIONS)
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(resolver),
    );
    let acceptor = tokio_rustls::TlsAcceptor::from(server_config);

    let client_config = client_config_with_roots(client_provider, ca_pem.as_bytes());
    let connector = tokio_rustls::TlsConnector::from(client_config);

    let (client_io, server_io) = tokio::io::duplex(4096);
    let server_name = ServerName::try_from(DOMAIN).unwrap().to_owned();

    let (client_result, server_result) = tokio::join!(
        connector.connect(server_name, client_io),
        acceptor.accept(server_io),
    );

    server_result.expect("server handshake");
    let client_tls = client_result.expect("client handshake");
    let (_, conn) = client_tls.get_ref();
    conn.peer_certificates().expect("peer certs")[0]
        .clone()
        .into_owned()
}

async fn roundtrip(provider: Arc<CryptoProvider>) {
    let (resolver, ca_pem) = deploy_test_cert(provider.clone()).await;
    let leaf = tls_handshake(resolver, provider.clone(), provider, &ca_pem).await;
    assert!(!leaf.as_ref().is_empty(), "leaf cert must not be empty");
}

#[cfg(feature = "ring")]
#[tokio::test]
async fn ring_provider_explicit() {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    roundtrip(provider).await;
}

#[cfg(feature = "aws-lc-rs")]
#[tokio::test]
async fn aws_lc_rs_provider_explicit() {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    roundtrip(provider).await;
}

/// Mixed handshake: server runs ring, client runs aws-lc-rs. Confirms the
/// `CertifiedKey` resolved by `AcmeState` interoperates across providers.
#[cfg(all(feature = "ring", feature = "aws-lc-rs"))]
#[tokio::test]
async fn ring_server_aws_lc_rs_client() {
    let server_provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    let (resolver, ca_pem) = deploy_test_cert(server_provider.clone()).await;
    let leaf = tls_handshake(resolver, server_provider, client_provider, &ca_pem).await;
    assert!(!leaf.as_ref().is_empty());
}

/// Verifies the crate works when neither `ring` nor `aws-lc-rs` crate
/// features are enabled and no default provider has been installed. The
/// caller must supply a `CryptoProvider` explicitly via
/// `AcmeConfig::crypto_provider`.
///
/// Compiled only in that configuration. The `rustls` dev-dependency carries
/// the `ring` feature so the test can still construct a provider, just as
/// a downstream user would do with their own provider crate.
#[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
#[tokio::test]
async fn no_built_in_provider() {
    assert!(
        rustls::crypto::CryptoProvider::get_default().is_none(),
        "no provider should be installed in this configuration",
    );
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    roundtrip(provider).await;
}
