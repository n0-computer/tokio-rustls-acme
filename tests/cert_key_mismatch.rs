//! A certificate must match its private key before it is deployed.

mod support;

use std::io;

use async_trait::async_trait;
use n0_future::StreamExt;
use tokio_rustls_acme::{
    AcmeConfig, CertCache, CertParseError, EventError,
    caches::{NoCache, TestCache},
};

const DOMAIN: &str = "example.com";

struct FixedCache {
    cert: Vec<u8>,
}

#[async_trait]
impl CertCache for FixedCache {
    type EC = io::Error;

    async fn load_cert(&self, _: &[String], _: &str) -> Result<Option<Vec<u8>>, io::Error> {
        Ok(Some(self.cert.clone()))
    }

    async fn store_cert(&self, _: &[String], _: &str, _: &[u8]) -> Result<(), io::Error> {
        Ok(())
    }
}

#[tokio::test]
async fn cached_certificate_with_foreign_key_is_rejected() {
    // Key of one test certificate, chain of another.
    let cache = TestCache::<io::Error, io::Error>::new();
    let domains = [DOMAIN.to_string()];
    let first = cache.load_cert(&domains, "").await.unwrap().unwrap();
    let second = cache.load_cert(&domains, "").await.unwrap().unwrap();
    let mut entry = pem::parse_many(first).unwrap();
    entry.truncate(1);
    entry.extend(pem::parse_many(second).unwrap().into_iter().skip(1));
    let cert = pem::encode_many(&entry).into_bytes();

    let mut state =
        AcmeConfig::new_with_client_tls_config([DOMAIN], support::client_config_without_roots())
            .cache_compose(FixedCache { cert }, NoCache::<io::Error, io::Error>::new())
            .state();
    let event = state.next().await.unwrap();

    assert!(
        matches!(
            event,
            Err(EventError::CachedCertParse(
                CertParseError::InvalidPrivateKey
            ))
        ),
        "expected the cached certificate to be rejected, got {event:?}"
    );
}
