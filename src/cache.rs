use std::fmt::Debug;

use async_trait::async_trait;

pub trait Cache: CertCache + AccountCache {}

impl<T> Cache for T where T: CertCache + AccountCache {}

/// Identifies which certificate chain variant to load or store.
///
/// ACME servers may offer multiple certificate chains for the same certificate
/// (see [RFC 8555 Section 7.4.2](https://datatracker.ietf.org/doc/html/rfc8555#section-7.4.2)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CertChainKind {
    /// The default (primary) certificate chain.
    Default,
    /// An alternate certificate chain (e.g., from `Link: rel="alternate"` headers).
    Alternate,
}

#[async_trait]
pub trait CertCache: Send + Sync {
    type EC: Debug;
    async fn load_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        chain: CertChainKind,
    ) -> Result<Option<Vec<u8>>, Self::EC>;
    async fn store_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        chain: CertChainKind,
        cert: &[u8],
    ) -> Result<(), Self::EC>;
}

#[async_trait]
pub trait AccountCache: Send + Sync {
    type EA: Debug;
    async fn load_account(
        &self,
        contact: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EA>;
    async fn store_account(
        &self,
        contact: &[String],
        directory_url: &str,
        account: &[u8],
    ) -> Result<(), Self::EA>;
}
