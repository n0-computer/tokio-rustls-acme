use std::fmt::Debug;

use async_trait::async_trait;

pub trait Cache: CertCache + AccountCache {}

impl<T> Cache for T where T: CertCache + AccountCache {}

#[async_trait]
pub trait CertCache: Send + Sync {
    type EC: Debug;
    async fn load_cert(
        &self,
        domains: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC>;
    async fn store_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        cert: &[u8],
    ) -> Result<(), Self::EC>;

    /// Loads the alternate certificate chain stored by [`CertCache::store_alt_cert`].
    ///
    /// Used with [`CertChainPreference::DualChain`](crate::CertChainPreference::DualChain),
    /// which serves an alternate chain next to the default one (RFC 8555 §7.4.2).
    /// The default implementation stores nothing, so the alternate is
    /// fetched again with the next order.
    async fn load_alt_cert(
        &self,
        _domains: &[String],
        _directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC> {
        Ok(None)
    }

    /// Stores the alternate certificate chain. See [`CertCache::load_alt_cert`].
    async fn store_alt_cert(
        &self,
        _domains: &[String],
        _directory_url: &str,
        _cert: &[u8],
    ) -> Result<(), Self::EC> {
        Ok(())
    }
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
