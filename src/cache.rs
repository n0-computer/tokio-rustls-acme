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

    /// Load an alternate certificate chain (used for [`DualChain`](crate::CertChainPreference::DualChain) mode).
    /// Default implementation returns `Ok(None)`.
    async fn load_alt_cert(
        &self,
        _domains: &[String],
        _directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC> {
        Ok(None)
    }

    /// Store an alternate certificate chain (used for [`DualChain`](crate::CertChainPreference::DualChain) mode).
    /// Default implementation is a no-op.
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
