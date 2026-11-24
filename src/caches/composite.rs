use crate::{AccountCache, CertCache};
use async_trait::async_trait;

/// A cache that keeps certificates in one cache and account keys in another.
pub struct CompositeCache<C: CertCache + Send + Sync, A: AccountCache + Send + Sync> {
    /// Cache that `load_cert` and `store_cert` delegate to.
    pub cert_cache: C,
    /// Cache that `load_account` and `store_account` delegate to.
    pub account_cache: A,
}

impl<C: CertCache + Send + Sync, A: AccountCache + Send + Sync> CompositeCache<C, A> {
    /// Combines `cert_cache` and `account_cache` into one cache.
    pub fn new(cert_cache: C, account_cache: A) -> Self {
        Self {
            cert_cache,
            account_cache,
        }
    }
    /// Returns the certificate cache and the account cache.
    pub fn into_inner(self) -> (C, A) {
        (self.cert_cache, self.account_cache)
    }
}

#[async_trait]
impl<C: CertCache + Send + Sync, A: AccountCache + Send + Sync> CertCache for CompositeCache<C, A> {
    type EC = C::EC;
    async fn load_cert(
        &self,
        domains: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC> {
        self.cert_cache.load_cert(domains, directory_url).await
    }

    async fn store_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        cert: &[u8],
    ) -> Result<(), Self::EC> {
        self.cert_cache
            .store_cert(domains, directory_url, cert)
            .await
    }

    async fn load_alt_cert(
        &self,
        domains: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC> {
        self.cert_cache.load_alt_cert(domains, directory_url).await
    }

    async fn store_alt_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        cert: &[u8],
    ) -> Result<(), Self::EC> {
        self.cert_cache
            .store_alt_cert(domains, directory_url, cert)
            .await
    }
}

#[async_trait]
impl<C: CertCache + Send + Sync, A: AccountCache + Send + Sync> AccountCache
    for CompositeCache<C, A>
{
    type EA = A::EA;
    async fn load_account(
        &self,
        contact: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EA> {
        self.account_cache
            .load_account(contact, directory_url)
            .await
    }

    async fn store_account(
        &self,
        contact: &[String],
        directory_url: &str,
        account: &[u8],
    ) -> Result<(), Self::EA> {
        self.account_cache
            .store_account(contact, directory_url, account)
            .await
    }
}
