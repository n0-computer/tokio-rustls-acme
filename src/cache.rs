use std::fmt::Debug;

use async_trait::async_trait;

/// A cache for both certificates and account keys.
pub trait Cache: CertCache + AccountCache {}

impl<T> Cache for T where T: CertCache + AccountCache {}

/// Storage for issued certificates and their private keys.
#[async_trait]
pub trait CertCache: Send + Sync {
    /// Error returned when loading or storing a certificate fails.
    type EC: Debug;
    /// Loads the PEM bundle stored for `domains` and `directory_url`, if any.
    async fn load_cert(
        &self,
        domains: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC>;
    /// Stores `cert`, a PEM private key followed by the certificate chain.
    async fn store_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        cert: &[u8],
    ) -> Result<(), Self::EC>;

    /// Loads the alternate chain of [`CertChainPreference::DualChain`], see `store_alt_cert`.
    ///
    /// The default implementation stores nothing, so a restart serves no alternate until the
    /// next renewal. A cache that wraps another must forward both methods. The state machine
    /// gives up on either after 10 seconds, and only logs it.
    ///
    /// [`CertChainPreference::DualChain`]: crate::CertChainPreference::DualChain
    async fn load_alt_cert(
        &self,
        _domains: &[String],
        _directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC> {
        Ok(None)
    }

    /// Stores the alternate chain `chain`, or removes the stored one if it is `None`.
    ///
    /// `chain` is PEM certificates, leaf first, without a key: it uses the certificate's key.
    async fn store_alt_cert(
        &self,
        _domains: &[String],
        _directory_url: &str,
        _chain: Option<&[u8]>,
    ) -> Result<(), Self::EC> {
        Ok(())
    }
}

/// Storage for ACME account keys.
#[async_trait]
pub trait AccountCache: Send + Sync {
    /// Error returned when loading or storing an account key fails.
    type EA: Debug;
    /// Loads the account key stored for `contact` and `directory_url`, if any.
    async fn load_account(
        &self,
        contact: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EA>;
    /// Stores `account`, a PKCS#8 DER account key, for `contact` and `directory_url`.
    async fn store_account(
        &self,
        contact: &[String],
        directory_url: &str,
        account: &[u8],
    ) -> Result<(), Self::EA>;
}
