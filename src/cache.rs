use std::fmt::{Debug, Display};

use async_trait::async_trait;

pub trait Cache: CertCache + AccountCache + Display {}

impl<T> Cache for T where T: CertCache + AccountCache + Display {}

#[async_trait]
pub trait CertCache: Send + Sync + Display {
    type EC: Debug + Display;
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
}

#[async_trait]
pub trait AccountCache: Send + Sync + Display {
    type EA: Debug + Display;
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
