use crate::crypto::digest::{Context, SHA256};
use crate::{AccountCache, CertCache};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::io::{ErrorKind, Write};
use std::path::Path;
use tokio::fs;

/// Suffix of the alternate chain file next to the certificate file.
const ALT_CERT_SUFFIX: &str = "_alt";

/// Mode of directories that [`DirCache`] creates.
#[cfg(unix)]
const DIR_MODE: u32 = 0o700;

/// A cache that stores certificates and account keys as files in a directory.
///
/// The files hold private keys. Files are written owner-only (`0600`) on Unix
/// and replaced atomically. The directory must not be writable by other users.
/// A crash during a write can leave a temporary file behind.
#[derive(Debug)]
pub struct DirCache<P: AsRef<Path> + Send + Sync> {
    inner: P,
}

impl<P: AsRef<Path> + Send + Sync> DirCache<P> {
    /// Creates a cache that stores its files in the directory `dir`.
    pub fn new(dir: P) -> Self {
        Self { inner: dir }
    }
    async fn read_if_exist(
        &self,
        file: impl AsRef<Path>,
    ) -> Result<Option<Vec<u8>>, std::io::Error> {
        let path = self.inner.as_ref().join(file);
        match fs::read(path).await {
            Ok(content) => Ok(Some(content)),
            Err(err) => match err.kind() {
                ErrorKind::NotFound => Ok(None),
                _ => Err(err),
            },
        }
    }
    async fn remove_if_exist(&self, file: impl AsRef<Path>) -> Result<(), std::io::Error> {
        match fs::remove_file(self.inner.as_ref().join(file)).await {
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }
    async fn write(
        &self,
        file: impl AsRef<Path>,
        contents: impl AsRef<[u8]>,
    ) -> Result<(), std::io::Error> {
        let dir = self.inner.as_ref().to_path_buf();
        let path = dir.join(file);
        let contents = contents.as_ref().to_vec();
        tokio::task::spawn_blocking(move || {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, DIR_MODE);
            builder.create(&dir)?;
            // `NamedTempFile` creates the file with mode `0600` on Unix.
            let mut tmp = tempfile::NamedTempFile::new_in(&dir)?;
            tmp.write_all(&contents)?;
            tmp.as_file().sync_all()?;
            tmp.persist(path).map_err(|err| err.error)?;
            Ok(())
        })
        .await
        .map_err(std::io::Error::other)?
    }

    fn cached_account_file_name(contact: &[String], directory_url: impl AsRef<str>) -> String {
        let mut ctx = Context::new(&SHA256);
        for el in contact {
            ctx.update(el.as_ref());
            ctx.update(&[0])
        }
        ctx.update(directory_url.as_ref().as_bytes());
        let hash = URL_SAFE_NO_PAD.encode(ctx.finish());
        format!("cached_account_{hash}")
    }
    fn cached_cert_file_name(domains: &[String], directory_url: impl AsRef<str>) -> String {
        let mut ctx = Context::new(&SHA256);
        for domain in domains {
            ctx.update(domain.as_ref());
            ctx.update(&[0])
        }
        ctx.update(directory_url.as_ref().as_bytes());
        let hash = URL_SAFE_NO_PAD.encode(ctx.finish());
        format!("cached_cert_{hash}")
    }
}

#[async_trait]
impl<P: AsRef<Path> + Send + Sync> CertCache for DirCache<P> {
    type EC = std::io::Error;
    async fn load_cert(
        &self,
        domains: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC> {
        let file_name = Self::cached_cert_file_name(domains, directory_url);
        self.read_if_exist(file_name).await
    }
    async fn store_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        cert: &[u8],
    ) -> Result<(), Self::EC> {
        let file_name = Self::cached_cert_file_name(domains, directory_url);
        self.write(file_name, cert).await
    }
    async fn load_alt_cert(
        &self,
        domains: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC> {
        let file_name = Self::cached_cert_file_name(domains, directory_url) + ALT_CERT_SUFFIX;
        self.read_if_exist(file_name).await
    }
    async fn store_alt_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        chain: Option<&[u8]>,
    ) -> Result<(), Self::EC> {
        let file_name = Self::cached_cert_file_name(domains, directory_url) + ALT_CERT_SUFFIX;
        match chain {
            Some(chain) => self.write(file_name, chain).await,
            None => self.remove_if_exist(file_name).await,
        }
    }
}

#[async_trait]
impl<P: AsRef<Path> + Send + Sync> AccountCache for DirCache<P> {
    type EA = std::io::Error;
    async fn load_account(
        &self,
        contact: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EA> {
        let file_name = Self::cached_account_file_name(contact, directory_url);
        self.read_if_exist(file_name).await
    }

    async fn store_account(
        &self,
        contact: &[String],
        directory_url: &str,
        account: &[u8],
    ) -> Result<(), Self::EA> {
        let file_name = Self::cached_account_file_name(contact, directory_url);
        self.write(file_name, account).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAINS: &[&str] = &["example.com"];
    const DIRECTORY_URL: &str = "https://acme.example/dir";

    #[tokio::test]
    async fn store_alt_cert_none_removes_the_alternate() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DirCache::new(dir.path());
        let domains: Vec<String> = DOMAINS.iter().map(|d| d.to_string()).collect();
        cache
            .store_alt_cert(&domains, DIRECTORY_URL, Some(b"alt"))
            .await
            .unwrap();
        assert_eq!(
            cache.load_alt_cert(&domains, DIRECTORY_URL).await.unwrap(),
            Some(b"alt".to_vec())
        );
        cache
            .store_alt_cert(&domains, DIRECTORY_URL, None)
            .await
            .unwrap();
        assert_eq!(
            cache.load_alt_cert(&domains, DIRECTORY_URL).await.unwrap(),
            None
        );
        // Removing again finds nothing to remove, which is fine.
        cache
            .store_alt_cert(&domains, DIRECTORY_URL, None)
            .await
            .unwrap();
    }
}
