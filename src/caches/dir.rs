use crate::crypto::digest::{Context, SHA256};
use crate::{AccountCache, CertCache};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::fs;
use tokio::io::AsyncWriteExt;

/// Counter that makes the names of temporary files unique within the process.
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A cache that stores certificates and account keys as files in a directory.
///
/// The files hold secrets. A certificate file starts with the private key of
/// the certificate. An account file holds the private key of the ACME account.
/// A user who can read these files can impersonate the server or control the
/// ACME account.
///
/// On Unix, the cache writes each file with mode `0o600`. If the directory
/// does not exist, the cache creates it and its missing parents with mode
/// `0o700`. The cache does not change the permissions of a directory that
/// already exists. On other platforms, files and directories get the default
/// permissions. On Windows, they inherit the ACL of the parent directory.
///
/// The cache writes each file to a temporary file in the same directory first
/// and then renames it over the old file. Thus a crash or a full disk does not
/// leave a truncated file behind.
///
/// Earlier releases of this crate wrote these files with the default
/// permissions. With the common umask `022`, other local users can read them.
/// The cache does not change the mode of a file when it reads it. An old
/// certificate file gets mode `0o600` when the next renewal replaces it. The
/// crate writes an account file only when it generates a new account key, so
/// an old account file keeps its mode. If you upgrade from such a release on
/// Unix, run `chmod 600` on the files and `chmod 700` on the directory.
pub struct DirCache<P: AsRef<Path> + Send + Sync> {
    inner: P,
}

impl<P: AsRef<Path> + Send + Sync> DirCache<P> {
    /// Creates a cache that stores its files in `dir`.
    ///
    /// The cache creates the directory when it writes the first file.
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
    /// Replaces `file` in the cache directory with `contents`.
    ///
    /// The rename also replaces an old file with open permissions or a planted
    /// symlink, instead of writing through it.
    async fn write(&self, file: &str, contents: &[u8]) -> Result<(), std::io::Error> {
        let dir = self.inner.as_ref();
        create_dir(dir).await?;
        let (temp_path, temp_file) = create_temp_file(dir, file).await?;
        let result = async {
            write_and_sync(temp_file, contents).await?;
            fs::rename(&temp_path, dir.join(file)).await
        }
        .await;
        if result.is_err() {
            // The write error matters more to the caller than a failed cleanup.
            fs::remove_file(&temp_path).await.ok();
        }
        result
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
        self.write(&file_name, cert).await
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
        self.write(&file_name, account).await
    }
}

/// Creates `dir` and its missing parents, on Unix with mode `0o700`.
///
/// A directory that already exists keeps its permissions.
async fn create_dir(dir: &Path) -> Result<(), std::io::Error> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder.create(dir).await
}

/// Creates a new temporary file for `file` in `dir`, on Unix with mode `0o600`.
///
/// The file name holds the process ID and a counter, so concurrent writers do
/// not collide. `create_new` fails on any existing path, a symlink included.
/// If the name exists, for example as a file that a crash left behind, the
/// function tries the next counter value.
async fn create_temp_file(dir: &Path, file: &str) -> Result<(PathBuf, fs::File), std::io::Error> {
    loop {
        let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!(".{file}.{}.{counter}.tmp", std::process::id()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&path).await {
            Ok(temp_file) => return Ok((path, temp_file)),
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
}

/// Writes `contents` to `file`, syncs it to disk, and closes it.
///
/// The file must be closed before the rename because Windows cannot rename an
/// open file.
async fn write_and_sync(mut file: fs::File, contents: &[u8]) -> Result<(), std::io::Error> {
    file.write_all(contents).await?;
    // `sync_all` does not report errors of buffered writes, `flush` does.
    file.flush().await?;
    file.sync_all().await
}
