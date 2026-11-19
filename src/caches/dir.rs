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
/// The files hold private keys. The directory must belong to the user of the
/// server and must not be writable by others.
///
/// Each store writes a temporary file and renames it over the old file, so a
/// crash does not leave a truncated file. This needs write access to the
/// directory. On Unix, new files get mode `0o600`, and a new cache directory
/// gets mode `0o700`.
///
/// A crash can leave a hidden `.tmp` file behind. You can delete it while no
/// store runs.
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
    /// If the directory sync after the rename fails, the function returns the
    /// error although the new file is in place.
    async fn write(&self, file: &str, contents: &[u8]) -> Result<(), std::io::Error> {
        let mut dir = self.inner.as_ref();
        // `mkdir` and `open` reject the empty path.
        if dir.as_os_str().is_empty() {
            dir = Path::new(".");
        }
        create_dir(dir).await?;
        let (temp_path, temp_file) = create_temp_file(dir, file).await?;
        let result = match write_and_sync(temp_file, contents).await {
            Ok(()) => fs::rename(&temp_path, dir.join(file)).await,
            Err(err) => Err(err),
        };
        if let Err(err) = result {
            fs::remove_file(&temp_path).await.ok();
            return Err(err);
        }
        #[cfg(unix)]
        sync_dir(dir).await?;
        Ok(())
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

/// Creates `dir` and its missing parents, `dir` on Unix with mode `0o700`.
///
/// Parents get the default permissions, so other users can traverse them.
/// On Unix, the function syncs the parent of each directory it creates.
async fn create_dir(dir: &Path) -> Result<(), std::io::Error> {
    let mut missing = Vec::new();
    for path in dir.ancestors() {
        // The empty parent of a relative path is the current directory.
        if path.as_os_str().is_empty() {
            break;
        }
        match fs::metadata(path).await {
            Ok(_) => break,
            Err(err) if err.kind() == ErrorKind::NotFound => missing.push(path),
            Err(err) => return Err(err),
        }
    }
    for path in missing.into_iter().rev() {
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        if path == dir {
            builder.mode(0o700);
        }
        match builder.create(path).await {
            Ok(()) => {
                #[cfg(unix)]
                sync_dir(parent_dir(path)).await?;
            }
            // Another store created the directory concurrently.
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {}
            Err(err) => return Err(err),
        }
    }
    let metadata = fs::metadata(dir).await?;
    if !metadata.is_dir() {
        return Err(std::io::Error::new(
            ErrorKind::AlreadyExists,
            format!("{} exists and is not a directory", dir.display()),
        ));
    }
    Ok(())
}

/// Returns the parent of `path`, or the current directory for a relative name.
#[cfg(unix)]
fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Syncs `dir` to disk, so a new entry in it survives a power loss.
///
/// Ignores `EINVAL` and `ENOTSUP` from filesystems without directory sync, as
/// PostgreSQL does. Ignores `EACCES`, because the open needs read access.
#[cfg(unix)]
async fn sync_dir(dir: &Path) -> Result<(), std::io::Error> {
    let result = match fs::File::open(dir).await {
        Ok(handle) => handle.sync_all().await,
        Err(err) => Err(err),
    };
    match result {
        Err(err)
            if matches!(
                err.kind(),
                ErrorKind::InvalidInput | ErrorKind::Unsupported | ErrorKind::PermissionDenied
            ) =>
        {
            Ok(())
        }
        result => result,
    }
}

/// Creates a new temporary file for `file` in `dir`, on Unix with mode `0o600`.
///
/// `create_new` refuses any existing path, a symlink included. On a collision,
/// the function tries the next counter value.
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
/// Takes `file` by value, so no handle stays open during the rename.
async fn write_and_sync(mut file: fs::File, contents: &[u8]) -> Result<(), std::io::Error> {
    file.write_all(contents).await?;
    // `sync_all` does not report errors of buffered writes, `flush` does.
    file.flush().await?;
    file.sync_all().await
}
