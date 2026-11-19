use crate::crypto::digest::{Context, SHA256};
use crate::{AccountCache, CertCache};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::fs::Metadata;
use std::io::ErrorKind;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::fs;
use tokio::io::AsyncWriteExt;

/// Counter that makes the names of temporary files unique within the process.
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A cache that stores certificates and account keys as files in a directory.
///
/// The files hold private keys, and the cache trusts the files it loads. The
/// directory must belong to the user of the server and must not be writable
/// by others.
///
/// Each store writes a temporary file and renames it over the old file, so a
/// crash does not leave a truncated file. This needs write access to the
/// directory. If the rename is not possible, the cache writes an existing file
/// in place and logs a warning. On Unix, it does this only for a single-link
/// file of the process user or root, and never in a world-writable directory.
///
/// On Unix, new files get mode `0o600`, and a new cache directory gets mode
/// `0o700`. A replaced file keeps the group and group bits of the old file,
/// but not its bits for other users or its ACL.
///
/// A crash can leave a hidden `.tmp` file behind. You can delete it while no
/// store runs.
///
/// Earlier releases wrote the files with default permissions. After an
/// upgrade on Unix, run `chmod 600` on the files and `chmod 700` on the
/// directory.
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
        let target = dir.join(file);
        // No in-place write ever follows a symlink.
        let old = match fs::symlink_metadata(&target).await {
            Ok(metadata) if metadata.is_file() => Some(metadata),
            _ => None,
        };
        let (temp_path, temp_file) = match create_temp_file(dir, file).await {
            Ok(temp) => temp,
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                let Some(old) = old else {
                    return Err(err);
                };
                if !may_write_in_place(dir).await {
                    return Err(err);
                }
                let Ok(Some(handle)) = open_in_place(&target, &old).await else {
                    return Err(err);
                };
                log::warn!(
                    "cannot create a temporary file in {}: {err}. Writing {} in place. \
                     Give the process write access to the directory for crash-safe writes.",
                    dir.display(),
                    target.display(),
                );
                return overwrite(handle, contents).await;
            }
            Err(err) => return Err(err),
        };
        let result = async {
            #[cfg(unix)]
            let temp_file = match &old {
                Some(old) => keep_group_access(temp_file, old).await?,
                None => temp_file,
            };
            write_and_sync(temp_file, contents).await
        }
        .await;
        if let Err(err) = result {
            fs::remove_file(&temp_path).await.ok();
            return Err(err);
        }
        if let Err(err) = fs::rename(&temp_path, &target).await {
            fs::remove_file(&temp_path).await.ok();
            // `PermissionDenied` covers a sticky directory. If root owns the
            // old file there, the in-place write may still work.
            let cannot_replace = matches!(
                err.kind(),
                ErrorKind::ResourceBusy | ErrorKind::CrossesDevices | ErrorKind::PermissionDenied
            );
            let in_place = old.is_some() && cannot_replace && may_write_in_place(dir).await;
            let Some(old) = old.filter(|_| in_place) else {
                return Err(err);
            };
            let Ok(Some(handle)) = open_in_place(&target, &old).await else {
                return Err(err);
            };
            log::warn!(
                "cannot replace {}: {err}. Writing it in place. \
                 A crash during this write can leave a truncated file. \
                 See the DirCache docs for setups with crash-safe writes.",
                target.display(),
            );
            return overwrite(handle, contents).await;
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

/// Gives the new `file` the group and the group bits of the `old` file.
///
/// Requires that `old` passes [`may_overwrite`], because another user could
/// plant a file with a group of their choice. Otherwise, or if the group
/// cannot be set, the file keeps mode `0o600`. The calls only touch the open
/// file, so they do not need a blocking thread.
#[cfg(unix)]
async fn keep_group_access(file: fs::File, old: &Metadata) -> Result<fs::File, std::io::Error> {
    let group_bits = old.mode() & 0o070;
    if group_bits == 0 {
        return Ok(file);
    }
    if !may_overwrite(old, euid()) {
        log::warn!(
            "the old cache file is not a regular file with one link of this user or root, \
             so the new file gets no group access.",
        );
        return Ok(file);
    }
    let file = file.into_std().await;
    let mode = if file.metadata()?.gid() == old.gid() {
        0o600 | group_bits
    } else {
        match std::os::unix::fs::fchown(&file, None, Some(old.gid())) {
            Ok(()) => 0o600 | group_bits,
            Err(err) => {
                // Group bits for another group would grant access the
                // operator did not choose.
                log::warn!(
                    "cannot give the new cache file the group {} of the old file: {err}. \
                     The new file gets no group access.",
                    old.gid(),
                );
                0o600
            }
        }
    };
    file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    Ok(fs::File::from_std(file))
}

/// Returns whether the cache may write an existing file in `dir` in place.
///
/// On Unix, refuses a directory that other users can write. They could plant
/// a file at a cache name and read the key from it.
#[cfg(unix)]
async fn may_write_in_place(dir: &Path) -> bool {
    match fs::metadata(dir).await {
        Ok(metadata) if metadata.mode() & 0o002 == 0 => true,
        Ok(_) => {
            log::warn!(
                "{} is writable by other users, so the cache does not write in place there.",
                dir.display(),
            );
            false
        }
        Err(_) => false,
    }
}

/// Returns whether the cache may write an existing file in `dir` in place.
#[cfg(not(unix))]
async fn may_write_in_place(_dir: &Path) -> bool {
    true
}

/// Opens `target` for an in-place write, or returns `None` if it must not.
///
/// Checks the open handle against `old`, so a file swapped in after the first
/// check is not written.
async fn open_in_place(target: &Path, old: &Metadata) -> Result<Option<fs::File>, std::io::Error> {
    let mut options = fs::OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options.open(target).await?;
    let metadata = file.metadata().await?;
    if !is_same_file(&metadata, old) {
        log::warn!(
            "{} changed during the store, so the cache does not write it in place.",
            target.display()
        );
        return Ok(None);
    }
    #[cfg(unix)]
    if !may_overwrite(&metadata, euid()) {
        log::warn!(
            "{} is not a regular file with one link of this user or root, \
             so the cache does not write it in place.",
            target.display()
        );
        return Ok(None);
    }
    Ok(Some(file))
}

/// Overwrites the opened `file` with `contents` and syncs it.
///
/// On Unix, the function first removes the permission bits for other users.
async fn overwrite(file: fs::File, contents: &[u8]) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        let mode = file.metadata().await?.mode();
        if mode & 0o007 != 0 {
            file.set_permissions(std::fs::Permissions::from_mode(mode & 0o7770))
                .await?;
        }
    }
    file.set_len(0).await?;
    write_and_sync(file, contents).await
}

/// Returns whether `a` and `b` describe the same file.
#[cfg(unix)]
fn is_same_file(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

/// Returns whether `a` and `b` describe the same file.
///
/// Other platforms have no stable file ID in `std`, so this only checks that
/// `a` is a regular file.
#[cfg(not(unix))]
fn is_same_file(a: &Metadata, _b: &Metadata) -> bool {
    a.is_file()
}

/// Returns the effective user ID of the process.
#[cfg(unix)]
fn euid() -> u32 {
    // SAFETY: `geteuid` only reads the effective user ID and cannot fail.
    unsafe { libc::geteuid() }
}

/// Returns whether the cache trusts a file that the user `uid` owns.
#[cfg(unix)]
fn is_trusted_owner(uid: u32, euid: u32) -> bool {
    uid == euid || uid == 0
}

/// Returns whether the cache may write the file with `metadata` in place.
///
/// A second link could expose the key under a name the cache does not control.
#[cfg(unix)]
fn may_overwrite(metadata: &Metadata, euid: u32) -> bool {
    metadata.is_file() && metadata.nlink() == 1 && is_trusted_owner(metadata.uid(), euid)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn trusts_own_files_and_files_of_root() {
        assert!(is_trusted_owner(1000, 1000));
        assert!(is_trusted_owner(0, 1000));
        assert!(is_trusted_owner(0, 0));
        assert!(!is_trusted_owner(1001, 1000));
        assert!(!is_trusted_owner(1000, 0));
    }

    /// A hard-linked old file does not pass its group bits to the new file.
    #[tokio::test]
    async fn hard_linked_old_file_keeps_no_group_access() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("old");
        std::fs::write(&old, b"key").unwrap();
        std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o640)).unwrap();
        std::fs::hard_link(&old, dir.path().join("link")).unwrap();
        let metadata = std::fs::metadata(&old).unwrap();

        let new = dir.path().join("new");
        let file = fs::File::create(&new).await.unwrap();
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .await
            .unwrap();
        keep_group_access(file, &metadata).await.unwrap();

        let mode = std::fs::metadata(&new).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode {mode:o}");
    }

    #[test]
    fn overwrites_only_single_linked_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, b"key").unwrap();
        let metadata = std::fs::metadata(&file).unwrap();
        let owner = metadata.uid();
        assert!(may_overwrite(&metadata, owner));

        // A user ID that neither owns the file nor is root.
        let stranger = if owner == 1 { 2 } else { 1 };
        assert_eq!(may_overwrite(&metadata, stranger), owner == 0);

        std::fs::hard_link(&file, dir.path().join("link")).unwrap();
        assert!(!may_overwrite(&std::fs::metadata(&file).unwrap(), owner));

        assert!(!may_overwrite(
            &std::fs::metadata(dir.path()).unwrap(),
            owner
        ));
    }
}
