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
/// The files hold secrets. A certificate file starts with the private key of
/// the certificate. An account file holds the private key of the ACME account.
/// A user who can read these files can impersonate the server or control the
/// ACME account.
///
/// The directory must belong to the user of the server and must not be
/// writable by others. The cache trusts the files that it loads. A user who
/// can write to the directory can plant a key or a certificate.
///
/// The cache writes each file to a temporary file in the same directory first
/// and then renames it over the old file. Thus a crash or a full disk does not
/// leave a truncated file behind. For this, the process needs write access to
/// the directory, not only to the files.
///
/// On Unix, the cache syncs the directory after the rename, so the new file
/// survives a power loss. It also syncs the parent of each directory that it
/// creates. The sync opens the directory, which needs read access. Without
/// read access, or on a filesystem without directory sync, the cache skips the
/// sync. The store then succeeds, but a power loss can undo it.
///
/// The rename replaces a symlink at the name of a cache file with a regular
/// file. The cache never writes through such a symlink, and the target of the
/// symlink keeps its old content.
///
/// In three cases, the cache cannot rename and writes the old file in place,
/// as earlier releases did. It logs a warning, because a crash during this
/// write can leave a truncated file behind. The cases are:
///
/// - The process cannot create a file in the directory. Give the process write
///   access to the directory to fix this.
/// - The rename fails with `EBUSY` or `EXDEV`, for example because the file is
///   bind-mounted into a container. Mount the directory instead.
/// - The rename fails with `EPERM` or `EACCES`. In a sticky directory, this
///   happens when another user owns the old file. Let the user of the process
///   own the file to fix this.
///
/// On Unix, the cache writes in place only into a regular file with a single
/// link. The user of the process or root must own the file. Another user could
/// plant a file at the cache name and read the key from it. The cache also
/// never writes in place in a directory that all users can write. In these
/// cases, the store fails with the original error.
///
/// On Unix, the cache writes each new file with mode `0o600`. If the directory
/// does not exist, the cache creates it with mode `0o700`. Missing parents of
/// the directory get the default permissions. The cache does not change the
/// permissions of a directory that already exists.
///
/// A store that replaces a file keeps the group and the group bits of the old
/// file. Thus a sidecar with group access can still read the new file. The
/// user of the process owns the new file. The cache keeps the group only if
/// the user of the process or root owns the old file. A file of another user
/// could be a trap that grants its group access to the key. If the cache does
/// not keep the group, the new file gets no group bits. The new file never
/// gets permission bits for other users.
///
/// The new file does not keep an ACL of the old file. On a file with an ACL,
/// the group bits show the ACL mask. Thus the owning group of the new file gets
/// the rights of that mask. Grant access through the group or through a default
/// ACL on the directory instead. An in-place write keeps the mode and the ACL
/// of the file as they are.
///
/// On other platforms, files and directories get the default permissions. On
/// Windows, they inherit the ACL of the parent directory.
///
/// A crash or a cancelled store can leave a hidden temporary file behind. Its
/// name ends in `.tmp`, and on Unix it has mode `0o600`. You can delete such a
/// file safely while no store runs.
///
/// Earlier releases of this crate wrote these files with the default
/// permissions. With the common umask `022`, other local users can read them.
/// The cache does not change the mode of a file when it reads it. An old
/// certificate file loses its bits for other users when the next renewal
/// replaces it, but it keeps its group bits. The crate writes an account file
/// only when it generates a new account key, so an old account file keeps its
/// mode. If you upgrade from such a release on Unix, run `chmod 600` on the
/// files and `chmod 700` on the directory.
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
    /// symlink, instead of writing through it. On Unix, a sync of the directory
    /// after the rename makes the new entry survive a power loss. If that sync
    /// fails with an unexpected error, the function returns the error although
    /// the new file is in place. If the function cannot create the temporary
    /// file or cannot rename it, it can write an existing regular file in
    /// place. The [`DirCache`] docs list these cases and their limits.
    async fn write(&self, file: &str, contents: &[u8]) -> Result<(), std::io::Error> {
        let mut dir = self.inner.as_ref();
        // An empty path means the current directory. Neither `mkdir` nor
        // `open` accepts it, so the cache spells it out.
        if dir.as_os_str().is_empty() {
            dir = Path::new(".");
        }
        create_dir(dir).await?;
        let target = dir.join(file);
        // `symlink_metadata` does not follow a symlink, so `old` is only set
        // for a regular file. The cache never writes through a symlink.
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
                let Some(handle) = open_in_place(&target, &old).await? else {
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
            // The write error matters more to the caller than a failed cleanup.
            fs::remove_file(&temp_path).await.ok();
            return Err(err);
        }
        if let Err(err) = fs::rename(&temp_path, &target).await {
            fs::remove_file(&temp_path).await.ok();
            // `PermissionDenied` covers a sticky directory in which another
            // user owns the old file. If root owns it, the in-place write may
            // still work.
            let cannot_replace = matches!(
                err.kind(),
                ErrorKind::ResourceBusy | ErrorKind::CrossesDevices | ErrorKind::PermissionDenied
            );
            let in_place = old.is_some() && cannot_replace && may_write_in_place(dir).await;
            let Some(old) = old.filter(|_| in_place) else {
                return Err(err);
            };
            let Some(handle) = open_in_place(&target, &old).await? else {
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
/// Missing parents get the default permissions, because they hold no secrets
/// and other users may need to traverse them. A directory that already exists
/// keeps its permissions. On Unix, the function syncs the parent of each
/// directory that it creates, so the new directory survives a power loss.
async fn create_dir(dir: &Path) -> Result<(), std::io::Error> {
    // `dir` and those of its parents that do not exist, innermost first.
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
/// Some filesystems do not support a sync of a directory and fail with
/// `EINVAL` or `ENOTSUP`. The function ignores these errors, as PostgreSQL
/// does, because the change in the directory has already succeeded. It also
/// ignores `EACCES`, because the sync must open the directory, which needs
/// read access. A process can change a directory with write access alone.
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
/// The function takes `file` by value and closes it before it returns. Thus
/// the cache holds no open handle to the file during the rename.
async fn write_and_sync(mut file: fs::File, contents: &[u8]) -> Result<(), std::io::Error> {
    file.write_all(contents).await?;
    // `sync_all` does not report errors of buffered writes, `flush` does.
    file.flush().await?;
    file.sync_all().await
}

/// Gives the new `file` the group and the group bits of the `old` file.
///
/// The file keeps mode `0o600` if the old file has no group bits or if the
/// function cannot change the group. It also keeps that mode if neither the
/// user of the process nor root owns the old file. Another user could plant
/// a file with a group of their choice, and a process of root could join it.
/// Bits for other users never carry over. The function sets the mode
/// explicitly, so the umask does not apply.
///
/// The calls only change the open file, so the function runs them directly
/// instead of on a blocking thread.
#[cfg(unix)]
async fn keep_group_access(file: fs::File, old: &Metadata) -> Result<fs::File, std::io::Error> {
    let group_bits = old.mode() & 0o070;
    if group_bits == 0 {
        return Ok(file);
    }
    if !is_trusted_owner(old.uid(), euid()) {
        log::warn!(
            "the old cache file belongs to user {}, so the new file gets no group access.",
            old.uid(),
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
                // Group bits for another group would grant access to users
                // that the operator did not choose.
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
/// On Unix, the function refuses a directory that other users can write. Such
/// a user can plant a regular file at a cache name, for example in `/tmp`. An
/// in-place write would put the key into that file, and its owner could read
/// it. A rename replaces a planted file instead, so it needs no such check.
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

/// Opens `target` for an in-place write if the cache may write it there.
///
/// The function returns `None` if the cache must not write the file. It opens the file without truncating it. It then checks that the
/// handle refers to the `old` file. Thus it does not write through a symlink
/// that replaced the file after the check. On Unix, the file must also pass
/// [`may_overwrite`]. The open does not follow a symlink and does not block on
/// a FIFO.
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
/// The file keeps its mode. A crash during the write can leave a truncated
/// file behind.
async fn overwrite(file: fs::File, contents: &[u8]) -> Result<(), std::io::Error> {
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
/// Other platforms have no stable file ID in `std`, so the function only
/// checks that `a` is a regular file.
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
///
/// The cache trusts files of the user `euid` of the process and of root.
/// Another user could plant a file at a cache name to read the key.
#[cfg(unix)]
fn is_trusted_owner(uid: u32, euid: u32) -> bool {
    uid == euid || uid == 0
}

/// Returns whether the cache may write the file with `metadata` in place.
///
/// The file must be a regular file with a single link, and its owner must
/// pass [`is_trusted_owner`]. A second link could expose the key under a
/// name that the cache does not control.
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
