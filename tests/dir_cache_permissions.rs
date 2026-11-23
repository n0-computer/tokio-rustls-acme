//! Unix tests for the file modes and symlink handling of `DirCache`.

#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use tokio_rustls_acme::{AccountCache, CertCache, caches::DirCache};

const DIRECTORY_URL: &str = "https://acme.example/directory";
/// Umask that lets group and others read new files.
const COMMON_UMASK: libc::mode_t = 0o022;
/// Mask of the permission bits in a file mode.
const PERMISSION_BITS: u32 = 0o777;
/// Expected mode of cache files.
const FILE_MODE: u32 = 0o600;
/// Expected mode of cache directories.
const DIR_MODE: u32 = 0o700;

/// Sets umask `022`, so a stricter umask of the caller cannot hide a bug.
fn set_common_umask() {
    // SAFETY: `umask` only replaces the file mode creation mask of the
    // process and cannot fail. The other test in this binary does not depend on
    // the umask.
    unsafe { libc::umask(COMMON_UMASK) };
}

/// Returns the only file in `dir` whose name starts with `prefix`.
fn cache_file(dir: &Path, prefix: &str) -> PathBuf {
    let mut files = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(prefix)
        });
    let file = files.next().expect("cache file exists");
    assert!(files.next().is_none(), "more than one {prefix} file");
    file
}

/// Returns the permission bits of `path`.
fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & PERMISSION_BITS
}

/// New files are `0600` and new directories, including missing parents, are `0700`.
#[tokio::test]
async fn new_files_and_directories_are_owner_only() {
    set_common_umask();
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("parent");
    let cache_dir = parent.join("cache");
    let cache = DirCache::new(&cache_dir);

    cache
        .store_cert(&["example.com".to_string()], DIRECTORY_URL, b"key")
        .await
        .unwrap();
    cache
        .store_account(&[], DIRECTORY_URL, b"account key")
        .await
        .unwrap();

    for prefix in ["cached_cert_", "cached_account_"] {
        let file = cache_file(&cache_dir, prefix);
        assert_eq!(mode(&file), FILE_MODE, "{file:?}");
    }
    assert_eq!(mode(&cache_dir), DIR_MODE, "{cache_dir:?}");
    assert_eq!(mode(&parent), DIR_MODE, "{parent:?}");
}

/// A symlink at the name of a cache file is replaced, not written through.
#[tokio::test]
async fn symlink_is_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let cache_dir = dir.path().join("cache");
    let outside = dir.path().join("outside");
    let cache = DirCache::new(&cache_dir);
    let domains = ["example.com".to_string()];

    // The first store reveals the file name for the symlink.
    cache
        .store_cert(&domains, DIRECTORY_URL, b"first")
        .await
        .unwrap();
    let file = cache_file(&cache_dir, "cached_cert_");
    fs::remove_file(&file).unwrap();
    fs::write(&outside, b"outside").unwrap();
    std::os::unix::fs::symlink(&outside, &file).unwrap();

    cache
        .store_cert(&domains, DIRECTORY_URL, b"second")
        .await
        .unwrap();

    assert_eq!(fs::read(&outside).unwrap(), b"outside");
    assert!(fs::symlink_metadata(&file).unwrap().file_type().is_file());
    assert_eq!(fs::read(&file).unwrap(), b"second");
}
