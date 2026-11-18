//! Tests for the file permissions of `DirCache`.
//!
//! `DirCache` stores the TLS private key and the ACME account key. Other
//! local users must not be able to read these files.

#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use tokio_rustls_acme::{AccountCache, CertCache, caches::DirCache};

const DIRECTORY_URL: &str = "https://acme.example/directory";

/// Sets the umask that most systems use by default.
///
/// With a stricter umask of the caller, the tests would pass whatever
/// `DirCache` does.
fn set_common_umask() {
    // SAFETY: `umask` only replaces the file mode creation mask of the
    // process and cannot fail. All tests in this binary set the same value.
    unsafe { libc::umask(0o022) };
}

/// Returns the only file in `dir` whose name starts with `prefix`.
fn cache_file(dir: &Path, prefix: &str) -> PathBuf {
    let mut files = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            let name = path.file_name().unwrap().to_string_lossy();
            name.starts_with(prefix)
        });
    let file = files.next().expect("cache file exists");
    assert!(files.next().is_none(), "more than one {prefix} file");
    file
}

/// Returns the permission bits of `path` for group and others.
fn group_and_other_bits(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o077
}

/// A stored TLS private key is readable by its owner only.
#[tokio::test]
async fn stored_certificate_key_is_owner_only() {
    set_common_umask();
    let dir = tempfile::tempdir().unwrap();
    let cache = DirCache::new(dir.path().join("cache"));

    cache
        .store_cert(
            &["example.com".to_string()],
            DIRECTORY_URL,
            b"key and chain",
        )
        .await
        .unwrap();

    let cache_dir = dir.path().join("cache");
    let file = cache_file(&cache_dir, "cached_cert_");
    assert_eq!(
        group_and_other_bits(&file),
        0,
        "other users can access the TLS private key in {file:?}"
    );
    assert_eq!(
        group_and_other_bits(&cache_dir),
        0,
        "other users can access the new cache directory {cache_dir:?}"
    );
    assert_eq!(
        fs::read_dir(&cache_dir).unwrap().count(),
        1,
        "the cache directory holds files other than the certificate"
    );
}

/// Only the new cache directory is owner-only, its missing parents are not.
///
/// The parents hold no secrets. Other service users may need to traverse
/// them, so they get the default permissions of the umask.
#[tokio::test]
async fn missing_parents_get_default_permissions() {
    set_common_umask();
    let dir = tempfile::tempdir().unwrap();
    let app_dir = dir.path().join("app");
    let data_dir = app_dir.join("data");
    let cache_dir = data_dir.join("acme");
    let cache = DirCache::new(&cache_dir);

    cache
        .store_account(&[], DIRECTORY_URL, b"account key")
        .await
        .unwrap();

    // Octal strings make a failure readable.
    let mode = |path: &Path| {
        format!(
            "{:o}",
            fs::metadata(path).unwrap().permissions().mode() & 0o777
        )
    };
    assert_eq!(mode(&cache_dir), "700", "cache directory {cache_dir:?}");
    assert_eq!(mode(&data_dir), "755", "parent {data_dir:?}");
    assert_eq!(mode(&app_dir), "755", "parent {app_dir:?}");
}

/// A stored ACME account key is readable by its owner only.
#[tokio::test]
async fn stored_account_key_is_owner_only() {
    set_common_umask();
    let dir = tempfile::tempdir().unwrap();
    let cache = DirCache::new(dir.path().join("cache"));

    cache
        .store_account(&[], DIRECTORY_URL, b"account key")
        .await
        .unwrap();

    let file = cache_file(&dir.path().join("cache"), "cached_account_");
    assert_eq!(
        group_and_other_bits(&file),
        0,
        "other users can access the ACME account key in {file:?}"
    );
}

/// A renewed TLS private key is readable by its owner only, even when it
/// replaces a world-readable file.
#[tokio::test]
async fn renewed_certificate_key_is_owner_only() {
    set_common_umask();
    let dir = tempfile::tempdir().unwrap();
    let cache = DirCache::new(dir.path());
    let domains = ["example.com".to_string()];

    // A file as a release without the fix created it.
    cache
        .store_cert(&domains, DIRECTORY_URL, b"old key and chain")
        .await
        .unwrap();
    let file = cache_file(dir.path(), "cached_cert_");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();

    cache
        .store_cert(&domains, DIRECTORY_URL, b"new key and chain")
        .await
        .unwrap();

    assert_eq!(
        group_and_other_bits(&file),
        0,
        "the renewed TLS private key in {file:?} kept the old open permissions"
    );
}

/// A symlink at the name of a cache file does not redirect the TLS private key.
///
/// The cache directory must not be writable by others, so no other user can
/// plant such a symlink. The rename is defense in depth: a stray symlink does
/// not send the key to another file.
#[tokio::test]
async fn certificate_key_is_not_written_through_symlink() {
    set_common_umask();
    let dir = tempfile::tempdir().unwrap();
    let cache_dir = dir.path().join("cache");
    let outside = dir.path().join("outside");
    let cache = DirCache::new(&cache_dir);
    let domains = ["example.com".to_string()];

    // Find the file name of the cache entry, then plant the symlink there.
    cache
        .store_cert(&domains, DIRECTORY_URL, b"first key and chain")
        .await
        .unwrap();
    let file = cache_file(&cache_dir, "cached_cert_");
    fs::remove_file(&file).unwrap();
    fs::write(&outside, b"outside").unwrap();
    std::os::unix::fs::symlink(&outside, &file).unwrap();

    cache
        .store_cert(&domains, DIRECTORY_URL, b"new key and chain")
        .await
        .unwrap();

    assert_eq!(
        fs::read(&outside).unwrap(),
        b"outside",
        "the TLS private key was written through the symlink"
    );
    assert!(
        fs::symlink_metadata(&file).unwrap().file_type().is_file(),
        "the cache entry {file:?} is not a regular file"
    );
    assert_eq!(fs::read(&file).unwrap(), b"new key and chain");
}
