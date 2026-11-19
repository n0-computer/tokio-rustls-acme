//! Tests that other local users cannot read the private keys in `DirCache`.

#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use tokio_rustls_acme::{AccountCache, CertCache, caches::DirCache};

const DIRECTORY_URL: &str = "https://acme.example/directory";

/// Sets umask `022`, so a stricter umask of the caller cannot hide a bug.
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

/// Returns the permission bits of `path` as an octal string.
fn mode(path: &Path) -> String {
    format!(
        "{:o}",
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    )
}

/// Returns whether the tests run as root, which ignores file permissions.
fn is_root() -> bool {
    // SAFETY: `geteuid` only reads the effective user ID and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// A stored TLS private key and ACME account key are readable by their owner only.
#[tokio::test]
async fn stored_keys_are_owner_only() {
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
    cache
        .store_account(&[], DIRECTORY_URL, b"account key")
        .await
        .unwrap();

    let cache_dir = dir.path().join("cache");
    for prefix in ["cached_cert_", "cached_account_"] {
        let file = cache_file(&cache_dir, prefix);
        assert_eq!(
            group_and_other_bits(&file),
            0,
            "other users can access the private key in {file:?}"
        );
    }
    assert_eq!(
        group_and_other_bits(&cache_dir),
        0,
        "other users can access the new cache directory {cache_dir:?}"
    );
    assert_eq!(
        fs::read_dir(&cache_dir).unwrap().count(),
        2,
        "the cache directory holds files other than the two keys"
    );
}

/// Only the new cache directory is owner-only, not its missing parents.
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

    assert_eq!(mode(&cache_dir), "700", "cache directory {cache_dir:?}");
    assert_eq!(mode(&data_dir), "755", "parent {data_dir:?}");
    assert_eq!(mode(&app_dir), "755", "parent {app_dir:?}");
}

/// Stores a certificate with `old_mode`, renews it, and returns the new mode.
async fn renew_with_old_mode(old_mode: u32) -> String {
    set_common_umask();
    let dir = tempfile::tempdir().unwrap();
    let cache = DirCache::new(dir.path());
    let domains = ["example.com".to_string()];

    cache
        .store_cert(&domains, DIRECTORY_URL, b"old key and chain")
        .await
        .unwrap();
    let file = cache_file(dir.path(), "cached_cert_");
    fs::set_permissions(&file, fs::Permissions::from_mode(old_mode)).unwrap();

    cache
        .store_cert(&domains, DIRECTORY_URL, b"new key and chain")
        .await
        .unwrap();

    assert_eq!(fs::read(&file).unwrap(), b"new key and chain");
    mode(&file)
}

/// A renewed TLS private key is owner-only, whatever the mode of the old file.
#[tokio::test]
async fn renewed_certificate_key_is_owner_only() {
    assert_eq!(renew_with_old_mode(0o644).await, "600");
}

/// A store into a directory without write access fails and leaves no file.
#[tokio::test]
async fn store_into_read_only_directory_fails() {
    if is_root() {
        return;
    }
    set_common_umask();
    let dir = tempfile::tempdir().unwrap();
    let cache_dir = dir.path().join("cache");
    fs::create_dir(&cache_dir).unwrap();
    fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o500)).unwrap();
    let cache = DirCache::new(&cache_dir);

    let result = cache
        .store_cert(&["example.com".to_string()], DIRECTORY_URL, b"key")
        .await;

    fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let err = result.expect_err("the store created a file in a read-only directory");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(fs::read_dir(&cache_dir).unwrap().count(), 0);
}

/// A store succeeds in a directory that the process can write but not read.
#[tokio::test]
async fn store_into_unreadable_directory_succeeds() {
    if is_root() {
        return;
    }
    set_common_umask();
    let dir = tempfile::tempdir().unwrap();
    let cache_dir = dir.path().join("cache");
    fs::create_dir(&cache_dir).unwrap();
    fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o300)).unwrap();
    let cache = DirCache::new(&cache_dir);
    let domains = ["example.com".to_string()];

    let result = cache
        .store_cert(&domains, DIRECTORY_URL, b"key and chain")
        .await;

    fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o700)).unwrap();
    result.unwrap();
    let cert = cache.load_cert(&domains, DIRECTORY_URL).await.unwrap();
    assert_eq!(cert.as_deref(), Some(&b"key and chain"[..]));
}

/// A symlink at the name of a cache file does not redirect the TLS private key.
#[tokio::test]
async fn certificate_key_is_not_written_through_symlink() {
    set_common_umask();
    let dir = tempfile::tempdir().unwrap();
    let cache_dir = dir.path().join("cache");
    let outside = dir.path().join("outside");
    let cache = DirCache::new(&cache_dir);
    let domains = ["example.com".to_string()];

    // The first store reveals the file name for the symlink.
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
