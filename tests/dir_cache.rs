//! Platform-independent tests for `DirCache`.
//!
//! Each store writes a temporary file and renames it over the cache entry.
//! These tests run on every platform, so CI covers the rename on Windows too.

use std::fs;

use tokio_rustls_acme::{AccountCache, CertCache, caches::DirCache};

const DIRECTORY_URL: &str = "https://acme.example/directory";

/// A second store replaces both entries and leaves no temporary file behind.
#[tokio::test]
async fn second_store_replaces_entries_without_temp_files() {
    let dir = tempfile::tempdir().unwrap();
    let cache = DirCache::new(dir.path());
    let domains = ["example.com".to_string()];
    let contact = ["mailto:admin@example.com".to_string()];

    cache
        .store_cert(&domains, DIRECTORY_URL, b"first key and chain")
        .await
        .unwrap();
    cache
        .store_account(&contact, DIRECTORY_URL, b"first account key")
        .await
        .unwrap();
    cache
        .store_cert(&domains, DIRECTORY_URL, b"second key and chain")
        .await
        .unwrap();
    cache
        .store_account(&contact, DIRECTORY_URL, b"second account key")
        .await
        .unwrap();

    let cert = cache.load_cert(&domains, DIRECTORY_URL).await.unwrap();
    assert_eq!(cert.as_deref(), Some(&b"second key and chain"[..]));
    let account = cache.load_account(&contact, DIRECTORY_URL).await.unwrap();
    assert_eq!(account.as_deref(), Some(&b"second account key"[..]));

    let mut names: Vec<String> = fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names.len(), 2, "unexpected files in the cache: {names:?}");
    assert!(
        names[0].starts_with("cached_account_"),
        "unexpected files in the cache: {names:?}"
    );
    assert!(
        names[1].starts_with("cached_cert_"),
        "unexpected files in the cache: {names:?}"
    );
}
