//! Platform-independent tests for `DirCache`.
//!
//! One test changes the current directory, so all other tests must use
//! absolute paths.

use std::{fs, path::Path};

use tokio_rustls_acme::{CertCache, caches::DirCache};

const DIRECTORY_URL: &str = "https://acme.example/directory";

/// Returns the names of all files in `dir`.
fn file_names(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}

/// A second store replaces the content and leaves no temporary file behind.
#[tokio::test]
async fn second_store_replaces_content() {
    let dir = tempfile::tempdir().unwrap();
    let cache = DirCache::new(dir.path());
    let domains = ["example.com".to_string()];

    for content in [&b"first"[..], b"second"] {
        cache
            .store_cert(&domains, DIRECTORY_URL, content)
            .await
            .unwrap();
    }

    let cert = cache.load_cert(&domains, DIRECTORY_URL).await.unwrap();
    assert_eq!(cert.as_deref(), Some(&b"second"[..]));
    let names = file_names(dir.path());
    assert!(
        names.len() == 1 && names[0].starts_with("cached_cert_"),
        "unexpected files in the cache: {names:?}"
    );
}

/// An empty cache path stores the entries in the current directory.
#[tokio::test]
async fn empty_path_uses_current_directory() {
    let dir = tempfile::tempdir().unwrap();
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();
    let cache = DirCache::new("");
    let domains = ["example.com".to_string()];

    let stored = cache.store_cert(&domains, DIRECTORY_URL, b"key").await;
    let cert = cache.load_cert(&domains, DIRECTORY_URL).await;
    // Windows cannot delete the current directory, so leave it first.
    std::env::set_current_dir(&original).unwrap();

    stored.unwrap();
    assert_eq!(cert.unwrap().as_deref(), Some(&b"key"[..]));
    let names = file_names(dir.path());
    assert!(
        names.len() == 1 && names[0].starts_with("cached_cert_"),
        "unexpected files in the cache: {names:?}"
    );
}
