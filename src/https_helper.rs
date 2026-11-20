use rustls::{ClientConfig, pki_types::InvalidDnsNameError};
use thiserror::Error;

pub(crate) use reqwest::Response;

#[derive(Copy, Clone)]
pub(crate) enum Method {
    Post,
    Get,
    Head,
}

impl From<Method> for reqwest::Method {
    fn from(m: Method) -> Self {
        match m {
            Method::Post => reqwest::Method::POST,
            Method::Get => reqwest::Method::GET,
            Method::Head => reqwest::Method::HEAD,
        }
    }
}

pub(crate) async fn https(
    client_config: &ClientConfig,
    url: impl AsRef<str>,
    method: Method,
    body: Option<String>,
) -> Result<Response, HttpsRequestError> {
    let method: reqwest::Method = method.into();
    let client = reqwest::ClientBuilder::new()
        .tls_backend_preconfigured(client_config.clone())
        .user_agent(concat!("tokio-rustls-acme/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let mut request = client.request(method, url.as_ref());
    if let Some(body) = body {
        request = request
            .body(body)
            .header("Content-Type", "application/jose+json");
    }

    let response = request.send().await?;
    let status = response.status();
    if !status.is_success() {
        return Err(HttpsRequestError::Non2xxStatus {
            status_code: status.into(),
            body: response.text().await?,
        });
    }
    Ok(response)
}

impl From<reqwest::Error> for HttpsRequestError {
    fn from(e: reqwest::Error) -> Self {
        Self::Http(e.into())
    }
}

/// An error from an HTTP request to the ACME server.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum HttpsRequestError {
    /// An I/O error.
    #[error("io error: {0:?}")]
    Io(#[from] std::io::Error),
    /// The URL host is not a valid DNS name.
    #[error("invalid dns name: {0:?}")]
    InvalidDnsName(#[from] InvalidDnsNameError),
    /// The HTTP client failed.
    #[error("http error: {0:?}")]
    Http(Box<dyn std::error::Error + Send + Sync + 'static>),
    /// The server answered with a status outside 2xx.
    #[error("non 2xx http status: {status_code} {body:?}")]
    Non2xxStatus {
        /// HTTP status code.
        status_code: u16,
        /// Response body.
        body: String,
    },
    /// The URL has no host.
    #[error("could not determine host from url")]
    UndefinedHost,
}
