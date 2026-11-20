use rustls::ClientConfig;
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
        .build()
        .map_err(HttpsRequestError::http)?;
    let mut request = client.request(method, url.as_ref());
    if let Some(body) = body {
        request = request
            .body(body)
            .header("Content-Type", "application/jose+json");
    }

    let response = request.send().await.map_err(HttpsRequestError::http)?;
    let status = response.status();
    if !status.is_success() {
        return Err(HttpsRequestError::Non2xxStatus {
            status_code: status.into(),
            body: response.text().await.map_err(HttpsRequestError::http)?,
        });
    }
    Ok(response)
}

impl HttpsRequestError {
    pub(crate) fn http(err: reqwest::Error) -> Self {
        Self::Http(err.into())
    }
}

/// An error from an HTTP request to the ACME server.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum HttpsRequestError {
    /// An I/O error.
    #[error("io error: {0:?}")]
    Io(#[from] std::io::Error),
    /// The HTTP client failed.
    ///
    /// Usually downcasts to `reqwest::Error`. The concrete type is not covered by semver.
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
