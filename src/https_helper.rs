use std::time::Duration;

use reqwest::redirect::Policy;
use rustls::ClientConfig;
use thiserror::Error;

pub(crate) use reqwest::Response;

/// Time limit to open the TCP connection and finish the TLS handshake.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Time limit for one request, from the connect until the end of the body.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum size of a response body in bytes, far above any ACME object.
const MAX_BODY_SIZE: usize = 1024 * 1024;

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
    https_only: bool,
) -> Result<Response, HttpsRequestError> {
    let redirect = match method {
        // RFC 8555 section 6.4 binds a signed request to the URL in its protected header.
        Method::Post => Policy::none(),
        Method::Get | Method::Head => Policy::default(),
    };
    let client = reqwest::ClientBuilder::new()
        .tls_backend_preconfigured(client_config.clone())
        .user_agent(concat!("tokio-rustls-acme/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(redirect)
        .https_only(https_only)
        .build()
        .map_err(HttpsRequestError::http)?;
    let mut request = client.request(method.into(), url.as_ref());
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
            body: text(response).await?,
        });
    }
    Ok(response)
}

pub(crate) fn is_https(url: &str) -> bool {
    url.get(..8)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
}

/// Reads the response body, up to [`MAX_BODY_SIZE`] bytes.
pub(crate) async fn bytes(mut response: Response) -> Result<Vec<u8>, HttpsRequestError> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(HttpsRequestError::http)? {
        if body.len() + chunk.len() > MAX_BODY_SIZE {
            return Err(HttpsRequestError::BodyTooLarge {
                limit: MAX_BODY_SIZE,
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Reads the response body as text, up to [`MAX_BODY_SIZE`] bytes.
pub(crate) async fn text(response: Response) -> Result<String, HttpsRequestError> {
    let body = bytes(response).await?;
    Ok(String::from_utf8_lossy(&body).into_owned())
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
    /// The response body exceeds the size limit.
    #[error("response body exceeds {limit} bytes")]
    BodyTooLarge {
        /// Limit in bytes.
        limit: usize,
    },
}
