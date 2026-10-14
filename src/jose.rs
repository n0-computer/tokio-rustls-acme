use crate::crypto::digest::{Digest, SHA256, digest};
use crate::crypto::hmac;
use crate::crypto::rand::SystemRandom;
use crate::crypto::signature::{EcdsaKeyPair, KeyPair};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;
use thiserror::Error;

pub(crate) fn sign(
    key: &EcdsaKeyPair,
    kid: Option<&str>,
    nonce: String,
    url: &str,
    payload: &str,
) -> Result<String, JoseError> {
    let jwk = match kid {
        None => Some(Jwk::new(key)),
        Some(_) => None,
    };
    let protected = Protected::base64(jwk, kid, Some(nonce.as_ref()), url)?;
    let payload = URL_SAFE_NO_PAD.encode(payload);
    let combined = format!("{}.{}", protected, payload);
    let signature = key.sign(&SystemRandom::new(), combined.as_bytes())?;
    let signature = URL_SAFE_NO_PAD.encode(signature.as_ref());
    let body = Body {
        protected,
        payload,
        signature,
    };
    Ok(serde_json::to_string(&body)?)
}

pub(crate) fn sign_eab(
    key: &EcdsaKeyPair,
    eab_key: &hmac::Key,
    kid: &str,
    url: &str,
) -> Result<Body, JoseError> {
    let protected = Protected::hmac_base64(kid, url)?;
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&Jwk::new(key))?);
    let combined = format!("{}.{}", protected, payload);
    let signature = hmac::sign(eab_key, combined.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(signature.as_ref());
    let body = Body {
        protected,
        payload,
        signature,
    };
    Ok(body)
}

pub(crate) fn key_authorization_sha256(
    key: &EcdsaKeyPair,
    token: &str,
) -> Result<Digest, JoseError> {
    let jwk = Jwk::new(key);
    let key_authorization = format!("{}.{}", token, jwk.thumb_sha256_base64()?);
    Ok(digest(&SHA256, key_authorization.as_bytes()))
}

#[derive(Serialize)]
pub(crate) struct Body {
    protected: String,
    payload: String,
    signature: String,
}

#[derive(Serialize)]
struct Protected<'a> {
    alg: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
    url: &'a str,
}

impl<'a> Protected<'a> {
    fn base64(
        jwk: Option<Jwk>,
        kid: Option<&'a str>,
        nonce: Option<&'a str>,
        url: &'a str,
    ) -> Result<String, JoseError> {
        let protected = Self {
            alg: "ES256",
            jwk,
            kid,
            nonce,
            url,
        };
        let protected = serde_json::to_vec(&protected)?;
        Ok(URL_SAFE_NO_PAD.encode(protected))
    }

    fn hmac_base64(kid: &'a str, url: &'a str) -> Result<String, JoseError> {
        let protected = Self {
            alg: "HS256",
            jwk: None,
            kid: Some(kid),
            nonce: None,
            url,
        };
        let protected = serde_json::to_vec(&protected)?;
        Ok(URL_SAFE_NO_PAD.encode(protected))
    }
}

#[derive(Serialize)]
struct Jwk {
    alg: &'static str,
    crv: &'static str,
    kty: &'static str,
    #[serde(rename = "use")]
    u: &'static str,
    x: String,
    y: String,
}

impl Jwk {
    pub(crate) fn new(key: &EcdsaKeyPair) -> Self {
        let (x, y) = key.public_key().as_ref()[1..].split_at(32);
        Self {
            alg: "ES256",
            crv: "P-256",
            kty: "EC",
            u: "sig",
            x: URL_SAFE_NO_PAD.encode(x),
            y: URL_SAFE_NO_PAD.encode(y),
        }
    }
    pub(crate) fn thumb_sha256_base64(&self) -> Result<String, JoseError> {
        let jwk_thumb = JwkThumb {
            crv: self.crv,
            kty: self.kty,
            x: &self.x,
            y: &self.y,
        };
        let json = serde_json::to_vec(&jwk_thumb)?;
        let hash = digest(&SHA256, &json);
        Ok(URL_SAFE_NO_PAD.encode(hash))
    }
}

#[derive(Serialize)]
struct JwkThumb<'a> {
    crv: &'a str,
    kty: &'a str,
    x: &'a str,
    y: &'a str,
}

#[derive(Error, Debug)]
pub enum JoseError {
    #[error("json serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] crate::crypto::error::Unspecified),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signature::{
        ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, UnparsedPublicKey,
    };

    #[derive(serde::Deserialize)]
    struct ParsedBody {
        protected: String,
        payload: String,
        signature: String,
    }

    #[test]
    fn sign_produces_verifiable_es256_jws() {
        let pkcs8 = crate::acme::Account::generate_key_pair();
        let key =
            crate::crypto::ecdsa_key_pair_from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8)
                .unwrap();
        let body = sign(&key, None, "nonce".into(), "https://example.com", "{}").unwrap();
        let body: ParsedBody = serde_json::from_str(&body).unwrap();

        let signature = URL_SAFE_NO_PAD.decode(&body.signature).unwrap();
        assert_eq!(signature.len(), 64, "ES256 signatures are fixed-size r||s");
        let signed = format!("{}.{}", body.protected, body.payload);
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.public_key().as_ref())
            .verify(signed.as_bytes(), &signature)
            .unwrap();
    }

    #[test]
    fn sign_eab_uses_hmac_sha256() {
        let pkcs8 = crate::acme::Account::generate_key_pair();
        let key =
            crate::crypto::ecdsa_key_pair_from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8)
                .unwrap();
        let eab_key = hmac::Key::new(hmac::HMAC_SHA256, b"secret");
        let body = sign_eab(&key, &eab_key, "kid", "https://example.com").unwrap();

        let signature = URL_SAFE_NO_PAD.decode(&body.signature).unwrap();
        let signed = format!("{}.{}", body.protected, body.payload);
        hmac::verify(&eab_key, signed.as_bytes(), &signature).unwrap();
    }
}
