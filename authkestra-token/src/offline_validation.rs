use arc_swap::ArcSwap;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;

/// Errors that can occur during offline validation.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Invalid token: {0}")]
    InvalidToken(String),
    #[error("Key not found in JWKS")]
    KeyNotFound,
    #[error("PASETO error: {0}")]
    Paseto(String),
}

/// Standard claims for JWT/PASETO validation.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub exp: Option<usize>,
    pub nbf: Option<usize>,
    pub iat: Option<usize>,
    pub jti: Option<String>,
}

/// A manager for cached JWK Sets.
pub struct JwksCache {
    jwks_uri: String,
    cache: ArcSwap<JwkSet>,
    last_refresh: RwLock<Instant>,
    refresh_interval: Duration,
}

impl JwksCache {
    /// Creates a new JWKS cache and fetches the initial set.
    pub async fn new(
        jwks_uri: String,
        refresh_interval: Duration,
    ) -> Result<Self, ValidationError> {
        let jwks = Self::fetch_jwks(&jwks_uri).await?;
        Ok(Self {
            jwks_uri,
            cache: ArcSwap::from_pointee(jwks),
            last_refresh: RwLock::new(Instant::now()),
            refresh_interval,
        })
    }

    /// Fetches the JWKS from the provider.
    async fn fetch_jwks(uri: &str) -> Result<JwkSet, ValidationError> {
        let jwks = reqwest::get(uri).await?.json::<JwkSet>().await?;
        Ok(jwks)
    }

    /// Refreshes the cache if the interval has passed.
    pub async fn refresh_if_needed(&self) -> Result<(), ValidationError> {
        let last_refresh = self.last_refresh.read().await;
        if last_refresh.elapsed() >= self.refresh_interval {
            drop(last_refresh);
            let mut last_refresh = self.last_refresh.write().await;
            // Double check after acquiring write lock
            if last_refresh.elapsed() >= self.refresh_interval {
                let jwks = Self::fetch_jwks(&self.jwks_uri).await?;
                self.cache.store(Arc::new(jwks));
                *last_refresh = Instant::now();
            }
        }
        Ok(())
    }

    /// Returns the current cached JWKS.
    pub fn get_jwks(&self) -> Arc<JwkSet> {
        self.cache.load_full()
    }
}

/// Validates a JWT against the cached JWKS.
pub async fn validate_jwt(
    token: &str,
    cache: &JwksCache,
    validation: &Validation,
) -> Result<Claims, ValidationError> {
    validate_jwt_generic::<Claims>(token, cache, validation).await
}

/// Validates a JWT against the cached JWKS with generic claims.
pub async fn validate_jwt_generic<T>(
    token: &str,
    cache: &JwksCache,
    validation: &Validation,
) -> Result<T, ValidationError>
where
    T: for<'de> Deserialize<'de>,
{
    cache.refresh_if_needed().await?;

    let header = decode_header(token)?;
    let kid = header
        .kid
        .ok_or_else(|| ValidationError::InvalidToken("Missing kid header".to_string()))?;

    let jwks = cache.get_jwks();
    let jwk = jwks.find(&kid).ok_or(ValidationError::KeyNotFound)?;

    let decoding_key = DecodingKey::from_jwk(jwk)?;
    let token_data = decode::<T>(token, &decoding_key, validation)?;

    Ok(token_data.claims)
}

/// Validates a PASETO V4 Local/Public token.
/// Note: This implementation assumes V4 Public for parity with JWKS-like usage if applicable,
/// but PASETO usually handles its own keying. This is a placeholder for the requested logic.
pub async fn validate_paseto(_token: &str, _key: &[u8]) -> Result<Claims, ValidationError> {
    // PASETO validation logic using the `paseto` crate
    // For now, returning an error as PASETO JWKS integration is non-standard
    Err(ValidationError::Paseto(
        "PASETO validation not yet fully implemented with JWKS".to_string(),
    ))
}
