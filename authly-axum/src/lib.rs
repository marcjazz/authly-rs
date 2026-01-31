use authly_session::{Session, SessionStore};
use authly_token::TokenManager;
use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use std::sync::Arc;
pub use tower_cookies::cookie::SameSite;
pub use tower_cookies::Cookie;
use tower_cookies::Cookies;

pub mod helpers;

pub use helpers::*;

#[derive(Clone)]
pub struct AuthlyState {
    pub store: Arc<dyn SessionStore>,
    pub config: SessionConfig,
    pub token_manager: Arc<TokenManager>,
}

impl FromRef<AuthlyState> for Arc<dyn SessionStore> {
    fn from_ref(state: &AuthlyState) -> Self {
        state.store.clone()
    }
}

impl FromRef<AuthlyState> for SessionConfig {
    fn from_ref(state: &AuthlyState) -> Self {
        state.config.clone()
    }
}

impl FromRef<AuthlyState> for Arc<TokenManager> {
    fn from_ref(state: &AuthlyState) -> Self {
        state.token_manager.clone()
    }
}

/// The extractor for a validated session.
pub struct AuthSession(pub Session);

impl<S> FromRequestParts<S> for AuthSession
where
    S: Send + Sync,
    Arc<dyn SessionStore>: FromRef<S>,
    SessionConfig: FromRef<S>,
{
    type Rejection = AuthlyAxumError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let session_store = Arc::<dyn SessionStore>::from_ref(state);
        let session_config = SessionConfig::from_ref(state);
        let cookies = Cookies::from_request_parts(parts, state)
            .await
            .map_err(|e| AuthlyAxumError::Internal(e.1.to_string()))?;

        let session = helpers::get_session(&session_store, &session_config, &cookies).await?;

        Ok(AuthSession(session))
    }
}

/// The extractor for a validated JWT.
///
/// Expects an `Authorization: Bearer <token>` header.
pub struct AuthToken(pub authly_token::Claims);

impl<S> FromRequestParts<S> for AuthToken
where
    S: Send + Sync,
    Arc<TokenManager>: FromRef<S>,
{
    type Rejection = AuthlyAxumError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let token_manager = Arc::<TokenManager>::from_ref(state);
        let token = helpers::get_token(parts, &token_manager).await?;
        Ok(AuthToken(token))
    }
}
