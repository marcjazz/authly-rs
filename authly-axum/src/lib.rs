use async_trait::async_trait;
use authly_session::{Session, SessionStore};
use axum::{
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, StatusCode},
};
use std::sync::Arc;
pub use tower_cookies::cookie::SameSite;
pub use tower_cookies::Cookie;
use tower_cookies::Cookies;

#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub cookie_name: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: SameSite,
    pub path: String,
    pub max_age: Option<chrono::Duration>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            cookie_name: "authly_session".to_string(),
            secure: true,
            http_only: true,
            same_site: SameSite::Lax,
            path: "/".to_string(),
            max_age: Some(chrono::Duration::hours(24)),
        }
    }
}

impl SessionConfig {
    pub fn create_cookie<'a>(&self, value: String) -> Cookie<'a> {
        let mut cookie = Cookie::new(self.cookie_name.clone(), value);
        cookie.set_path(self.path.clone());
        cookie.set_secure(self.secure);
        cookie.set_http_only(self.http_only);
        cookie.set_same_site(self.same_site);
        if let Some(max_age) = self.max_age {
            cookie.set_max_age(Some(tower_cookies::cookie::time::Duration::seconds(
                max_age.num_seconds(),
            )));
        }
        cookie
    }
}

#[derive(Clone)]
pub struct AuthlyState {
    pub store: Arc<dyn SessionStore>,
    pub config: SessionConfig,
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

/// The extractor for a validated session.
pub struct AuthSession(pub Session);

#[async_trait]
impl<S> FromRequestParts<S> for AuthSession
where
    S: Send + Sync,
    Arc<dyn SessionStore>: FromRef<S>,
    SessionConfig: FromRef<S>,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let store = Arc::from_ref(state);
        let config = SessionConfig::from_ref(state);

        let cookies = <Cookies as FromRequestParts<S>>::from_request_parts(parts, state)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Cookies error".to_string()))?;

        let session_id = cookies
            .get(&config.cookie_name)
            .map(|c: Cookie| c.value().to_string())
            .ok_or((StatusCode::UNAUTHORIZED, "Missing session cookie".to_string()))?;

        let session = store
            .load_session(&session_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or((StatusCode::UNAUTHORIZED, "Invalid session".to_string()))?;

        Ok(AuthSession(session))
    }
}
