use async_trait::async_trait;
use authly_core::OAuthProvider;
use authly_flow::OAuth2Flow;
use authly_session::{Session, SessionStore};
use axum::{
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Redirect},
};
use std::sync::Arc;
pub use tower_cookies::cookie::SameSite;
pub use tower_cookies::Cookie;
use tower_cookies::Cookies;

#[derive(serde::Deserialize)]
pub struct OAuthCallbackParams {
    pub code: String,
    pub state: String,
}

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

/// Helper to initiate the OAuth2 login flow.
///
/// This generates the authorization URL and sets a CSRF state cookie.
pub fn initiate_oauth_login<P, M>(
    flow: &OAuth2Flow<P, M>,
    cookies: &Cookies,
    scopes: &[&str],
) -> Redirect
where
    P: OAuthProvider,
    M: authly_core::UserMapper,
{
    let (url, csrf_state) = flow.initiate_login(scopes);

    let mut cookie = Cookie::new("oauth_state", csrf_state);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);

    cookies.add(cookie);

    Redirect::to(&url)
}

/// Helper to handle the OAuth2 callback boilerplate.
pub async fn handle_oauth_callback<P, M>(
    flow: &OAuth2Flow<P, M>,
    cookies: Cookies,
    params: OAuthCallbackParams,
    store: Arc<dyn SessionStore>,
    config: SessionConfig,
    success_url: &str,
) -> Result<impl IntoResponse, (StatusCode, String)>
where
    P: OAuthProvider + Send + Sync,
    M: authly_core::UserMapper + Send + Sync,
{
    let expected_state = cookies
        .get("oauth_state")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    // Remove the state cookie after use
    let mut remove_cookie = Cookie::new("oauth_state", "");
    remove_cookie.set_path("/");
    cookies.remove(remove_cookie);

    let (mut identity, token, _local_user) = flow
        .finalize_login(&params.code, &params.state, &expected_state)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("Authentication failed: {}", e)))?;

    // Store tokens in identity attributes
    identity
        .attributes
        .insert("access_token".to_string(), token.access_token);

    if let Some(expires_in) = token.expires_in {
        let expires_at = chrono::Utc::now().timestamp() + expires_in as i64;
        identity
            .attributes
            .insert("expires_at".to_string(), expires_at.to_string());
    }

    if let Some(rt) = token.refresh_token {
        identity.attributes.insert("refresh_token".to_string(), rt);
    }

    let session = Session {
        id: uuid::Uuid::new_v4().to_string(),
        identity,
        expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
    };

    store
        .save_session(&session)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to save session: {}", e),
            )
        })?;

    let cookie = config.create_cookie(session.id);
    cookies.add(cookie);

    Ok(Redirect::to(success_url).into_response())
}
