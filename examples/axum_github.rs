use authly_axum::AuthSession;
use authly_flow::OAuth2Flow;
use authly_providers_github::GithubProvider;
use authly_session::{Session, SessionStore};
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect},
    routing::get,
    Router,
};
use std::collections::HashMap;
use std::sync::Arc;
use tower_cookies::{cookie::SameSite, Cookie, Cookies, CookieManagerLayer};

#[derive(Clone)]
struct AppState {
    github_flow: Arc<OAuth2Flow<GithubProvider>>,
    session_store: Arc<dyn SessionStore>,
}

// Implement FromRef for Axum
impl axum::extract::FromRef<AppState> for Arc<dyn SessionStore> {
    fn from_ref(state: &AppState) -> Self {
        state.session_store.clone()
    }
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let client_id = std::env::var("AUTHLY_GITHUB_CLIENT_ID")
        .expect("AUTHLY_GITHUB_CLIENT_ID must be set");
    let client_secret = std::env::var("AUTHLY_GITHUB_CLIENT_SECRET")
        .expect("AUTHLY_GITHUB_CLIENT_SECRET must be set");
    let redirect_uri = std::env::var("AUTHLY_GITHUB_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:3000/auth/github/callback".to_string());

    let provider = GithubProvider::new(
        client_id,
        client_secret,
        redirect_uri,
    );
    let github_flow = Arc::new(OAuth2Flow::new(provider));
    
    // Use Redis if REDIS_URL is set, otherwise fallback to MemoryStore
    let session_store: Arc<dyn SessionStore> = if let Ok(redis_url) = std::env::var("REDIS_URL") {
        println!("Using RedisStore at {}", redis_url);
        Arc::new(authly_session::RedisStore::new(&redis_url, "authly".into()).unwrap())
    } else {
        println!("Using MemoryStore");
        Arc::new(MemoryStore::default())
    };

    let state = AppState {
        github_flow,
        session_store,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/auth/github", get(github_login))
        .route("/auth/github/callback", get(github_callback))
        .route("/protected", get(protected))
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> impl IntoResponse {
    "Welcome! Go to /auth/github to login."
}

async fn github_login(State(state): State<AppState>) -> impl IntoResponse {
    let (url, _csrf_state) = state.github_flow.initiate_login();
    // In real app, store _csrf_state in a secure cookie
    Redirect::to(&url)
}

#[derive(serde::Deserialize)]
struct CallbackParams {
    code: String,
    state: String,
}

async fn github_callback(
    State(state): State<AppState>,
    cookies: Cookies,
    Query(params): Query<CallbackParams>,
) -> impl IntoResponse {
    let identity = state
        .github_flow
        .finalize_login(&params.code, &params.state)
        .await
        .unwrap();

    let session = Session {
        id: uuid::Uuid::new_v4().to_string(),
        identity,
        expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
    };

    state.session_store.save_session(&session).await.unwrap();
    
    let mut cookie = Cookie::new("authly_session", session.id);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    
    cookies.add(cookie);

    Redirect::to("/protected")
}

async fn protected(AuthSession(session): AuthSession) -> impl IntoResponse {
    format!("Hello, {}! Your ID is {}", session.identity.username.unwrap_or_default(), session.identity.external_id)
}

// Minimal MemoryStore for example
#[derive(Default)]
struct MemoryStore {
    sessions: std::sync::Mutex<HashMap<String, Session>>,
}

#[async_trait::async_trait]
impl SessionStore for MemoryStore {
    async fn load_session(&self, id: &str) -> Result<Option<Session>, authly_core::AuthError> {
        Ok(self.sessions.lock().unwrap().get(id).cloned())
    }
    async fn save_session(&self, session: &Session) -> Result<(), authly_core::AuthError> {
        self.sessions.lock().unwrap().insert(session.id.clone(), session.clone());
        Ok(())
    }
    async fn delete_session(&self, id: &str) -> Result<(), authly_core::AuthError> {
        self.sessions.lock().unwrap().remove(id);
        Ok(())
    }
}
