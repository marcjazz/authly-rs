use authly_axum::{handle_oauth_callback_jwt, initiate_oauth_login, AuthToken, OAuthCallbackParams};
use authly_flow::OAuth2Flow;
use authly_providers_github::GithubProvider;
use authly_token::TokenManager;
use axum::{
    extract::{Query, State, FromRef},
    response::IntoResponse,
    routing::get,
    Router,
};
use std::sync::Arc;
use tower_cookies::{Cookies, CookieManagerLayer};

#[derive(Clone)]
struct AppState {
    github_flow: Arc<OAuth2Flow<GithubProvider>>,
    token_manager: Arc<TokenManager>,
}

impl FromRef<AppState> for Arc<TokenManager> {
    fn from_ref(state: &AppState) -> Self {
        state.token_manager.clone()
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
    let jwt_secret = std::env::var("AUTHLY_JWT_SECRET")
        .unwrap_or_else(|_| "super-secret-key-change-me-in-production".to_string());

    let provider = GithubProvider::new(
        client_id,
        client_secret,
        redirect_uri,
    );
    let github_flow = Arc::new(OAuth2Flow::new(provider));
    let token_manager = Arc::new(TokenManager::new(jwt_secret.as_bytes()));

    let state = AppState {
        github_flow,
        token_manager,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/auth/github", get(github_login))
        .route("/auth/github/callback", get(github_callback))
        .route("/protected", get(protected))
        .layer(CookieManagerLayer::new())
        .with_state(state);

    println!("Starting server on http://localhost:3000");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> impl IntoResponse {
    "Welcome! Go to /auth/github to login (Stateless JWT mode)."
}

async fn github_login(
    State(state): State<AppState>,
    cookies: Cookies,
) -> impl IntoResponse {
    initiate_oauth_login(&state.github_flow, &cookies, &["user:email"])
}

async fn github_callback(
    State(state): State<AppState>,
    cookies: Cookies,
    Query(params): Query<OAuthCallbackParams>,
) -> impl IntoResponse {
    handle_oauth_callback_jwt(
        &state.github_flow,
        cookies,
        params,
        state.token_manager.clone(),
        3600,
    )
    .await
}

async fn protected(AuthToken(identity): AuthToken) -> impl IntoResponse {
    format!(
        "Hello, {}! Your ID is {}. You are authenticated via the new AuthToken extractor.", 
        identity.username.unwrap_or_default(), 
        identity.external_id
    )
}
