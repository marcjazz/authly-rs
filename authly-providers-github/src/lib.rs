use async_trait::async_trait;
use authly_core::{AuthError, Identity, OAuthProvider};
use serde::Deserialize;
use std::collections::HashMap;

pub struct GithubProvider {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    http_client: reqwest::Client,
    token_url: String,
    user_url: String,
}

impl GithubProvider {
    pub fn new(client_id: String, client_secret: String, redirect_uri: String) -> Self {
        Self {
            client_id,
            client_secret,
            redirect_uri,
            http_client: reqwest::Client::new(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            user_url: "https://api.github.com/user".to_string(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_test_urls(mut self, token_url: String, user_url: String) -> Self {
        self.token_url = token_url;
        self.user_url = user_url;
        self
    }
}

#[derive(Deserialize)]
struct GithubAccessTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct GithubUserResponse {
    id: u64,
    login: String,
    email: Option<String>,
}

#[async_trait]
impl OAuthProvider for GithubProvider {
    fn get_authorization_url(&self, state: &str, scopes: &[&str]) -> String {
        let scope_param = if scopes.is_empty() {
            "user:email".to_string()
        } else {
            scopes.join(" ")
        };

        format!(
            "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}&scope={}",
            self.client_id, self.redirect_uri, state, scope_param
        )
    }

    async fn exchange_code_for_identity(&self, code: &str) -> Result<Identity, AuthError> {
        // 1. Exchange code for access token
        let token_response = self.http_client
            .post(&self.token_url)
            .header("Accept", "application/json")
            .form(&[
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("code", &code.to_string()),
                ("redirect_uri", &self.redirect_uri),
            ])
            .send()
            .await
            .map_err(|_| AuthError::Network)?
            .json::<GithubAccessTokenResponse>()
            .await
            .map_err(|e| AuthError::Provider(format!("Failed to parse token response: {}", e)))?;

        // 2. Get user information
        let user_response = self.http_client
            .get(&self.user_url)
            .header("Authorization", format!("Bearer {}", token_response.access_token))
            .header("User-Agent", "authly-rs")
            .send()
            .await
            .map_err(|_| AuthError::Network)?
            .json::<GithubUserResponse>()
            .await
            .map_err(|e| AuthError::Provider(format!("Failed to parse user response: {}", e)))?;

        // 3. Map to Identity
        Ok(Identity {
            provider_id: "github".to_string(),
            external_id: user_response.id.to_string(),
            email: user_response.email,
            username: Some(user_response.login),
            attributes: HashMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    #[tokio::test]
    async fn test_exchange_code_for_identity() {
        let mut server = Server::new_async().await;
        let token_url = format!("{}/login/oauth/access_token", server.url());
        let user_url = format!("{}/user", server.url());

        let _token_mock = server.mock("POST", "/login/oauth/access_token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token": "test_token"}"#)
            .create_async()
            .await;

        let _user_mock = server.mock("GET", "/user")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id": 123, "login": "testuser", "email": "test@example.com"}"#)
            .create_async()
            .await;

        let provider = GithubProvider::new(
            "client_id".to_string(),
            "client_secret".to_string(),
            "http://localhost/callback".to_string(),
        ).with_test_urls(token_url, user_url);

        let identity = provider.exchange_code_for_identity("test_code").await.unwrap();

        assert_eq!(identity.provider_id, "github");
        assert_eq!(identity.external_id, "123");
        assert_eq!(identity.username, Some("testuser".to_string()));
        assert_eq!(identity.email, Some("test@example.com".to_string()));
    }
}
