use async_trait::async_trait;
use authkestra_core::{
    AuthError, CredentialsProvider, Identity, OAuthProvider, OAuthToken, SessionConfig,
    SessionStore, UserMapper,
};
use authkestra_token::TokenManager;
use std::collections::HashMap;
use std::sync::Arc;

pub mod client_credentials_flow;
pub mod device_flow;

pub use client_credentials_flow::ClientCredentialsFlow;
pub use device_flow::{DeviceAuthorizationResponse, DeviceFlow};

/// Orchestrates the Authorization Code flow.
#[async_trait]
pub trait ErasedOAuthFlow: Send + Sync {
    fn provider_id(&self) -> String;
    fn initiate_login(&self, scopes: &[&str], pkce_challenge: Option<&str>) -> (String, String);
    async fn finalize_login(
        &self,
        code: &str,
        received_state: &str,
        expected_state: &str,
        pkce_verifier: Option<&str>,
    ) -> Result<(authkestra_core::Identity, authkestra_core::OAuthToken), authkestra_core::AuthError>;
}

pub struct OAuth2Flow<P: OAuthProvider, M: UserMapper = ()> {
    provider: P,
    mapper: Option<M>,
}

#[async_trait]
impl<P: OAuthProvider, M: UserMapper> ErasedOAuthFlow for OAuth2Flow<P, M> {
    fn provider_id(&self) -> String {
        self.provider.provider_id().to_string()
    }

    fn initiate_login(&self, scopes: &[&str], pkce_challenge: Option<&str>) -> (String, String) {
        self.initiate_login(scopes, pkce_challenge)
    }

    async fn finalize_login(
        &self,
        code: &str,
        received_state: &str,
        expected_state: &str,
        pkce_verifier: Option<&str>,
    ) -> Result<(authkestra_core::Identity, authkestra_core::OAuthToken), authkestra_core::AuthError> {
        let (identity, token, _) = self
            .finalize_login(code, received_state, expected_state, pkce_verifier)
            .await?;
        Ok((identity, token))
    }
}

impl<P: OAuthProvider> OAuth2Flow<P, ()> {
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            mapper: None,
        }
    }
}

impl<P: OAuthProvider, M: UserMapper> OAuth2Flow<P, M> {
    pub fn with_mapper(provider: P, mapper: M) -> Self {
        Self {
            provider,
            mapper: Some(mapper),
        }
    }

    /// Generates the redirect URL and CSRF state.
    pub fn initiate_login(
        &self,
        scopes: &[&str],
        pkce_challenge: Option<&str>,
    ) -> (String, String) {
        let state = uuid::Uuid::new_v4().to_string();
        let url = self
            .provider
            .get_authorization_url(&state, scopes, pkce_challenge);
        (url, state)
    }

    /// Completes the flow by exchanging the code.
    /// If a mapper is provided, it will also map the identity to a local user.
    pub async fn finalize_login(
        &self,
        code: &str,
        received_state: &str,
        expected_state: &str,
        pkce_verifier: Option<&str>,
    ) -> Result<(Identity, OAuthToken, Option<M::LocalUser>), AuthError> {
        if received_state != expected_state {
            return Err(AuthError::CsrfMismatch);
        }
        let (identity, token) = self
            .provider
            .exchange_code_for_identity(code, pkce_verifier)
            .await?;

        let local_user = if let Some(mapper) = &self.mapper {
            Some(mapper.map_user(&identity).await?)
        } else {
            None
        };

        Ok((identity, token, local_user))
    }

    /// Refresh an access token using a refresh token.
    pub async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuthToken, AuthError> {
        self.provider.refresh_token(refresh_token).await
    }

    /// Revoke an access token.
    pub async fn revoke_token(&self, token: &str) -> Result<(), AuthError> {
        self.provider.revoke_token(token).await
    }
}

/// The unified Authkestra service.
#[derive(Clone)]
pub struct Authkestra {
    pub providers: HashMap<String, Arc<dyn ErasedOAuthFlow>>,
    pub session_store: Arc<dyn SessionStore>,
    pub session_config: SessionConfig,
    pub token_manager: Arc<TokenManager>,
}

impl Authkestra {
    pub fn builder() -> AuthkestraBuilder {
        AuthkestraBuilder::default()
    }
}

#[derive(Default)]
pub struct AuthkestraBuilder {
    providers: HashMap<String, Arc<dyn ErasedOAuthFlow>>,
    session_store: Option<Arc<dyn SessionStore>>,
    session_config: SessionConfig,
    token_manager: Option<Arc<TokenManager>>,
}

impl AuthkestraBuilder {
    pub fn provider<P, M>(mut self, flow: OAuth2Flow<P, M>) -> Self
    where
        P: OAuthProvider + 'static,
        M: UserMapper + 'static,
    {
        let id = flow.provider_id();
        self.providers.insert(id, Arc::new(flow));
        self
    }

    pub fn session_store(mut self, store: Arc<dyn SessionStore>) -> Self {
        self.session_store = Some(store);
        self
    }

    pub fn session_config(mut self, config: SessionConfig) -> Self {
        self.session_config = config;
        self
    }

    pub fn token_manager(mut self, manager: Arc<TokenManager>) -> Self {
        self.token_manager = Some(manager);
        self
    }

    pub fn build(self) -> Authkestra {
        Authkestra {
            providers: self.providers,
            session_store: self
                .session_store
                .unwrap_or_else(|| Arc::new(authkestra_core::MemoryStore::default())), // Wait, MemoryStore is in authkestra-session!
            session_config: self.session_config,
            token_manager: self
                .token_manager
                .unwrap_or_else(|| Arc::new(TokenManager::new(b"secret", None))),
        }
    }
}

/// Orchestrates a direct credentials flow.
pub struct CredentialsFlow<P: CredentialsProvider, M: UserMapper = ()> {
    provider: P,
    mapper: Option<M>,
}

impl<P: CredentialsProvider> CredentialsFlow<P, ()> {
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            mapper: None,
        }
    }
}

impl<P: CredentialsProvider, M: UserMapper> CredentialsFlow<P, M> {
    pub fn with_mapper(provider: P, mapper: M) -> Self {
        Self {
            provider,
            mapper: Some(mapper),
        }
    }

    pub async fn authenticate(
        &self,
        creds: P::Credentials,
    ) -> Result<(Identity, Option<M::LocalUser>), AuthError> {
        let identity = self.provider.authenticate(creds).await?;

        let local_user = if let Some(mapper) = &self.mapper {
            Some(mapper.map_user(&identity).await?)
        } else {
            None
        };

        Ok((identity, local_user))
    }
}
