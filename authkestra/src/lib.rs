//! Authkestra is a modular authentication framework for Rust.
//!
//! This crate serves as a facade, re-exporting functionality from other `authkestra-*` crates
//! based on enabled features.

pub use authkestra_core as core;

#[cfg(feature = "flow")]
pub use authkestra_flow as flow;

#[cfg(feature = "session")]
pub use authkestra_session as session;

#[cfg(feature = "token")]
pub use authkestra_token as token;

#[cfg(feature = "oidc")]
pub use authkestra_oidc as oidc;

#[cfg(feature = "axum")]
pub use authkestra_axum as axum;

#[cfg(feature = "actix")]
pub use authkestra_actix as actix;

#[cfg(feature = "flow")]
mod aliases {
    pub use crate::flow::{
        Authkestra, AuthkestraClient, AuthkestraFull, AuthkestraResourceServer, AuthkestraSpa,
        Configured, HasSessionStoreMarker as HasSessionStore,
        HasTokenManagerMarker as HasTokenManager, Missing, NoSessionStoreMarker as NoSessionStore,
        NoTokenManagerMarker as NoTokenManager,
    };
}

#[cfg(feature = "flow")]
pub use aliases::*;

#[cfg(all(feature = "flow", feature = "axum"))]
/// Axum-specific type aliases for Authkestra state.
pub mod axum_aliases {
    pub use crate::aliases::*;
    use crate::axum::AuthkestraState;

    /// Axum state for a full OIDC client with sessions.
    pub type AuthkestraClientState = AuthkestraState<HasSessionStore, NoTokenManager>;
    /// Axum state for a Single Page Application (SPA) using JWTs.
    pub type AuthkestraSpaState = AuthkestraState<NoSessionStore, HasTokenManager>;
    /// Axum state for a Resource Server (API) validating tokens.
    pub type AuthkestraResourceServerState = AuthkestraState<NoSessionStore, HasTokenManager>;
}

#[cfg(all(feature = "flow", feature = "axum"))]
pub use axum_aliases::*;

/// Authentication providers.
pub mod providers {
    #[cfg(feature = "github")]
    pub use authkestra_providers_github as github;

    #[cfg(feature = "google")]
    pub use authkestra_providers_google as google;

    #[cfg(feature = "discord")]
    pub use authkestra_providers_discord as discord;
}
