# Project Cleanup and Feature Addition Plan

This document outlines the plan for cleaning up the `authkestra` examples, adding new features for JWT validation, and implementing provider ID inference.

## Part 1: Examples Cleanup

The goal is to make the examples more concise, consistent, and comprehensive.

### 1.1. Redundant Examples

- **`get_started.rs`**: This example is largely a subset of `axum_oauth.rs`. It will be removed.

### 1.2. Examples to Keep/Merge

- **`actix_github.rs`**: Keep as a clear, standalone Actix example.
- **`axum_credentials.rs`**: Keep as the primary example for credentials-based authentication.
- **`axum_oauth.rs`**: Keep as the primary example for multi-provider OAuth. The "get started" simplicity will be merged into this by adding more comments and ensuring the single-provider case is easy to understand.
- **`axum_spa_jwt.rs`**: Keep as the primary example for SPA (JWT) flows with Axum.
- **`client_credentials_flow.rs`**: Keep as a standalone example for the client credentials flow.
- **`device_flow.rs`**: Keep as a standalone example for the device authorization flow.
- **`offline_validation.rs`**: Keep as a standalone example for JWT validation logic.
- **`oidc_generic.rs`**: Keep as the primary example for generic OIDC providers.

### 1.3. New Examples to Create

- **`actix_spa_jwt.rs`**: An Actix equivalent of `axum_spa_jwt.rs` to demonstrate a JWT-based flow for SPAs with Actix.
- **`actix_credentials.rs`**: An Actix equivalent of `axum_credentials.rs` for credentials-based authentication.
- **`actix_resource_server.rs`**: An example of an Actix resource server that protects its endpoints using JWTs from an external OIDC provider.
- **`axum_resource_server.rs`**: An example of an Axum resource server with the same functionality as above.

## Part 2: JWT Validation Spec

The objective is to create extractors for Actix and Axum that validate JWTs from an OIDC provider, suitable for protecting resource server APIs.

### 2.1. Design

A new extractor, `Jwt<C>`, will be created in both `authkestra-actix` and `authkestra-axum`, where `C` is the type of the claims.

**`authkestra-actix`:**

```rust
use actix_web::{web, App, HttpServer};
use authkestra_actix::Jwt;
use serde::Deserialize;

#[derive(Deserialize)]
struct Claims {
    sub: String,
    // ... other claims
}

async fn protected(claims: Jwt<Claims>) -> String {
    format!("Hello, {}!", claims.sub)
}
```

**`authkestra-axum`:**

```rust
use axum::{routing::get, Router};
use authkestra_axum::Jwt;
use serde::Deserialize;

#[derive(Deserialize)]
struct Claims {
    sub: String,
    // ... other claims
}

async fn protected(claims: Jwt<Claims>) -> String {
    format!("Hello, {}!", claims.sub)
}
```

### 2.2. Implementation Details

- The `Jwt` extractor will require a `JwksCache` and a `jsonwebtoken::Validation` to be configured in the application state.
- `JwksCache` will be from the `authkestra-token` crate and will be responsible for fetching and caching the provider's JWKS.
- The `Validation` struct will be configured with the expected issuer and audience.
- The extractor will get the token from the `Authorization: Bearer` header and use `authkestra_token::offline_validation::validate_jwt` to validate it.

## Part 3: Provider ID Inference Spec

The goal is to allow the `provider_id` to be inferred from the request, rather than being explicitly in the URL path.

### 3.1. `ProviderInference` Trait

A new trait will be introduced in `authkestra-core`:

```rust
use http::Request;

pub trait ProviderInference: Send + Sync {
    fn infer_provider_id<B>(&self, req: &Request<B>) -> Option<String>;
}
```

### 3.2. Inference Strategies

Implementations for common strategies will be provided:

- **`QueryParamInference`**: Infers the `provider_id` from a query parameter (e.g., `?provider=github`).
- **`HostInference`**: Infers the `provider_id` from a subdomain (e.g., `github.myapp.com`).
- **`HeaderInference`**: Infers the `provider_id` from a custom header (e.g., `X-Provider-ID`).

### 3.3. Integration

- The `AuthkestraBuilder` in `authkestra-flow` will be updated to accept a `ProviderInference` implementation.
- The login handlers in `authkestra-actix` and `authkestra-axum` will be modified to use the configured inference strategy if the `provider` path parameter is not present.
- A mapping from the inferred ID to the registered provider ID will be supported to allow for aliases.

This plan will be implemented in the `code` mode.
