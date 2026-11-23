//! Types shared across the Botstadia platform.
//!
//! Everything here compiles for native targets and for both wasm targets
//! (`wasm32-unknown-unknown` and `wasm32-wasip2`), so it must stay free of
//! platform-specific code.

pub mod api;
pub mod auth;
pub mod error;
pub mod notices;
pub mod platform;

use serde::{Deserialize, Serialize};

/// The api route that answers with a [`HelloResponse`].
pub const ROUTE_HELLO: &str = "/hello";

/// The api route used for liveness checks, answering with a [`HealthResponse`].
pub const ROUTE_HEALTH: &str = "/health";

/// Body of `GET /hello`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloResponse {
    /// A human-readable greeting.
    pub message: String,
    /// The deployment environment that answered (`dev` or `prod`).
    pub env: String,
}

impl HelloResponse {
    pub fn new(env: impl Into<String>) -> Self {
        Self {
            message: "Hello from the Botstadia API!".to_string(),
            env: env.into(),
        }
    }
}

/// Body of `GET /health`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    /// The deployment environment that answered (`dev` or `prod`).
    pub env: String,
    /// Whether the worker received its secrets. Proves the secret pipeline
    /// (`.env` -> `.dev.vars` locally, `wrangler secret put` in prod) without
    /// ever exposing a value.
    pub secrets_configured: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_round_trips_through_json() {
        let hello = HelloResponse::new("dev");
        let json = serde_json::to_string(&hello).unwrap();
        assert_eq!(
            json,
            r#"{"message":"Hello from the Botstadia API!","env":"dev"}"#
        );
        let back: HelloResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back, hello);
    }

    #[test]
    fn health_round_trips_through_json() {
        let health = HealthResponse {
            status: "ok".to_string(),
            env: "prod".to_string(),
            secrets_configured: true,
        };
        let json = serde_json::to_string(&health).unwrap();
        let back: HealthResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back, health);
    }
}
