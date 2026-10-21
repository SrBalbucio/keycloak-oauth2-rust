//! OAuth2/OIDC **Authorization Code + PKCE** para Keycloak, em Rust.
//!
//! Voltada a clientes públicos (apps desktop, sem `client_secret`): abre o login no navegador,
//! escuta o callback em `127.0.0.1`, troca o código por tokens e cobre refresh, logout
//! (RP-initiated), userinfo e descoberta OIDC.
//!
//! ```no_run
//! use keycloak_oauth2::KeycloakClient;
//!
//! let client = KeycloakClient::builder()
//!     .base_url("https://localhost:8080")
//!     .realm("myrealm")
//!     .client_id("meu-client")
//!     .scope("openid profile")
//!     .redirect_port(8765)
//!     .build()?;
//!
//! let mut session = client.login()?;
//! if let Some(claims) = &session.claims {
//!     println!("Logado como {:?}", claims.preferred_username);
//! }
//! if session.expired() {
//!     session.refresh()?;
//! }
//! session.logout(None)?;
//! # Ok::<(), keycloak_oauth2::KeycloakError>(())
//! ```
//!
//! Para controlar o navegador por fora (ex.: opener plugin no Tauri), use
//! [`KeycloakClient::begin_login`] + [`KeycloakClient::complete_login`].

mod auth_url;
mod callback;
mod config;
mod discovery;
mod endpoints;
mod error;
mod id_token;
mod pkce;
mod tokens;
mod userinfo;

pub mod client;

pub use client::{KeycloakClient, LoginFlow, Session};
pub use config::{KeycloakClientBuilder, KeycloakConfig};
pub use discovery::OidcDiscovery;
pub use endpoints::Endpoints;
pub use error::{KeycloakError, Result};
pub use id_token::{IdTokenClaims, RealmAccess};
pub use pkce::{code_challenge_s256, generate_code_verifier};
pub use tokens::TokenSet;
pub use userinfo::UserInfo;
