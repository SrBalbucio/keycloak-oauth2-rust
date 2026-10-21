//! Login completo contra um Keycloak local (login/logout/refresh).
//!
//! ```bash
//! KEYCLOAK_BASE_URL=https://localhost:8080 \
//! KEYCLOAK_REALM=myrealm \
//! KEYCLOAK_CLIENT_ID=meu-client \
//! cargo run --example login
//! ```

use std::env;
use std::io::{BufRead, Write};

use keycloak_oauth2::KeycloakClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url = env::var("KEYCLOAK_BASE_URL").unwrap_or_else(|_| "http://localhost:8080".into());
    let realm = env::var("KEYCLOAK_REALM").unwrap_or_else(|_| "master".into());
    let client_id = env::var("KEYCLOAK_CLIENT_ID").unwrap_or_else(|_| "meu-client".into());

    let client = KeycloakClient::builder()
        .base_url(base_url)
        .realm(realm.clone())
        .client_id(client_id)
        .redirect_port(8765)
        .build()?;

    println!("Abrindo navegador para login (realm: {realm})...");
    let mut session = client.login()?;

    if let Some(claims) = &session.claims {
        println!(
            "Usuário: {}",
            claims.preferred_username.as_deref().unwrap_or(&claims.sub)
        );
    }
    println!(
        "Access token expira em {:?}",
        session.time_left().unwrap_or_default()
    );
    if let Ok(user) = client.userinfo(&session.tokens.access_token) {
        println!("userinfo.sub = {}", user.sub);
    }

    prompt("Pressione Enter para renovar os tokens...");
    session.refresh()?;
    println!(
        "Renovado. Novo access token expira em {:?}",
        session.time_left().unwrap_or_default()
    );

    prompt("Pressione Enter para encerrar a sessão no navegador...");
    match session.logout(None) {
        Ok(()) => println!("Logout solicitado no navegador. Fim."),
        Err(e) => println!("Logout falhou: {e}"),
    }
    Ok(())
}

fn prompt(message: &str) {
    print!("{message} ");
    std::io::stdout().flush().ok();
    std::io::stdin().lock().lines().next();
}
