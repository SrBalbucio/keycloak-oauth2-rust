//! Testes de integração sobre `wiremock` — nada de rede externa.
//!
//! `reqwest::blocking` (e qualquer `KeycloakClient`/`Session`, que o contêm) não pode ser
//! criado nem dropado dentro do runtime async do teste — todo uso fica em `spawn_blocking`,
//! devolvendo apenas dados planos para as asserções.

use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use keycloak_oauth2::{KeycloakClient, KeycloakError};
use serde_json::json;
use url::Url;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const REALM: &str = "test";
const CLIENT_ID: &str = "test-app";
const ISSUER_PATH: &str = "/realms/test";
const TOKEN_PATH: &str = "/realms/test/protocol/openid-connect/token";

fn b64url(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(value.as_bytes())
}

fn fake_id_token(issuer: &str, nonce: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = json!({
        "iss": issuer,
        "aud": CLIENT_ID,
        "sub": "user-1",
        "exp": now + 600,
        "iat": now,
        "nonce": nonce,
        "preferred_username": "joao"
    });
    format!(
        "{}.{}.nao-verificado",
        b64url(r#"{"alg":"RS256","typ":"JWT"}"#),
        b64url(&claims.to_string())
    )
}

fn token_body(issuer: &str, nonce: &str) -> String {
    json!({
        "access_token": "at-1",
        "refresh_token": "rt-1",
        "id_token": fake_id_token(issuer, nonce),
        "token_type": "Bearer",
        "expires_in": 300,
        "scope": "openid profile"
    })
    .to_string()
}

fn token_endpoint_mock(body: String) -> Mock {
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .and(body_string_contains("grant_type=authorization_code"))
        .and(body_string_contains("code_verifier="))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .expect(1)
}

fn refresh_endpoint_mock() -> Mock {
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                json!({
                    "access_token": "at-2",
                    "token_type": "Bearer",
                    "expires_in": 300
                })
                .to_string(),
            ),
        )
        .expect(1)
}

fn query_param(url: &str, name: &str) -> String {
    Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
        .unwrap()
}

fn simulate_browser(redirect_uri: String, query: String) {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        let _ = reqwest::blocking::get(format!("{redirect_uri}?{query}"));
    });
}

#[tokio::test]
async fn login_completo_com_callback_e_id_token_validados() {
    let server = MockServer::start().await;
    let issuer = format!("{}{}", server.uri(), ISSUER_PATH);

    // Fase 1: cliente + begin_login nascem e morrem em thread bloqueante.
    let uri = server.uri();
    let (flow, client) = tokio::task::spawn_blocking(move || {
        let client = test_client(&uri, Duration::from_secs(5));
        let flow = client.begin_login().unwrap();
        (flow, client)
    })
    .await
    .unwrap();
    let nonce = query_param(&flow.url, "nonce");

    server
        .register(token_endpoint_mock(token_body(&issuer, &nonce)))
        .await;

    let state = query_param(&flow.url, "state");
    simulate_browser(
        flow.redirect_uri.clone(),
        format!("code=abc123&state={state}"),
    );

    // Fase 2: login completo; apenas dados planos voltam para a thread async.
    let result = tokio::task::spawn_blocking(move || {
        let session = client.complete_login(flow).unwrap();
        (
            session.tokens.access_token.clone(),
            session.time_left().is_some(),
            session.claims.map(|c| (c.iss, c.preferred_username, c.sub)),
        )
    })
    .await
    .unwrap();

    assert_eq!(result.0, "at-1");
    assert!(result.1);
    let claims = result.2.expect("id token presente e validado");
    assert_eq!(claims.0, issuer);
    assert_eq!(claims.1.as_deref(), Some("joao"));
    assert_eq!(claims.2, "user-1");
    server.verify().await;
}

#[tokio::test]
async fn state_invalido_nao_consome_o_fluxo() {
    let server = MockServer::start().await;
    let issuer = format!("{}{}", server.uri(), ISSUER_PATH);

    let uri = server.uri();
    let (flow, client) = tokio::task::spawn_blocking(move || {
        let client = test_client(&uri, Duration::from_secs(5));
        let flow = client.begin_login().unwrap();
        (flow, client)
    })
    .await
    .unwrap();
    let nonce = query_param(&flow.url, "nonce");
    let state = query_param(&flow.url, "state");

    server
        .register(token_endpoint_mock(token_body(&issuer, &nonce)))
        .await;

    let redirect_uri = flow.redirect_uri.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        let _ = reqwest::blocking::get(format!("{redirect_uri}?code=x&state=errado"));
        std::thread::sleep(Duration::from_millis(300));
        let _ = reqwest::blocking::get(format!("{redirect_uri}?code=abc&state={state}"));
    });

    let access_token = tokio::task::spawn_blocking(move || {
        client.complete_login(flow).unwrap().tokens.access_token
    })
    .await
    .unwrap();
    assert_eq!(access_token, "at-1");
}

#[tokio::test]
async fn fluxo_so_aceita_um_uso() {
    let server = MockServer::start().await;
    let uri = server.uri();
    let (first, second) = tokio::task::spawn_blocking(move || {
        let client = test_client(&uri, Duration::from_millis(300));
        let flow = client.begin_login().unwrap();
        let first = client.complete_login(flow.clone()).unwrap_err();
        let second = client.complete_login(flow).unwrap_err();
        (first, second)
    })
    .await
    .unwrap();

    assert!(matches!(first, KeycloakError::CallbackTimeout { .. }));
    assert!(matches!(second, KeycloakError::InvalidState));
}

#[tokio::test]
async fn descoberta_oidc_sobrescreve_endpoints_e_cacha() {
    let server = MockServer::start().await;
    server
        .register(
            Mock::given(method("GET"))
                .and(path(format!(
                    "{ISSUER_PATH}/.well-known/openid-configuration"
                )))
                .respond_with(
                    ResponseTemplate::new(200).set_body_string(
                        json!({
                            "issuer": format!("{}/realms/test", server.uri()),
                            "authorization_endpoint": format!("{}/autorizar", server.uri()),
                            "token_endpoint": format!("{}/tokenizar", server.uri()),
                            "userinfo_endpoint": format!("{}/quem", server.uri()),
                            "end_session_endpoint": format!("{}/sair", server.uri()),
                            "jwks_uri": format!("{}/chaves", server.uri())
                        })
                        .to_string(),
                    ),
                )
                .expect(1),
        )
        .await;

    let uri = server.uri();
    let endpoints = tokio::task::spawn_blocking(move || {
        let client = test_client_with_discovery(&uri, Duration::from_secs(5), true);
        let first = client.endpoints();
        let second = client.endpoints();
        (first, second)
    })
    .await
    .unwrap();

    assert_eq!(endpoints.0, endpoints.1, "segunda leitura vem do cache");
    assert_eq!(
        endpoints.0.authorization,
        format!("{}/autorizar", server.uri())
    );
    assert_eq!(endpoints.0.token, format!("{}/tokenizar", server.uri()));
    assert_eq!(
        endpoints.0.end_session.as_deref(),
        Some(&*format!("{}/sair", server.uri()))
    );
    server.verify().await;
}

#[tokio::test]
async fn falha_de_descoberta_cai_nos_endpoints_derivados() {
    let server = MockServer::start().await;
    server
        .register(
            Mock::given(method("GET"))
                .and(path(format!(
                    "{ISSUER_PATH}/.well-known/openid-configuration"
                )))
                .respond_with(ResponseTemplate::new(500))
                .expect(1),
        )
        .await;

    let uri = server.uri();
    let endpoints = tokio::task::spawn_blocking(move || {
        let client = test_client_with_discovery(&uri, Duration::from_secs(5), true);
        client.endpoints()
    })
    .await
    .unwrap();
    assert_eq!(
        endpoints.authorization,
        format!("{}{ISSUER_PATH}/protocol/openid-connect/auth", server.uri())
    );
    server.verify().await;
}

#[tokio::test]
async fn troca_de_codigo_rejeitada_vira_erro_tipado() {
    let server = MockServer::start().await;
    server
        .register(
            Mock::given(method("POST"))
                .and(path(TOKEN_PATH))
                .respond_with(
                    ResponseTemplate::new(400).set_body_string(
                        json!({
                            "error": "invalid_grant",
                            "error_description": "Code not valid"
                        })
                        .to_string(),
                    ),
                ),
        )
        .await;

    let uri = server.uri();
    let err = tokio::task::spawn_blocking(move || {
        let client = test_client(&uri, Duration::from_secs(5));
        client.exchange_code("bad", "verifier")
    })
    .await
    .unwrap()
    .unwrap_err();

    match err {
        KeycloakError::TokenRejected {
            status,
            error,
            description,
        } => {
            assert_eq!(status, 400);
            assert_eq!(error, "invalid_grant");
            assert_eq!(description.as_deref(), Some("Code not valid"));
        }
        other => panic!("erro inesperado: {other}"),
    }
}

#[tokio::test]
async fn refresh_preserva_tokens_omitidos() {
    let server = MockServer::start().await;
    let issuer = format!("{}{}", server.uri(), ISSUER_PATH);

    let uri = server.uri();
    let (flow, client) = tokio::task::spawn_blocking(move || {
        let client = test_client(&uri, Duration::from_secs(5));
        let flow = client.begin_login().unwrap();
        (flow, client)
    })
    .await
    .unwrap();
    let nonce = query_param(&flow.url, "nonce");

    server
        .register(token_endpoint_mock(token_body(&issuer, &nonce)))
        .await;
    server.register(refresh_endpoint_mock()).await;

    let state = query_param(&flow.url, "state");
    simulate_browser(flow.redirect_uri.clone(), format!("code=abc&state={state}"));

    let (access, refresh, id_token) = tokio::task::spawn_blocking(move || {
        let mut session = client.complete_login(flow).unwrap();
        session.refresh().unwrap();
        (
            session.tokens.access_token.clone(),
            session.tokens.refresh_token.clone(),
            session.tokens.id_token.clone(),
        )
    })
    .await
    .unwrap();

    assert_eq!(access, "at-2");
    assert_eq!(refresh.as_deref(), Some("rt-1"));
    assert!(id_token.is_some());
    server.verify().await;
}

#[tokio::test]
async fn userinfo_consulta_com_bearer() {
    let server = MockServer::start().await;
    server
        .register(
            Mock::given(method("GET"))
                .and(path(format!(
                    "{ISSUER_PATH}/protocol/openid-connect/userinfo"
                )))
                .and(header("authorization", "Bearer at-1"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_string(
                        json!({
                            "sub": "user-1",
                            "preferred_username": "joao",
                            "email": "joao@example.com",
                            "custom_claim": {"a": 1}
                        })
                        .to_string(),
                    ),
                ),
        )
        .await;

    let uri = server.uri();
    let info = tokio::task::spawn_blocking(move || {
        let client = test_client(&uri, Duration::from_secs(5));
        client.userinfo("at-1").unwrap()
    })
    .await
    .unwrap();

    assert_eq!(info.sub, "user-1");
    assert_eq!(info.preferred_username.as_deref(), Some("joao"));
    assert_eq!(info.extra.get("custom_claim"), Some(&json!({"a": 1})));
}

fn test_client(server_uri: &str, callback_timeout: Duration) -> KeycloakClient {
    test_client_with_discovery(server_uri, callback_timeout, false)
}

fn test_client_with_discovery(
    server_uri: &str,
    callback_timeout: Duration,
    use_discovery: bool,
) -> KeycloakClient {
    KeycloakClient::builder()
        .base_url(server_uri)
        .realm(REALM)
        .client_id(CLIENT_ID)
        .redirect_port(0)
        .use_discovery(use_discovery)
        .callback_timeout(callback_timeout)
        .build()
        .unwrap()
}
