# keycloak-oauth2

[![Licença MIT](https://img.shields.io/badge/licen%C3%A7a-MIT-blue.svg)](LICENSE)
[![crates.io](https://img.shields.io/crates/v/keycloak-oauth2.svg)](https://crates.io/crates/keycloak-oauth2)

Biblioteca Rust de autenticação **OAuth2/OIDC Authorization Code + PKCE** para Keycloak.
Abre o login no navegador do usuário, escuta o callback em `localhost`, troca o código por
tokens e cuida de **refresh**, **logout** e **descoberta OIDC**.

Voltada a **clientes públicos** — apps desktop, CLIs e serviços, sem `client_secret`.

- Authorization Code + **PKCE S256** obrigatório
- Callback **loopback** (`127.0.0.1`) com servidor que fica aberto entre logins
- **Descoberta OIDC** (`.well-known/openid-configuration`) com fallback para endpoints derivados
- **Refresh** de token (client público), com preservação de tokens omitidos na resposta
- **Logout** RP-initiated (`end_session_endpoint` + `id_token_hint`)
- **Validação de ID token** por claims (`iss`/`aud`/`exp`/`nonce`)
- `state` single-use com TTL e `nonce` por login
- TLS via **rustls** (sem OpenSSL nativo); API síncrona

---

## Pré-requisitos

- Rust 1.75+ (MSRV)
- Keycloak rodando (ex.: `https://localhost:8080`) com um realm e um client configurados

## Configuração no Keycloak

1. Acesse o Keycloak Admin (ex.: `http://localhost:8080/admin`).
2. Crie ou escolha um realm (ex.: `myrealm`).
3. Em **Clients**, crie um client **público** (Client authentication: *off*):
   - **Valid redirect URIs**: exatamente a URL do callback, ex. `http://localhost:8765/callback`
   - **Web origins**: pode usar `+` se precisar de CORS
4. Salve.

A `redirect_uri` usada na autorização e na troca de tokens é sempre
`http://localhost:{redirect_port}{redirect_path}` e precisa bater com o **Valid redirect URIs**.

## Uso

```rust,no_run
use keycloak_oauth2::KeycloakClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = KeycloakClient::builder()
        .base_url("https://localhost:8080")
        .realm("myrealm")
        .client_id("meu-client")
        .scope("openid profile")
        .redirect_port(8765)
        .build()?;

    // abre o navegador, espera o callback e troca o código por tokens
    let mut session = client.login()?;

    if let Some(claims) = &session.claims {
        println!("Logado como {:?}", claims.preferred_username);
    }

    if session.expired() {
        session.refresh()?;
    }

    // encerra a sessão SSO no navegador
    session.logout(None)?;
    Ok(())
}
```

A API síncrona é deliberada: em runtimes async (ex.: apps desktop), rode dentro de
`spawn_blocking` (ou use
`begin_login()`/`complete_login()` para controlar o navegador por fora — ex. opener plugin):

```rust,no_run
# use keycloak_oauth2::KeycloakClient;
# fn demo(client: &KeycloakClient) -> keycloak_oauth2::Result<()> {
let flow = client.begin_login()?;      // não abre navegador
// abra flow.url por conta própria, então:
let session = client.complete_login(flow)?;
# Ok(())
# }
```

### Configuração

| Parâmetro | Default | Descrição |
|---|---|---|
| `base_url` | `http://localhost:8080` | URL base do Keycloak |
| `realm` | `master` | Nome do realm |
| `client_id` | *(obrigatório)* | Client ID público no Keycloak |
| `scope` / `scopes` | `openid` | Escopos solicitados |
| `redirect_port` | `8765` | Porta do servidor loopback (`0` = porta efêmera por login) |
| `redirect_path` | `/callback` | Caminho do callback (deve casar com o client no Keycloak) |
| `http_timeout` | 15s | Timeout das chamadas HTTP (token, userinfo, descoberta) |
| `callback_timeout` | 5 min | Tempo máximo esperando o callback do navegador |
| `use_discovery` | `true` | Descoberta OIDC; em falha cai nos endpoints derivados |
| `validate_id_token` | `true` | Valida claims do ID token (`iss`/`aud`/`exp`/`nonce`) |
| `id_token_leeway` | 30s | Tolerância relógio na validação de `exp` |

### Controle do fluxo

```rust,no_run
# use keycloak_oauth2::KeycloakClient;
# fn demo(client: &KeycloakClient) -> keycloak_oauth2::Result<()> {
let flow = client.begin_login()?;              // sobe o loopback, gera state/nonce/PKCE
// ... abra flow.url no navegador por conta própria ...
let session = client.complete_login(flow)?;    // valida state, troca código, valida ID token

let tokens = client.refresh_tokens(&session.tokens)?;      // renovação avulsa
let info = client.userinfo(&session.tokens.access_token)?; // perfil do usuário
let url = client.end_session_url(session.tokens.id_token.as_deref(), None);
# Ok(())
# }
```

## Exemplo completo

Com o Keycloak local no ar:

```bash
KEYCLOAK_BASE_URL=https://localhost:8080 \
KEYCLOAK_REALM=myrealm \
KEYCLOAK_CLIENT_ID=meu-client \
cargo run --example login
```

O exemplo faz login, mostra claims, renova o token e encerra a sessão no navegador.

### Subir um Keycloak de teste (docker)

```bash
docker run --rm -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak start-dev
```

Depois: criar o realm, criar um client **público** com redirect
`http://localhost:8765/callback` e criar um usuário de teste.

## Testes

```bash
cargo test
```

Unitários (PKCE RFC 7636, validação de ID token, endpoints derivados) e de integração com
`wiremock` (descoberta, troca de código, refresh, userinfo, callback loopback) — sem rede externa.

## Escopo

**v1:** o listado acima. **Futuro (sob decisão):** verificação de assinatura do ID token via
JWKS, API async atrás de feature e client confidencial.

## Licença

[MIT](LICENSE).
