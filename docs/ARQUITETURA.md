# Arquitetura — keycloak-oauth2-rust

Lib Rust de **OAuth2/OIDC (Authorization Code + PKCE)** para Keycloak, voltada a aplicações
desktop (cliente público, sem `client_secret`): login no navegador, callback loopback, troca
de código, refresh, logout (RP-initiated), userinfo e descoberta OIDC.

Documentação de uso: `README.md`. Decisões: `docs/DECISOES.md`.

---

## Módulos

| Módulo | Responsabilidade |
|---|---|
| `config` | Builder da configuração (`base_url`, `realm`, `client_id`, escopos, portas/timeouts) e validação. |
| `endpoints` | URLs OIDC — derivados de `base_url`/`realm` (fallback) ou vindos da descoberta. |
| `discovery` | Fetch/cache do `.well-known/openid-configuration` do realm. |
| `pkce` | Geração de `code_verifier` e `code_challenge` S256 (vetores do RFC 7636 em teste). |
| `auth_url` | Montagem da URL de autorização (`response_type=code`, PKCE, `state`, `nonce`). |
| `callback` | Servidor loopback (`tiny_http`), páginas HTML de sucesso/erro, draining de callbacks órfãos. |
| `tokens` | `TokenSet` (access/refresh/id, `expires_in`, `expires_at` calculado). |
| `id_token` | Decodificação e validação de claims do ID token (`iss`/`aud`/`exp`/`nonce`/`azp`). |
| `userinfo` | `UserInfo` tipado do endpoint `userinfo`. |
| `client` | `KeycloakClient` — orquestra `begin_login`/`complete_login`/`login`, troca de código, refresh, logout; `Session` para o consumidor. |
| `error` | `KeycloakError` tipado (`thiserror`). |

## Fluxo de login

```
begin_login()                complete_login(flow)
  │                            │
  │ endpoints() ── descoberta? │ loop (recv_timeout até callback_timeout):
  │   ├─ cache                  │  path errado      → 404, continua
  │   └─ falha → derivados     │  error do IdP     → página de erro + AuthorizationRejected
  │ state/nonce/verifier novos │  state inválido   → página invalid_state, continua (não consome)
  │ pending = {state, verifier,│  code + state ok  → página de sucesso, troca o código
  │            TTL 10 min}     │                    └─ POST token (grant_type=authorization_code,
  │ servidor loopback aberto   │                       code_verifier, redirect_uri, client_id)
  │ URL de autorização         │ ID token presente → decodifica + valida claims (iss/aud/exp/nonce)
  ▼                            ▼
LoginFlow { url, redirect_uri }  Session { tokens, claims }
```

- `login()` = `begin_login` + abrir navegador (`open`) + `complete_login`.
- O servidor de callback **fica aberto** entre logins (D-010), preso a `127.0.0.1`.
- `state` é single-use com TTL (D-008); requests órfãos são drenados no próximo login.
- Porta `0` → porta efêmera por login (útil em testes; `LoginFlow.redirect_uri` sempre reflete a porta real).

## Renovação e encerramento

- `Session::refresh()` → `grant_type=refresh_token` (client público: só `client_id`); preserva
  `refresh_token`/`id_token` antigos se a resposta omitir (D-011).
- `Session::logout()` → abre o navegador no `end_session_endpoint` com `id_token_hint`
  (e `post_logout_redirect_uri` opcional). `end_session_url()` expõe a URL para fluxos custom.

## HTTP e TLS

- `reqwest` **blocking** com `rustls-tls` (D-004); timeout configurável.
- Callback com `tiny_http` (sem runtime async imposto ao consumidor); API síncrona (D-002).

## Segurança (resumo)

- Somente cliente público com PKCE S256 (D-003); nenhum segredo na lib.
- Tokens não são persistidos pela lib (D-006).
- ID token validado por claims na origem direta do token endpoint (D-005); JWKS é feature futura.
- Callback preso a loopback; state single-use com TTL; `nonce` ligando login ↔ ID token.
