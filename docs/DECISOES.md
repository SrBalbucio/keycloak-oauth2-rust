# Decisões — keycloak-oauth2-rust

Registro de decisões de arquitetura/escopo (estilo ADR resumido). Toda decisão relevante deve
ser adicionada aqui, com data e justificativa curta.

> **Nunca** altere o corpo de uma decisão já tomada; se ela mudar, adicione uma nova entrada
> supersendendo (ex.: "D-010 supersede D-002").

---

| ID | Data | Decisão | Justificativa / contexto |
|---|---|---|---|
| D-001 | 2026-10-21 | Nome público da crate: **`keycloak-oauth2`** (confirmado livre no crates.io em 2026-10-21). O repositório mantém o nome `keycloak-oauth2-rust`. | `keycloak-oauth2` estava livre no registro e é o nome idiomático; sufixo `-rust` em nome de crate é redundante. |
| D-002 | 2026-10-21 | API **síncrona (blocking)** como núcleo; async só no futuro, atrás de feature, se houver consumidor. | O callback loopback é inerentemente bloqueante; consumidores desktop (ex.: Tauri) rodam a lib em threads próprias (`spawn_blocking`). Evita duplicar API antes de demanda real. |
| D-003 | 2026-10-21 | **Apenas cliente público OAuth2** (Authorization Code + PKCE S256); sem suporte a `client_secret` na v1. | O foco são apps desktop, onde segredo embutido no binário é proibido. Confidential client amplia escopo sem consumidor hoje. |
| D-004 | 2026-10-21 | HTTP via **`reqwest` com `rustls-tls`** (sem TLS nativo do SO). | Alvos Windows + Linux; rustls elimina dependência de OpenSSL do sistema e facilita cross-compile e CI. |
| D-005 | 2026-10-21 | ID token validado por **claims** (`iss`/`aud`/`exp`/`nonce`, com azp para múltiplos audiences) **sem verificação de assinatura JWKS** na v1; JWKS/JWS entra como feature futura. | Na troca de código o token vem **direto do token endpoint via TLS** — a validação de assinatura é dispensada nessa origem (OIDC Core §3.1.3.7). Assinatura só importa para tokens recebidos por outros canais. |
| D-006 | 2026-10-21 | A lib **não armazena tokens**: devolve `TokenSet` e cabe ao consumidor persistir (no desktop, storage seguro do SO). | Separação de responsabilidades; armazenamento seguro de tokens é próprio de cada plataforma. |
| D-007 | 2026-10-21 | **Descoberta OIDC** (`.well-known/openid-configuration`) com **fallback para endpoints derivados** de `base_url`/`realm` quando a descoberta falha (com `log::warn`). Descoberta desligável (`use_discovery(false)`). | Degradação graciosa: sem a descoberta, o cliente segue funcionando com os endpoints derivados no formato padrão do Keycloak. Issuer validado é sempre o do `Endpoints` efetivo (descoberto ou derivado). |
| D-008 | 2026-10-21 | `state` é **single-use com TTL de 10 min** e `nonce` por login. | CSRF state sem TTL permite reuso indefinido; `nonce` é pré-requisito para ligar as claims do ID token ao login iniciado. |
| D-009 | 2026-10-21 | CI **Woodpecker** (`fmt --check` + `clippy -D warnings` + `test`); MSRV declarado **1.75** (edition 2021); versionamento **semver** a partir de `0.1.0`. | MSRV conservador para maximizar consumidores; na prática o piso real é o das dependências. |
| D-010 | 2026-10-21 | Servidor de callback loopback fica **aberto entre logins**, sempre em `127.0.0.1`; `redirect_port=0` cria porta efêmera por login (útil em testes e para evitar colisão). Requests fora do fluxo corrente recebem página de erro e não consomem o fluxo. | Reabrir a porta a cada login cria janelas de colisão. Bind em loopback restringe a superfície à própria máquina. |
| D-011 | 2026-10-21 | Renovação preserva `refresh_token` e `id_token` antigos quando a resposta de refresh os omite. | Keycloak normalmente os devolve, mas o comportamento é opcional no protocolo; preservar evita perder sessão por resposta mínima. |
