# AGENTS — keycloak-oauth2-rust

Regras de trabalho para este repositório. Decisões detalhadas em `docs/DECISOES.md`.

## Idioma e commits

- Documentação, mensagens de erro e doc comments em **pt-BR**; termos técnicos podem ficar em inglês.
- Commits curtos e imperativos, agrupando mudanças coesas.
- **Nunca** versionar segredos, tokens ou chaves.

## Build e qualidade (obrigatório antes de commit)

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`
- Itens públicos documentados com rustdoc (doc comments); doctests com `no_run` quando dependem de rede.

## Arquitetura e segurança

- **Apenas cliente público OAuth2 (PKCE S256)** — não adicionar suporte a `client_secret` sem decisão nova em `docs/DECISOES.md`.
- **Sem armazenamento de tokens na lib** — a lib devolve `TokenSet`; persistência é responsabilidade do consumidor (storage seguro do SO no desktop).
- Validação de ID token por **claims** (iss/aud/exp/nonce) na v1; assinatura via JWKS é feature futura (D-005).
- TLS sempre via **rustls** (portabilidade Windows/Linux, sem OpenSSL nativo).
- **Nunca** dependência de caminho local (`path =`) — consumo via crates.io.
- `state` e `nonce` são single-use com TTL; não enfraquecer.
- Versionamento **semver**; mudanças que quebram API só em major.

## Testes

- Vetores de teste do RFC 7636 para PKCE não podem ser alterados.
- Testes de integração usam `wiremock` — nada de rede externa real.
- A validação ponta a ponta contra Keycloak local é manual, via `cargo run --example login` — roteiro no README.
