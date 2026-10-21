use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::auth_url;
use crate::callback::{
    drain, error_page, respond_page, success_page, CallbackServer, PendingAttempt, LOGIN_TTL,
};
use crate::config::{KeycloakClientBuilder, KeycloakConfig};
use crate::discovery;
use crate::endpoints::Endpoints;
use crate::error::{token_rejected, KeycloakError, Result};
use crate::id_token::IdTokenClaims;
use crate::pkce;
use crate::tokens::TokenSet;
use crate::userinfo::UserInfo;

/// Cliente OAuth2/OIDC (Authorization Code + PKCE) de um realm do Keycloak.
///
/// Barato de clonar; um único cliente atende vários logins (o servidor de callback
/// fica aberto entre eles). Veja [`KeycloakClientBuilder`] para a configuração.
#[derive(Clone)]
pub struct KeycloakClient {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for KeycloakClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeycloakClient")
            .field("base_url", &self.inner.config.base_url)
            .field("realm", &self.inner.config.realm)
            .field("client_id", &self.inner.config.client_id)
            .finish_non_exhaustive()
    }
}

pub(crate) struct Inner {
    config: KeycloakConfig,
    http: reqwest::blocking::Client,
    endpoints: RwLock<Option<Endpoints>>,
    pending: Mutex<Option<PendingAttempt>>,
    callback: Mutex<Option<CallbackServer>>,
}

/// Fluxo de login iniciado por [`KeycloakClient::begin_login`]: servidor de callback já
/// ativo, `state`/`nonce`/PKCE gerados e URL de autorização pronta para abrir no navegador.
#[derive(Debug, Clone)]
pub struct LoginFlow {
    /// URL de autorização para abrir no navegador do usuário.
    pub url: String,
    /// `redirect_uri` efetivo (reflete a porta real, inclusive com `redirect_port(0)`).
    pub redirect_uri: String,
    pub(crate) state: String,
}

/// Sessão resultante de um login bem-sucedido.
///
/// `tokens` nunca são persistidos pela lib ([D-006]) — guarde-os onde fizer sentido
/// (no desktop, storage seguro do SO).
#[derive(Debug, Clone)]
pub struct Session {
    client: KeycloakClient,
    /// Tokens do login (ou da última renovação).
    pub tokens: TokenSet,
    /// Claims do ID token (presente quando a resposta o trouxe).
    pub claims: Option<IdTokenClaims>,
}

impl Session {
    /// Renova os tokens via `refresh_token`, atualizando `tokens` e `claims` in place.
    pub fn refresh(&mut self) -> Result<()> {
        let tokens = self.client.refresh_tokens(&self.tokens)?;
        self.claims = tokens
            .id_token
            .as_deref()
            .and_then(|t| IdTokenClaims::from_jwt(t).ok());
        self.tokens = tokens;
        Ok(())
    }

    /// `true` quando o access token já expirou (ver [`TokenSet::expired`]).
    pub fn expired(&self) -> bool {
        self.tokens.expired()
    }

    /// Tempo restante estimado do access token.
    pub fn time_left(&self) -> Option<Duration> {
        self.tokens.time_left()
    }

    /// Encerra a sessão SSO abrindo o `end_session_endpoint` no navegador, com
    /// `id_token_hint` e `post_logout_redirect_uri` (opcional).
    pub fn logout(&self, post_logout_redirect_uri: Option<&str>) -> Result<()> {
        let url = self
            .client
            .end_session_url(self.tokens.id_token.as_deref(), post_logout_redirect_uri);
        open::that(&url).map_err(|e| KeycloakError::Browser(format!("{e}")))
    }
}

impl KeycloakClient {
    /// Inicia a construção de um cliente.
    pub fn builder() -> KeycloakClientBuilder {
        KeycloakClientBuilder::new()
    }

    pub(crate) fn from_config(config: KeycloakConfig) -> Result<Self> {
        let http = reqwest::blocking::Client::builder()
            .timeout(config.http_timeout)
            .build()?;
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                http,
                endpoints: RwLock::new(None),
                pending: Mutex::new(None),
                callback: Mutex::new(None),
            }),
        })
    }

    /// Login completo: sobe o callback, abre o navegador e espera o usuário autenticar.
    ///
    /// Se o navegador não puder ser aberto, a URL é impressa em stderr e o fluxo continua.
    pub fn login(&self) -> Result<Session> {
        let flow = self.begin_login()?;
        if let Err(e) = open::that(&flow.url) {
            eprintln!(
                "Não foi possível abrir o navegador ({e}). Abra manualmente:\n{}",
                flow.url
            );
        }
        self.complete_login(flow)
    }

    /// Primeira metade do login, sem abrir navegador: sobe o servidor de callback,
    /// registra a tentativa (single-use) e devolve a [`LoginFlow`] com a URL de autorização.
    pub fn begin_login(&self) -> Result<LoginFlow> {
        let endpoints = self.endpoints();
        let mut callback_guard = lock(&self.inner.callback);
        if self.inner.config.redirect_port == 0 || callback_guard.is_none() {
            *callback_guard = Some(CallbackServer::bind(self.inner.config.redirect_port)?);
        }
        let server = callback_guard
            .as_ref()
            .ok_or(KeycloakError::CallbackClosed)?;
        drain(&server.server);

        // A porta efetiva pode ser efêmera (`redirect_port(0)`), então o `redirect_uri`
        // do fluxo vem da porta realmente vinculada (host `localhost`, bind em 127.0.0.1).
        let redirect_uri = format!(
            "http://localhost:{}{}",
            server.addr.port(),
            self.inner.config.redirect_path
        );

        let state = random_token();
        let nonce = random_token();
        let code_verifier = pkce::generate_code_verifier();
        let code_challenge = pkce::code_challenge_s256(&code_verifier);
        let url = auth_url::build(
            &self.inner.config,
            &endpoints,
            &state,
            &nonce,
            &code_challenge,
            &redirect_uri,
        );
        *lock(&self.inner.pending) = Some(PendingAttempt {
            state: state.clone(),
            nonce,
            code_verifier,
            redirect_uri: redirect_uri.clone(),
            created_at: Instant::now(),
        });
        Ok(LoginFlow {
            url,
            redirect_uri,
            state,
        })
    }

    /// Segunda metade do login: espera o callback do navegador, valida o `state`
    /// (single-use, com TTL), troca o código por tokens e valida o ID token.
    pub fn complete_login(&self, flow: LoginFlow) -> Result<Session> {
        let pending = match lock(&self.inner.pending).take() {
            Some(p) if p.state == flow.state => p,
            _ => return Err(KeycloakError::InvalidState),
        };
        if pending.created_at.elapsed() > LOGIN_TTL {
            return Err(KeycloakError::LoginExpired);
        }

        let callback_guard = lock(&self.inner.callback);
        let server = callback_guard
            .as_ref()
            .ok_or(KeycloakError::CallbackClosed)?;
        let deadline = Instant::now() + self.inner.config.callback_timeout;
        let timeout_secs = self.inner.config.callback_timeout.as_secs();

        let (code, code_verifier) = loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(KeycloakError::CallbackTimeout { timeout_secs })?;
            let request = match server.server.recv_timeout(remaining) {
                Ok(Some(request)) => request,
                Ok(None) => return Err(KeycloakError::CallbackTimeout { timeout_secs }),
                Err(e) => return Err(KeycloakError::from(e)),
            };

            let raw = format!("http://localhost{}", request.url());
            let parsed = match url::Url::parse(&raw) {
                Ok(parsed) => parsed,
                Err(_) => {
                    respond_page(
                        request,
                        400,
                        error_page("invalid_request", "URL de callback malformada."),
                    )?;
                    continue;
                }
            };
            if parsed.path() != self.inner.config.redirect_path {
                respond_page(
                    request,
                    404,
                    error_page("not_found", "Caminho de callback desconhecido."),
                )?;
                continue;
            }

            let (mut code, mut state, mut error, mut description) = (None, None, None, None);
            for (key, value) in parsed.query_pairs() {
                match key.as_ref() {
                    "code" => code = Some(value.into_owned()),
                    "state" => state = Some(value.into_owned()),
                    "error" => error = Some(value.into_owned()),
                    "error_description" => description = Some(value.into_owned()),
                    _ => {}
                }
            }

            if let Some(error) = error {
                respond_page(
                    request,
                    400,
                    error_page(&error, description.as_deref().unwrap_or("")),
                )?;
                return Err(KeycloakError::AuthorizationRejected {
                    error,
                    description: description.unwrap_or_default(),
                });
            }

            let (Some(code), Some(state)) = (code, state) else {
                respond_page(
                    request,
                    400,
                    error_page(
                        "invalid_request",
                        "Parâmetros code e state são obrigatórios.",
                    ),
                )?;
                continue;
            };

            if state != pending.state {
                respond_page(
                    request,
                    400,
                    error_page(
                        "invalid_state",
                        "state desconhecido ou já utilizado; inicie o login novamente.",
                    ),
                )?;
                continue;
            }

            respond_page(request, 200, success_page())?;
            break (code, pending.code_verifier.clone());
        };

        let tokens = self.exchange_code_at(&code, &code_verifier, &pending.redirect_uri)?;
        self.session_from_tokens(tokens, &pending.nonce)
    }

    /// Troca um código de autorização por tokens (PKCE). Público para fluxos customizados
    /// (ex.: callback recebido por deep link em vez do servidor loopback); usa o
    /// `redirect_uri` da configuração — o fluxo `begin_login`/`complete_login` usa a porta
    /// efetivamente vinculada.
    pub fn exchange_code(&self, code: &str, code_verifier: &str) -> Result<TokenSet> {
        self.exchange_code_at(code, code_verifier, &self.inner.config.redirect_uri())
    }

    fn exchange_code_at(
        &self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
    ) -> Result<TokenSet> {
        let endpoints = self.endpoints();
        let params = [
            ("grant_type", "authorization_code".to_string()),
            ("code", code.to_string()),
            ("redirect_uri", redirect_uri.to_string()),
            ("client_id", self.inner.config.client_id.clone()),
            ("code_verifier", code_verifier.to_string()),
        ];
        let response = self
            .inner
            .http
            .post(&endpoints.token)
            .form(&params)
            .send()?;
        finish_token_response(response)
    }

    /// Renova tokens via `refresh_token` (client público: só `client_id` é enviado).
    ///
    /// `refresh_token` e `id_token` antigos são preservados quando a resposta os omite ([D-011]).
    pub fn refresh_tokens(&self, tokens: &TokenSet) -> Result<TokenSet> {
        let refresh_token =
            tokens
                .refresh_token
                .as_deref()
                .ok_or(KeycloakError::InvalidTokenResponse(
                    "tokens sem refresh_token não podem ser renovados".into(),
                ))?;
        let endpoints = self.endpoints();
        let params = [
            ("grant_type", "refresh_token".to_string()),
            ("client_id", self.inner.config.client_id.clone()),
            ("refresh_token", refresh_token.to_string()),
        ];
        let response = self
            .inner
            .http
            .post(&endpoints.token)
            .form(&params)
            .send()?;
        let mut renewed = finish_token_response(response)?;
        if renewed.refresh_token.is_none() {
            renewed.refresh_token = tokens.refresh_token.clone();
        }
        if renewed.id_token.is_none() {
            renewed.id_token = tokens.id_token.clone();
        }
        Ok(renewed)
    }

    /// Consulta o endpoint `userinfo` com o access token dado.
    pub fn userinfo(&self, access_token: &str) -> Result<UserInfo> {
        let endpoints = self.endpoints();
        let url = endpoints
            .userinfo
            .ok_or_else(|| KeycloakError::Discovery("realm não expõe userinfo_endpoint".into()))?;
        let response = self.inner.http.get(&url).bearer_auth(access_token).send()?;
        let status = response.status();
        let body = response.text()?;
        if !status.is_success() {
            return Err(KeycloakError::UserInfo {
                status: status.as_u16(),
                body,
            });
        }
        serde_json::from_str(&body)
            .map_err(|e| KeycloakError::InvalidTokenResponse(format!("userinfo inválido: {e}")))
    }

    /// Monta a URL de logout RP-initiated (`end_session_endpoint`) sem abrir navegador —
    /// útil para fluxos customizados. [`Session::logout`] já faz o caminho completo.
    pub fn end_session_url(
        &self,
        id_token_hint: Option<&str>,
        post_logout_redirect_uri: Option<&str>,
    ) -> String {
        let endpoints = self.endpoints();
        let base = endpoints.end_session.unwrap_or_else(|| {
            format!(
                "{}/protocol/openid-connect/logout",
                endpoints.issuer.trim_end_matches('/')
            )
        });
        let mut query = form_urlencoded::Serializer::new(String::new());
        if let Some(hint) = id_token_hint {
            query.append_pair("id_token_hint", hint);
        }
        if let Some(redirect) = post_logout_redirect_uri {
            query.append_pair("post_logout_redirect_uri", redirect);
        }
        let query = query.finish();
        if query.is_empty() {
            base
        } else {
            format!("{base}?{query}")
        }
    }

    /// Endpoints OIDC efetivos: cache da descoberta ou, em falha/desligada, os derivados
    /// de `base_url`/`realm` ([D-007]).
    pub fn endpoints(&self) -> Endpoints {
        if !self.inner.config.use_discovery {
            return Endpoints::derived(&self.inner.config.base_url, &self.inner.config.realm);
        }
        {
            let mut cache = write_lock(&self.inner.endpoints);
            if let Some(endpoints) = cache.as_ref() {
                return endpoints.clone();
            }
            let issuer = self.inner.config.issuer();
            match discovery::fetch(&self.inner.http, &issuer) {
                Ok(document) => {
                    let endpoints = Endpoints::from_discovery(&document);
                    *cache = Some(endpoints.clone());
                    return endpoints;
                }
                Err(e) => log::warn!(
                    "descoberta OIDC falhou ({e}); usando endpoints derivados de base_url/realm"
                ),
            }
        }
        Endpoints::derived(&self.inner.config.base_url, &self.inner.config.realm)
    }

    fn session_from_tokens(&self, tokens: TokenSet, nonce: &str) -> Result<Session> {
        let claims = match tokens.id_token.as_deref() {
            Some(id_token) => {
                let claims = IdTokenClaims::from_jwt(id_token)?;
                if self.inner.config.validate_id_token {
                    let endpoints = self.endpoints();
                    claims.validate(
                        &endpoints.issuer,
                        &self.inner.config.client_id,
                        Some(nonce),
                        self.inner.config.id_token_leeway_secs,
                    )?;
                }
                Some(claims)
            }
            None => None,
        };
        Ok(Session {
            client: self.clone(),
            tokens,
            claims,
        })
    }
}

fn finish_token_response(response: reqwest::blocking::Response) -> Result<TokenSet> {
    let status = response.status();
    let body = response.text()?;
    if !status.is_success() {
        return Err(token_rejected(status.as_u16(), &body));
    }
    TokenSet::from_response(&body)
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write_lock<T>(rwlock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    rwlock
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_aleatorios_sao_url_safe_e_unicos() {
        let a = random_token();
        let b = random_token();
        assert_eq!(a.len(), 43);
        assert_ne!(a, b);
    }

    #[test]
    fn end_session_url_monta_parametros() {
        let client = KeycloakClient::builder()
            .base_url("https://auth.test")
            .realm("hyper")
            .client_id("app")
            .use_discovery(false)
            .build()
            .unwrap();
        assert_eq!(
            client.end_session_url(Some("id-1"), Some("http://localhost:8765/bye")),
            "https://auth.test/realms/hyper/protocol/openid-connect/logout?id_token_hint=id-1&post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A8765%2Fbye"
        );
        assert_eq!(
            client.end_session_url(None, None),
            "https://auth.test/realms/hyper/protocol/openid-connect/logout"
        );
    }
}
