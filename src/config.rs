use std::time::Duration;

/// Configuração efetiva da [`crate::KeycloakClient`] (construída via
/// [`crate::KeycloakClientBuilder`]).
#[derive(Debug, Clone)]
pub struct KeycloakConfig {
    pub(crate) base_url: String,
    pub(crate) realm: String,
    pub(crate) client_id: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) redirect_port: u16,
    pub(crate) redirect_path: String,
    pub(crate) http_timeout: Duration,
    pub(crate) callback_timeout: Duration,
    pub(crate) use_discovery: bool,
    pub(crate) validate_id_token: bool,
    pub(crate) id_token_leeway_secs: u64,
}

impl KeycloakConfig {
    /// Issuer esperado do realm (formato Keycloak: `{base_url}/realms/{realm}`).
    pub fn issuer(&self) -> String {
        format!(
            "{}/realms/{}",
            self.base_url.trim_end_matches('/'),
            self.realm
        )
    }

    /// `redirect_uri` efetivo: `http://localhost:{redirect_port}{redirect_path}`.
    pub fn redirect_uri(&self) -> String {
        format!(
            "http://localhost:{}{}",
            self.redirect_port, self.redirect_path
        )
    }
}

/// Builder de [`crate::KeycloakClient`].
///
/// ```no_run
/// use keycloak_oauth2::KeycloakClient;
///
/// let client = KeycloakClient::builder()
///     .base_url("https://localhost:8080")
///     .realm("myrealm")
///     .client_id("meu-client")
///     .scope("openid profile")
///     .redirect_port(8765)
///     .build()?;
/// # Ok::<(), keycloak_oauth2::KeycloakError>(())
/// ```
#[derive(Debug, Clone)]
pub struct KeycloakClientBuilder {
    pub(crate) config: KeycloakConfig,
}

impl KeycloakClientBuilder {
    pub(crate) fn new() -> Self {
        Self {
            config: KeycloakConfig {
                base_url: "http://localhost:8080".to_string(),
                realm: "master".to_string(),
                client_id: String::new(),
                scopes: vec!["openid".to_string()],
                redirect_port: 8765,
                redirect_path: "/callback".to_string(),
                http_timeout: crate::error::http_timeout_default(),
                callback_timeout: Duration::from_secs(300),
                use_discovery: true,
                validate_id_token: true,
                id_token_leeway_secs: 30,
            },
        }
    }

    /// URL base do Keycloak (ex.: `https://localhost:8080`).
    pub fn base_url(mut self, value: impl Into<String>) -> Self {
        self.config.base_url = value.into();
        self
    }

    /// Nome do realm.
    pub fn realm(mut self, value: impl Into<String>) -> Self {
        self.config.realm = value.into();
        self
    }

    /// Client ID público cadastrado no Keycloak.
    pub fn client_id(mut self, value: impl Into<String>) -> Self {
        self.config.client_id = value.into();
        self
    }

    /// Escopos como string separada por espaço (substitui os anteriores).
    pub fn scope(mut self, value: impl Into<String>) -> Self {
        self.config.scopes = value
            .into()
            .split_whitespace()
            .map(str::to_string)
            .collect();
        self
    }

    /// Escopos como coleção (substitui os anteriores).
    pub fn scopes<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.config.scopes = values.into_iter().map(Into::into).collect();
        self
    }

    /// Porta do servidor de callback (default `8765`; `0` = porta efêmera por login).
    pub fn redirect_port(mut self, value: u16) -> Self {
        self.config.redirect_port = value;
        self
    }

    /// Caminho do callback (default `/callback`; precisa casar com o client no Keycloak).
    pub fn redirect_path(mut self, value: impl Into<String>) -> Self {
        self.config.redirect_path = value.into();
        self
    }

    /// Timeout das chamadas HTTP (default 15s).
    pub fn http_timeout(mut self, value: Duration) -> Self {
        self.config.http_timeout = value;
        self
    }

    /// Tempo máximo aguardando o callback do navegador (default 5 min).
    pub fn callback_timeout(mut self, value: Duration) -> Self {
        self.config.callback_timeout = value;
        self
    }

    /// Liga/desliga a descoberta OIDC (default `true`; desligada, usa endpoints derivados).
    pub fn use_discovery(mut self, value: bool) -> Self {
        self.config.use_discovery = value;
        self
    }

    /// Liga/desliga a validação de claims do ID token (default `true`).
    pub fn validate_id_token(mut self, value: bool) -> Self {
        self.config.validate_id_token = value;
        self
    }

    /// Tolerância de relógio (segundos) na validação de `exp` (default 30).
    pub fn id_token_leeway(mut self, value: u64) -> Self {
        self.config.id_token_leeway_secs = value;
        self
    }

    /// Valida a configuração e constrói o cliente.
    pub fn build(self) -> crate::Result<crate::KeycloakClient> {
        if self.config.base_url.trim().is_empty() {
            return Err(crate::KeycloakError::Config("base_url vazio".into()));
        }
        if !self.config.base_url.starts_with("http://")
            && !self.config.base_url.starts_with("https://")
        {
            return Err(crate::KeycloakError::Config(
                "base_url precisa começar com http:// ou https://".into(),
            ));
        }
        if self.config.realm.trim().is_empty() {
            return Err(crate::KeycloakError::Config("realm vazio".into()));
        }
        if self.config.client_id.trim().is_empty() {
            return Err(crate::KeycloakError::Config(
                "client_id é obrigatório".into(),
            ));
        }
        if self.config.redirect_path.is_empty() || !self.config.redirect_path.starts_with('/') {
            return Err(crate::KeycloakError::Config(
                "redirect_path precisa começar com '/'".into(),
            ));
        }
        crate::client::KeycloakClient::from_config(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_sao_estaveis() {
        let config = KeycloakClientBuilder::new().config;
        assert_eq!(config.base_url, "http://localhost:8080");
        assert_eq!(config.realm, "master");
        assert_eq!(config.redirect_port, 8765);
        assert_eq!(config.redirect_path, "/callback");
        assert_eq!(config.scopes, vec!["openid".to_string()]);
        assert!(config.use_discovery);
        assert!(config.validate_id_token);
    }

    #[test]
    fn issuer_e_redirect_uri_derivados() {
        let config = KeycloakClientBuilder::new()
            .base_url("https://auth.test/")
            .realm("hyper")
            .config;
        assert_eq!(config.issuer(), "https://auth.test/realms/hyper");
        assert_eq!(config.redirect_uri(), "http://localhost:8765/callback");
    }

    #[test]
    fn scope_string_quebra_por_espaco() {
        let config = KeycloakClientBuilder::new()
            .scope("openid profile email")
            .config;
        assert_eq!(config.scopes, vec!["openid", "profile", "email"]);
    }

    #[test]
    fn validacoes_de_campo() {
        let err = KeycloakClientBuilder::new()
            .client_id("x")
            .base_url("ftp://x")
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("http"));

        let err = KeycloakClientBuilder::new().build().unwrap_err();
        assert!(err.to_string().contains("client_id"));

        let err = KeycloakClientBuilder::new()
            .client_id("x")
            .redirect_path("callback")
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("redirect_path"));
    }
}
