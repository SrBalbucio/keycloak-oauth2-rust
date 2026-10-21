use std::time::Duration;

/// Erros da [`crate::KeycloakClient`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeycloakError {
    /// Configuração inválida (campos vazios, path de redirect malformado etc.).
    #[error("configuração inválida: {0}")]
    Config(String),

    /// Falha na descoberta OIDC (`.well-known/openid-configuration`).
    #[error("descoberta OIDC falhou: {0}")]
    Discovery(String),

    /// Falha de rede/HTTP nas chamadas ao Keycloak.
    #[error("falha de rede: {0}")]
    Network(#[from] reqwest::Error),

    /// O endpoint de token rejeitou a solicitação (ex.: `invalid_grant`).
    #[error(
        "endpoint de token respondeu {status}: {error}{details}",
        details = description
            .as_deref()
            .map(|d| format!(": {d}"))
            .unwrap_or_default()
    )]
    TokenRejected {
        status: u16,
        error: String,
        description: Option<String>,
    },

    /// Resposta do endpoint de token não é um conjunto de tokens válido.
    #[error("resposta de token inválida: {0}")]
    InvalidTokenResponse(String),

    /// O servidor de autorização devolveu `error` no callback do login.
    #[error("login rejeitado pelo servidor de autorização: {error}: {description}")]
    AuthorizationRejected { error: String, description: String },

    /// `state` desconhecido, já utilizado ou divergente do fluxo corrente.
    #[error("state inválido: desconhecido, já utilizado ou de outro fluxo")]
    InvalidState,

    /// O fluxo de login excedeu o TTL e precisa ser reiniciado.
    #[error("fluxo de login expirado; inicie um novo login")]
    LoginExpired,

    /// Ninguém completou o login dentro de `callback_timeout`.
    #[error("timeout aguardando o callback de login ({timeout_secs}s)")]
    CallbackTimeout { timeout_secs: u64 },

    /// O servidor de callback não está mais disponível.
    #[error("servidor de callback não está ativo")]
    CallbackClosed,

    /// Falha ao vincular a porta do callback.
    #[error("porta de callback {port} indisponível")]
    CallbackBind {
        port: u16,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Erro de E/S no servidor de callback.
    #[error("erro de E/S no callback: {0}")]
    CallbackIo(#[from] std::io::Error),

    /// ID token malformado ou com claims inválidas.
    #[error("id token inválido: {0}")]
    InvalidIdToken(String),

    /// O endpoint de userinfo respondeu com erro.
    #[error("userinfo respondeu {status}: {body}")]
    UserInfo { status: u16, body: String },

    /// Falha ao abrir o navegador para login/logout.
    #[error("falha ao abrir o navegador: {0}")]
    Browser(String),
}

/// Resultado padrão das operações da lib.
pub type Result<T> = std::result::Result<T, KeycloakError>;

pub(crate) fn token_rejected(status: u16, body: &str) -> KeycloakError {
    #[derive(serde::Deserialize)]
    struct Body {
        error: Option<String>,
        error_description: Option<String>,
    }

    match serde_json::from_str::<Body>(body) {
        Ok(parsed) => KeycloakError::TokenRejected {
            status,
            error: parsed.error.unwrap_or_else(|| "unknown".to_string()),
            description: parsed.error_description,
        },
        Err(_) => {
            let truncated: String = body.chars().take(200).collect();
            KeycloakError::TokenRejected {
                status,
                error: "unknown".to_string(),
                description: Some(truncated),
            }
        }
    }
}

pub(crate) fn http_timeout_default() -> Duration {
    Duration::from_secs(15)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpo_erro_oauth_e_mapeado() {
        let err = token_rejected(
            400,
            r#"{"error":"invalid_grant","error_description":"Code not valid"}"#,
        );
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
            other => panic!("variante inesperada: {other:?}"),
        }
    }

    #[test]
    fn corpo_nao_json_vira_erro_desconhecido() {
        let err = token_rejected(502, "<html>bad gateway</html>");
        match err {
            KeycloakError::TokenRejected { status, error, .. } => {
                assert_eq!(status, 502);
                assert_eq!(error, "unknown");
            }
            other => panic!("variante inesperada: {other:?}"),
        }
    }
}
