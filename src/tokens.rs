use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

/// Conjunto de tokens devolvido pelo endpoint de token.
///
/// A lib não persiste tokens ([D-006]): guarde-os no storage seguro do SO quando necessário.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSet {
    /// Access token para chamar APIs (ex.: `Authorization: Bearer ...`).
    pub access_token: String,
    /// Refresh token, quando o servidor o devolve.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// ID token (presente com o escopo `openid`).
    #[serde(default)]
    pub id_token: Option<String>,
    /// Tipo do token (normalmente `Bearer`).
    #[serde(default)]
    pub token_type: Option<String>,
    /// Validade do access token em segundos, como veio na resposta.
    #[serde(default)]
    pub expires_in: Option<u64>,
    /// Escopos efetivamente concedidos.
    #[serde(default)]
    pub scope: Option<String>,
    /// `session_state` do Keycloak (opaco).
    #[serde(default)]
    pub session_state: Option<String>,
    /// Momento estimado de expiração do access token (`now + expires_in`).
    #[serde(skip)]
    pub expires_at: Option<SystemTime>,
}

impl TokenSet {
    pub(crate) fn from_response(body: &str) -> crate::Result<Self> {
        let mut set: TokenSet = serde_json::from_str(body).map_err(|e| {
            crate::KeycloakError::InvalidTokenResponse(format!(
                "esperado JSON com access_token: {e}"
            ))
        })?;
        if let Some(secs) = set.expires_in {
            set.expires_at = SystemTime::now().checked_add(Duration::from_secs(secs));
        }
        Ok(set)
    }

    /// `true` quando `expires_at` já passou (ou nunca foi informado junto com `expires_in > 0`).
    pub fn expired(&self) -> bool {
        match self.expires_at {
            Some(at) => at <= SystemTime::now(),
            None => false,
        }
    }

    /// Tempo restante estimado do access token.
    pub fn time_left(&self) -> Option<Duration> {
        self.expires_at
            .and_then(|at| at.duration_since(SystemTime::now()).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = r#"{
        "access_token": "at-1",
        "refresh_token": "rt-1",
        "id_token": "id-1",
        "token_type": "Bearer",
        "expires_in": 300,
        "scope": "openid profile",
        "session_state": "ss-1"
    }"#;

    #[test]
    fn parse_completo_calcula_expiracao() {
        let set = TokenSet::from_response(BODY).unwrap();
        assert_eq!(set.access_token, "at-1");
        assert_eq!(set.refresh_token.as_deref(), Some("rt-1"));
        assert_eq!(set.token_type.as_deref(), Some("Bearer"));
        let left = set.time_left().unwrap();
        assert!(left <= Duration::from_secs(300));
        assert!(left > Duration::from_secs(290));
        assert!(!set.expired());
    }

    #[test]
    fn sem_access_token_e_erro() {
        let err = TokenSet::from_response(r#"{"error":"invalid_grant"}"#).unwrap_err();
        assert!(matches!(err, crate::KeycloakError::InvalidTokenResponse(_)));
    }
}
