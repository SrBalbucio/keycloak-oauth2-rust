use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Papéis do realm no Keycloak (`realm_access.roles`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmAccess {
    pub roles: Vec<String>,
}

/// Claims do payload de um ID token (JWT), já decodificadas.
///
/// Campos conhecidos ficam tipados; todo o resto é preservado em [`IdTokenClaims::extra`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    #[serde(deserialize_with = "audience_vec")]
    pub aud: Vec<String>,
    pub exp: i64,
    #[serde(default)]
    pub iat: Option<i64>,
    #[serde(default)]
    pub auth_time: Option<i64>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub azp: Option<String>,
    #[serde(default)]
    pub session_state: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub family_name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub realm_access: Option<RealmAccess>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl IdTokenClaims {
    /// Decodifica o payload de um JWT (segmento central em base64url) **sem verificar a
    /// assinatura** — na troca de código o token vem direto do token endpoint via TLS,
    /// onde a verificação de assinatura é dispensada (OIDC Core §3.1.3.7, [D-005]).
    pub fn from_jwt(token: &str) -> crate::Result<Self> {
        let segments: Vec<&str> = token.split('.').collect();
        if segments.len() != 3 {
            return Err(crate::KeycloakError::InvalidIdToken(format!(
                "JWT precisa de 3 segmentos, recebidos {}",
                segments.len()
            )));
        }
        let payload = decode_b64url(segments[1]).map_err(|e| {
            crate::KeycloakError::InvalidIdToken(format!("payload em base64url inválido: {e}"))
        })?;
        serde_json::from_slice(&payload)
            .map_err(|e| crate::KeycloakError::InvalidIdToken(format!("claims inválidas: {e}")))
    }

    /// Valida as claims contra o login corrente: `iss`, `aud` (com `azp` em múltiplos
    /// audiences), `exp` (com tolerância de relógio) e `nonce`.
    pub fn validate(
        &self,
        issuer: &str,
        audience: &str,
        nonce: Option<&str>,
        leeway_secs: u64,
    ) -> crate::Result<()> {
        if self.iss != issuer {
            return Err(crate::KeycloakError::InvalidIdToken(format!(
                "issuer divergente: esperado '{issuer}', recebido '{}'",
                self.iss
            )));
        }
        if !self.aud.iter().any(|a| a == audience) {
            return Err(crate::KeycloakError::InvalidIdToken(format!(
                "audience '{audience}' ausente em {:?}",
                self.aud
            )));
        }
        if self.aud.len() > 1 {
            if let Some(azp) = &self.azp {
                if azp != audience {
                    return Err(crate::KeycloakError::InvalidIdToken(format!(
                        "azp '{azp}' difere do client '{audience}'"
                    )));
                }
            }
        }
        let now = unix_now()?;
        if now > self.exp.saturating_add(leeway_secs as i64) {
            return Err(crate::KeycloakError::InvalidIdToken(
                "token expirado".to_string(),
            ));
        }
        if let Some(expected) = nonce {
            match &self.nonce {
                Some(n) if n == expected => {}
                _ => {
                    return Err(crate::KeycloakError::InvalidIdToken(
                        "nonce não corresponde ao login iniciado".to_string(),
                    ))
                }
            }
        }
        Ok(())
    }
}

fn decode_b64url(segment: &str) -> std::io::Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .or_else(|_| URL_SAFE.decode(segment))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

fn unix_now() -> crate::Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| crate::KeycloakError::InvalidIdToken(format!("relógio do sistema: {e}")))
}

fn audience_vec<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }

    use OneOrMany::{Many, One};

    match OneOrMany::deserialize(deserializer)? {
        One(s) => Ok(vec![s]),
        Many(v) => Ok(v),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn b64(value: &str) -> String {
        URL_SAFE_NO_PAD.encode(value.as_bytes())
    }

    fn jwt(claims: &serde_json::Value) -> String {
        format!(
            "{}.{}.sig",
            b64(r#"{"alg":"RS256","typ":"JWT"}"#),
            b64(&claims.to_string())
        )
    }

    fn claims(overrides: serde_json::Value) -> serde_json::Value {
        let base = serde_json::json!({
            "iss": "https://auth.test/realms/hyper",
            "aud": "app",
            "sub": "user-1",
            "exp": 4_102_444_800i64,
            "nonce": "n-1"
        });
        let serde_json::Value::Object(mut map) = base else {
            unreachable!()
        };
        let serde_json::Value::Object(extra) = overrides else {
            unreachable!()
        };
        for (k, v) in extra {
            map.insert(k, v);
        }
        serde_json::Value::Object(map)
    }

    const ISSUER: &str = "https://auth.test/realms/hyper";

    #[test]
    fn decodifica_e_valida_fluxo_feliz() {
        let parsed = IdTokenClaims::from_jwt(&jwt(&claims(serde_json::json!({})))).unwrap();
        parsed.validate(ISSUER, "app", Some("n-1"), 30).unwrap();
        assert_eq!(parsed.sub, "user-1");
    }

    #[test]
    fn aud_como_array_e_azp_divergente_falham() {
        let parsed = IdTokenClaims::from_jwt(&jwt(&claims(serde_json::json!({
            "aud": ["app", "other"], "azp": "other"
        }))))
        .unwrap();
        assert_eq!(parsed.aud, vec!["app", "other"]);
        let err = parsed.validate(ISSUER, "app", None, 30).unwrap_err();
        assert!(err.to_string().contains("azp"));

        let parsed = IdTokenClaims::from_jwt(&jwt(&claims(serde_json::json!({
            "aud": ["other"]
        }))))
        .unwrap();
        assert!(parsed.validate(ISSUER, "app", None, 30).is_err());
    }

    #[test]
    fn issuer_e_nonce_divergentes_falham() {
        let parsed = IdTokenClaims::from_jwt(&jwt(&claims(serde_json::json!({
            "iss": "https://evil.test/realms/hyper"
        }))))
        .unwrap();
        assert!(parsed.validate(ISSUER, "app", None, 30).is_err());

        let parsed = IdTokenClaims::from_jwt(&jwt(&claims(serde_json::json!({
            "nonce": "n-2"
        }))))
        .unwrap();
        let err = parsed.validate(ISSUER, "app", Some("n-1"), 30).unwrap_err();
        assert!(err.to_string().contains("nonce"));

        let parsed = IdTokenClaims::from_jwt(&jwt(&claims(serde_json::json!({})))).unwrap();
        assert!(parsed.validate(ISSUER, "app", None, 30).is_ok());
    }

    #[test]
    fn expirado_falha_e_leeway_ajuda() {
        let expired = serde_json::json!({ "exp": 1_000_000 });
        let parsed = IdTokenClaims::from_jwt(&jwt(&claims(expired))).unwrap();
        assert!(parsed.validate(ISSUER, "app", None, 30).is_err());
        assert!(parsed.validate(ISSUER, "app", None, u64::MAX / 2).is_ok());
    }

    #[test]
    fn jwt_malformado_e_erro() {
        assert!(IdTokenClaims::from_jwt("so-um-ponto").is_err());
        assert!(IdTokenClaims::from_jwt("a.!!!.c").is_err());
    }
}
