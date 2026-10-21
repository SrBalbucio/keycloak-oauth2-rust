/// Endpoints OIDC efetivos usados pelo cliente — vindos da descoberta
/// (`.well-known/openid-configuration`) ou derivados de `base_url`/`realm` (fallback,
/// paridade com a base Java).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    /// Issuer do realm (descoberto ou derivado).
    pub issuer: String,
    /// Endpoint de autorização.
    pub authorization: String,
    /// Endpoint de token.
    pub token: String,
    /// Endpoint de userinfo.
    pub userinfo: Option<String>,
    /// `end_session_endpoint` (logout RP-initiated).
    pub end_session: Option<String>,
    /// `jwks_uri` (reservado para verificação de assinatura futura).
    pub jwks: Option<String>,
}

impl Endpoints {
    /// Deriva os endpoints no formato padrão do Keycloak.
    pub fn derived(base_url: &str, realm: &str) -> Self {
        let issuer = format!("{}/realms/{}", base_url.trim_end_matches('/'), realm);
        let base = format!("{issuer}/protocol/openid-connect");
        Self {
            authorization: format!("{base}/auth"),
            token: format!("{base}/token"),
            userinfo: Some(format!("{base}/userinfo")),
            end_session: Some(format!("{base}/logout")),
            jwks: Some(format!("{base}/certs")),
            issuer,
        }
    }

    pub(crate) fn from_discovery(discovery: &super::discovery::OidcDiscovery) -> Self {
        Self {
            issuer: discovery.issuer.clone(),
            authorization: discovery.authorization_endpoint.clone(),
            token: discovery.token_endpoint.clone(),
            userinfo: discovery.userinfo_endpoint.clone(),
            end_session: discovery.end_session_endpoint.clone(),
            jwks: discovery.jwks_uri.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivados_seguem_o_formato_keycloak() {
        let ep = Endpoints::derived("https://auth.test/", "hyper");
        assert_eq!(ep.issuer, "https://auth.test/realms/hyper");
        assert_eq!(
            ep.authorization,
            "https://auth.test/realms/hyper/protocol/openid-connect/auth"
        );
        assert_eq!(
            ep.token,
            "https://auth.test/realms/hyper/protocol/openid-connect/token"
        );
        assert_eq!(
            ep.userinfo.as_deref(),
            Some("https://auth.test/realms/hyper/protocol/openid-connect/userinfo")
        );
        assert_eq!(
            ep.end_session.as_deref(),
            Some("https://auth.test/realms/hyper/protocol/openid-connect/logout")
        );
        assert_eq!(
            ep.jwks.as_deref(),
            Some("https://auth.test/realms/hyper/protocol/openid-connect/certs")
        );
    }
}
