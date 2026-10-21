use crate::config::KeycloakConfig;
use crate::endpoints::Endpoints;

/// Monta a URL de autorização com `response_type=code`, PKCE S256, `state` e `nonce`.
pub(crate) fn build(
    config: &KeycloakConfig,
    endpoints: &Endpoints,
    state: &str,
    nonce: &str,
    code_challenge: &str,
    redirect_uri: &str,
) -> String {
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", &config.client_id)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", &config.scopes.join(" "))
        .append_pair("state", state)
        .append_pair("nonce", nonce)
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();
    format!("{}?{}", endpoints.authorization, query)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> KeycloakConfig {
        crate::KeycloakClientBuilder::new()
            .base_url("https://auth.test")
            .realm("hyper")
            .client_id("app&co")
            .scope("openid profile")
            .config
    }

    #[test]
    fn url_contem_todos_os_parametros() {
        let ep = Endpoints::derived("https://auth.test", "hyper");
        let url = build(
            &config(),
            &ep,
            "st-1",
            "no-1",
            "ch-1",
            "http://localhost:8765/callback",
        );
        assert!(url.starts_with("https://auth.test/realms/hyper/protocol/openid-connect/auth?"));
        assert!(url.contains("client_id=app%26co"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("redirect_uri=http%3A%2F%2Flocalhost%3A8765%2Fcallback"));
        assert!(url.contains("scope=openid+profile"));
        assert!(url.contains("state=st-1"));
        assert!(url.contains("nonce=no-1"));
        assert!(url.contains("code_challenge=ch-1"));
        assert!(url.contains("code_challenge_method=S256"));
    }
}
