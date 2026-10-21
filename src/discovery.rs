use serde::Deserialize;

/// Documento `.well-known/openid-configuration` do realm (campos usados pela lib).
#[derive(Debug, Clone, Deserialize)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
}

pub(crate) fn fetch(
    http: &reqwest::blocking::Client,
    issuer: &str,
) -> crate::Result<OidcDiscovery> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let response = http
        .get(&url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()?;
    let status = response.status();
    let body = response.text()?;
    if !status.is_success() {
        return Err(crate::KeycloakError::Discovery(format!(
            "HTTP {status} em {url}"
        )));
    }
    serde_json::from_str(&body)
        .map_err(|e| crate::KeycloakError::Discovery(format!("JSON inválido de {url}: {e}")))
}
