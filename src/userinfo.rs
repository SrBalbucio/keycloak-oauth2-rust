use serde::{Deserialize, Serialize};

use crate::id_token::RealmAccess;

/// Perfil do usuário devolvido pelo endpoint `userinfo`.
///
/// Campos conhecidos ficam tipados; todo o resto é preservado em [`UserInfo::extra`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    /// Identificador do usuário no realm (imutável).
    pub sub: String,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
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
    pub extra: serde_json::Map<String, serde_json::Value>,
}
