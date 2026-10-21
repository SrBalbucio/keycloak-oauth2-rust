use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Gera um `code_verifier` (43 caracteres, base64url de 32 bytes aleatórios) dentro do
/// intervalo do RFC 7636 (43-128 caracteres, sem `=`/`+`/`/`).
pub fn generate_code_verifier() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Calcula o `code_challenge` S256: `BASE64URL(SHA256(code_verifier))`, sem padding.
pub fn code_challenge_s256(code_verifier: &str) -> String {
    let digest = Sha256::digest(code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vetor do RFC 7636, Apêndice B.
    #[test]
    fn vetor_do_rfc_7636() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            code_challenge_s256(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn verifier_gerado_tem_43_caracteres_url_safe() {
        let verifier = generate_code_verifier();
        assert_eq!(verifier.len(), 43);
        assert!(verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }
}
