use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tiny_http::{Header, Response, Server};

use crate::error::KeycloakError;

/// Tentativa de login corrente (single-use, com TTL) guardada pelo cliente.
pub(crate) struct PendingAttempt {
    pub(crate) state: String,
    pub(crate) nonce: String,
    pub(crate) code_verifier: String,
    pub(crate) redirect_uri: String,
    pub(crate) created_at: Instant,
}

/// TTL do fluxo de login: `state`/`verifier` expiram junto ([D-008]).
pub(crate) const LOGIN_TTL: Duration = Duration::from_secs(600);

/// Servidor loopback do callback, preso a `127.0.0.1` ([D-010]).
pub(crate) struct CallbackServer {
    pub(crate) server: Server,
    pub(crate) addr: SocketAddr,
}

impl CallbackServer {
    pub(crate) fn bind(port: u16) -> crate::Result<Self> {
        let listener = std::net::TcpListener::bind(("127.0.0.1", port)).map_err(|e| {
            KeycloakError::CallbackBind {
                port,
                source: Box::new(e),
            }
        })?;
        let addr = listener
            .local_addr()
            .map_err(|e| KeycloakError::CallbackBind {
                port,
                source: Box::new(e),
            })?;
        let server = Server::from_listener(listener, None)
            .map_err(|source| KeycloakError::CallbackBind { port, source })?;
        Ok(Self { server, addr })
    }
}

/// Descarta callbacks órfãos de fluxos anteriores, respondendo com página de expiração.
pub(crate) fn drain(server: &Server) {
    while let Ok(Some(request)) = server.try_recv() {
        let _ = respond_page(
            request,
            200,
            error_page(
                "expired",
                "Este callback já expirou; inicie o login novamente.",
            ),
        );
    }
}

pub(crate) fn respond_page(
    request: tiny_http::Request,
    status: u16,
    html: String,
) -> std::io::Result<()> {
    let content_type: Header =
        Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..])
            .expect("header estático");
    let response = Response::from_string(html)
        .with_status_code(status)
        .with_header(content_type);
    request.respond(response)
}

pub(crate) fn success_page() -> String {
    PAGE_SUCCESS.to_string()
}

pub(crate) fn error_page(error: &str, description: &str) -> String {
    format!(
        "<!DOCTYPE html><html lang=\"pt-BR\"><head><meta charset=\"UTF-8\">\
<title>Falha no login</title></head><body><h1>Falha no login</h1>\
<p><strong>{}</strong></p><p>{}</p></body></html>",
        escape_html(error),
        escape_html(description)
    )
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

const PAGE_SUCCESS: &str = "<!DOCTYPE html><html lang=\"pt-BR\"><head><meta charset=\"UTF-8\">\
<title>Login realizado</title></head><body><h1>Login realizado com sucesso</h1>\
<p>Você já pode fechar esta página e voltar ao aplicativo.</p></body></html>";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paginas_escapam_html() {
        let page = error_page("<script>", "\"inject\"");
        assert!(!page.contains("<script>"));
        assert!(!page.contains("\"inject\""));
        assert!(page.contains("&lt;script&gt;"));
        assert!(page.contains("&quot;inject&quot;"));
    }

    #[test]
    fn bind_em_porta_ocupada_falha_graciosamente() {
        let first = CallbackServer::bind(0).unwrap();
        let port = first.addr.port();
        let result = CallbackServer::bind(port);
        assert!(matches!(result, Err(KeycloakError::CallbackBind { .. })));
    }
}
