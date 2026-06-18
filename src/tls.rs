//! TLS termination via `rustls` + `tokio-rustls`.
//!
//! axum 0.7 has no built-in TLS, so we run a small accept loop: take a TCP connection,
//! complete the rustls handshake, then hand the encrypted stream to hyper, serving the same
//! axum [`Router`] the plaintext path uses. Certificates come either from PEM files
//! ([`load_server_config`]) or from ACME (which writes those same files; see [`crate::acme`]).

use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::http::Request;
use axum::Router;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tower::{Service, ServiceExt};
use tracing::{debug, info, warn};

/// Install a process-wide default crypto provider (ring). Idempotent and best-effort: if a
/// provider is already installed (e.g. by the JWKS HTTP client) this is a no-op. Pinning one
/// avoids the "no process-level CryptoProvider" ambiguity when multiple providers are linked.
pub fn init_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build a rustls [`ServerConfig`] from a PEM certificate chain and private key. Uses an
/// explicit ring provider so it doesn't depend on which provider happens to be the process
/// default. Advertises HTTP/1.1 via ALPN (the proxy speaks HTTP/1.1 upstream).
pub fn load_server_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;

    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .context("selecting TLS protocol versions")?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("building rustls ServerConfig (does the key match the certificate?)")?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).with_context(|| format!("opening certificate file {path}"))?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing certificates from {path}"))?;
    anyhow::ensure!(!certs.is_empty(), "no certificates found in {path}");
    Ok(certs)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).with_context(|| format!("opening private key file {path}"))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("parsing private key from {path}"))?
        .with_context(|| format!("no private key found in {path}"))
}

/// Serve `app` over TLS on `listener` until `shutdown` flips true. Each connection is
/// handshaked and served on its own task, so a slow handshake can't block new accepts and a
/// graceful shutdown stops accepting while letting the listener drop.
pub async fn serve(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    app: Router,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let acceptor = TlsAcceptor::from(config);
    // `into_make_service_with_connect_info` injects `ConnectInfo(peer)` per connection, which
    // the proxy handler relies on for client-IP resolution.
    let mut make_service = app.into_make_service_with_connect_info::<SocketAddr>();

    info!(listen = %listener.local_addr().map(|a| a.to_string()).unwrap_or_default(), "TLS listener up");

    loop {
        let (stream, peer) = tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
                continue;
            }
            accepted = listener.accept() => match accepted {
                Ok(v) => v,
                Err(e) => { warn!(error = %e, "TLS accept error"); continue; }
            },
        };

        let acceptor = acceptor.clone();
        // Connection-scoped tower service carrying this peer's ConnectInfo.
        let tower_service = unwrap_infallible(make_service.call(peer).await);

        tokio::spawn(async move {
            // Bound the handshake so a client that never completes it can't pin a task/socket
            // indefinitely (this runs before any auth/rate-limit checks).
            let tls_stream = match tokio::time::timeout(
                Duration::from_secs(10),
                acceptor.accept(stream),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    debug!(error = %e, %peer, "TLS handshake failed");
                    return;
                }
                Err(_) => {
                    debug!(%peer, "TLS handshake timed out");
                    return;
                }
            };
            let io = TokioIo::new(tls_stream);
            let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
                tower_service.clone().oneshot(request)
            });
            if let Err(e) = ConnBuilder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, hyper_service)
                .await
            {
                debug!(error = %e, %peer, "error serving TLS connection");
            }
        });
    }
    Ok(())
}

fn unwrap_infallible<T>(result: Result<T, std::convert::Infallible>) -> T {
    match result {
        Ok(value) => value,
        Err(never) => match never {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_server_config_errors_on_missing_files() {
        assert!(load_server_config("/no/such/cert.pem", "/no/such/key.pem").is_err());
    }
}
