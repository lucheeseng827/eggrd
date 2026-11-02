//! `[trusted_client_cert_header]` through the real pipeline: a certificate a load balancer
//! forwards in a header, in each format balancers write, authenticates with `auth.mode = "mtls"`
//! and is forwarded as `X-Forwarded-Client-Cert` — but only from `trusted_proxies`, never as the
//! raw header, and, with `ca_path`, only when it verifies.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::HeaderMap;
use axum::Router;
use base64::Engine;
use tokio::net::TcpListener;

mod common;
use common::{uri, Ca, Dir, Leaf};

use edgeguard::config::Config;
use edgeguard::{build_router, build_state};

const HEADER: &str = "x-client-cert";
const WEB: &str = "spiffe://prod/ns/web";

/// Answers with the forwarded client certificate it got, and whether the raw header got through.
async fn upstream() -> SocketAddr {
    let app = Router::new().fallback(|headers: HeaderMap| async move {
        let get = |name: &str| {
            headers
                .get(name)
                .map(|v| v.to_str().unwrap().to_string())
                .unwrap_or_else(|| "-".into())
        };
        format!(
            "xfcc={} raw={}",
            get("x-forwarded-client-cert"),
            get(HEADER)
        )
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// `auth.mode = "mtls"` allowing only `WEB`, forwarding XFCC, with the header trusted from
/// `trusted` (the test connects from 127.0.0.1).
fn cfg(up: SocketAddr, format: &str, trusted: &str) -> Config {
    let mut cfg = Config::default();
    cfg.server.upstream = format!("http://{up}");
    cfg.ratelimit.enabled = false;
    cfg.auth.mode = "mtls".into();
    cfg.auth.mtls.allowed = vec![WEB.into()];
    cfg.tls.client_auth.forward_client_cert = "xfcc".into();
    cfg.trusted_client_cert_header.name = "X-Client-Cert".into();
    cfg.trusted_client_cert_header.format = format.into();
    cfg.trusted_client_cert_header.trusted_proxies = vec![trusted.into()];
    cfg
}

async fn proxy(cfg: Config) -> (SocketAddr, Arc<edgeguard::metrics::Metrics>) {
    let state = build_state(Arc::new(cfg)).unwrap();
    let metrics = Arc::clone(&state.metrics);
    let app = build_router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (addr, metrics)
}

async fn get(addr: SocketAddr, values: &[String]) -> (u16, String) {
    let mut req = reqwest::Client::new().get(format!("http://{addr}/orders"));
    for v in values {
        req = req.header(HEADER, v);
    }
    let resp = req.send().await.unwrap();
    (resp.status().as_u16(), resp.text().await.unwrap())
}

/// URL-encoding as an ALB writes it: `+`, `=` and `/` left as they are.
fn alb_escape(text: &str) -> String {
    text.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~+=/".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn b64(der: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(der)
}

fn sha256(der: &[u8]) -> String {
    use std::fmt::Write;
    ring_sha256(der).iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn ring_sha256(der: &[u8]) -> Vec<u8> {
    edgeguard::client_auth::ClientCert::from_der(der)
        .sha256
        .as_bytes()
        .chunks(2)
        .map(|h| u8::from_str_radix(std::str::from_utf8(h).unwrap(), 16).unwrap())
        .collect()
}

fn counter(metrics: &edgeguard::metrics::Metrics, result: &str) -> u64 {
    let line = format!("edgeguard_client_cert_header_total{{result=\"{result}\"}} ");
    metrics
        .render()
        .lines()
        .find_map(|l| l.strip_prefix(&line)?.parse().ok())
        .unwrap_or_else(|| panic!("no {line}"))
}

fn web(ca: &Ca) -> Leaf {
    ca.client_with(vec![uri(WEB)], "web", 7)
}

#[tokio::test]
async fn a_trusted_balancers_certificate_in_each_format_authenticates_and_is_forwarded() {
    let up = upstream().await;
    let ca = Ca::new("partner CA");
    let leaf = web(&ca);
    let traefik = b64(&leaf.der)
        .replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D");
    let xfcc = format!(
        "By=spiffe://prod/ns/lb;Hash={};Cert=\"{}\";URI={WEB}",
        sha256(&leaf.der),
        alb_escape(&leaf.cert)
    );
    for (format, value) in [
        ("pem", alb_escape(&leaf.cert)),
        ("pem", leaf.cert.replace('\n', " ")),
        ("der", b64(&leaf.der)),
        ("der", traefik),
        ("xfcc", xfcc),
    ] {
        let (addr, metrics) = proxy(cfg(up, format, "127.0.0.1")).await;
        let (status, body) = get(addr, std::slice::from_ref(&value)).await;
        assert_eq!(status, 200, "{format} {value}: {body}");
        assert!(
            body.contains(&format!("Hash={}", sha256(&leaf.der))) && body.contains(WEB),
            "{format}: forwarded as XFCC: {body}"
        );
        assert!(
            body.ends_with("raw=-"),
            "{format}: the raw header never reaches the app: {body}"
        );
        assert_eq!(counter(&metrics, "accepted"), 1);
        // The principal the consumer series and the access log key on.
        assert!(metrics.render().contains(&format!(
            "edgeguard_consumer_requests_total{{consumer=\"{WEB}\",status_class=\"2xx\"}} 1"
        )));
    }
}

#[tokio::test]
async fn an_xfcc_without_a_certificate_is_read_from_its_names() {
    let up = upstream().await;
    let (addr, _) = proxy(cfg(up, "xfcc", "127.0.0.1")).await;
    // Istio's default: names and a hash, no Cert. Two hops; the last is the trusted one's.
    let value = format!(
        "By=spiffe://prod/ns/outer;URI=spiffe://prod/ns/evil,By=spiffe://prod/ns/lb;Hash=ABC123;Subject=\"CN=web,O=Prod\";URI={WEB}"
    );
    let (status, body) = get(addr, &[value]).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("Hash=abc123"), "{body}");
    assert!(body.contains(&format!("URI=\"{WEB}\"")), "{body}");
}

#[tokio::test]
async fn from_a_peer_outside_trusted_proxies_the_header_is_dropped() {
    let up = upstream().await;
    let ca = Ca::new("partner CA");
    let value = alb_escape(&web(&ca).cert);
    let (addr, metrics) = proxy(cfg(up, "pem", "10.0.0.0/8")).await;
    let (status, _) = get(addr, std::slice::from_ref(&value)).await;
    assert_eq!(status, 401, "a header is no certificate from just anyone");
    assert_eq!(counter(&metrics, "untrusted_peer"), 1);
    assert_eq!(counter(&metrics, "accepted"), 0);

    // Without auth the request goes through, still without the header, and with no XFCC.
    let mut open = cfg(up, "pem", "10.0.0.0/8");
    open.auth.mode = "none".into();
    let (addr, _) = proxy(open).await;
    let (status, body) = get(addr, &[value]).await;
    assert_eq!(status, 200);
    assert_eq!(body, "xfcc=- raw=-");
}

#[tokio::test]
async fn a_header_that_is_not_a_certificate_or_is_sent_twice_is_refused() {
    let up = upstream().await;
    let ca = Ca::new("partner CA");
    let good = alb_escape(&web(&ca).cert);
    let (addr, metrics) = proxy(cfg(up, "pem", "127.0.0.1")).await;
    assert_eq!(get(addr, &["not a certificate".into()]).await.0, 401);
    assert_eq!(get(addr, &[good.clone(), good]).await.0, 401);
    assert_eq!(counter(&metrics, "invalid"), 2);
    let (addr, metrics) = proxy(cfg(up, "der", "127.0.0.1")).await;
    assert_eq!(get(addr, &[b64(b"0 but not DER")]).await.0, 401);
    assert_eq!(counter(&metrics, "invalid"), 1);
}

#[tokio::test]
async fn with_ca_path_the_forwarded_certificate_must_verify() {
    edgeguard::tls::init_crypto();
    let dir = Dir::new();
    let up = upstream().await;
    let (partner, stranger) = (Ca::new("partner CA"), Ca::new("someone else"));
    let mut c = cfg(up, "pem", "127.0.0.1");
    c.trusted_client_cert_header.ca_path = dir.write("partner-ca.pem", &partner.pem);
    let (addr, metrics) = proxy(c.clone()).await;
    assert_eq!(get(addr, &[alb_escape(&web(&partner).cert)]).await.0, 200);
    assert_eq!(get(addr, &[alb_escape(&web(&stranger).cert)]).await.0, 401);
    assert_eq!(counter(&metrics, "unverified"), 1);

    // Revoked by its CRL.
    c.trusted_client_cert_header.crl_paths = vec![dir.write("partner.crl", &partner.crl(&[7]))];
    let (addr, metrics) = proxy(c.clone()).await;
    assert_eq!(get(addr, &[alb_escape(&web(&partner).cert)]).await.0, 401);
    assert_eq!(counter(&metrics, "unverified"), 1);

    // Nothing to verify in an XFCC that carries only names.
    let mut x = c;
    x.trusted_client_cert_header.format = "xfcc".into();
    x.trusted_client_cert_header.crl_paths.clear();
    let (addr, metrics) = proxy(x).await;
    assert_eq!(get(addr, &[format!("URI={WEB}")]).await.0, 401);
    assert_eq!(counter(&metrics, "unverified"), 1);
}

#[tokio::test]
async fn the_tls_endpoint_reports_the_header_and_its_cas() {
    edgeguard::tls::init_crypto();
    let dir = Dir::new();
    let up = upstream().await;
    let partner = Ca::new("partner CA");
    let mut c = cfg(up, "der", "10.20.0.0/16");
    c.trusted_client_cert_header.ca_path = dir.write("partner-ca.pem", &partner.pem);
    let (addr, metrics) = proxy(c).await;
    let j: serde_json::Value = reqwest::get(format!("http://{addr}/__edgeguard/tls"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let h = &j["trusted_client_cert_header"];
    assert_eq!(h["name"], "x-client-cert");
    assert_eq!(h["format"], "der");
    assert_eq!(h["trusted_proxies"], serde_json::json!(["10.20.0.0/16"]));
    assert_eq!(h["trusted_proxy_names"], serde_json::json!([]));
    assert_eq!(h["cas"][0]["name"], "partner CA");
    assert!(metrics.render().contains("cert=\"header-ca:partner CA\"}"));
}
