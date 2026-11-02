//! What reaches the upstream when a client sends a header more than once: every value, in order,
//! as it was sent; an HTTP/2 client's split cookies as one `Cookie` header; and, where the edge
//! authenticates with a header, nothing at all if that header is repeated.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, HeaderValue, Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::{json, Map, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use edgeguard::config::Config;
use edgeguard::{build_router, build_state};

/// Every request the upstream received: its headers, each name with its values in order.
type Seen = Arc<Mutex<Vec<Map<String, Value>>>>;

/// An upstream that records the headers of every request and answers with them as JSON; an
/// upgrade request gets a `101`.
async fn recorder() -> (SocketAddr, Seen) {
    let seen: Seen = Arc::default();
    let record = Arc::clone(&seen);
    let app = Router::new().fallback(any(move |req: Request<Body>| {
        let record = Arc::clone(&record);
        async move {
            let mut headers = Map::new();
            for name in req.headers().keys() {
                let values: Vec<Value> = req
                    .headers()
                    .get_all(name)
                    .iter()
                    .map(|v| json!(String::from_utf8_lossy(v.as_bytes())))
                    .collect();
                headers.insert(name.to_string(), Value::Array(values));
            }
            record.lock().unwrap().push(headers.clone());
            let mut resp = Response::new(Body::from(Value::Object(headers).to_string()));
            if req.headers().contains_key(header::UPGRADE) {
                *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                resp.headers_mut()
                    .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
                resp.headers_mut()
                    .insert(header::UPGRADE, HeaderValue::from_static("echo"));
            }
            resp
        }
    }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, seen)
}

fn cfg(upstream: SocketAddr) -> Config {
    let mut c = Config::default();
    c.server.upstream = format!("http://{upstream}");
    c.auth.mode = "none".into();
    c.ratelimit.enabled = false;
    c.validation.websocket_passthrough = true;
    c
}

async fn edge(cfg: Config) -> SocketAddr {
    let app = build_router(build_state(Arc::new(cfg)).unwrap());
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
    addr
}

/// A GET over HTTP/1.1 with `headers`, each appended, so a name given twice is sent twice.
async fn get(addr: SocketAddr, headers: &[(&str, &str)]) -> (StatusCode, String) {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let mut req = Request::get(format!("http://{addr}/orders"));
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    let resp = client
        .request(req.body(Full::new(Bytes::new())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).to_string())
}

fn last(seen: &Seen) -> Map<String, Value> {
    seen.lock().unwrap().last().cloned().expect("a request")
}

#[tokio::test]
async fn a_header_sent_twice_reaches_the_upstream_twice() {
    let (up, seen) = recorder().await;
    let addr = edge(cfg(up)).await;
    let (status, _) = get(
        addr,
        &[
            ("x-multi", "1"),
            ("accept", "text/html"),
            ("x-multi", "2"),
            ("accept", "application/json"),
            // The edge's own: whatever the client sent, one value, the edge's.
            ("x-forwarded-for", "198.51.100.1"),
            ("x-forwarded-for", "198.51.100.2"),
            ("x-request-id", "client-1"),
            ("x-request-id", "client-2"),
        ],
    )
    .await;
    assert_eq!(status, 200);
    let h = last(&seen);
    assert_eq!(h["x-multi"], json!(["1", "2"]), "both, in the order sent");
    assert_eq!(h["accept"], json!(["text/html", "application/json"]));
    assert_eq!(h["x-forwarded-for"], json!(["127.0.0.1"]));
    assert_eq!(h["x-request-id"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn an_http2_clients_cookies_reach_the_upstream_as_one_header() {
    let (up, seen) = recorder().await;
    let addr = edge(cfg(up)).await;
    let (mut send, conn) = hyper::client::conn::http2::handshake(
        TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(TcpStream::connect(addr).await.unwrap()),
    )
    .await
    .expect("h2c");
    tokio::spawn(conn);
    // RFC 9113 §8.2.3: an HTTP/2 client may send each cookie as its own field.
    let req = Request::get(format!("http://{addr}/orders"))
        .header(header::COOKIE, "session=abc")
        .header(header::COOKIE, "theme=dark")
        .header("x-multi", "1")
        .header("x-multi", "2")
        .body(Body::empty())
        .unwrap();
    let resp = send.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.version(), axum::http::Version::HTTP_2);
    let h = last(&seen);
    assert_eq!(h["cookie"], json!(["session=abc; theme=dark"]));
    assert_eq!(h["x-multi"], json!(["1", "2"]));
}

#[tokio::test]
async fn a_websocket_handshake_forwards_repeated_headers_too() {
    let (up, seen) = recorder().await;
    let addr = edge(cfg(up)).await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(
        b"GET /ws HTTP/1.1\r\nHost: edge\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\
          X-Multi: 1\r\nX-Multi: 2\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n",
    )
    .await
    .unwrap();
    let mut head = [0u8; 12];
    s.read_exact(&mut head).await.unwrap();
    assert_eq!(&head, b"HTTP/1.1 101");
    let h = last(&seen);
    assert_eq!(h["x-multi"], json!(["1", "2"]));
    assert_eq!(h["cookie"], json!(["a=1; b=2"]));
}

/// The edge checks the first value; an app that read the second would believe a credential the
/// edge never checked. So a repeated credential header never reaches the app.
#[tokio::test]
async fn a_repeated_credential_header_is_refused_before_the_upstream() {
    let (up, seen) = recorder().await;
    let mut c = cfg(up);
    c.auth.mode = "apikey".into();
    c.auth.api_keys = vec!["sk_live_abc".into()];
    let addr = edge(c).await;

    let (status, _) = get(addr, &[("x-api-key", "sk_live_abc")]).await;
    assert_eq!(status, 200);
    assert_eq!(seen.lock().unwrap().len(), 1);
    let (status, _) = get(
        addr,
        &[("x-api-key", "sk_live_abc"), ("x-api-key", "sk_forged")],
    )
    .await;
    assert_eq!(status, 401);
    let (status, _) = get(
        addr,
        &[
            ("authorization", "Bearer sk_live_abc"),
            ("authorization", "Bearer forged.jwt.token"),
        ],
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "neither reached the upstream"
    );

    // With the key in its own header, two Authorization headers are the app's to judge, and both
    // reach it.
    let (status, _) = get(
        addr,
        &[
            ("x-api-key", "sk_live_abc"),
            ("authorization", "Bearer app-1"),
            ("authorization", "Bearer app-2"),
        ],
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        last(&seen)["authorization"],
        json!(["Bearer app-1", "Bearer app-2"])
    );
}

#[tokio::test]
async fn basic_auth_refuses_two_authorization_headers_even_when_both_are_valid() {
    let (up, seen) = recorder().await;
    let mut c = cfg(up);
    c.auth.mode = "basic".into();
    c.auth.users = [("admin".to_string(), "secret".to_string())].into();
    let addr = edge(c).await;
    let good = "Basic YWRtaW46c2VjcmV0"; // admin:secret
    assert_eq!(get(addr, &[("authorization", good)]).await.0, 200);
    let (status, _) = get(addr, &[("authorization", good), ("authorization", good)]).await;
    assert_eq!(status, 401);
    assert_eq!(seen.lock().unwrap().len(), 1);
}
