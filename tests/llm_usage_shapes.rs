//! LLM metering beyond OpenAI Chat Completions: the Anthropic Messages and OpenAI Responses usage
//! shapes, buffered and streamed, through the real pipeline, and a token budget binding on them.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, HeaderValue, Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::net::TcpListener;

use edgeguard::config::{BudgetCfg, Config, ModelPrice};
use edgeguard::{build_router, build_state};

const MODEL: &str = "claude-sonnet-4";

fn cfg(upstream: SocketAddr, stream: bool) -> Config {
    let mut cfg = Config::default();
    cfg.server.upstream = format!("http://{upstream}");
    cfg.auth.mode = "none".into();
    cfg.ratelimit.enabled = false;
    cfg.validation.stream_passthrough = stream;
    cfg.llm.enabled = true;
    let mut models = BTreeMap::new();
    for model in [MODEL, "gpt-5"] {
        models.insert(
            model.to_string(),
            ModelPrice {
                input_per_1m: 3.0,
                output_per_1m: 15.0,
                cached_per_1m: 0.3,
                ..Default::default()
            },
        );
    }
    cfg.llm.models = models;
    cfg
}

/// An upstream that answers every request with `body` as `content_type`, counting requests.
async fn upstream(body: String, content_type: &'static str) -> (SocketAddr, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&hits);
    let app = Router::new().fallback(any(move || {
        let body = body.clone();
        let seen = Arc::clone(&seen);
        async move {
            seen.fetch_add(1, Ordering::SeqCst);
            let mut resp = Response::new(Body::from(body));
            resp.headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
            resp
        }
    }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, hits)
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

async fn post(edge: SocketAddr, path: &str, body: &'static str) -> (StatusCode, String) {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::post(format!("http://{edge}{path}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

async fn metrics(edge: SocketAddr) -> String {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::get(format!("http://{edge}/__edgeguard/metrics"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).to_string()
}

/// Wait for `needle` in the metrics: a streamed response is metered when its body is dropped,
/// just after the client has read it.
async fn metrics_with(edge: SocketAddr, needle: &str) -> String {
    for _ in 0..80 {
        let text = metrics(edge).await;
        if text.contains(needle) {
            return text;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let text = metrics(edge).await;
    panic!("never saw {needle:?} in:\n{text}");
}

const MESSAGES_BODY: &str =
    r#"{"model":"claude-sonnet-4","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}"#;

/// An Anthropic Messages stream: `message_start` (the input side), `filler` bytes of content
/// deltas, then `message_delta` (the output count).
fn anthropic_stream(input: u64, cache_read: u64, output: u64, filler: usize) -> String {
    let mut s = format!(
        "event: message_start\ndata: {{\"type\":\"message_start\",\"message\":{{\"id\":\"msg_1\",\
         \"type\":\"message\",\"model\":\"{MODEL}\",\"usage\":{{\"input_tokens\":{input},\
         \"cache_read_input_tokens\":{cache_read},\"cache_creation_input_tokens\":0,\
         \"output_tokens\":1}}}}}}\n\n"
    );
    let delta = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\
                 \"delta\":{\"type\":\"text_delta\",\"text\":\"lorem ipsum dolor sit amet \"}}\n\n";
    while s.len() < filler {
        s.push_str(delta);
    }
    s.push_str(&format!(
        "event: message_delta\ndata: {{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\
         \"end_turn\"}},\"usage\":{{\"output_tokens\":{output}}}}}\n\n\
         event: message_stop\ndata: {{\"type\":\"message_stop\"}}\n\n"
    ));
    s
}

#[tokio::test]
async fn an_anthropic_messages_response_is_metered_with_its_cache_reads() {
    let body = format!(
        r#"{{"id":"msg_1","type":"message","model":"{MODEL}","content":[],"usage":{{"input_tokens":100,"cache_creation_input_tokens":20,"cache_read_input_tokens":50,"output_tokens":30}}}}"#
    );
    let (up, _) = upstream(body, "application/json").await;
    let edge = edge(cfg(up, false)).await;
    assert_eq!(post(edge, "/v1/messages", MESSAGES_BODY).await.0, 200);
    let text = metrics(edge).await;
    // The prompt is input + cache writes + cache reads; the reads are its cached part.
    assert!(
        text.contains("edgeguard_llm_tokens_total{direction=\"input\"} 170"),
        "{text}"
    );
    assert!(
        text.contains("edgeguard_llm_tokens_total{direction=\"output\"} 30"),
        "{text}"
    );
    assert!(
        text.contains("edgeguard_llm_cached_tokens_total 50"),
        "{text}"
    );
    assert!(
        text.contains("edgeguard_llm_requests_total{result=\"metered\"} 1"),
        "{text}"
    );
    // 120 uncached in @ $3/M = 360 µ$; 50 cached @ $0.30/M = 15 µ$; 30 out @ $15/M = 450 µ$.
    assert!(
        text.contains("edgeguard_llm_cost_microdollars_total 825"),
        "{text}"
    );
}

#[tokio::test]
async fn a_long_anthropic_stream_is_metered_from_its_first_frame_and_its_last() {
    // Far more than the 16 KiB tail the meter used to keep: `message_start` was lost.
    let (up, _) = upstream(
        anthropic_stream(500, 0, 900, 64 * 1024),
        "text/event-stream",
    )
    .await;
    let edge = edge(cfg(up, true)).await;
    let (status, body) = post(edge, "/v1/messages", MESSAGES_BODY).await;
    assert_eq!(status, 200);
    assert!(
        body.len() > 64 * 1024,
        "the stream reached the client whole"
    );
    let text = metrics_with(edge, "edgeguard_llm_requests_total{result=\"metered\"} 1").await;
    assert!(
        text.contains("edgeguard_llm_tokens_total{direction=\"input\"} 500"),
        "{text}"
    );
    assert!(
        text.contains("edgeguard_llm_tokens_total{direction=\"output\"} 900"),
        "{text}"
    );
}

#[tokio::test]
async fn a_responses_stream_is_metered_from_a_response_completed_longer_than_any_tail() {
    let text = "x".repeat(40 * 1024);
    let sse = format!(
        "event: response.created\ndata: {{\"type\":\"response.created\",\"response\":{{\"usage\":null}}}}\n\n\
         event: response.completed\ndata: {{\"type\":\"response.completed\",\"response\":{{\"id\":\"resp_1\",\
         \"output\":[{{\"type\":\"message\",\"content\":[{{\"type\":\"output_text\",\"text\":\"{text}\"}}]}}],\
         \"usage\":{{\"input_tokens\":12,\"input_tokens_details\":{{\"cached_tokens\":2}},\"output_tokens\":8,\
         \"output_tokens_details\":{{\"reasoning_tokens\":3}}}}}}}}\n\n"
    );
    let (up, _) = upstream(sse, "text/event-stream").await;
    let edge = edge(cfg(up, true)).await;
    let request = r#"{"model":"gpt-5","stream":true,"max_output_tokens":16,"input":"hi"}"#;
    assert_eq!(post(edge, "/v1/responses", request).await.0, 200);
    let text = metrics_with(edge, "edgeguard_llm_requests_total{result=\"metered\"} 1").await;
    assert!(
        text.contains("edgeguard_llm_tokens_total{direction=\"input\"} 12"),
        "{text}"
    );
    assert!(
        text.contains("edgeguard_llm_tokens_total{direction=\"output\"} 8"),
        "{text}"
    );
    assert!(
        text.contains("edgeguard_llm_cached_tokens_total 2"),
        "{text}"
    );
    assert!(
        text.contains("edgeguard_llm_reasoning_tokens_total 3"),
        "{text}"
    );
}

#[tokio::test]
async fn a_token_budget_binds_on_anthropic_streams() {
    // The first request is admitted on its small reserve, then reconciled to the 290 tokens the
    // stream reports; the second's reserve no longer fits, and it never reaches the provider. When
    // the stream's usage went unread, the reservation was released and every request got through.
    let (up, hits) = upstream(anthropic_stream(200, 0, 90, 0), "text/event-stream").await;
    let mut c = cfg(up, true);
    c.llm.budgets = vec![BudgetCfg {
        name: "tight".into(),
        scope: "global".into(),
        unit: "tokens".into(),
        limit: 300.0,
        window: "1h".into(),
    }];
    let edge = edge(c).await;
    assert_eq!(post(edge, "/v1/messages", MESSAGES_BODY).await.0, 200);
    metrics_with(edge, "edgeguard_llm_requests_total{result=\"metered\"} 1").await;
    assert_eq!(post(edge, "/v1/messages", MESSAGES_BODY).await.0, 429);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the second never reached the provider"
    );
}
