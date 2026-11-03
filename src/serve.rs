//! The accept loop every listener runs — public (plain or TLS), admin and redirect.
//!
//! One loop, so the protections below cannot differ between listeners:
//!
//! * **Header-read timeout.** A connection must deliver a complete request head within
//!   `server.header_read_timeout`, whether it is new, slow, or a keep-alive connection idle between
//!   requests. hyper has this timeout built in, but it only applies once a `Timer` is installed, and
//!   it only starts after HTTP-version detection, which has no timeout of its own: a client that
//!   connects and sends nothing would otherwise hold its socket forever. So the first bytes are read
//!   here, under the same deadline, and replayed to hyper ([`Prefixed`]). For a new connection
//!   it is one deadline from accept to the first complete request head, a PROXY header included
//!   (a TLS handshake between them has its own 10 s bound and is not counted), so dripping the
//!   header and then the request head cannot hold a socket for two timeouts. Each later request
//!   on a kept-alive connection gets hyper's timeout of its own. HTTP/1 only, as hyper's is.
//! * **Connection cap.** `server.max_connections` open connections at most; one more is closed as
//!   soon as it is accepted, and counted.
//! * **PROXY protocol.** With `server.proxy_protocol`, a header a trusted load balancer sends at
//!   the start of the connection names the client, before anything else is read (before the TLS
//!   handshake, which it precedes on the wire). See [`crate::proxy_protocol`]. The admin listener
//!   reads it too, as optional ([`ServeOpts::for_admin`]).
//! * **No ClientHello.** On a TLS listener, a connection that closes before sending a byte of
//!   handshake (a TCP health check, or a balancer's PROXY `LOCAL` check that sends only the header)
//!   is not a handshake, failed or otherwise: it is counted apart, in
//!   [`ListenerStats::no_client_hello`], and in neither handshake series.
//! * **Graceful drain.** When `shutdown` flips, keep accepting for `drain_delay` (so a load balancer
//!   has time to stop routing here), then stop accepting, ask every connection to finish its
//!   in-flight request and close, and wait up to `drain_timeout` for them.
//!
//! Upgraded connections (WebSocket tunnels) leave hyper's connection once the upgrade completes,
//! so they are not counted here and are not waited for.
//!
//! Each listener's [`ListenerStats`] also counts its requests in flight, from a request's head
//! until hyper has taken the end of its response body (or dropped it), and on TLS listeners every
//! handshake that ended. The metrics render them per listener.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, Result};
use axum::extract::ConnectInfo;
use axum::http::Request;
use axum::middleware::AddExtension;
use axum::Router;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{watch, Notify};
use tokio_rustls::TlsAcceptor;
use tower::{Service, ServiceExt};
use tracing::{debug, info, warn};

use crate::config::{parse_duration, ServerCfg};
use crate::proxy_protocol::{Outcome, ProxyProtocol};

/// Bound on the TLS handshake. It runs before any auth or rate limiting, so a client that never
/// finishes it must not pin a task and a socket.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The HTTP/2 connection preface. hyper reads up to this many bytes to tell HTTP/1 from HTTP/2.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// How one listener accepts, times out, caps and drains connections. Built from `[server]` by
/// [`ServeOpts::from_cfg`]. These are listener settings, read once at startup: a config reload
/// does not change them.
#[derive(Clone, Debug)]
pub struct ServeOpts {
    /// Deadline for a complete request head. `None` disables it.
    pub header_read_timeout: Option<Duration>,
    /// Most connections open at once; `0` is unlimited.
    pub max_connections: usize,
    /// How long to keep accepting after shutdown is signalled.
    pub drain_delay: Duration,
    /// How long to wait for open connections once accepting stops.
    pub drain_timeout: Duration,
    /// Read a PROXY protocol header first, believing it from these peers. `None` reads none.
    pub proxy_protocol: Option<Arc<ProxyProtocol>>,
    /// This listener's connection counts. Get it from
    /// [`Metrics::listener_stats`](crate::metrics::Metrics::listener_stats) to export them.
    pub stats: Arc<ListenerStats>,
}

impl Default for ServeOpts {
    fn default() -> Self {
        ServeOpts::from_cfg(&ServerCfg::default()).expect("the default [server] settings parse")
    }
}

impl ServeOpts {
    /// The listener settings in `[server]`, with fresh, unexported [`ListenerStats`]. A duration
    /// that does not parse is an error, so a typo fails startup rather than disabling a timeout.
    pub fn from_cfg(cfg: &ServerCfg) -> Result<Self> {
        let duration = |name: &str, value: &str| {
            parse_duration(value).with_context(|| format!("server.{name} = {value:?}"))
        };
        let header_read_timeout = duration("header_read_timeout", &cfg.header_read_timeout)?;
        Ok(ServeOpts {
            header_read_timeout: (!header_read_timeout.is_zero()).then_some(header_read_timeout),
            max_connections: cfg.max_connections,
            drain_delay: duration("drain_delay", &cfg.drain_delay)?,
            drain_timeout: duration("drain_timeout", &cfg.drain_timeout)?,
            proxy_protocol: ProxyProtocol::from_cfg(
                cfg.proxy_protocol,
                &cfg.proxy_protocol_trusted,
            )?
            .map(Arc::new),
            stats: Arc::default(),
        })
    }

    /// The same settings, counting into `stats`.
    pub fn with_stats(mut self, stats: Arc<ListenerStats>) -> Self {
        self.stats = stats;
        self
    }

    /// The admin listener's settings, from the public listener's. No connection cap and no drain
    /// delay: it must answer probes while the public port is full, and has nothing to hand off.
    ///
    /// PROXY protocol, when the public listener reads it, is read here too, from the same
    /// `proxy_protocol_trusted` peers and with the same rules, but a header is optional: an AWS
    /// NLB's health check sends a v2 `LOCAL` header even to a separate health-check port, and
    /// without reading it the check's request is unparseable and every target fails. A probe or
    /// scrape that sends no header is served as itself and counted `direct`, from a trusted
    /// address or not; a header from outside `proxy_protocol_trusted` is still refused.
    pub fn for_admin(&self) -> Self {
        ServeOpts {
            max_connections: 0,
            drain_delay: Duration::ZERO,
            proxy_protocol: self
                .proxy_protocol
                .as_ref()
                .map(|pp| Arc::new(pp.header_optional())),
            stats: Arc::default(),
            ..self.clone()
        }
    }
}

/// The address at the other end of a request's TCP connection, attached to every request. The
/// same as its `ConnectInfo` unless a PROXY protocol header named the client, in which case this
/// is the load balancer's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpPeer(pub SocketAddr);

/// The TLS version a request's connection negotiated, attached to every request on a TLS
/// listener: `"TLSv1.3"` or `"TLSv1.2"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsVersion(pub &'static str);

/// What a TLS connection attaches to each of its requests.
struct TlsConn {
    version: Option<TlsVersion>,
    client_cert: Option<Arc<crate::client_auth::ClientCert>>,
}

/// Why a TLS handshake failed, as counted in [`ListenerStats::tls_failures`].
pub const TLS_FAILURE_REASONS: [&str; 3] = ["client_cert", "timeout", "other"];

/// Live connection counts for one listener.
#[derive(Debug, Default)]
pub struct ListenerStats {
    open: AtomicUsize,
    rejected: AtomicU64,
    /// `max_connections` of the listener serving with these stats; `0` for no cap.
    max: AtomicUsize,
    /// Woken when `open` drops to zero, for the drain.
    idle: Notify,
    /// Set once the listener serves TLS, so the handshake series are only rendered for it.
    tls: std::sync::atomic::AtomicBool,
    /// Failed handshakes, parallel to [`TLS_FAILURE_REASONS`].
    tls_failures: [AtomicU64; 3],
    /// TLS connections closed before sending any of a ClientHello. Not handshakes: in neither
    /// `tls_failures` nor `tls_handshakes`.
    no_client_hello: AtomicU64,
    /// Handshakes that ended, successful or not: the failures above are a subset.
    tls_handshakes: AtomicU64,
    /// Requests still being answered. See [`InFlight`].
    in_flight: AtomicUsize,
    /// Set once the listener reads PROXY protocol headers.
    proxy_protocol: std::sync::atomic::AtomicBool,
    /// Connections by what their first bytes were, parallel to [`Outcome::ALL`].
    proxy_protocol_outcomes: [AtomicU64; 7],
}

impl ListenerStats {
    /// Connections open now, including those still in their TLS handshake.
    pub fn open(&self) -> usize {
        self.open.load(Ordering::Acquire)
    }

    /// Connections closed at accept because the listener was at `max_connections`.
    pub fn rejected(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }

    /// The listener's `max_connections`, `0` when it has none.
    pub fn max(&self) -> usize {
        self.max.load(Ordering::Relaxed)
    }

    /// Whether this listener terminates TLS.
    pub fn is_tls(&self) -> bool {
        self.tls.load(Ordering::Relaxed)
    }

    /// Failed TLS handshakes for each of [`TLS_FAILURE_REASONS`], in that order. `client_cert`
    /// counts clients refused for their certificate: none presented where one is required, an
    /// unknown CA, revoked or expired.
    pub fn tls_failures(&self) -> [u64; 3] {
        std::array::from_fn(|i| self.tls_failures[i].load(Ordering::Relaxed))
    }

    /// Connections to a TLS listener that closed, or were reset, before sending a byte of the
    /// handshake: TCP health checks, port scans, and a balancer's PROXY protocol health check
    /// (a `LOCAL` header, then nothing). No handshake was attempted, so they are in neither
    /// [`Self::tls_failures`] nor [`Self::tls_handshakes`].
    pub fn no_client_hello(&self) -> u64 {
        self.no_client_hello.load(Ordering::Relaxed)
    }

    /// TLS handshakes that ended, successful or not: [`Self::tls_failures`] are among them. A
    /// handshake cut short by shutdown is in neither, and neither is a connection that closed
    /// before its ClientHello ([`Self::no_client_hello`]). One that sent nothing until the
    /// handshake deadline is a `timeout` failure, and counted.
    pub fn tls_handshakes(&self) -> u64 {
        self.tls_handshakes.load(Ordering::Relaxed)
    }

    /// Requests on this listener still being answered: from the request's head until hyper has
    /// taken the end of its response body (a streamed one included), or gives the request up
    /// because its connection closed. A WebSocket upgrade counts until its `101`, not for the
    /// life of the tunnel.
    ///
    /// The end of the body is the last point hyper exposes per request. Its last bytes may still
    /// be in the connection's write buffer then, not yet handed to the socket. So a client that
    /// stops reading near the end of a response holds its connection, which
    /// [`Self::open`] counts, not a request.
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Acquire)
    }

    /// Whether this listener reads PROXY protocol headers.
    pub fn reads_proxy_protocol(&self) -> bool {
        self.proxy_protocol.load(Ordering::Relaxed)
    }

    /// Connections for each of [`Outcome::ALL`], in that order.
    pub fn proxy_protocol_outcomes(&self) -> [u64; 7] {
        std::array::from_fn(|i| self.proxy_protocol_outcomes[i].load(Ordering::Relaxed))
    }

    fn proxy_protocol_seen(&self, outcome: Outcome) {
        if let Some(i) = Outcome::ALL.iter().position(|o| *o == outcome) {
            self.proxy_protocol_outcomes[i].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Count a handshake that failed for `reason` (one of [`TLS_FAILURE_REASONS`]), in the
    /// total as well as by reason.
    fn tls_failed(&self, reason: &str) {
        self.tls_handshakes.fetch_add(1, Ordering::Relaxed);
        if let Some(i) = TLS_FAILURE_REASONS.iter().position(|r| *r == reason) {
            self.tls_failures[i].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Count a handshake that succeeded: in the total only.
    fn tls_succeeded(&self) {
        self.tls_handshakes.fetch_add(1, Ordering::Relaxed);
    }

    /// Resolve once no connection is open.
    async fn wait_idle(&self) {
        loop {
            // Register before checking, so a close between the check and the await still wakes us.
            let notified = self.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.open() == 0 {
                return;
            }
            notified.await;
        }
    }
}

/// Holds one slot in [`ListenerStats::open`] for the life of a connection task.
struct ConnSlot(Arc<ListenerStats>);

/// Holds one count in [`ListenerStats::in_flight`] for one request: taken when hyper hands the
/// request over, carried by its response body ([`Counted`]), and given back when that body is
/// dropped. hyper drops it once it has taken the body's last frame (before flushing what it has
/// buffered: it has no per-request point after the flush), when the connection closes under it,
/// or with the request's future if no response was produced.
struct InFlight(Arc<ListenerStats>);

impl InFlight {
    fn start(stats: &Arc<ListenerStats>) -> Self {
        stats.in_flight.fetch_add(1, Ordering::AcqRel);
        InFlight(Arc::clone(stats))
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A response body that holds its request's [`InFlight`] count. Everything else is the inner
/// body's, so hyper frames the response exactly as it would without the count: its framing reads
/// `size_hint` and `is_end_stream`.
struct Counted<B> {
    body: B,
    _in_flight: InFlight,
}

impl<B: hyper::body::Body + Unpin> hyper::body::Body for Counted<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.get_mut().body).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        if self.0.open.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.idle.notify_waiters();
        }
    }
}

/// Serve `app` on `listener` until `shutdown` flips true, then drain. TLS when `tls` is given,
/// plain HTTP (HTTP/1, and HTTP/2 with prior knowledge) otherwise. Returns once the drain has
/// finished or timed out.
pub async fn serve(
    listener: TcpListener,
    tls: Option<Arc<ServerConfig>>,
    app: Router,
    opts: ServeOpts,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let acceptor = tls.map(TlsAcceptor::from);
    if acceptor.is_some() {
        opts.stats.tls.store(true, Ordering::Relaxed);
    }
    opts.stats
        .max
        .store(opts.max_connections, Ordering::Relaxed);
    if opts.proxy_protocol.is_some() {
        opts.stats.proxy_protocol.store(true, Ordering::Relaxed);
    }
    // `into_make_service_with_connect_info` injects `ConnectInfo(client)` per connection, which
    // the proxy handler relies on for client-IP resolution. Made in the connection's task, once a
    // PROXY header has named the client.
    let make_service = app.into_make_service_with_connect_info::<SocketAddr>();
    // Tells every connection task to finish its in-flight request and close.
    let (drain_tx, drain_rx) = watch::channel(false);
    let stats = Arc::clone(&opts.stats);
    let local = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();

    // Set once shutdown is signalled: accepting continues until then, for `drain_delay`.
    let mut stop_accepting_at: Option<tokio::time::Instant> = None;
    let mut saturated = false;
    loop {
        let stop_at = stop_accepting_at;
        let (stream, peer) = tokio::select! {
            _ = signalled(&mut shutdown), if stop_at.is_none() => {
                if opts.drain_delay.is_zero() {
                    break;
                }
                info!(listen = %local, delay = ?opts.drain_delay, "shutdown signalled; still accepting during drain_delay");
                stop_accepting_at = Some(tokio::time::Instant::now() + opts.drain_delay);
                continue;
            }
            _ = tokio::time::sleep_until(stop_at.unwrap_or_else(tokio::time::Instant::now)), if stop_at.is_some() => break,
            accepted = listener.accept() => match accepted {
                Ok(v) => v,
                Err(e) => {
                    // Per-connection failures (the peer reset before we accepted) are routine. The
                    // rest — out of file descriptors, above all — return at once on every retry, so
                    // pause instead of spinning on them.
                    if !is_connection_error(&e) {
                        warn!(error = %e, listen = %local, "accept error; pausing for 1s");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    continue;
                }
            },
        };

        // Only this loop adds to `open`; tasks only subtract. So a count read here can only be
        // stale on the high side, which errs toward rejecting.
        if opts.max_connections != 0 && stats.open() >= opts.max_connections {
            stats.rejected.fetch_add(1, Ordering::Relaxed);
            if !saturated {
                warn!(listen = %local, max_connections = opts.max_connections, "connection cap reached; closing new connections until one frees up");
                saturated = true;
            }
            debug!(%peer, "closed at accept: max_connections reached");
            drop(stream);
            continue;
        }
        if saturated {
            info!(listen = %local, "below the connection cap again");
            saturated = false;
        }
        stats.open.fetch_add(1, Ordering::AcqRel);
        let slot = ConnSlot(Arc::clone(&stats));

        let mut make_service = make_service.clone();
        let acceptor = acceptor.clone();
        let proxy_protocol = opts.proxy_protocol.clone();
        let header_read_timeout = opts.header_read_timeout;
        let mut drain = drain_rx.clone();
        let stats = Arc::clone(&stats);
        tokio::spawn(async move {
            let _slot = slot;
            let mut stream = stream;
            let accepted_at = tokio::time::Instant::now();
            // The client this connection is served as, and what was read past its PROXY header.
            let (client, mut rest) = match &proxy_protocol {
                None => (peer, Vec::new()),
                Some(pp) => {
                    // A balancer sends the header as soon as it connects. With the header-read
                    // timeout off, the handshake's bound still keeps a silent peer from staying.
                    let limit = header_read_timeout.unwrap_or(TLS_HANDSHAKE_TIMEOUT);
                    let read = tokio::select! {
                        read = tokio::time::timeout_at(accepted_at + limit, pp.accept(&mut stream, peer)) => read,
                        _ = signalled(&mut drain) => return,
                    };
                    let accepted = match read {
                        Ok(Ok(accepted)) => accepted,
                        Ok(Err(e)) => {
                            // Reset before a single byte: on a TLS listener that is a connection
                            // that never sent a ClientHello, as it is without PROXY protocol.
                            if acceptor.is_some() && e.nothing_read {
                                stats.no_client_hello.fetch_add(1, Ordering::Relaxed);
                                debug!(error = %e, %peer, "reset before sending a PROXY header or a ClientHello");
                            } else {
                                debug!(error = %e, %peer, "read error before the PROXY protocol header");
                            }
                            return;
                        }
                        Err(_) => {
                            stats.proxy_protocol_seen(Outcome::Timeout);
                            debug!(%peer, "closed: nothing within header_read_timeout to tell a PROXY header from a request");
                            return;
                        }
                    };
                    stats.proxy_protocol_seen(accepted.outcome);
                    if !accepted.outcome.serves() {
                        debug!(%peer, result = accepted.outcome.label(), "closed: PROXY protocol header refused");
                        return;
                    }
                    (accepted.client, accepted.rest)
                }
            };
            // One `header_read_timeout` covers the PROXY header and the first request head
            // together: what the PROXY stage used is taken off what the request head gets, so a
            // client dripping both is closed after one timeout, not two. A TLS handshake between
            // them has its own bound and is not counted against it.
            let head_timeouts = header_read_timeout.map(|limit| HeadTimeouts {
                each: limit,
                first: limit.saturating_sub(accepted_at.elapsed()),
            });
            // The handshake's bound covers the wait for its first byte too.
            let handshake_deadline = tokio::time::Instant::now() + TLS_HANDSHAKE_TIMEOUT;
            if acceptor.is_some() && rest.is_empty() {
                // Wait for the ClientHello's first bytes before starting the handshake, so that a
                // connection that closes without sending any (a TCP health check, or a balancer's
                // PROXY `LOCAL` check, which sends the header and nothing more) is counted as what
                // it is, not as a failed handshake.
                let mut first = vec![0u8; 1024];
                let read = tokio::select! {
                    read = tokio::time::timeout_at(handshake_deadline, stream.read(&mut first)) => read,
                    _ = signalled(&mut drain) => return,
                };
                match read {
                    Ok(Ok(n)) if n > 0 => {
                        first.truncate(n);
                        rest = first;
                    }
                    // Closed or reset before a byte of handshake.
                    Ok(_) => {
                        stats.no_client_hello.fetch_add(1, Ordering::Relaxed);
                        debug!(%peer, "closed before sending a ClientHello");
                        return;
                    }
                    Err(_) => {
                        stats.tls_failed("timeout");
                        debug!(%peer, "TLS handshake timed out");
                        return;
                    }
                }
            }
            let stream = Prefixed {
                prefix: rest,
                pos: 0,
                inner: stream,
            };
            // Connection-scoped tower service carrying this client's ConnectInfo.
            let tower_service = unwrap_infallible(make_service.call(client).await);
            match acceptor {
                None => {
                    serve_connection(
                        stream,
                        peer,
                        tower_service,
                        head_timeouts,
                        None,
                        drain,
                        stats,
                    )
                    .await
                }
                Some(acceptor) => {
                    let tls_stream = tokio::select! {
                        handshake = tokio::time::timeout_at(handshake_deadline, acceptor.accept(stream)) => match handshake {
                            Ok(Ok(s)) => {
                                stats.tls_succeeded();
                                s
                            }
                            Ok(Err(e)) => {
                                let reason = if is_client_cert_error(&e) { "client_cert" } else { "other" };
                                stats.tls_failed(reason);
                                debug!(error = %e, %peer, reason, "TLS handshake failed");
                                return;
                            }
                            Err(_) => {
                                stats.tls_failed("timeout");
                                debug!(%peer, "TLS handshake timed out");
                                return;
                            }
                        },
                        _ = signalled(&mut drain) => return,
                    };
                    // Read the client's certificate once, here: rustls has verified it, and it
                    // cannot change for the life of the connection. Likewise the version.
                    let session = tls_stream.get_ref().1;
                    let tls = TlsConn {
                        version: match session.protocol_version() {
                            Some(rustls::ProtocolVersion::TLSv1_3) => Some(TlsVersion("TLSv1.3")),
                            Some(rustls::ProtocolVersion::TLSv1_2) => Some(TlsVersion("TLSv1.2")),
                            _ => None,
                        },
                        client_cert: session
                            .peer_certificates()
                            .and_then(|chain| chain.first())
                            .map(|leaf| Arc::new(crate::client_auth::ClientCert::from_der(leaf))),
                    };
                    serve_connection(
                        tls_stream,
                        peer,
                        tower_service,
                        head_timeouts,
                        Some(tls),
                        drain,
                        stats,
                    )
                    .await
                }
            }
        });
    }

    // Closing the listening socket now makes new connections fail fast rather than queue in a
    // backlog nothing will read.
    drop(listener);
    let _ = drain_tx.send(true);
    let in_flight = stats.open();
    if in_flight == 0 {
        return Ok(());
    }
    info!(listen = %local, connections = in_flight, timeout = ?opts.drain_timeout, "draining connections");
    if tokio::time::timeout(opts.drain_timeout, stats.wait_idle())
        .await
        .is_err()
    {
        warn!(listen = %local, connections = stats.open(), "drain_timeout reached; closing the remaining connections");
    } else {
        info!(listen = %local, "drained");
    }
    Ok(())
}

/// Serve one connection with hyper: under the header-read timeout when one is set, and shutting
/// down gracefully (finish the in-flight request, then close) when `drain` flips. `head_timeouts`
/// is `None` when `header_read_timeout` is off. `peer` is the
/// TCP peer, attached to every request as [`TcpPeer`]. On a TLS connection, the version and any
/// verified client certificate are attached too. Each request is counted in `stats`' in-flight
/// count until hyper has taken the end of its response body.
async fn serve_connection<I>(
    mut io: I,
    peer: SocketAddr,
    service: AddExtension<Router, ConnectInfo<SocketAddr>>,
    head_timeouts: Option<HeadTimeouts>,
    tls: Option<TlsConn>,
    mut drain: watch::Receiver<bool>,
    stats: Arc<ListenerStats>,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = ConnBuilder::new(TokioExecutor::new());
    // When the first request's head must be complete: what is left of `header_read_timeout`
    // after a PROXY header, from now. hyper's own header timeout covers each request head, but
    // starts only when it begins reading one, after the bytes read here; so without this a client
    // dripping a PROXY header (or the first byte) and then the head held the connection for two
    // timeouts. Later requests on a kept-alive connection get hyper's timeout alone.
    let first_head_by = head_timeouts.map(|t| tokio::time::Instant::now() + t.first);
    let prefix = match head_timeouts {
        Some(HeadTimeouts { each: limit, .. }) => {
            let first_by = first_head_by.expect("set with head_timeouts");
            let first = tokio::select! {
                first = tokio::time::timeout_at(first_by, read_preface(&mut io)) => first,
                _ = signalled(&mut drain) => return,
            };
            let prefix = match first {
                Ok(Ok(Some(prefix))) => prefix,
                // Closed before sending anything that could start a request.
                Ok(Ok(None)) => return,
                Ok(Err(e)) => {
                    debug!(error = %e, %peer, "read error before the first request");
                    return;
                }
                Err(_) => {
                    debug!(%peer, "closed: no request within header_read_timeout");
                    return;
                }
            };
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(limit);
            prefix
        }
        None => {
            // Stated explicitly: hyper's built-in default would otherwise apply, or not, depending
            // on whether a timer happens to be set.
            builder.http1().header_read_timeout(None);
            Vec::new()
        }
    };

    // Like hyper's header timeout, the first-head deadline is HTTP/1's: an HTTP/2 connection
    // that has sent its preface may wait idle for its first request.
    let first_head_by = first_head_by.filter(|_| prefix != H2_PREFACE);
    // Set once the first request's head has arrived, which ends the first-head deadline.
    let first_head = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let io = TokioIo::new(Prefixed {
        prefix,
        pos: 0,
        inner: io,
    });
    let seen = Arc::clone(&first_head);
    let hyper_service = hyper::service::service_fn(move |mut request: Request<Incoming>| {
        seen.store(true, Ordering::Release);
        let in_flight = InFlight::start(&stats);
        request.extensions_mut().insert(TcpPeer(peer));
        if let Some(tls) = &tls {
            if let Some(version) = tls.version {
                request.extensions_mut().insert(version);
            }
            if let Some(cert) = &tls.client_cert {
                request.extensions_mut().insert(Arc::clone(cert));
            }
        }
        let response = service.clone().oneshot(request);
        async move {
            let response = response.await?;
            Ok::<_, std::convert::Infallible>(response.map(|body| Counted {
                body,
                _in_flight: in_flight,
            }))
        }
    });
    let conn = builder.serve_connection_with_upgrades(io, hyper_service);
    tokio::pin!(conn);
    // Resolves at the first-head deadline if no request head has arrived by then; never otherwise.
    let first_head_late = async {
        match first_head_by {
            Some(at) => {
                tokio::time::sleep_until(at).await;
                if first_head.load(Ordering::Acquire) {
                    std::future::pending::<()>().await;
                }
            }
            None => std::future::pending::<()>().await,
        }
    };
    let result = tokio::select! {
        result = conn.as_mut() => result,
        _ = first_head_late => {
            debug!(%peer, "closed: no complete request within header_read_timeout");
            return;
        }
        _ = signalled(&mut drain) => {
            conn.as_mut().graceful_shutdown();
            conn.await
        }
    };
    if let Err(e) = result {
        debug!(error = %e, %peer, "connection ended with an error");
    }
}

/// `header_read_timeout` for one connection.
#[derive(Debug, Clone, Copy)]
struct HeadTimeouts {
    /// For each request head (hyper's), from when it starts reading one.
    each: Duration,
    /// For the first request head, from when the connection reaches hyper: what is left of the
    /// timeout after the PROXY header.
    first: Duration,
}

/// Read until the bytes either rule out the HTTP/2 preface or complete it, so the version check
/// hyper runs next is answered from what is already here. `None` when the peer closes first.
async fn read_preface<I: AsyncRead + Unpin>(io: &mut I) -> io::Result<Option<Vec<u8>>> {
    let mut buf = vec![0u8; H2_PREFACE.len()];
    let mut filled = 0;
    while filled < buf.len() {
        let n = io.read(&mut buf[filled..]).await?;
        if n == 0 {
            return Ok(None);
        }
        let start = filled;
        filled += n;
        if buf[start..filled] != H2_PREFACE[start..filled] {
            break;
        }
    }
    buf.truncate(filled);
    Ok(Some(buf))
}

/// An I/O stream with bytes already read from it put back in front.
struct Prefixed<I> {
    prefix: Vec<u8>,
    pos: usize,
    inner: I,
}

impl<I: AsyncRead + Unpin> AsyncRead for Prefixed<I> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let n = (this.prefix.len() - this.pos).min(buf.remaining());
            buf.put_slice(&this.prefix[this.pos..this.pos + n]);
            this.pos += n;
            if this.pos == this.prefix.len() {
                this.prefix = Vec::new();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for Prefixed<I> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Resolve once `rx` reads `true`. If the sender is dropped first, never resolve: nobody is left
/// who could ask for a shutdown.
async fn signalled(rx: &mut watch::Receiver<bool>) {
    if rx.wait_for(|v| *v).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Whether a failed handshake was the client's certificate being refused.
fn is_client_cert_error(e: &io::Error) -> bool {
    matches!(
        e.get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>()),
        Some(rustls::Error::NoCertificatesPresented | rustls::Error::InvalidCertificate(_))
    )
}

/// Errors that belong to one connection attempt rather than to the listener.
fn is_connection_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
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
    use tokio::io::AsyncWriteExt;

    #[test]
    fn defaults_come_from_the_server_section() {
        let o = ServeOpts::default();
        assert_eq!(o.header_read_timeout, Some(Duration::from_secs(30)));
        assert_eq!(o.max_connections, 0);
        assert_eq!(o.drain_delay, Duration::ZERO);
        assert_eq!(o.drain_timeout, Duration::from_secs(25));
    }

    #[test]
    fn zero_disables_the_header_timeout_and_a_typo_is_an_error() {
        let mut cfg = ServerCfg {
            header_read_timeout: "0".into(),
            ..Default::default()
        };
        assert_eq!(ServeOpts::from_cfg(&cfg).unwrap().header_read_timeout, None);
        cfg.header_read_timeout = "30 seconds".into();
        let Err(e) = ServeOpts::from_cfg(&cfg) else {
            panic!("an unparseable duration must not silently disable the timeout");
        };
        assert!(format!("{e:#}").contains("server.header_read_timeout"));
    }

    #[tokio::test]
    async fn read_preface_stops_at_the_first_byte_that_is_not_http2() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        let got = read_preface(&mut server).await.unwrap().unwrap();
        assert!(!got.is_empty() && b"GET / HTTP/1.1\r\n".starts_with(&got));
    }

    #[tokio::test]
    async fn read_preface_collects_a_fragmented_http2_preface() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            for chunk in H2_PREFACE.chunks(5) {
                client.write_all(chunk).await.unwrap();
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            client
        });
        let got = read_preface(&mut server).await.unwrap().unwrap();
        assert_eq!(got, H2_PREFACE);
        drop(writer.await.unwrap());
    }

    #[tokio::test]
    async fn read_preface_is_none_when_the_peer_closes_first() {
        let (client, mut server) = tokio::io::duplex(64);
        drop(client);
        assert!(read_preface(&mut server).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn prefixed_replays_its_prefix_once_then_reads_the_stream() {
        let (mut client, server) = tokio::io::duplex(64);
        client.write_all(b"world").await.unwrap();
        drop(client);
        let mut io = Prefixed {
            prefix: b"hello ".to_vec(),
            pos: 0,
            inner: server,
        };
        let mut out = String::new();
        io.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "hello world");
    }
}
