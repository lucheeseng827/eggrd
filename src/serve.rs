//! The accept loop every listener runs — public (plain or TLS), admin and redirect.
//!
//! One loop, so the protections below cannot differ between listeners:
//!
//! * **Header-read timeout.** A connection must deliver a complete request head within
//!   `server.header_read_timeout`, whether it is new, slow, or a keep-alive connection idle between
//!   requests. hyper has this timeout built in, but it only applies once a `Timer` is installed, and
//!   it only starts after HTTP-version detection, which has no timeout of its own: a client that
//!   connects and sends nothing would otherwise hold its socket forever. So the first bytes are read
//!   here, under the same deadline, and replayed to hyper ([`Prefixed`]).
//! * **Connection cap.** `server.max_connections` open connections at most; one more is closed as
//!   soon as it is accepted, and counted.
//! * **PROXY protocol.** With `server.proxy_protocol`, a header a trusted load balancer sends at
//!   the start of the connection names the client, before anything else is read (before the TLS
//!   handshake, which it precedes on the wire). See [`crate::proxy_protocol`].
//! * **Graceful drain.** When `shutdown` flips, keep accepting for `drain_delay` (so a load balancer
//!   has time to stop routing here), then stop accepting, ask every connection to finish its
//!   in-flight request and close, and wait up to `drain_timeout` for them.
//!
//! Upgraded connections (WebSocket tunnels) leave hyper's connection once the upgrade completes,
//! so they are not counted here and are not waited for.

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

    fn tls_failed(&self, reason: &str) {
        if let Some(i) = TLS_FAILURE_REASONS.iter().position(|r| *r == reason) {
            self.tls_failures[i].fetch_add(1, Ordering::Relaxed);
        }
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
            // The client this connection is served as, and what was read past its PROXY header.
            let (client, rest) = match &proxy_protocol {
                None => (peer, Vec::new()),
                Some(pp) => {
                    // A balancer sends the header as soon as it connects. With the header-read
                    // timeout off, the handshake's bound still keeps a silent peer from staying.
                    let limit = header_read_timeout.unwrap_or(TLS_HANDSHAKE_TIMEOUT);
                    let read = tokio::select! {
                        read = tokio::time::timeout(limit, pp.accept(&mut stream, peer)) => read,
                        _ = signalled(&mut drain) => return,
                    };
                    let accepted = match read {
                        Ok(Ok(accepted)) => accepted,
                        Ok(Err(e)) => {
                            debug!(error = %e, %peer, "read error before the PROXY protocol header");
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
                        header_read_timeout,
                        None,
                        drain,
                    )
                    .await
                }
                Some(acceptor) => {
                    let tls_stream = tokio::select! {
                        handshake = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)) => match handshake {
                            Ok(Ok(s)) => s,
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
                        header_read_timeout,
                        Some(tls),
                        drain,
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
/// down gracefully (finish the in-flight request, then close) when `drain` flips. `peer` is the
/// TCP peer, attached to every request as [`TcpPeer`]. On a TLS connection, the version and any
/// verified client certificate are attached too.
async fn serve_connection<I>(
    mut io: I,
    peer: SocketAddr,
    service: AddExtension<Router, ConnectInfo<SocketAddr>>,
    header_read_timeout: Option<Duration>,
    tls: Option<TlsConn>,
    mut drain: watch::Receiver<bool>,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = ConnBuilder::new(TokioExecutor::new());
    let prefix = match header_read_timeout {
        Some(limit) => {
            let first = tokio::select! {
                first = tokio::time::timeout(limit, read_preface(&mut io)) => first,
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

    let io = TokioIo::new(Prefixed {
        prefix,
        pos: 0,
        inner: io,
    });
    let hyper_service = hyper::service::service_fn(move |mut request: Request<Incoming>| {
        request.extensions_mut().insert(TcpPeer(peer));
        if let Some(tls) = &tls {
            if let Some(version) = tls.version {
                request.extensions_mut().insert(version);
            }
            if let Some(cert) = &tls.client_cert {
                request.extensions_mut().insert(Arc::clone(cert));
            }
        }
        service.clone().oneshot(request)
    });
    let conn = builder.serve_connection_with_upgrades(io, hyper_service);
    tokio::pin!(conn);
    let result = tokio::select! {
        result = conn.as_mut() => result,
        _ = signalled(&mut drain) => {
            conn.as_mut().graceful_shutdown();
            conn.await
        }
    };
    if let Err(e) = result {
        debug!(error = %e, %peer, "connection ended with an error");
    }
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
