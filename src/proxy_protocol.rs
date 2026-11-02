//! The PROXY protocol (v1 and v2), as an L4 load balancer sends it: one header, at the very start
//! of the connection, naming the client the balancer accepted the connection from.
//!
//! A balancer that passes TCP through (AWS NLB, a GCP TCP proxy, HAProxy, F5) cannot add
//! `X-Forwarded-For`, so without this the edge sees every connection as coming from the balancer.
//! [`ProxyProtocol::accept`] reads the header before anything else — before the TLS handshake on
//! a TLS listener, since the header is outside TLS — and hands back the client's address and the
//! bytes it read past the header, for the caller to replay.
//!
//! The header is believed only from `trusted` peers. From anyone else a connection that starts
//! with one is refused: it is a client choosing its own address. One that does not is served as
//! it is, so health checks and other direct callers keep working. Only the bytes needed to tell
//! are read, and a connection without a header gets them back untouched.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::access::Cidr;

/// The v2 signature.
const V2_SIG: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
/// What a v1 header starts with.
const V1_START: &[u8] = b"PROXY ";
/// A v1 header is at most this long, CRLF included (the spec's 107).
const V1_MAX: usize = 107;
/// A v2 header past this is refused rather than buffered. The addresses take at most 216 bytes;
/// the rest is TLVs, which balancers keep small (AWS adds a VPC endpoint id).
const V2_MAX: usize = 4096;

/// What became of a connection's first bytes: `edgeguard_proxy_protocol_total{result}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A trusted peer's header named the client: its address is the connection's.
    Proxied,
    /// A trusted peer's header named no client (v2 `LOCAL`, v1 `UNKNOWN`): the balancer's own
    /// health check. The peer's address stands.
    Local,
    /// A trusted peer sent no header: its address stands. A balancer that should be sending one
    /// is not.
    Missing,
    /// An untrusted peer sent no header: an ordinary direct connection.
    Direct,
    /// An untrusted peer sent a header: refused, it would be choosing its own address.
    Untrusted,
    /// A header that does not parse: refused.
    Invalid,
    /// Nothing decisive arrived within the listener's header read timeout: closed.
    Timeout,
}

impl Outcome {
    pub const ALL: [Outcome; 7] = [
        Outcome::Proxied,
        Outcome::Local,
        Outcome::Missing,
        Outcome::Direct,
        Outcome::Untrusted,
        Outcome::Invalid,
        Outcome::Timeout,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Outcome::Proxied => "proxied",
            Outcome::Local => "local",
            Outcome::Missing => "missing",
            Outcome::Direct => "direct",
            Outcome::Untrusted => "untrusted",
            Outcome::Invalid => "invalid",
            Outcome::Timeout => "timeout",
        }
    }

    /// Whether the connection is served.
    pub fn serves(self) -> bool {
        matches!(
            self,
            Outcome::Proxied | Outcome::Local | Outcome::Missing | Outcome::Direct
        )
    }
}

/// `server.proxy_protocol`, compiled.
#[derive(Debug)]
pub struct ProxyProtocol {
    trusted: Vec<Cidr>,
}

/// A connection after its header: the client address to serve it as, and the bytes read past the
/// header, to be replayed before the rest of the stream.
#[derive(Debug)]
pub struct Accepted {
    pub outcome: Outcome,
    pub client: SocketAddr,
    pub rest: Vec<u8>,
}

impl ProxyProtocol {
    /// `None` when off. Fails on no trusted addresses, or a `/0` among them.
    pub fn from_cfg(on: bool, trusted: &[String]) -> Result<Option<ProxyProtocol>> {
        if !on {
            return Ok(None);
        }
        anyhow::ensure!(
            !trusted.is_empty(),
            "server.proxy_protocol_trusted is required with server.proxy_protocol: without it a \
             PROXY header would be believed from anyone, and any client could choose its address"
        );
        let cidrs = trusted
            .iter()
            .map(|t| Cidr::parse(t).context("server.proxy_protocol_trusted"))
            .collect::<Result<Vec<_>>>()?;
        if let Some((text, _)) = trusted.iter().zip(&cidrs).find(|(_, c)| c.is_everything()) {
            anyhow::bail!(
                "server.proxy_protocol_trusted contains {text:?}, every address: any client could \
                 choose its own address. List the load balancer's addresses."
            );
        }
        Ok(Some(ProxyProtocol { trusted: cidrs }))
    }

    pub fn trusts(&self, peer: IpAddr) -> bool {
        let peer = peer.to_canonical();
        self.trusted.iter().any(|c| c.contains(peer))
    }

    /// Read just enough of `io` to tell whether it starts with a PROXY header, and the header if
    /// it does. Never fails on what the peer sends: a refused or unreadable connection is an
    /// [`Outcome`] that does not serve. An I/O error is passed up.
    pub async fn accept<I: AsyncRead + Unpin>(
        &self,
        io: &mut I,
        peer: SocketAddr,
    ) -> io::Result<Accepted> {
        let trusted = self.trusts(peer.ip());
        let (header, rest) = read_header(io).await?;
        let refuse = |outcome| Accepted {
            outcome,
            client: peer,
            rest: Vec::new(),
        };
        Ok(match header {
            Header::None => Accepted {
                outcome: if trusted {
                    Outcome::Missing
                } else {
                    Outcome::Direct
                },
                client: peer,
                rest,
            },
            _ if !trusted => refuse(Outcome::Untrusted),
            Header::Invalid(_) => refuse(Outcome::Invalid),
            Header::Local => Accepted {
                outcome: Outcome::Local,
                client: peer,
                rest,
            },
            Header::Proxy(client) => Accepted {
                outcome: Outcome::Proxied,
                client,
                rest,
            },
        })
    }
}

/// What a connection started with.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Header {
    /// No PROXY header: the bytes are the protocol itself (HTTP, a TLS ClientHello).
    None,
    /// A header naming no client.
    Local,
    /// A header naming this client.
    Proxy(SocketAddr),
    /// A header, or the start of one, that does not parse.
    Invalid(&'static str),
}

/// Read from `io` until its first bytes decide [`Header`]. Returns it with the bytes read past
/// the header (everything read, when there is none). A peer that closes partway through a header
/// gave an invalid one; one that closes before deciding anything gave none.
pub(crate) async fn read_header<I: AsyncRead + Unpin>(io: &mut I) -> io::Result<(Header, Vec<u8>)> {
    let mut buf = Vec::with_capacity(256);
    let mut chunk = [0u8; 512];
    loop {
        match parse(&buf) {
            Parse::Done(header, used) => {
                let rest = buf.split_off(used);
                return Ok((header, rest));
            }
            Parse::NotProxy => return Ok((Header::None, buf)),
            Parse::Need => {}
        }
        let n = io.read(&mut chunk).await?;
        if n == 0 {
            // Closed before the header was complete; if nothing at all came, there was none.
            let header = if buf.is_empty() {
                Header::None
            } else {
                Header::Invalid("the connection closed inside the header")
            };
            return Ok((header, Vec::new()));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

enum Parse {
    /// A complete header, and how many bytes it took.
    Done(Header, usize),
    /// These bytes are not the start of a header.
    NotProxy,
    /// Not decided yet.
    Need,
}

fn parse(buf: &[u8]) -> Parse {
    if buf.is_empty() {
        return Parse::Need;
    }
    let v2 = buf.len().min(V2_SIG.len());
    if buf[..v2] == V2_SIG[..v2] {
        return if buf.len() < 16 {
            Parse::Need
        } else {
            parse_v2(buf)
        };
    }
    let v1 = buf.len().min(V1_START.len());
    if buf[..v1] == V1_START[..v1] {
        return if buf.len() < V1_START.len() {
            Parse::Need
        } else {
            parse_v1(buf)
        };
    }
    Parse::NotProxy
}

/// `PROXY TCP4 <src> <dst> <sport> <dport>\r\n`, `TCP6` likewise, or `PROXY UNKNOWN …\r\n`.
fn parse_v1(buf: &[u8]) -> Parse {
    let Some(end) = buf.windows(2).position(|w| w == b"\r\n") else {
        return if buf.len() >= V1_MAX {
            Parse::Done(
                Header::Invalid("a v1 header without CRLF in 107 bytes"),
                buf.len(),
            )
        } else {
            Parse::Need
        };
    };
    let used = end + 2;
    if used > V1_MAX {
        return Parse::Done(Header::Invalid("a v1 header over 107 bytes"), used);
    }
    let Ok(line) = std::str::from_utf8(&buf[V1_START.len()..end]) else {
        return Parse::Done(Header::Invalid("a v1 header that is not ASCII"), used);
    };
    let fields: Vec<&str> = line.split(' ').collect();
    let header = match fields.as_slice() {
        ["UNKNOWN", ..] => Header::Local,
        [proto @ ("TCP4" | "TCP6"), src, _dst, sport, _dport] => {
            match (src.parse::<IpAddr>(), sport.parse::<u16>()) {
                (Ok(ip), Ok(port)) if ip.is_ipv4() == (*proto == "TCP4") => {
                    Header::Proxy(SocketAddr::new(ip, port))
                }
                _ => Header::Invalid("a v1 header with a bad address or port"),
            }
        }
        _ => Header::Invalid("a v1 header that is not TCP4, TCP6 or UNKNOWN"),
    };
    Parse::Done(header, used)
}

/// The 16-byte v2 preamble — signature, version and command, family and transport, length — then
/// the addresses and any TLVs, which are skipped.
fn parse_v2(buf: &[u8]) -> Parse {
    let len = usize::from(u16::from_be_bytes([buf[14], buf[15]]));
    let used = 16 + len;
    if used > V2_MAX {
        return Parse::Done(Header::Invalid("a v2 header over 4096 bytes"), buf.len());
    }
    if buf.len() < used {
        return Parse::Need;
    }
    let (version, command) = (buf[12] >> 4, buf[12] & 0x0f);
    if version != 2 {
        return Parse::Done(Header::Invalid("a v2 signature with another version"), used);
    }
    let addrs = &buf[16..used];
    let header = match (command, buf[13] >> 4) {
        // LOCAL: the balancer speaking for itself, a health check. Addresses are to be ignored.
        (0, _) => Header::Local,
        // PROXY over AF_INET: src, dst, sport, dport.
        (1, 1) if addrs.len() >= 12 => {
            let ip = Ipv4Addr::new(addrs[0], addrs[1], addrs[2], addrs[3]);
            Header::Proxy(SocketAddr::new(
                IpAddr::V4(ip),
                u16::from_be_bytes([addrs[8], addrs[9]]),
            ))
        }
        // AF_INET6.
        (1, 2) if addrs.len() >= 36 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&addrs[..16]);
            Header::Proxy(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                u16::from_be_bytes([addrs[32], addrs[33]]),
            ))
        }
        // AF_UNSPEC or AF_UNIX: no address this edge could use; the connection's own stands.
        (1, 0 | 3) => Header::Local,
        (1, 1 | 2) => Header::Invalid("a v2 header too short for its addresses"),
        _ => Header::Invalid("a v2 header with an unknown command or family"),
    };
    Parse::Done(header, used)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn read(bytes: &[u8]) -> (Header, Vec<u8>) {
        let mut io = bytes;
        read_header(&mut io).await.unwrap()
    }

    fn v2(command: u8, family: u8, addrs: &[u8]) -> Vec<u8> {
        let mut h = V2_SIG.to_vec();
        h.push(0x20 | command);
        h.push(family << 4 | 1);
        h.extend_from_slice(&(addrs.len() as u16).to_be_bytes());
        h.extend_from_slice(addrs);
        h
    }

    fn inet(src: [u8; 4], sport: u16) -> Vec<u8> {
        let mut a = src.to_vec();
        a.extend_from_slice(&[10, 0, 0, 1]);
        a.extend_from_slice(&sport.to_be_bytes());
        a.extend_from_slice(&443u16.to_be_bytes());
        a
    }

    #[tokio::test]
    async fn requests_and_handshakes_are_not_headers_and_lose_nothing() {
        for start in [
            &b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"[..],
            b"POST /orders HTTP/1.1\r\n",
            b"PUT /x HTTP/1.1\r\n",
            b"PATCH /x HTTP/1.1\r\n",
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
            b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03",
        ] {
            let (header, rest) = read(start).await;
            assert_eq!(header, Header::None, "{start:?}");
            assert!(
                start.starts_with(&rest) && !rest.is_empty(),
                "{start:?}: {rest:?}"
            );
        }
        assert_eq!(read(b"").await, (Header::None, Vec::new()));
    }

    #[tokio::test]
    async fn v1_headers() {
        let (h, rest) =
            read(b"PROXY TCP4 203.0.113.7 10.0.0.1 51234 443\r\nGET / HTTP/1.1\r\n").await;
        assert_eq!(h, Header::Proxy("203.0.113.7:51234".parse().unwrap()));
        assert_eq!(rest, b"GET / HTTP/1.1\r\n", "what follows is replayed");
        let (h, _) = read(b"PROXY TCP6 2001:db8::7 2001:db8::1 51234 443\r\n").await;
        assert_eq!(h, Header::Proxy("[2001:db8::7]:51234".parse().unwrap()));
        assert_eq!(read(b"PROXY UNKNOWN\r\n").await.0, Header::Local);
        for bad in [
            &b"PROXY TCP4 2001:db8::7 10.0.0.1 1 2\r\n"[..],
            b"PROXY TCP4 203.0.113.7 10.0.0.1 99999 443\r\n",
            b"PROXY UDP4 203.0.113.7 10.0.0.1 1 2\r\n",
            b"PROXY TCP4 203.0.113.7\r\n",
        ] {
            assert!(matches!(read(bad).await.0, Header::Invalid(_)), "{bad:?}");
        }
        let long = [b"PROXY ".as_slice(), &[b'1'; 120]].concat();
        assert!(matches!(read(&long).await.0, Header::Invalid(_)));
        assert!(
            matches!(read(b"PROXY TCP4 1.2").await.0, Header::Invalid(_)),
            "closed inside it"
        );
    }

    #[tokio::test]
    async fn v2_headers() {
        let mut bytes = v2(1, 1, &inet([203, 0, 113, 7], 51234));
        bytes.extend_from_slice(b"\x16\x03\x01");
        let (h, rest) = read(&bytes).await;
        assert_eq!(h, Header::Proxy("203.0.113.7:51234".parse().unwrap()));
        assert_eq!(rest, b"\x16\x03\x01");

        let mut six = [0u8; 36];
        six[..16].copy_from_slice(&"2001:db8::7".parse::<Ipv6Addr>().unwrap().octets());
        six[32..34].copy_from_slice(&4321u16.to_be_bytes());
        assert_eq!(
            read(&v2(1, 2, &six)).await.0,
            Header::Proxy("[2001:db8::7]:4321".parse().unwrap())
        );
        // TLVs after the addresses (AWS's VPC endpoint id) are skipped.
        let mut tlv = inet([198, 51, 100, 9], 80);
        tlv.extend_from_slice(&[0xea, 0x00, 0x04, b'v', b'p', b'c', b'e']);
        assert_eq!(
            read(&v2(1, 1, &tlv)).await.0,
            Header::Proxy("198.51.100.9:80".parse().unwrap())
        );
        assert_eq!(
            read(&v2(0, 1, &inet([1, 2, 3, 4], 5))).await.0,
            Header::Local,
            "LOCAL"
        );
        assert_eq!(read(&v2(1, 0, &[])).await.0, Header::Local, "AF_UNSPEC");

        let mut wrong_version = v2(1, 1, &inet([1, 2, 3, 4], 5));
        wrong_version[12] = 0x11;
        assert!(matches!(read(&wrong_version).await.0, Header::Invalid(_)));
        assert!(
            matches!(read(&v2(1, 1, &[1, 2, 3])).await.0, Header::Invalid(_)),
            "short"
        );
        let mut huge = V2_SIG.to_vec();
        huge.extend_from_slice(&[0x21, 0x11, 0xff, 0xff]);
        assert!(
            matches!(read(&huge).await.0, Header::Invalid(_)),
            "oversized"
        );
        assert!(
            matches!(read(&V2_SIG[..8]).await.0, Header::Invalid(_)),
            "closed inside it"
        );
    }

    #[test]
    fn settings_that_would_trust_anyone_are_refused() {
        assert!(ProxyProtocol::from_cfg(false, &[]).unwrap().is_none());
        let err = |t: &[&str]| {
            let t: Vec<String> = t.iter().map(|s| s.to_string()).collect();
            format!("{:#}", ProxyProtocol::from_cfg(true, &t).unwrap_err())
        };
        assert!(err(&[]).contains("proxy_protocol_trusted is required"));
        assert!(err(&["0.0.0.0/0"]).contains("every address"));
        assert!(err(&["nonsense"]).contains("proxy_protocol_trusted"));
        let pp = ProxyProtocol::from_cfg(true, &["10.0.0.0/16".into()])
            .unwrap()
            .unwrap();
        assert!(pp.trusts("10.0.3.4".parse().unwrap()));
        assert!(pp.trusts("::ffff:10.0.3.4".parse().unwrap()));
        assert!(!pp.trusts("10.1.0.1".parse().unwrap()));
    }
}
