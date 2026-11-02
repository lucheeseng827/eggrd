//! A throwaway PKI for the TLS tests: CAs, leaf certificates (server or client, with DNS, IP or
//! URI names), CRLs, a scratch directory for the PEM files, and an HTTP CONNECT proxy.
#![allow(dead_code)] // each test crate uses a different part of it

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose,
    RevokedCertParams, SanType, SerialNumber,
};

pub struct Ca {
    params: CertificateParams,
    key: KeyPair,
    pub pem: String,
}

impl Ca {
    pub fn new(name: &str) -> Ca {
        Ca::build(name, None)
    }

    /// A CA that expires `days` from now.
    pub fn expiring(name: &str, days: i64) -> Ca {
        Ca::build(name, Some(days))
    }

    fn build(name: &str, days: Option<i64>) -> Ca {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        if let Some(days) = days {
            let now = time::OffsetDateTime::now_utc();
            params.not_before = now - time::Duration::days(30);
            params.not_after = now + time::Duration::days(days);
        }
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, name);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let key = KeyPair::generate().unwrap();
        let pem = params.self_signed(&key).unwrap().pem();
        Ca { params, key, pem }
    }

    /// A leaf for `names` (DNS names or IPs), for a server or for a client.
    pub fn issue(&self, names: &[&str], usage: ExtendedKeyUsagePurpose) -> Leaf {
        let params =
            CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        self.sign(
            params,
            names.first().copied().unwrap_or("leaf"),
            usage,
            None,
        )
    }

    pub fn server(&self, names: &[&str]) -> Leaf {
        self.issue(names, ExtendedKeyUsagePurpose::ServerAuth)
    }

    pub fn client(&self, name: &str) -> Leaf {
        self.issue(&[name], ExtendedKeyUsagePurpose::ClientAuth)
    }

    /// A client certificate with exactly these alternative names, this CN and this serial.
    pub fn client_with(&self, sans: Vec<SanType>, cn: &str, serial: u64) -> Leaf {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = sans;
        self.sign(
            params,
            cn,
            ExtendedKeyUsagePurpose::ClientAuth,
            Some(serial),
        )
    }

    /// A client certificate for `name` that expires `days` from now.
    pub fn client_expiring(&self, name: &str, days: i64) -> Leaf {
        let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(30);
        params.not_after = now + time::Duration::days(days);
        self.sign(params, name, ExtendedKeyUsagePurpose::ClientAuth, None)
    }

    /// A CRL from this CA revoking the certificates with these serials.
    pub fn crl(&self, revoked: &[u64]) -> String {
        self.crl_next_update(revoked, time::Duration::days(1))
    }

    /// [`Ca::crl`], promising the next CRL `next` from now (negative: already overdue).
    pub fn crl_next_update(&self, revoked: &[u64], next: time::Duration) -> String {
        let now = time::OffsetDateTime::now_utc();
        // An overdue CRL was issued a day before it fell due; otherwise, a minute ago.
        let this_update = if next.is_negative() {
            now + next - time::Duration::days(1)
        } else {
            now - time::Duration::minutes(1)
        };
        CertificateRevocationListParams {
            this_update,
            next_update: now + next,
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: revoked
                .iter()
                .map(|s| RevokedCertParams {
                    serial_number: SerialNumber::from(*s),
                    revocation_time: now - time::Duration::minutes(1),
                    reason_code: None,
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(&Issuer::from_params(&self.params, &self.key))
        .unwrap()
        .pem()
        .unwrap()
    }

    fn sign(
        &self,
        mut params: CertificateParams,
        cn: &str,
        usage: ExtendedKeyUsagePurpose,
        serial: Option<u64>,
    ) -> Leaf {
        params.distinguished_name.push(DnType::CommonName, cn);
        params.extended_key_usages = vec![usage];
        params.serial_number = serial.map(SerialNumber::from);
        let key = KeyPair::generate().unwrap();
        let cert = params
            .signed_by(&key, &Issuer::from_params(&self.params, &self.key))
            .unwrap();
        Leaf {
            der: cert.der().to_vec(),
            cert: cert.pem(),
            key: key.serialize_pem(),
        }
    }
}

pub struct Leaf {
    pub cert: String,
    pub key: String,
    pub der: Vec<u8>,
}

impl Leaf {
    /// The certificate and key in one PEM, as `reqwest::Identity::from_pem` wants them.
    pub fn identity_pem(&self) -> Vec<u8> {
        format!("{}{}", self.cert, self.key).into_bytes()
    }
}

/// A URI alternative name (a SPIFFE ID, say).
pub fn uri(value: &str) -> SanType {
    SanType::URI(value.try_into().unwrap())
}

/// A DNS alternative name.
pub fn dns(value: &str) -> SanType {
    SanType::DnsName(value.try_into().unwrap())
}

/// A scratch directory for one test's PEM files.
pub struct Dir(PathBuf);

impl Dir {
    pub fn new() -> Dir {
        let dir = std::env::temp_dir().join(format!(
            "eg-tls-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Dir(dir)
    }

    pub fn path(&self) -> &std::path::Path {
        &self.0
    }

    pub fn write(&self, name: &str, contents: &str) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, contents).unwrap();
        path.to_string_lossy().into_owned()
    }

    /// Write `leaf` as `<name>.pem` + `<name>.key`; returns (cert path, key path).
    pub fn pair(&self, name: &str, leaf: &Leaf) -> (String, String) {
        (
            self.write(&format!("{name}.pem"), &leaf.cert),
            self.write(&format!("{name}.key"), &leaf.key),
        )
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Every `CONNECT` a proxy was asked for, with its `Proxy-Authorization`.
pub type Connects = Arc<Mutex<Vec<(String, Option<String>)>>>;

/// A minimal HTTP CONNECT proxy: it records each request line, then splices the tunnel.
pub async fn connect_proxy() -> (SocketAddr, Connects) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connects: Connects = Arc::default();
    let seen = Arc::clone(&connects);
    tokio::spawn(async move {
        loop {
            let (mut client, _) = listener.accept().await.unwrap();
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if client.read(&mut byte).await.unwrap() == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let head = String::from_utf8(head).unwrap();
                let mut lines = head.lines();
                let request = lines.next().unwrap().to_string();
                let auth = lines.find_map(|l| {
                    let (name, value) = l.split_once(':')?;
                    name.eq_ignore_ascii_case("proxy-authorization")
                        .then(|| value.trim().to_string())
                });
                let target = request
                    .split(' ')
                    .nth(1)
                    .unwrap()
                    .replace("localhost", "127.0.0.1");
                seen.lock().unwrap().push((request, auth));
                let mut upstream = TcpStream::connect(target).await.unwrap();
                client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .unwrap();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    (addr, connects)
}
