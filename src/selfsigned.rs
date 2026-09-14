//! Self-signed certificate generation, so TLS works on the first run with no prerequisites.
//!
//! The gap this closes: enabling `[tls]` used to require the operator to *already have* a
//! certificate — from a public CA, an internal CA, or a hand-run `openssl req -x509 …`. For the
//! audience this proxy exists for (an app that reached production without a front door), "go
//! generate a keypair first" is where adoption stops. `[tls] self_signed = true` makes the
//! binary produce its own certificate on first boot and serve HTTPS immediately.
//!
//! **What a self-signed certificate is and is not.** It encrypts the connection, so the six
//! hardening headers, `Secure` cookies and HSTS become meaningful and traffic is no longer
//! readable on the wire. It does *not* prove identity: no CA vouches for it, so a browser shows
//! an interstitial and a strict client rejects it outright. That makes it right for localhost,
//! a private network, a sidecar hop, or a staging box behind a VPN — and wrong for the public
//! internet, where `[tls.acme]` should issue a real certificate instead. [`crate::doctor`] says
//! so out loud when it sees this enabled.
//!
//! **Dependency note.** This uses `rcgen`, which the 0.3.0 notes describe as "dropped". That is
//! true of *direct* use — `instant-acme` 0.8 builds its own key and CSR in `finalize()`, so the
//! ACME path no longer constructs a certificate here. But `instant-acme` depends on `rcgen`
//! itself, so the crate was still compiled on every build; re-declaring it is a direct edge to a
//! node already in the graph. It adds no crate to the build and no transitive dependency.

use std::io::Write;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use tracing::{info, warn};

/// Hostnames used when the operator names none. `localhost` plus both loopback literals covers
/// the case this feature exists for — running the proxy on the machine you are testing from.
pub const DEFAULT_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

/// A generated certificate and its private key, both PEM-encoded.
pub struct SelfSigned {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Build a self-signed certificate covering `hosts`, valid for `days`.
///
/// Every host becomes a subject-alternative name — a DNS SAN, or an IP SAN when it parses as an
/// address, because clients match IP literals against IP SANs and ignore DNS entries for them.
/// The CN is set to the first host for the benefit of old tooling that still reads it, but SANs
/// are what every current client actually checks.
pub fn generate(hosts: &[String], days: u32) -> Result<SelfSigned> {
    anyhow::ensure!(!hosts.is_empty(), "no hosts to put in the certificate");
    anyhow::ensure!(days > 0, "certificate validity must be at least one day");

    let mut params = CertificateParams::default();
    params.subject_alt_names =
        hosts
            .iter()
            .map(|h| match h.parse::<IpAddr>() {
                Ok(ip) => Ok(SanType::IpAddress(ip)),
                // `Ia5String` rejects non-ASCII, which is exactly the validation we want here: a
                // hostname that cannot be encoded is a config error, not something to paper over.
                Err(_) => h.clone().try_into().map(SanType::DnsName).with_context(|| {
                    format!("{h:?} is neither an IP address nor an ASCII hostname")
                }),
            })
            .collect::<Result<Vec<_>>>()?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, hosts[0].clone());
    dn.push(DnType::OrganizationName, "EdgeGuard self-signed");
    params.distinguished_name = dn;

    // Backdate by an hour so a client whose clock runs slightly behind the generating host does
    // not reject a certificate created seconds ago as "not yet valid".
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    // `OffsetDateTime + Duration` panics past the representable range, and `days` comes straight
    // from `--days` / config — so `--days 4294967295` would abort the process instead of telling
    // the operator their number is wrong. User input must not reach a panic path.
    params.not_after = now
        .checked_add(time::Duration::days(i64::from(days)))
        .context("certificate validity exceeds the supported date range")?;

    let key = KeyPair::generate().context("generating the certificate key pair")?;
    let cert = params
        .self_signed(&key)
        .context("self-signing the certificate")?;

    Ok(SelfSigned {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// Is anything present at `path` — including a symlink whose target is missing?
///
/// `Path::exists()` follows symlinks and reports `false` for a dangling one, which makes a
/// "don't clobber what's already there" check quietly wrong: a `cert.pem` symlinked to a target
/// that is temporarily absent reads as "no file", and the rename in [`publish`] then
/// replaces the *symlink itself* with a regular file. `symlink_metadata` does not follow, so the
/// link is seen. Anything other than "not found" — including a permissions error we cannot see
/// through — counts as present, because the safe answer to "is something there?" is yes.
pub fn path_present(path: &str) -> bool {
    !matches!(
        std::fs::symlink_metadata(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound
    )
}

/// Generate a certificate for `hosts` and write it to `cert_path`/`key_path`.
///
/// Creates parent directories as needed. The key is written `0600` on Unix — a private key that
/// lands world-readable is a worse outcome than the missing certificate we set out to fix.
pub fn write_to(
    hosts: &[String],
    days: u32,
    cert_path: &str,
    key_path: &str,
) -> Result<SelfSigned> {
    // The same path for both would write the certificate and then overwrite it with the key,
    // reporting success and leaving a pair TLS can never load. Catch it before touching disk.
    anyhow::ensure!(
        cert_path != key_path,
        "tls.cert_path and tls.key_path must be different files (both are {cert_path:?}); \
         the key would overwrite the certificate"
    );

    let generated = generate(hosts, days)?;

    for path in [cert_path, key_path] {
        if let Some(parent) = Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating directory {}", parent.display()))?;
            }
        }
    }

    // Stage BOTH files first, then rename both into place — in that order, and it matters.
    // Staging one and publishing it before the other is even written means an ordinary I/O
    // error on the second (a full disk, a revoked permission) returns an error having already
    // replaced the first: a new certificate live against the old key, with no crash required.
    // Writing both to temporary files first reduces the exposure to the gap between two
    // renames, which is a syscall apart and needs an actual crash to land in.
    let cert_tmp = stage(cert_path, &generated.cert_pem, false)
        .with_context(|| format!("staging certificate for {cert_path}"))?;
    let key_tmp = match stage(key_path, &generated.key_pem, true) {
        Ok(tmp) => tmp,
        Err(e) => {
            // Nothing live has changed yet, so drop the staged certificate and leave the
            // existing pair exactly as it was.
            let _ = std::fs::remove_file(&cert_tmp);
            return Err(e).with_context(|| format!("staging private key for {key_path}"));
        }
    };

    // Publishing is two renames, and the second can fail on its own — a rename is not only
    // interrupted by a crash (a directory in the way, a read-only mount, EXDEV). So take a
    // backup of the live certificate first and put it back if the key never lands: after any
    // failure here the operator's existing pair is exactly as it was, rather than a new
    // certificate paired with the old key.
    let backup = backup_path(cert_path);
    let had_cert = match std::fs::rename(cert_path, &backup) {
        Ok(()) => true,
        // Nothing to preserve on a first generation.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            let _ = std::fs::remove_file(&cert_tmp);
            let _ = std::fs::remove_file(&key_tmp);
            return Err(e).with_context(|| format!("setting aside the existing {cert_path}"));
        }
    };

    let published = publish(&cert_tmp, cert_path).and_then(|()| publish(&key_tmp, key_path));

    match published {
        Ok(()) => {
            if had_cert {
                let _ = std::fs::remove_file(&backup);
            }
        }
        Err(e) => {
            // Undo the certificate, so the pair on disk stays internally consistent.
            let _ = std::fs::remove_file(cert_path);
            if had_cert {
                let _ = std::fs::rename(&backup, cert_path);
            }
            let _ = std::fs::remove_file(&cert_tmp);
            let _ = std::fs::remove_file(&key_tmp);
            return Err(e).with_context(|| {
                format!("publishing the certificate pair ({cert_path} and {key_path})")
            });
        }
    }

    info!(
        cert = %cert_path,
        key = %key_path,
        hosts = %hosts.join(", "),
        days,
        "generated a self-signed certificate (clients must trust it explicitly; \
         use [tls.acme] for a publicly trusted one)"
    );
    Ok(generated)
}

/// Write `contents` to a temporary file beside `path` and return that temporary path.
///
/// Staging separately from publishing is what lets [`write_to`] get both files onto disk before
/// either live path changes. When `private`, the temp file is created `0600` — and because it is
/// always a *new* file that mode actually applies: `OpenOptionsExt::mode` only sets permissions
/// at creation, so writing straight into an existing `0644` key (which [`ensure`] does when
/// regenerating half a pair) would have left the new key material world-readable. The mode is
/// also set on the open handle, so it holds regardless of umask.
fn stage(path: &str, contents: &str, private: bool) -> Result<String> {
    let tmp = format!("{path}.tmp.{}", std::process::id());
    // A leftover temp file from a killed run must not block every future attempt.
    if Path::new(&tmp).exists() {
        let _ = std::fs::remove_file(&tmp);
    }

    let mut opts = std::fs::OpenOptions::new();
    // `create_new` so we never inherit the contents or the permissions of a stale temp file.
    opts.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let result = (|| -> Result<()> {
        let mut file = opts.open(&tmp)?;
        #[cfg(unix)]
        if private {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(contents.as_bytes())?;
        // Durable before it is published, so a crash cannot leave an empty file at a live path.
        file.sync_all()?;
        Ok(())
    })();

    match result {
        Ok(()) => Ok(tmp),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Where the previous certificate is parked while the new pair is published. Process-scoped so
/// two runs cannot fight over the same name, and beside the original so the rename stays within
/// one filesystem.
fn backup_path(path: &str) -> String {
    format!("{path}.bak.{}", std::process::id())
}

/// Move a file staged by [`stage`] onto its live path. `rename` is atomic, so a reader sees
/// either the complete previous file or the complete new one, never a partial write, and the
/// mode set at staging carries across.
fn publish(tmp: &str, path: &str) -> Result<()> {
    std::fs::rename(tmp, path)?;
    Ok(())
}

/// Ensure a certificate exists at `cert_path`/`key_path`, generating a self-signed one if not.
///
/// Generation is skipped when a certificate is already on disk, so a restart reuses the existing
/// keypair rather than handing every client a new identity to be surprised by. Returns `true` if
/// a certificate was generated on this call.
///
/// **Single-process by design.** The check and the write are not guarded by a cross-process
/// lock, so replicas booting simultaneously against the same writable path can each decide to
/// generate. Each file lands atomically (see [`stage`] and [`publish`]), so nobody reads a half-written
/// one, but the replicas can end up serving different certificates, or one can fail to start on
/// a cert/key pair from two different runs.
///
/// Whether a lock would help depends on the storage, so be precise about it. On **shared**
/// storage a lock spanning the existence check and both writes would work: the first replica
/// generates, the rest find a complete pair and reuse it, and they end up with one identity. On
/// **per-replica** storage it cannot — there is nothing to coordinate through, and each replica
/// necessarily holds a different self-signed identity. Since the second case has no fix at this
/// layer and the first is better solved by not generating at boot at all, the documented answer
/// for either is to generate once with `edgeguard cert` and mount the result read-only.
/// First-boot generation targets the single-instance case it was added for.
pub fn ensure(hosts: &[String], days: u32, cert_path: &str, key_path: &str) -> Result<bool> {
    anyhow::ensure!(
        !cert_path.is_empty() && !key_path.is_empty(),
        "tls.self_signed needs tls.cert_path and tls.key_path set — they are where the \
         generated certificate is written"
    );

    let have_cert = path_present(cert_path);
    let have_key = path_present(key_path);
    if have_cert && have_key {
        info!(cert = %cert_path, "self-signed: reusing the existing certificate");
        return Ok(false);
    }
    // One half present is a broken pair: a cert whose key is gone can't be served, and serving
    // the old key with a new cert would fail the rustls consistency check at load. Say which
    // file is missing and regenerate both, rather than failing with a key-mismatch error later.
    if have_cert != have_key {
        warn!(
            missing = if have_cert { key_path } else { cert_path },
            "self-signed: only half of the certificate pair is present; regenerating both"
        );
    }

    write_to(hosts, days, cert_path, key_path)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn generates_a_loadable_certificate_and_key() {
        let dir = std::env::temp_dir().join(format!("eg-selfsigned-{}", std::process::id()));
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        let cert_s = cert.to_str().unwrap();
        let key_s = key.to_str().unwrap();

        let generated = write_to(&hosts(&DEFAULT_HOSTS), 30, cert_s, key_s);
        // `SelfSigned` intentionally has no `Debug` — it holds a private key, and a derived
        // `Debug` is precisely how one reaches a log line — so report the error, not the value.
        assert!(
            generated.is_ok(),
            "generation failed: {:?}",
            generated.err()
        );

        // The real assertion: rustls accepts the pair. A certificate this crate cannot serve is
        // not a certificate, however well-formed the PEM looks.
        crate::tls::init_crypto();
        assert!(
            crate::tls::load_server_config(cert_s, key_s).is_ok(),
            "rustls rejected the generated certificate/key pair"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn key_file_is_not_world_readable() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = std::env::temp_dir().join(format!("eg-perm-{}", std::process::id()));
            let cert = dir.join("cert.pem");
            let key = dir.join("key.pem");
            write_to(
                &hosts(&["localhost"]),
                1,
                cert.to_str().unwrap(),
                key.to_str().unwrap(),
            )
            .unwrap();
            let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "private key mode was {mode:o}, expected 600");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn ensure_is_idempotent() {
        let dir = std::env::temp_dir().join(format!("eg-ensure-{}", std::process::id()));
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        let (c, k) = (cert.to_str().unwrap(), key.to_str().unwrap());

        assert!(
            ensure(&hosts(&["localhost"]), 1, c, k).unwrap(),
            "first call should generate"
        );
        let first = std::fs::read_to_string(&cert).unwrap();
        assert!(
            !ensure(&hosts(&["localhost"]), 1, c, k).unwrap(),
            "second call should reuse"
        );
        assert_eq!(
            first,
            std::fs::read_to_string(&cert).unwrap(),
            "cert was regenerated"
        );

        // A half-present pair regenerates rather than failing later at load time.
        std::fs::remove_file(&key).unwrap();
        assert!(
            ensure(&hosts(&["localhost"]), 1, c, k).unwrap(),
            "half a pair should regenerate"
        );
        assert_ne!(first, std::fs::read_to_string(&cert).unwrap());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_empty_hosts_and_zero_validity() {
        assert!(generate(&[], 30).is_err());
        assert!(generate(&hosts(&["localhost"]), 0).is_err());
    }

    #[test]
    fn an_unrepresentable_validity_errors_rather_than_panicking() {
        // `--days 4294967295` pushes not_after past what OffsetDateTime can represent. Adding
        // with `+` panics there; user input must produce an error instead.
        assert!(generate(&hosts(&["localhost"]), u32::MAX).is_err());
        assert!(generate(&hosts(&["localhost"]), 365).is_ok());
    }

    #[test]
    fn rejects_the_same_path_for_certificate_and_key() {
        let dir = std::env::temp_dir().join(format!("eg-samepath-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let both = dir.join("pair.pem");
        let both = both.to_str().unwrap();
        // Otherwise the key overwrites the certificate and the command reports success.
        assert!(write_to(&hosts(&["localhost"]), 1, both, both).is_err());
        assert!(
            !Path::new(both).exists(),
            "nothing should have been written"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn regenerating_over_an_existing_world_readable_key_tightens_it() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("eg-remode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        let (c, k) = (cert.to_str().unwrap(), key.to_str().unwrap());

        // A key left behind at 0644 — by an older build, a config-management run, or a restore.
        std::fs::write(&key, "stale").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();

        // Half a pair, so `ensure` regenerates and writes over that existing file. `mode()` on
        // OpenOptions only applies when it CREATES the file, so writing in place would have left
        // the new key material readable by every other user on the box.
        assert!(ensure(&hosts(&["localhost"]), 1, c, k).unwrap());
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "regenerated key mode was {mode:o}, expected 600"
        );
        assert_ne!(std::fs::read_to_string(&key).unwrap(), "stale");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_counts_as_present() {
        let dir = std::env::temp_dir().join(format!("eg-symlink-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let link = dir.join("cert.pem");
        std::os::unix::fs::symlink(dir.join("nowhere.pem"), &link).unwrap();

        // `Path::exists()` follows the link, finds nothing, and says "absent" — which would let
        // a no-force `edgeguard cert` replace the operator's symlink with a regular file.
        assert!(
            !Path::new(&link).exists(),
            "precondition: exists() is fooled by this"
        );
        assert!(
            path_present(link.to_str().unwrap()),
            "the link itself is there"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_key_write_leaves_the_existing_pair_untouched() {
        // A staging failure on the key must not publish the new certificate: an ordinary I/O
        // error (full disk, revoked permission) would otherwise leave a new cert live against
        // the old key, with no crash involved. A directory in place of the key file makes the
        // open fail the same way.
        let dir = std::env::temp_dir().join(format!("eg-keyfail-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("cert.pem");
        std::fs::write(&cert, "OLD CERT").unwrap();
        let key = dir.join("key.pem");
        std::fs::create_dir_all(&key).unwrap(); // a directory: staging beside it still fails to rename

        let before = std::fs::read_to_string(&cert).unwrap();
        let r = write_to(
            &hosts(&["localhost"]),
            1,
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
        );
        assert!(r.is_err(), "writing over a directory should fail");
        assert_eq!(
            std::fs::read_to_string(&cert).unwrap(),
            before,
            "the live certificate was replaced despite the key write failing"
        );

        let strays: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(strays.is_empty(), "staging files left behind: {strays:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn leaves_no_temporary_files_behind() {
        let dir = std::env::temp_dir().join(format!("eg-tmp-{}", std::process::id()));
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        write_to(
            &hosts(&["localhost"]),
            1,
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
        )
        .unwrap();
        let strays: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(strays.is_empty(), "staging files left behind: {strays:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_requires_paths() {
        assert!(ensure(&hosts(&["localhost"]), 1, "", "").is_err());
    }

    #[test]
    fn ip_hosts_become_ip_sans_not_dns_names() {
        let generated = generate(&hosts(&["localhost", "127.0.0.1"]), 1).unwrap();
        assert!(generated
            .cert_pem
            .starts_with("-----BEGIN CERTIFICATE-----"));
        // Parse back through rustls-pemfile to confirm it is a single well-formed leaf.
        let mut reader = std::io::BufReader::new(generated.cert_pem.as_bytes());
        let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(certs.len(), 1);
    }
}
