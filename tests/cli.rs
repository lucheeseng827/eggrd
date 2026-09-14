//! CLI surface tests: they run the real binary, because the bug these cover was invisible to
//! every in-process test.
//!
//! `edgeguard --version` used to start a proxy. The argument parser ended in `_ => {}`, so any
//! token it did not recognise was discarded in silence — a typo like `--wrpa "npm start"` came up
//! as a healthy-looking but unwrapped, unconfigured proxy. Nothing in the suite executed the
//! binary, so nothing could see it.
//!
//! Only paths that terminate are exercised here. The bare serve path deliberately blocks
//! forever, so a test that invoked it would hang rather than fail.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_edgeguard"))
}

#[test]
fn version_flag_prints_the_crate_version_and_exits_zero() {
    for flag in ["--version", "-V"] {
        let out = bin().arg(flag).output().expect("failed to run edgeguard");
        assert!(
            out.status.success(),
            "{flag} should exit 0, got {:?}",
            out.status
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            stdout.trim(),
            format!("edgeguard {}", env!("CARGO_PKG_VERSION")),
            "{flag} printed {stdout:?}"
        );
    }
}

#[test]
fn version_is_reported_not_swallowed_into_serving() {
    // The regression in one line: this must terminate. Before the fix it bound a port instead.
    let out = bin()
        .arg("--version")
        .output()
        .expect("failed to run edgeguard");
    assert!(out.status.success());
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("listening"),
        "--version started a listener instead of printing a version"
    );
}

#[test]
fn help_flag_exits_zero_and_documents_version() {
    let out = bin()
        .arg("--help")
        .output()
        .expect("failed to run edgeguard");
    assert!(out.status.success(), "--help should exit 0");
    // Usage goes to stderr; check both so the test does not encode which.
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("--version"),
        "help does not mention --version:\n{text}"
    );
}

#[test]
fn unknown_argument_on_the_serve_path_is_rejected() {
    // The exact shape of the original bug: a misspelt --wrap must not start an unwrapped proxy.
    let out = bin()
        .args(["--wrpa", "npm start"])
        .output()
        .expect("failed to run edgeguard");
    assert!(
        !out.status.success(),
        "a misspelt flag must fail rather than start a proxy"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--wrpa"),
        "the error should name the offending argument:\n{err}"
    );
}

#[test]
fn unknown_arguments_are_rejected_by_every_subcommand() {
    // doctor and init already rejected these; generate and the serve path did not. Covering all
    // four keeps them from drifting apart again.
    for (args, label) in [
        (vec!["generate", "--targt", "vercel"], "generate"),
        (vec!["doctor", "--confg", "x.toml"], "doctor"),
        (vec!["init", "--forse"], "init"),
        (vec!["cert", "--hosts", "a"], "cert"),
    ] {
        let out = bin().args(&args).output().expect("failed to run edgeguard");
        assert!(
            !out.status.success(),
            "`edgeguard {label}` accepted an unknown flag instead of failing"
        );
    }
}

#[test]
fn version_works_for_subcommands_too() {
    for sub in ["generate", "doctor", "init", "cert"] {
        let out = bin()
            .args([sub, "--version"])
            .output()
            .expect("failed to run edgeguard");
        assert!(out.status.success(), "`{sub} --version` should exit 0");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            format!("edgeguard {}", env!("CARGO_PKG_VERSION"))
        );
    }
}

/// A scratch directory unique to this test, removed on drop so a failure doesn't leak files.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let dir = std::env::temp_dir().join(format!(
            "eg-cli-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("creating the scratch directory");
        TempDir(dir)
    }
    fn path(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().into_owned()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn cert_writes_a_usable_pair_and_says_what_it_is_not() {
    let dir = TempDir::new("cert");
    let (cert, key) = (dir.path("cert.pem"), dir.path("key.pem"));

    let out = bin()
        .args([
            "cert",
            "--host",
            "app.example.com,127.0.0.1",
            "--days",
            "30",
            "--cert-out",
            &cert,
            "--key-out",
            &key,
        ])
        .output()
        .expect("failed to run edgeguard");
    assert!(out.status.success(), "`edgeguard cert` failed: {out:?}");

    let pem = std::fs::read_to_string(&cert).expect("certificate written");
    assert!(
        pem.starts_with("-----BEGIN CERTIFICATE-----"),
        "not a PEM chain"
    );
    assert!(
        std::fs::read_to_string(&key)
            .expect("key written")
            .contains("PRIVATE KEY"),
        "not a PEM private key"
    );

    // The warning is the point: a user who does not know what self-signed means must not be left
    // believing they now have a publicly trusted certificate.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("self-signed") && stderr.contains("proves no identity"),
        "cert did not say what it is not: {stderr}"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "private key mode was {mode:o}, expected 600");
    }
}

#[test]
fn cert_refuses_to_clobber_without_force() {
    let dir = TempDir::new("clobber");
    let (cert, key) = (dir.path("cert.pem"), dir.path("key.pem"));
    let args = ["cert", "--cert-out", &cert, "--key-out", &key];

    assert!(
        bin().args(args).output().unwrap().status.success(),
        "first write should succeed"
    );
    let first = std::fs::read_to_string(&cert).unwrap();

    // Overwriting is not recoverable: the previous key is gone and anything that trusted the old
    // certificate breaks. So it must take an explicit --force.
    assert!(
        !bin().args(args).output().unwrap().status.success(),
        "a second `cert` without --force should fail"
    );
    assert_eq!(
        first,
        std::fs::read_to_string(&cert).unwrap(),
        "the file was overwritten anyway"
    );

    assert!(
        bin()
            .args(args)
            .arg("--force")
            .output()
            .unwrap()
            .status
            .success(),
        "--force should overwrite"
    );
    assert_ne!(
        first,
        std::fs::read_to_string(&cert).unwrap(),
        "--force did not replace it"
    );
}

#[test]
fn cert_rejects_a_non_numeric_days_value() {
    let dir = TempDir::new("days");
    let out = bin()
        .args([
            "cert",
            "--days",
            "ninety",
            "--cert-out",
            &dir.path("c.pem"),
            "--key-out",
            &dir.path("k.pem"),
        ])
        .output()
        .expect("failed to run edgeguard");
    assert!(
        !out.status.success(),
        "`--days ninety` should be rejected, not defaulted"
    );
}

#[test]
fn doctor_errors_when_tls_is_on_with_no_certificate_source() {
    let dir = TempDir::new("doctor");
    let cfg = dir.path("edgeguard.toml");
    // TLS on, no cert paths, no ACME, no self_signed: the proxy cannot start, so this has to be
    // an error exit and not a warning the operator scrolls past.
    std::fs::write(&cfg, "[tls]\nenabled = true\n").unwrap();

    let out = bin()
        .args(["doctor", "--config", &cfg])
        .output()
        .expect("failed to run edgeguard");
    assert!(
        !out.status.success(),
        "doctor should exit non-zero on a config that cannot start"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        (stderr.clone() + stdout).contains("no certificate to serve"),
        "doctor did not name the problem: {stderr}"
    );
}
