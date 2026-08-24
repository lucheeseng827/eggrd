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
    for sub in ["generate", "doctor", "init"] {
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
