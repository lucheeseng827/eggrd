//! Every eggrd config this repository ships parses with no key the parser ignores: an example
//! with a misspelt or retired key teaches the mistake to everyone who copies it.

use std::path::{Path, PathBuf};

use edgeguard::config::Config;

/// The shipped configs: files and directories relative to the crate, each `*.toml` under a
/// directory taken when its name starts with `edgeguard` or the directory holds only configs.
/// A path missing from this checkout (the public mirror carries fewer) is skipped.
fn shipped() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    for file in [
        "edgeguard.toml",
        "examples/tls-termination.toml",
        "monitoring/edgeguard.demo.toml",
        "posters/proxy.toml",
    ] {
        out.push(root.join(file));
    }
    for (dir, any_name) in [
        ("deploy/reference", true),
        ("loadtest/configs", true),
        ("llm-bench/proxies/eggrd", true),
        ("workshop", false),
    ] {
        collect(&root.join(dir), any_name, &mut out);
    }
    out.retain(|p| p.exists());
    out.sort();
    out
}

fn collect(dir: &Path, any_name: bool, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, any_name, out);
        } else if path.extension().is_some_and(|e| e == "toml") {
            let name = path.file_name().unwrap().to_string_lossy();
            if any_name || name.starts_with("edgeguard") {
                out.push(path);
            }
        }
    }
}

#[test]
fn every_shipped_config_has_only_keys_the_parser_knows() {
    let files = shipped();
    assert!(
        files.iter().any(|p| p.ends_with("edgeguard.toml")),
        "the annotated example is always here"
    );
    let mut problems = Vec::new();
    for file in &files {
        if let Err(e) = Config::load(file.to_str()) {
            problems.push(format!("{}: does not load: {e:#}", file.display()));
            continue;
        }
        // Asked directly, so that a file the check could not read fails here instead of passing
        // as one with no unknown keys.
        let raw = std::fs::read_to_string(file).unwrap();
        match edgeguard::unknown_keys::check(&raw) {
            Some(keys) => {
                for key in keys {
                    problems.push(format!("{}: {key}", file.display()));
                }
            }
            None => problems.push(format!(
                "{}: the unknown-key check could not read it",
                file.display()
            )),
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
