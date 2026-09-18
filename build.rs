//! Embed the commit that produced this binary.
//!
//! Published capacity envelopes must name that commit, not whatever `git
//! rev-parse HEAD` returns in the directory where the soak happened to run.
//! A dirty tree is marked `-dirty` so it cannot be published as a clean sha.
//!
//! No `cargo:rerun-if-changed` lines: emitting any of them would stop Cargo
//! from rerunning this script on package-file edits, and a dirty edit would
//! keep a clean sha.

use std::process::Command;

fn main() {
    let sha = command_stdout(&["rev-parse", "--verify", "HEAD"]);
    let dirty = command_stdout(&["status", "--porcelain"]);
    let embedded = match (sha, dirty) {
        (Some(sha), Some(status)) if full_lower_sha(&sha) && status.is_empty() => sha,
        (Some(sha), Some(_)) if full_lower_sha(&sha) => format!("{sha}-dirty"),
        _ => "unknown".to_string(),
    };
    println!("cargo:rustc-env=A3S_GATEWAY_GIT_SHA={embedded}");
}

fn command_stdout(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|text| text.trim().to_string())
}

fn full_lower_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
