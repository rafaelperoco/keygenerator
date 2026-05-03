//! Generate an auditable password from Rust by shelling out to
//! secretgenerator. The CLI prints a stable JSON envelope (schema v1).
//!
//! This snippet pins the schema version with `--require-schema-version=1`
//! so a future incompatible change fails loudly instead of silently
//! changing field shapes.
//!
//! Install once:
//!     brew install rafaelperoco/tap/secretgenerator
//!     # or: npm install -g @secretgenerator/cli

use std::process::Command;

use serde::Deserialize;

#[derive(Deserialize)]
struct CrackTimeEstimate {
    profile_id: String,
    human_readable: String,
}

#[derive(Deserialize)]
struct Output {
    password: String,
    entropy_bits: f64,
    crack_time_estimates: Vec<CrackTimeEstimate>,
}

fn generate_password(length: u32) -> std::io::Result<Output> {
    let out = Command::new("secretgenerator")
        .args([
            "password",
            "--json",
            "--require-schema-version=1",
            "--show-crack-time",
            "--length",
            &length.to_string(),
            "--charset",
            "alphanum-symbols-v1",
        ])
        .output()?;
    if !out.status.success() {
        return Err(std::io::Error::other(String::from_utf8_lossy(&out.stderr).to_string()));
    }
    serde_json::from_slice(&out.stdout).map_err(std::io::Error::other)
}

fn main() -> std::io::Result<()> {
    let r = generate_password(24)?;
    println!("password: {}", r.password);
    println!("entropy:  {:.1} bits", r.entropy_bits);
    if let Some(ns) = r
        .crack_time_estimates
        .iter()
        .find(|e| e.profile_id == "nation-state-v1")
    {
        println!("crack:    {} (nation-state)", ns.human_readable);
    }
    Ok(())
}
