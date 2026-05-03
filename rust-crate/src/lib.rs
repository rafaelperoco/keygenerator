//! Rust bindings for the auditable
//! [`secretgenerator`](https://github.com/rafaelperoco/secretgenerator)
//! CLI.
//!
//! Each function in this crate corresponds to a CLI subcommand. The
//! function shells out to `secretgenerator`, parses the schema-v1 JSON
//! envelope, and returns a typed [`Output`]. When the CLI exits
//! non-zero a [`Error::Cli`] is returned with the structured error
//! envelope attached so callers can branch on stable error codes
//! (`E_ENTROPY_TOO_LOW`, `E_CHARSET_EMPTY`, `E_CLASS_IMPOSSIBLE`, etc.)
//! rather than parsing free-form messages.
//!
//! # Install the binary
//!
//! ```sh
//! npm install -g @secretgenerator/cli
//! # or: brew install rafaelperoco/tap/secretgenerator
//! # or: go install github.com/rafaelperoco/secretgenerator/cmd/secretgenerator@latest
//! ```
//!
//! # Quick start
//!
//! ```no_run
//! use secretgenerator::{password, PasswordOptions};
//!
//! let out = password(
//!     PasswordOptions::default()
//!         .length(24)
//!         .charset("alphanum-symbols-v1")
//!         .require_classes("lower,upper,digit,symbol"),
//! )?;
//! println!("{} ({} bits)", out.password, out.entropy_bits);
//! # Ok::<_, secretgenerator::Error>(())
//! ```

#![forbid(unsafe_code)]

use std::io::Write;
use std::process::{Command, Stdio};

use serde::Deserialize;
use thiserror::Error;

/// The schema version this crate is pinned to.
pub const SCHEMA_VERSION: i64 = 1;

/// Schema-v1 envelope returned by every generation subcommand.
#[derive(Debug, Clone, Deserialize)]
pub struct Output {
    pub schema_version: i64,
    pub password: String,
    pub length: i64,
    pub charset_id: String,
    pub charset_size: i64,
    pub entropy_bits: f64,
    pub algorithm: String,
    pub subcommand: String,
    pub version: String,
    pub commit: String,
    pub build_date: String,
    pub request_id: String,
    pub timestamp_utc: String,
    #[serde(default)]
    pub crack_time_estimates: Vec<CrackTimeEstimate>,
}

/// One attacker scenario applied to a credential's entropy.
#[derive(Debug, Clone, Deserialize)]
pub struct CrackTimeEstimate {
    pub profile_id: String,
    pub description: String,
    pub seconds: f64,
    pub human_readable: String,
}

/// Structured error envelope emitted by the CLI when a subcommand
/// fails. The `code` field is the part of the contract you are meant
/// to branch on.
#[derive(Debug, Clone, Deserialize)]
pub struct ErrorEnvelope {
    pub error: ErrorDetail,
    #[serde(default)]
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub hint: Option<String>,
}

/// Detailed CLI failure payload, boxed in [`Error::Cli`] so the
/// enum stays small.
#[derive(Debug)]
pub struct CliFailure {
    pub code: i32,
    pub message: String,
    pub envelope: Option<ErrorEnvelope>,
}

/// Error type returned by every function in this crate.
#[derive(Error, Debug)]
pub enum Error {
    #[error("`secretgenerator` not on PATH: install via brew/npm/go")]
    BinaryNotFound,
    #[error("io error spawning secretgenerator: {0}")]
    Io(#[from] std::io::Error),
    #[error("could not parse JSON from CLI: {0}")]
    Json(#[from] serde_json::Error),
    #[error("secretgenerator exited {}: {}", .0.code, .0.message)]
    Cli(Box<CliFailure>),
}

impl Error {
    /// Stable error code from the envelope (e.g. `E_ENTROPY_TOO_LOW`).
    /// `None` when the failure was not a structured CLI error.
    pub fn cli_code(&self) -> Option<&str> {
        match self {
            Error::Cli(f) => f.envelope.as_ref().map(|e| e.error.code.as_str()),
            _ => None,
        }
    }
}

fn run(args: &[String], stdin: Option<&str>) -> Result<Output, Error> {
    let mut cmd = Command::new("secretgenerator");
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::BinaryNotFound
        } else {
            Error::Io(e)
        }
    })?;
    if let (Some(input), Some(mut sink)) = (stdin, child.stdin.take()) {
        sink.write_all(input.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let envelope = serde_json::from_str::<ErrorEnvelope>(&stderr)
            .or_else(|_| serde_json::from_str::<ErrorEnvelope>(&stdout))
            .ok();
        return Err(Error::Cli(Box::new(CliFailure {
            code: out.status.code().unwrap_or(-1),
            message: if !stderr.is_empty() { stderr } else { stdout },
            envelope,
        })));
    }
    Ok(serde_json::from_slice(&out.stdout)?)
}

fn run_estimates(args: &[String], stdin: Option<&str>) -> Result<EstimateOutput, Error> {
    // entropy is the only subcommand that returns an envelope without
    // a populated `password`/`length`/etc. — we deserialize into a
    // partial struct.
    let mut cmd = Command::new("secretgenerator");
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::BinaryNotFound
        } else {
            Error::Io(e)
        }
    })?;
    if let (Some(input), Some(mut sink)) = (stdin, child.stdin.take()) {
        sink.write_all(input.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        return Err(Error::Cli(Box::new(CliFailure {
            code: out.status.code().unwrap_or(-1),
            message: stderr,
            envelope: None,
        })));
    }
    Ok(serde_json::from_slice(&out.stdout)?)
}

/// Schema-v1 envelope for the `entropy` subcommand. The CLI does not
/// echo the password it analyzes, so [`Output`] would not deserialize
/// cleanly — this struct keeps just the fields the subcommand
/// populates.
#[derive(Debug, Clone, Deserialize)]
pub struct EstimateOutput {
    pub schema_version: i64,
    pub entropy_bits: f64,
    #[serde(default)]
    pub crack_time_estimates: Vec<CrackTimeEstimate>,
    pub request_id: String,
}

fn common_args(
    require_schema: Option<i64>,
    show_crack_time: bool,
    audit_log: Option<&str>,
) -> Vec<String> {
    let mut a = vec!["--json".to_string()];
    if let Some(v) = require_schema {
        a.push(format!("--require-schema-version={v}"));
    }
    if show_crack_time {
        a.push("--show-crack-time".to_string());
    }
    if let Some(p) = audit_log {
        a.push("--audit-log".to_string());
        a.push(p.to_string());
    }
    a
}

// ----- password ------------------------------------------------------

/// Builder for [`password`].
#[derive(Debug, Clone)]
pub struct PasswordOptions {
    length: u32,
    charset: String,
    require_classes: Option<String>,
    exclude: Option<String>,
    min_entropy_bits: Option<f64>,
    allow_weak: bool,
    show_crack_time: bool,
    audit_log: Option<String>,
    require_schema_version: Option<i64>,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            charset: "alphanum-v1".to_string(),
            require_classes: None,
            exclude: None,
            min_entropy_bits: None,
            allow_weak: false,
            show_crack_time: true,
            audit_log: None,
            require_schema_version: Some(SCHEMA_VERSION),
        }
    }
}

impl PasswordOptions {
    pub fn length(mut self, n: u32) -> Self {
        self.length = n;
        self
    }
    pub fn charset(mut self, c: impl Into<String>) -> Self {
        self.charset = c.into();
        self
    }
    pub fn require_classes(mut self, c: impl Into<String>) -> Self {
        self.require_classes = Some(c.into());
        self
    }
    pub fn exclude(mut self, e: impl Into<String>) -> Self {
        self.exclude = Some(e.into());
        self
    }
    pub fn min_entropy_bits(mut self, b: f64) -> Self {
        self.min_entropy_bits = Some(b);
        self
    }
    pub fn allow_weak(mut self, a: bool) -> Self {
        self.allow_weak = a;
        self
    }
    pub fn show_crack_time(mut self, s: bool) -> Self {
        self.show_crack_time = s;
        self
    }
    pub fn audit_log(mut self, p: impl Into<String>) -> Self {
        self.audit_log = Some(p.into());
        self
    }
}

/// Generate a random password.
pub fn password(opts: PasswordOptions) -> Result<Output, Error> {
    let mut args = common_args(
        opts.require_schema_version,
        opts.show_crack_time,
        opts.audit_log.as_deref(),
    );
    args.insert(0, "password".to_string());
    args.push("--length".to_string());
    args.push(opts.length.to_string());
    args.push("--charset".to_string());
    args.push(opts.charset);
    if let Some(c) = opts.require_classes {
        args.push("--require-classes".to_string());
        args.push(c);
    }
    if let Some(e) = opts.exclude {
        args.push("--exclude".to_string());
        args.push(e);
    }
    if let Some(b) = opts.min_entropy_bits {
        args.push("--min-entropy-bits".to_string());
        args.push(b.to_string());
    }
    if opts.allow_weak {
        args.push("--allow-weak".to_string());
    }
    run(&args, None)
}

// ----- passphrase ----------------------------------------------------

#[derive(Debug, Clone)]
pub struct PassphraseOptions {
    words: u32,
    separator: String,
    capitalize: bool,
    digit_suffix: bool,
    min_entropy_bits: Option<f64>,
    allow_weak: bool,
    show_crack_time: bool,
    audit_log: Option<String>,
    require_schema_version: Option<i64>,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 8,
            separator: "-".to_string(),
            capitalize: false,
            digit_suffix: false,
            min_entropy_bits: None,
            allow_weak: false,
            show_crack_time: true,
            audit_log: None,
            require_schema_version: Some(SCHEMA_VERSION),
        }
    }
}

impl PassphraseOptions {
    pub fn words(mut self, n: u32) -> Self {
        self.words = n;
        self
    }
    pub fn separator(mut self, s: impl Into<String>) -> Self {
        self.separator = s.into();
        self
    }
    pub fn capitalize(mut self, c: bool) -> Self {
        self.capitalize = c;
        self
    }
    pub fn digit_suffix(mut self, d: bool) -> Self {
        self.digit_suffix = d;
        self
    }
    pub fn min_entropy_bits(mut self, b: f64) -> Self {
        self.min_entropy_bits = Some(b);
        self
    }
    pub fn allow_weak(mut self, a: bool) -> Self {
        self.allow_weak = a;
        self
    }
    pub fn show_crack_time(mut self, s: bool) -> Self {
        self.show_crack_time = s;
        self
    }
}

pub fn passphrase(opts: PassphraseOptions) -> Result<Output, Error> {
    let mut args = common_args(
        opts.require_schema_version,
        opts.show_crack_time,
        opts.audit_log.as_deref(),
    );
    args.insert(0, "passphrase".to_string());
    args.push("--words".to_string());
    args.push(opts.words.to_string());
    args.push("--separator".to_string());
    args.push(opts.separator);
    if opts.capitalize {
        args.push("--capitalize".to_string());
    }
    if opts.digit_suffix {
        args.push("--digit-suffix".to_string());
    }
    if let Some(b) = opts.min_entropy_bits {
        args.push("--min-entropy-bits".to_string());
        args.push(b.to_string());
    }
    if opts.allow_weak {
        args.push("--allow-weak".to_string());
    }
    run(&args, None)
}

// ----- secret --------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SecretOptions {
    bytes: u32,
    prefix: Option<String>,
    min_entropy_bits: Option<f64>,
    allow_weak: bool,
    show_crack_time: bool,
    audit_log: Option<String>,
    require_schema_version: Option<i64>,
}

impl Default for SecretOptions {
    fn default() -> Self {
        Self {
            bytes: 32,
            prefix: None,
            min_entropy_bits: None,
            allow_weak: false,
            show_crack_time: true,
            audit_log: None,
            require_schema_version: Some(SCHEMA_VERSION),
        }
    }
}

impl SecretOptions {
    pub fn bytes(mut self, n: u32) -> Self {
        self.bytes = n;
        self
    }
    pub fn prefix(mut self, p: impl Into<String>) -> Self {
        self.prefix = Some(p.into());
        self
    }
}

pub fn secret(opts: SecretOptions) -> Result<Output, Error> {
    let mut args = common_args(
        opts.require_schema_version,
        opts.show_crack_time,
        opts.audit_log.as_deref(),
    );
    args.insert(0, "secret".to_string());
    args.push("--bytes".to_string());
    args.push(opts.bytes.to_string());
    if let Some(p) = opts.prefix {
        args.push("--prefix".to_string());
        args.push(p);
    }
    if let Some(b) = opts.min_entropy_bits {
        args.push("--min-entropy-bits".to_string());
        args.push(b.to_string());
    }
    if opts.allow_weak {
        args.push("--allow-weak".to_string());
    }
    run(&args, None)
}

// ----- api-key -------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ApiKeyOptions {
    length: u32,
    prefix: String,
    separator: String,
    min_entropy_bits: Option<f64>,
    allow_weak: bool,
    show_crack_time: bool,
    audit_log: Option<String>,
    require_schema_version: Option<i64>,
}

impl Default for ApiKeyOptions {
    fn default() -> Self {
        Self {
            length: 32,
            prefix: "sk".to_string(),
            separator: "_".to_string(),
            min_entropy_bits: None,
            allow_weak: false,
            show_crack_time: true,
            audit_log: None,
            require_schema_version: Some(SCHEMA_VERSION),
        }
    }
}

impl ApiKeyOptions {
    pub fn length(mut self, n: u32) -> Self {
        self.length = n;
        self
    }
    pub fn prefix(mut self, p: impl Into<String>) -> Self {
        self.prefix = p.into();
        self
    }
    pub fn separator(mut self, s: impl Into<String>) -> Self {
        self.separator = s.into();
        self
    }
}

pub fn api_key(opts: ApiKeyOptions) -> Result<Output, Error> {
    let mut args = common_args(
        opts.require_schema_version,
        opts.show_crack_time,
        opts.audit_log.as_deref(),
    );
    args.insert(0, "api-key".to_string());
    args.push("--length".to_string());
    args.push(opts.length.to_string());
    args.push("--prefix".to_string());
    args.push(opts.prefix);
    args.push("--separator".to_string());
    args.push(opts.separator);
    if let Some(b) = opts.min_entropy_bits {
        args.push("--min-entropy-bits".to_string());
        args.push(b.to_string());
    }
    if opts.allow_weak {
        args.push("--allow-weak".to_string());
    }
    run(&args, None)
}

// ----- pin -----------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PinOptions {
    digits: u32,
    acknowledge_low_entropy: bool,
    allow_weak_pattern: bool,
    show_crack_time: bool,
    audit_log: Option<String>,
    require_schema_version: Option<i64>,
}

impl Default for PinOptions {
    fn default() -> Self {
        Self {
            digits: 6,
            acknowledge_low_entropy: true,
            allow_weak_pattern: false,
            show_crack_time: false,
            audit_log: None,
            require_schema_version: Some(SCHEMA_VERSION),
        }
    }
}

impl PinOptions {
    pub fn digits(mut self, n: u32) -> Self {
        self.digits = n;
        self
    }
    pub fn acknowledge_low_entropy(mut self, a: bool) -> Self {
        self.acknowledge_low_entropy = a;
        self
    }
    pub fn allow_weak_pattern(mut self, a: bool) -> Self {
        self.allow_weak_pattern = a;
        self
    }
}

pub fn pin(opts: PinOptions) -> Result<Output, Error> {
    let mut args = common_args(
        opts.require_schema_version,
        opts.show_crack_time,
        opts.audit_log.as_deref(),
    );
    args.insert(0, "pin".to_string());
    args.push("--digits".to_string());
    args.push(opts.digits.to_string());
    if opts.acknowledge_low_entropy {
        args.push("--acknowledge-low-entropy".to_string());
    }
    if opts.allow_weak_pattern {
        args.push("--allow-weak-pattern".to_string());
    }
    run(&args, None)
}

// ----- entropy -------------------------------------------------------

/// Estimate the entropy and crack time of an existing string. The
/// candidate is piped on stdin so it never appears in argv.
pub fn entropy(candidate: &str) -> Result<EstimateOutput, Error> {
    let args = vec![
        "entropy".to_string(),
        "--json".to_string(),
        format!("--require-schema-version={SCHEMA_VERSION}"),
        "--show-crack-time".to_string(),
    ];
    run_estimates(&args, Some(candidate))
}
