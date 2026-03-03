//! CLI entry point for the `cargo code-sign` subcommand.
//!
//! General environment variables:
//! - `CARGO_CODE_SIGN_TEST_BINARIES`: set to `1` to also sign test binaries.
//!
//! Runs `cargo build --message-format=json` with the user's arguments, parses the artifact messages
//! to find produced binaries and cdylibs, then signs each one.

use std::ffi::OsString;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::{exit, Command, Stdio};
use std::{env, io::BufReader};

use cargo_metadata::{Artifact, Message};

use native_code_sign as sign;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    match std::env::args_os().nth(1) {
        Some(arg) if arg == "code-sign" => code_sign(),
        _ => shoo(),
    }
}

fn shoo() -> ! {
    eprintln!("'cargo code-sign' should be invoked through Cargo, e.g.:\n  cargo code-sign build --release");
    exit(1);
}

/// Entry point for `cargo code-sign`.
///
/// Runs the subcommand and exits the process with an appropriate exit code.
fn code_sign() {
    match run() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: cargo-code-sign: {e}");
            std::process::exit(1);
        }
    }
}

/// Errors that can occur during `cargo code-sign`.
#[derive(Debug, thiserror::Error)]
enum RunError {
    #[error("invalid signing configuration for target {target}: {source}")]
    Config {
        target: String,
        #[source]
        source: sign::SignConfigError,
    },
    #[error("failed to invoke cargo: {0}")]
    CargoSpawn(#[source] std::io::Error),
    #[error("failed to parse cargo message stream: {0}")]
    CargoMessageStream(#[source] std::io::Error),
    #[error("failed to wait for cargo: {0}")]
    CargoWait(#[source] std::io::Error),
    #[error("cargo exited with {0}")]
    CargoFailed(std::process::ExitStatus),
    #[error("failed to invoke rustc: {0}")]
    RustcQuery(#[source] std::io::Error),
    #[error("failed to parse host target triple from rustc output")]
    RustcParse,
    #[error("failed to prepare signing session: {0}")]
    SigningSessionSetup(#[source] sign::SignError),
    #[error("{0} artifact(s) failed to sign")]
    MultipleSignFailures(usize),
    #[error("invalid value `{value}` for environment variable `{name}`: expected a boolish value")]
    InvalidEnvironmentVariable { name: String, value: String },
    #[error(
        "incompatible `--message-format={0}`: cargo-code-sign requires JSON output to detect artifacts"
    )]
    IncompatibleMessageFormat(String),
}

fn run() -> Result<(), RunError> {
    // Collect user args after `cargo code-sign` (e.g. `build --release`).
    let args: Vec<_> = env::args_os().skip(2).collect();

    let cargo = cargo();

    // Determine the target triple for signer selection.
    //
    // Look for `--target` in user args, otherwise query rustc for the host triple.
    let target = match target_from_args(&args) {
        Some(t) => t,
        None => rustc_host_target_triple()?,
    };

    let signer = match sign::Signer::from_env(&target) {
        Ok(Some(s)) => {
            tracing::info!("signing credentials configured for target {target}");
            Some(s)
        }
        Ok(None) => {
            tracing::info!("no signing credentials configured for target {target}");
            None
        }
        Err(source) => {
            return Err(RunError::Config { target, source });
        }
    };

    // Check for an existing `--message-format`. If the caller provided one (e.g. maturin passes
    // `--message-format=json-render-diagnostics`), it must be a JSON variant so we can parse
    // artifact messages. Non-JSON formats are incompatible and we fail immediately.
    let forward_json = match message_format_from_args(&args) {
        Some(fmt) if fmt.starts_with("json") => true,
        Some(fmt) => return Err(RunError::IncompatibleMessageFormat(fmt)),
        None => false,
    };

    let mut cmd = Command::new(&cargo);

    if forward_json {
        // The caller's --message-format is already in `args` and is JSON-compatible, so just
        // pass everything through.
        cmd.args(&args);
    } else {
        // Use `json-render-diagnostics` so cargo renders compiler diagnostics as colored text on
        // stderr while still emitting JSON artifact messages on stdout for us to parse.
        //
        // Insert before any `--` separator so it's treated as a cargo flag, not a rustc flag —
        // e.g. when maturin calls `cargo rustc ... -- <rustc-flags>`, naively appending would
        // place it after `--`.
        if let Some(pos) = args.iter().position(|a| a == "--") {
            cmd.args(&args[..pos]);
            cmd.arg("--message-format=json-render-diagnostics");
            cmd.args(&args[pos..]);
        } else {
            cmd.args(&args);
            cmd.arg("--message-format=json-render-diagnostics");
        }
    }

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::inherit());
    let mut child = cmd.spawn().map_err(RunError::CargoSpawn)?;
    let stdout = child.stdout.take().expect("stdout was piped");
    let reader = BufReader::new(stdout);

    // Allow opt-in to signing test binaries.
    let sign_test_binaries = parse_boolish_env("CARGO_CODE_SIGN_TEST_BINARIES")?.unwrap_or(false);

    let mut artifacts_to_sign: Vec<PathBuf> = Vec::new();

    // We always parse cargo's JSON stdout for artifact detection. When the caller originally
    // passed `--message-format` (e.g. maturin), we also forward every line verbatim so they
    // get the JSON stream they expect.
    let mut stdout = forward_json.then(|| std::io::stdout().lock());
    for line in reader.lines() {
        let line = line.map_err(RunError::CargoMessageStream)?;

        if let Some(out) = stdout.as_mut() {
            let _ = writeln!(out, "{line}");
        }

        let Ok(Message::CompilerArtifact(artifact)) = serde_json::from_str::<Message>(&line) else {
            continue;
        };
        artifacts_to_sign.extend(signable_paths(&artifact, sign_test_binaries));
    }

    let status = child.wait().map_err(RunError::CargoWait)?;
    if !status.success() {
        return Err(RunError::CargoFailed(status));
    }

    // Sign all collected artifacts if a signer is configured.
    let Some(signer) = signer else {
        tracing::warn!("no signer configured, skipping signing");
        return Ok(());
    };

    if artifacts_to_sign.is_empty() {
        tracing::debug!("no signable artifacts produced");
        return Ok(());
    }

    let session = signer
        .begin_session()
        .map_err(RunError::SigningSessionSetup)?;

    tracing::info!("signing {} artifact(s)", artifacts_to_sign.len());
    let mut failures = 0;
    for path in &artifacts_to_sign {
        match session.sign(path) {
            Ok(()) => {
                tracing::info!("signed {}", path.display());
            }
            Err(source) => {
                eprintln!(
                    "error: cargo-code-sign: failed to sign {}: {source}",
                    path.display()
                );
                failures += 1;
            }
        }
    }

    if failures > 0 {
        return Err(RunError::MultipleSignFailures(failures));
    }

    Ok(())
}

/// Extract signable file paths from a cargo artifact message.
///
/// Only `bin` and `cdylib` targets produce distributable artifacts worth signing. Other kinds
/// (build scripts, proc-macros, benches) are internal to the build and should not be signed.
fn signable_paths(artifact: &Artifact, sign_test_binaries: bool) -> Vec<PathBuf> {
    if artifact.target.is_bin() || (artifact.target.is_test() && sign_test_binaries) {
        if let Some(exe) = &artifact.executable {
            return vec![PathBuf::from(exe.clone())];
        }
    } else if artifact.target.is_cdylib() {
        // Filter to shared library extensions only.
        //
        // cdylibs list all outputs in `filenames`, which includes non-signable files like .d
        // dep-info and .lib import libraries.
        return artifact
            .filenames
            .iter()
            .filter(|f| matches!(f.extension().unwrap_or_default(), "dylib" | "so" | "dll"))
            .cloned()
            .map(PathBuf::from)
            .collect();
    }

    Vec::new()
}

/// Find `--message-format <fmt>` or `--message-format=<fmt>` in an argument list.
///
/// Returns the format value if present, or `None` if no `--message-format` was specified.
fn message_format_from_args(args: &[OsString]) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(s) = arg.to_str() else {
            continue;
        };
        if s == "--message-format" {
            return iter.next().and_then(|a| a.to_str().map(String::from));
        }
        if let Some(val) = s.strip_prefix("--message-format=") {
            return Some(val.to_string());
        }
    }
    None
}

/// Find `--target <triple>` or `--target=<triple>` in an argument list.
fn target_from_args(args: &[OsString]) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(s) = arg.to_str() else {
            continue;
        };
        if s == "--target" {
            return iter.next().and_then(|a| a.to_str().map(String::from));
        }
        if let Some(val) = s.strip_prefix("--target=") {
            return Some(val.to_string());
        }
    }
    None
}

/// Get the host target triple from rustc.
fn rustc_host_target_triple() -> Result<String, RunError> {
    let output = Command::new("rustc")
        .arg("-vV")
        .output()
        .map_err(RunError::RustcQuery)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or(RunError::RustcParse)
}

/// Parse a boolean environment variable.
///
/// Accepts the same values as Clap's `BoolishValueParser`.
fn parse_boolish_env(name: &str) -> Result<Option<bool>, RunError> {
    let Some(val) = env::var_os(name) else {
        return Ok(None);
    };
    let Some(s) = val.to_str() else {
        return Err(RunError::InvalidEnvironmentVariable {
            name: name.to_string(),
            value: val.to_string_lossy().into_owned(),
        });
    };
    match s.to_ascii_lowercase().as_str() {
        "y" | "yes" | "t" | "true" | "on" | "1" => Ok(Some(true)),
        "n" | "no" | "f" | "false" | "off" | "0" => Ok(Some(false)),
        _ => Err(RunError::InvalidEnvironmentVariable {
            name: name.to_string(),
            value: s.to_string(),
        }),
    }
}

/// Determine the cargo command to use.
///
/// Reads `CARGO_CODE_SIGN_CARGO` then `CARGO` and falls back to "cargo".
fn cargo() -> OsString {
    // When invoked as `cargo code-sign`, cargo itself overwrites the `CARGO` env var to point at
    // the cargo binary before spawning cargo-code-sign. This means any user-supplied `CARGO` value
    // is lost. `CARGO_CODE_SIGN_CARGO` provides a way to specify the inner cargo command that
    // survives the subcommand dispatch.
    env::var_os("CARGO_CODE_SIGN_CARGO")
        .or_else(|| env::var_os("CARGO"))
        .unwrap_or_else(|| "cargo".into())
}
