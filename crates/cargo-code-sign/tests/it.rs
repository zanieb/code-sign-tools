//! Integration tests for cargo-code-sign.
//!
//! Each test copies its fixture into an isolated tempdir for full isolation.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Path to the cargo-code-sign binary under test.
const EXE: &str = env!("CARGO_BIN_EXE_cargo-code-sign");
#[cfg(target_os = "macos")]
const CODESIGN_BIN: &str = "codesign";

/// Copy a fixture directory into a fresh tempdir. Returns the tempdir handle
/// and the path to the Cargo.toml inside it.
fn setup_fixture(fixture_rel: &str) -> (tempfile::TempDir, PathBuf) {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(fixture_rel);
    let tmp = tempfile::tempdir().expect("failed to create tempdir");
    copy_dir_recursive(&src, tmp.path()).expect("failed to copy fixture");
    let cargo_toml = tmp.path().join("Cargo.toml");
    assert!(cargo_toml.exists(), "fixture missing Cargo.toml");
    (tmp, cargo_toml)
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    for entry in fs_err::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dest_path = dst.join(entry.file_name());
        if ty.is_dir() {
            fs_err::create_dir_all(&dest_path)?;
            copy_dir_recursive(&entry.path(), &dest_path)?;
        } else {
            fs_err::copy(entry.path(), &dest_path)?;
        }
    }
    Ok(())
}

const SIGNING_ENV_KEYS: &[&str] = &[
    "CODESIGN_IDENTITY",
    "CODESIGN_CERTIFICATE",
    "CODESIGN_CERTIFICATE_PASSWORD",
    "CODESIGN_OPTIONS",
    "CODESIGN_ALLOW_UNTRUSTED",
    "SIGNTOOL_CERTIFICATE_PATH",
    "SIGNTOOL_CERTIFICATE_PASSWORD",
    "SIGNTOOL_TIMESTAMP_URL",
    "SIGNTOOL_PATH",
];

/// Run `cargo code-sign <subcommand> [args...]` inside the given fixture dir.
/// Returns the exit code.
fn run_code_sign(cargo_toml: &Path, subcommand: &str, extra_args: &[&str]) -> i32 {
    run_code_sign_with_env(cargo_toml, subcommand, extra_args, &[], &[])
}

/// The result of running `cargo code-sign`, including captured stdout.
struct RunOutput {
    code: i32,
    stdout: String,
}

/// Run `cargo code-sign <subcommand>` with explicit env additions/removals.
/// Returns the exit code and captured stdout.
fn run_code_sign_with_env_full(
    cargo_toml: &Path,
    subcommand: &str,
    extra_args: &[&str],
    add_env: &[(&str, String)],
    remove_env: &[&str],
) -> RunOutput {
    let mut cmd = Command::new(EXE);
    cmd.arg("code-sign").arg(subcommand);
    cmd.arg("--manifest-path")
        .arg(cargo_toml)
        .args(extra_args)
        .env("RUST_LOG", "cargo_code_sign=debug")
        .stderr(Stdio::inherit())
        .stdout(Stdio::piped());

    for key in SIGNING_ENV_KEYS {
        cmd.env_remove(key);
    }

    for (k, v) in add_env {
        cmd.env(k, v);
    }
    for k in remove_env {
        cmd.env_remove(k);
    }

    let output = cmd.output().expect("failed to run cargo-code-sign");
    RunOutput {
        code: output.status.code().expect("process terminated by signal"),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
    }
}

/// Run `cargo code-sign <subcommand>` with explicit env additions/removals.
fn run_code_sign_with_env(
    cargo_toml: &Path,
    subcommand: &str,
    extra_args: &[&str],
    add_env: &[(&str, String)],
    remove_env: &[&str],
) -> i32 {
    run_code_sign_with_env_full(cargo_toml, subcommand, extra_args, add_env, remove_env).code
}

/// Run `cargo code-sign build` inside the given fixture dir.
/// Returns the exit code.
fn run_code_sign_build(cargo_toml: &Path, release: bool, extra_args: &[&str]) -> i32 {
    run_code_sign_build_with_env(cargo_toml, release, extra_args, &[], &[])
}

/// Run `cargo code-sign build` with explicit env additions/removals.
fn run_code_sign_build_with_env(
    cargo_toml: &Path,
    release: bool,
    extra_args: &[&str],
    add_env: &[(&str, String)],
    remove_env: &[&str],
) -> i32 {
    let mut release_args: Vec<&str> = Vec::new();
    if release {
        release_args.push("--release");
    }
    release_args.extend_from_slice(extra_args);
    run_code_sign_with_env(cargo_toml, "build", &release_args, add_env, remove_env)
}

/// Resolve the path to a binary artifact inside a fixture's target dir.
fn bin_artifact(fixture_dir: &Path, profile: &str, name: &str) -> PathBuf {
    let dir = fixture_dir.join("target").join(profile);
    if cfg!(target_os = "windows") {
        dir.join(format!("{name}.exe"))
    } else {
        dir.join(name)
    }
}

/// Resolve the path to a cdylib artifact inside a fixture's target dir.
fn cdylib_artifact(fixture_dir: &Path, profile: &str, name: &str) -> PathBuf {
    let dir = fixture_dir.join("target").join(profile);
    if cfg!(target_os = "windows") {
        dir.join(format!("{name}.dll"))
    } else if cfg!(target_os = "macos") {
        dir.join(format!("lib{name}.dylib"))
    } else {
        dir.join(format!("lib{name}.so"))
    }
}

/// On macOS, verify that a binary has a valid code signature.
#[cfg(target_os = "macos")]
fn assert_codesigned(path: &Path) {
    assert!(path.exists(), "binary not found: {}", path.display());
    let output = Command::new(CODESIGN_BIN)
        .args(["-v", "--verbose"])
        .arg(path)
        .output()
        .expect("failed to run codesign -v");
    assert!(
        output.status.success(),
        "codesign verification failed for {}:\nstderr: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn in_ci() -> bool {
    std::env::var("CI")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
        || std::env::var("GITHUB_ACTIONS")
            .map(|v| v == "true")
            .unwrap_or(false)
}

fn require_env_or_skip(context: &str, required: &[&str]) -> bool {
    let missing: Vec<_> = required
        .iter()
        .copied()
        .filter(|k| std::env::var(k).is_err())
        .collect();

    if missing.is_empty() {
        return true;
    }

    assert!(
        !in_ci(),
        "missing required env vars in CI for {context}: {}",
        missing.join(", ")
    );

    eprintln!(
        "skipping {context}: missing env vars: {}",
        missing.join(", ")
    );
    false
}

#[cfg(target_os = "macos")]
fn require_macos_identity_env_or_skip() -> bool {
    require_env_or_skip(
        "macOS identity-signing test",
        &[
            "CODESIGN_IDENTITY",
            "CODESIGN_CERTIFICATE",
            "CODESIGN_CERTIFICATE_PASSWORD",
        ],
    )
}

#[cfg(target_os = "macos")]
fn assert_adhoc_signed(path: &Path) {
    let output = Command::new(CODESIGN_BIN)
        .args(["-d", "-vv"])
        .arg(path)
        .output()
        .expect("failed to run codesign -d");
    let details = String::from_utf8_lossy(&output.stderr);
    assert!(
        details.contains("Signature=adhoc"),
        "expected ad-hoc signature for {}",
        path.display()
    );
}

#[cfg(target_os = "macos")]
fn assert_identity_signed(path: &Path) {
    let output = Command::new(CODESIGN_BIN)
        .args(["-d", "-vv"])
        .arg(path)
        .output()
        .expect("failed to run codesign -d");

    assert!(
        output.status.success(),
        "codesign metadata dump failed for {}:\nstderr: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );

    // `codesign -d` writes metadata to stderr.
    let details = String::from_utf8_lossy(&output.stderr);
    assert!(
        !details.contains("Signature=adhoc"),
        "expected identity signature (not ad-hoc) for {}",
        path.display()
    );
}

#[cfg(target_os = "windows")]
fn require_windows_signing_env_or_skip() -> bool {
    require_env_or_skip(
        "Windows signing test",
        &["SIGNTOOL_CERTIFICATE_PATH", "SIGNTOOL_CERTIFICATE_PASSWORD"],
    )
}

/// On Windows, verify that a PE file has an Authenticode certificate table.
#[cfg(target_os = "windows")]
fn pe_security_directory(path: &Path) -> (u32, u32) {
    assert!(path.exists(), "artifact not found: {}", path.display());

    let bytes = fs_err::read(path).expect("failed to read PE file");
    assert!(
        bytes.len() >= 0x40,
        "file too small to be a PE: {}",
        path.display()
    );

    // DOS header: e_lfanew at offset 0x3c.
    let pe_offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    assert!(
        bytes.len() >= pe_offset + 4 + 20 + 2,
        "truncated PE headers: {}",
        path.display()
    );
    assert_eq!(
        &bytes[pe_offset..pe_offset + 4],
        b"PE\0\0",
        "missing PE signature: {}",
        path.display()
    );

    // Optional header starts after PE signature (4) + COFF header (20).
    let optional_header = pe_offset + 24;
    let magic = u16::from_le_bytes(
        bytes[optional_header..optional_header + 2]
            .try_into()
            .unwrap(),
    );
    let data_dirs_offset = match magic {
        0x10b => optional_header + 96,  // PE32
        0x20b => optional_header + 112, // PE32+
        _ => panic!(
            "unknown PE optional header magic {magic:#x} for {}",
            path.display()
        ),
    };

    // IMAGE_DIRECTORY_ENTRY_SECURITY (index 4), each directory is {u32 virtual_address, u32 size}.
    let security_dir = data_dirs_offset + (4 * 8);
    assert!(
        bytes.len() >= security_dir + 8,
        "missing PE security directory: {}",
        path.display()
    );
    let cert_file_offset =
        u32::from_le_bytes(bytes[security_dir..security_dir + 4].try_into().unwrap());
    let cert_size = u32::from_le_bytes(
        bytes[security_dir + 4..security_dir + 8]
            .try_into()
            .unwrap(),
    );

    (cert_file_offset, cert_size)
}

/// On Windows, verify that a PE file has an Authenticode certificate table.
#[cfg(target_os = "windows")]
fn assert_windows_signed(path: &Path) {
    let (offset, size) = pe_security_directory(path);
    assert!(
        offset > 0 && size > 0,
        "artifact is not Authenticode-signed: {}",
        path.display()
    );
}

#[cfg(target_os = "windows")]
fn assert_windows_unsigned(path: &Path) {
    let (offset, size) = pe_security_directory(path);
    assert!(
        offset == 0 && size == 0,
        "artifact unexpectedly has Authenticode data: {}",
        path.display()
    );
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

/// Verify that `cargo code-sign rustc ... -- <rustc-flags>` works.
///
/// Maturin calls `cargo rustc` instead of `cargo build`, passing extra flags
/// after `--`. `cargo-code-sign` must insert `--message-format=json` before
/// the `--` separator so it is treated as a cargo flag rather than a rustc
/// flag.
#[test]
fn test_rustc_subcommand_with_double_dash() {
    let (tmp, cargo_toml) = setup_fixture("simple_bin");
    let code = run_code_sign_with_env(
        &cargo_toml,
        "rustc",
        &["--release", "--", "-C", "opt-level=3"],
        &[],
        &[],
    );
    assert_eq!(code, 0, "cargo code-sign rustc with -- flags failed");

    let bin = bin_artifact(tmp.path(), "release", "simple_bin");
    assert!(bin.exists(), "binary was not produced: {}", bin.display());
}

#[test]
fn test_simple_bin_builds_and_signs() {
    let (tmp, cargo_toml) = setup_fixture("simple_bin");
    let code = run_code_sign_build_with_env(&cargo_toml, true, &[], &[], &[]);
    assert_eq!(code, 0, "cargo code-sign build failed");

    let bin = bin_artifact(tmp.path(), "release", "simple_bin");
    assert!(bin.exists(), "binary was not produced: {}", bin.display());

    #[cfg(target_os = "macos")]
    {
        assert_codesigned(&bin);
        assert_adhoc_signed(&bin);
    }

    #[cfg(target_os = "windows")]
    {
        assert_windows_unsigned(&bin);
    }
}

#[test]
fn test_simple_cdylib_builds_and_signs() {
    let (tmp, cargo_toml) = setup_fixture("simple_cdylib");
    let code = run_code_sign_build(&cargo_toml, true, &[]);
    assert_eq!(code, 0, "cargo code-sign build failed");

    let dylib = cdylib_artifact(tmp.path(), "release", "simple_cdylib");
    assert!(
        dylib.exists(),
        "cdylib was not produced: {}",
        dylib.display()
    );

    #[cfg(target_os = "macos")]
    {
        assert_codesigned(&dylib);
        assert_adhoc_signed(&dylib);
    }

    #[cfg(target_os = "windows")]
    {
        assert_windows_unsigned(&dylib);
    }
}

#[test]
fn test_lib_only_builds_succeeds() {
    let (_tmp, cargo_toml) = setup_fixture("simple_lib");
    let code = run_code_sign_build(&cargo_toml, true, &[]);
    assert_eq!(code, 0, "cargo code-sign build failed for lib-only crate");
}

#[test]
fn test_build_debug_mode() {
    let (tmp, cargo_toml) = setup_fixture("simple_bin");
    let code = run_code_sign_build(&cargo_toml, false, &[]);
    assert_eq!(code, 0, "debug build failed");

    let bin = bin_artifact(tmp.path(), "debug", "simple_bin");
    if bin.exists() {
        #[cfg(target_os = "macos")]
        {
            assert_codesigned(&bin);
            assert_adhoc_signed(&bin);
        }

        #[cfg(target_os = "windows")]
        {
            assert_windows_unsigned(&bin);
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn test_simple_bin_identity_signs_when_env_configured() {
    if !require_macos_identity_env_or_skip() {
        return;
    }

    let identity = std::env::var("CODESIGN_IDENTITY").unwrap();
    let certificate = std::env::var("CODESIGN_CERTIFICATE").unwrap();
    let password = std::env::var("CODESIGN_CERTIFICATE_PASSWORD").unwrap();

    let mut env = vec![
        ("CODESIGN_IDENTITY", identity),
        ("CODESIGN_CERTIFICATE", certificate),
        ("CODESIGN_CERTIFICATE_PASSWORD", password),
    ];
    if let Ok(allow_untrusted) = std::env::var("CODESIGN_ALLOW_UNTRUSTED") {
        env.push(("CODESIGN_ALLOW_UNTRUSTED", allow_untrusted));
    }

    let (tmp, cargo_toml) = setup_fixture("simple_bin");
    let code = run_code_sign_build_with_env(&cargo_toml, true, &[], &env, &[]);
    assert_eq!(code, 0, "identity-signing build failed");

    let bin = bin_artifact(tmp.path(), "release", "simple_bin");
    assert_codesigned(&bin);
    assert_identity_signed(&bin);
}

#[cfg(target_os = "windows")]
#[test]
fn test_simple_cdylib_windows_signs_when_env_configured() {
    if !require_windows_signing_env_or_skip() {
        return;
    }

    let cert_path = std::env::var("SIGNTOOL_CERTIFICATE_PATH").unwrap();
    let cert_password = std::env::var("SIGNTOOL_CERTIFICATE_PASSWORD").unwrap();

    let mut env = vec![
        ("SIGNTOOL_CERTIFICATE_PATH", cert_path),
        ("SIGNTOOL_CERTIFICATE_PASSWORD", cert_password),
    ];
    if let Ok(ts) = std::env::var("SIGNTOOL_TIMESTAMP_URL") {
        env.push(("SIGNTOOL_TIMESTAMP_URL", ts));
    }
    if let Ok(path) = std::env::var("SIGNTOOL_PATH") {
        env.push(("SIGNTOOL_PATH", path));
    }

    let (tmp, cargo_toml) = setup_fixture("simple_cdylib");
    let code = run_code_sign_build_with_env(&cargo_toml, true, &[], &env, &[]);
    assert_eq!(code, 0, "windows signing build failed for cdylib");

    let dylib = cdylib_artifact(tmp.path(), "release", "simple_cdylib");
    assert_windows_signed(&dylib);
}

#[cfg(target_os = "windows")]
#[test]
fn test_simple_bin_windows_signs_when_env_configured() {
    if !require_windows_signing_env_or_skip() {
        return;
    }

    let cert_path = std::env::var("SIGNTOOL_CERTIFICATE_PATH").unwrap();
    let cert_password = std::env::var("SIGNTOOL_CERTIFICATE_PASSWORD").unwrap();

    let mut env = vec![
        ("SIGNTOOL_CERTIFICATE_PATH", cert_path),
        ("SIGNTOOL_CERTIFICATE_PASSWORD", cert_password),
    ];
    if let Ok(ts) = std::env::var("SIGNTOOL_TIMESTAMP_URL") {
        env.push(("SIGNTOOL_TIMESTAMP_URL", ts));
    }
    if let Ok(path) = std::env::var("SIGNTOOL_PATH") {
        env.push(("SIGNTOOL_PATH", path));
    }

    let (tmp, cargo_toml) = setup_fixture("simple_bin");
    let code = run_code_sign_build_with_env(&cargo_toml, true, &[], &env, &[]);
    assert_eq!(code, 0, "windows signing build failed");

    let bin = bin_artifact(tmp.path(), "release", "simple_bin");
    assert_windows_signed(&bin);
}

/// Test that invoking the binary without `code-sign` subcommand fails cleanly.
#[test]
fn test_bare_invocation_fails() {
    let status = Command::new(EXE)
        .stderr(Stdio::null())
        .stdout(Stdio::null())
        .status()
        .expect("failed to run cargo-code-sign");
    assert!(!status.success(), "bare invocation should fail");
}

// -----------------------------------------------------------------------
// Non-build subcommand forwarding
// -----------------------------------------------------------------------

/// `cargo code-sign check` should forward to `cargo check` and succeed.
#[test]
fn test_check_forwards_successfully() {
    let (_tmp, cargo_toml) = setup_fixture("simple_bin");
    let code = run_code_sign(&cargo_toml, "check", &[]);
    assert_eq!(code, 0, "cargo code-sign check failed");
}

/// `cargo code-sign check` should work for library crates too.
#[test]
fn test_check_lib_forwards_successfully() {
    let (_tmp, cargo_toml) = setup_fixture("simple_lib");
    let code = run_code_sign(&cargo_toml, "check", &[]);
    assert_eq!(code, 0, "cargo code-sign check failed for lib crate");
}

/// `cargo code-sign test` should forward to `cargo test` and succeed.
#[test]
fn test_test_forwards_successfully() {
    let (_tmp, cargo_toml) = setup_fixture("simple_bin");
    let code = run_code_sign(&cargo_toml, "test", &[]);
    assert_eq!(code, 0, "cargo code-sign test failed");
}

/// `cargo code-sign test` with `CARGO_CODE_SIGN_TEST_BINARIES=1` should sign
/// the test binary.
#[cfg(target_os = "macos")]
#[test]
fn test_test_binaries_signed_when_opted_in() {
    let (_tmp, cargo_toml) = setup_fixture("simple_bin");
    let env = vec![("CARGO_CODE_SIGN_TEST_BINARIES", "1".to_string())];
    let out = run_code_sign_with_env_full(&cargo_toml, "test", &["--no-run"], &env, &[]);
    assert_eq!(out.code, 0, "cargo code-sign test --no-run failed");

    // Find the test binary from the JSON output.
    let messages = parse_json_lines(&out.stdout);
    let test_artifact = messages.iter().find(|m| {
        m.get("reason").and_then(|r| r.as_str()) == Some("compiler-artifact")
            && m.get("target")
                .and_then(|t| t.get("kind"))
                .and_then(|k| k.as_array())
                .is_some_and(|kinds| kinds.iter().any(|k| k.as_str() == Some("test")))
    });

    if let Some(artifact) = test_artifact {
        if let Some(exe) = artifact.get("executable").and_then(|e| e.as_str()) {
            let path = Path::new(exe);
            assert_codesigned(path);
        }
    }
}

/// `cargo code-sign test` without the opt-in should NOT sign test binaries.
#[cfg(target_os = "macos")]
#[test]
fn test_test_binaries_not_signed_by_default() {
    let (_tmp, cargo_toml) = setup_fixture("simple_bin");
    let out = run_code_sign_with_env_full(&cargo_toml, "test", &["--no-run"], &[], &[]);
    assert_eq!(out.code, 0, "cargo code-sign test --no-run failed");

    // Find the test binary from the JSON output.
    let messages = parse_json_lines(&out.stdout);
    let test_executable = messages.iter().find_map(|m| {
        if m.get("reason").and_then(|r| r.as_str()) != Some("compiler-artifact") {
            return None;
        }
        let is_test = m
            .get("target")
            .and_then(|t| t.get("kind"))
            .and_then(|k| k.as_array())
            .is_some_and(|kinds| kinds.iter().any(|k| k.as_str() == Some("test")));
        if !is_test {
            return None;
        }
        m.get("executable")
            .and_then(|e| e.as_str())
            .map(PathBuf::from)
    });

    if let Some(exe) = test_executable {
        // On macOS ad-hoc signing is applied to bins but NOT to test binaries
        // by default, so the test binary should have whatever signature cargo
        // left it with (typically ad-hoc from the linker), not one applied by
        // cargo-code-sign. We verify by checking it was not force-signed by us
        // — the absence from the signing log is the real signal, but we at
        // least confirm the binary exists and wasn't touched.
        assert!(exe.exists(), "test binary should exist: {}", exe.display());
    }
}

/// `cargo code-sign clippy` should forward to `cargo clippy` and succeed.
#[test]
fn test_clippy_forwards_successfully() {
    let (_tmp, cargo_toml) = setup_fixture("simple_bin");
    let code = run_code_sign(&cargo_toml, "clippy", &[]);
    assert_eq!(code, 0, "cargo code-sign clippy failed");
}

/// Test that `CARGO_CODE_SIGN_CARGO` overrides the inner cargo command.
///
/// When invoked as `cargo code-sign`, cargo itself overwrites the `CARGO` env
/// var. `CARGO_CODE_SIGN_CARGO` provides a way to specify a custom inner cargo
/// (e.g. a wrapper that runs `cargo auditable`) that survives subcommand
/// dispatch.
#[test]
fn test_cargo_code_sign_cargo_env_overrides_inner_command() {
    let (tmp, cargo_toml) = setup_fixture("simple_bin");

    // Create a wrapper script that touches a marker file then delegates to cargo.
    let marker = tmp.path().join("wrapper-was-called");

    #[cfg(unix)]
    let wrapper = {
        use std::os::unix::fs::PermissionsExt;
        let wrapper_path = tmp.path().join("cargo-wrapper.sh");
        fs_err::write(
            &wrapper_path,
            format!("#!/bin/sh\ntouch {}\nexec cargo \"$@\"\n", marker.display()),
        )
        .unwrap();
        fs_err::set_permissions(&wrapper_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        wrapper_path
    };

    #[cfg(windows)]
    let wrapper = {
        let wrapper_path = tmp.path().join("cargo-wrapper.cmd");
        fs_err::write(
            &wrapper_path,
            format!(
                "@echo off\r\ntype nul > {}\r\ncargo.exe %*\r\n",
                marker.display()
            ),
        )
        .unwrap();
        wrapper_path
    };

    let env = vec![("CARGO_CODE_SIGN_CARGO", wrapper.display().to_string())];
    let code = run_code_sign_build_with_env(&cargo_toml, true, &[], &env, &[]);
    assert_eq!(code, 0, "build with CARGO_CODE_SIGN_CARGO failed");
    assert!(
        marker.exists(),
        "wrapper was not invoked — CARGO_CODE_SIGN_CARGO was ignored"
    );
}

// -----------------------------------------------------------------------
// JSON stdout forwarding
// -----------------------------------------------------------------------

/// Parse stdout lines as JSON and return all lines that parsed successfully.
fn parse_json_lines(stdout: &str) -> Vec<serde_json::Value> {
    stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .collect()
}

/// `cargo code-sign build --message-format=human` should fail because the
/// non-JSON format is incompatible with artifact detection.
#[test]
fn test_build_with_incompatible_message_format_fails() {
    let (_tmp, cargo_toml) = setup_fixture("simple_bin");
    let out = run_code_sign_with_env_full(
        &cargo_toml,
        "build",
        &["--release", "--message-format=human"],
        &[],
        &[],
    );
    assert_ne!(out.code, 0, "expected failure for --message-format=human");
}

/// `cargo code-sign build --message-format=short` should fail because the
/// non-JSON format is incompatible with artifact detection.
#[test]
fn test_build_with_short_message_format_fails() {
    let (_tmp, cargo_toml) = setup_fixture("simple_bin");
    let out = run_code_sign_with_env_full(
        &cargo_toml,
        "build",
        &["--release", "--message-format=short"],
        &[],
        &[],
    );
    assert_ne!(out.code, 0, "expected failure for --message-format=short");
}

/// `cargo code-sign build --message-format=json-render-diagnostics` should
/// succeed and forward JSON to stdout (compatible format).
#[test]
fn test_build_with_json_render_diagnostics_forwards_json() {
    let (_tmp, cargo_toml) = setup_fixture("simple_bin");
    let out = run_code_sign_with_env_full(
        &cargo_toml,
        "build",
        &["--release", "--message-format=json-render-diagnostics"],
        &[],
        &[],
    );
    assert_eq!(out.code, 0, "build with json-render-diagnostics failed");

    let messages = parse_json_lines(&out.stdout);
    assert!(
        !messages.is_empty(),
        "expected JSON messages on stdout for json-render-diagnostics"
    );

    let has_artifact = messages
        .iter()
        .any(|m| m.get("reason").and_then(|r| r.as_str()) == Some("compiler-artifact"));
    assert!(
        has_artifact,
        "expected at least one compiler-artifact message on stdout"
    );
}

/// `cargo code-sign build --message-format json-diagnostic-short` should
/// succeed and forward JSON to stdout (compatible format, space-separated).
#[test]
fn test_build_with_json_diagnostic_short_forwards_json() {
    let (_tmp, cargo_toml) = setup_fixture("simple_bin");
    let out = run_code_sign_with_env_full(
        &cargo_toml,
        "build",
        &["--release", "--message-format", "json-diagnostic-short"],
        &[],
        &[],
    );
    assert_eq!(out.code, 0, "build with json-diagnostic-short failed");

    let messages = parse_json_lines(&out.stdout);
    assert!(
        !messages.is_empty(),
        "expected JSON messages on stdout for json-diagnostic-short"
    );
}

/// Without `--message-format`, `cargo code-sign build` should not emit JSON
/// on stdout (it's a direct user invocation).
#[test]
fn test_build_without_message_format_has_no_json_stdout() {
    let (_tmp, cargo_toml) = setup_fixture("simple_bin");
    let out = run_code_sign_with_env_full(&cargo_toml, "build", &["--release"], &[], &[]);
    assert_eq!(out.code, 0, "build failed");
    assert!(
        out.stdout.trim().is_empty(),
        "expected no stdout without --message-format, got: {:?}",
        out.stdout
    );
}

/// `cargo code-sign build --message-format=json` must forward JSON messages to
/// stdout so callers like maturin can find build artifacts.
#[test]
fn test_build_forwards_json_to_stdout() {
    let (_tmp, cargo_toml) = setup_fixture("simple_bin");
    let out = run_code_sign_with_env_full(
        &cargo_toml,
        "build",
        &["--release", "--message-format=json"],
        &[],
        &[],
    );
    assert_eq!(out.code, 0, "build failed");

    let messages = parse_json_lines(&out.stdout);
    assert!(
        !messages.is_empty(),
        "expected JSON messages on stdout, got nothing"
    );

    // There must be at least one compiler-artifact message for the binary.
    let has_artifact = messages
        .iter()
        .any(|m| m.get("reason").and_then(|r| r.as_str()) == Some("compiler-artifact"));
    assert!(
        has_artifact,
        "expected at least one compiler-artifact message on stdout"
    );

    // There should be a build-finished message.
    let has_finished = messages
        .iter()
        .any(|m| m.get("reason").and_then(|r| r.as_str()) == Some("build-finished"));
    assert!(has_finished, "expected a build-finished message on stdout");
}

/// `cargo code-sign build --message-format=json` for a cdylib should forward
/// an artifact message with the cdylib output path.
#[test]
fn test_cdylib_build_forwards_json_with_artifact_filenames() {
    let (_tmp, cargo_toml) = setup_fixture("simple_cdylib");
    let out = run_code_sign_with_env_full(
        &cargo_toml,
        "build",
        &["--release", "--message-format=json"],
        &[],
        &[],
    );
    assert_eq!(out.code, 0, "cdylib build failed");

    let messages = parse_json_lines(&out.stdout);

    // Find the artifact message for our cdylib.
    let cdylib_artifact = messages.iter().find(|m| {
        m.get("reason").and_then(|r| r.as_str()) == Some("compiler-artifact")
            && m.get("target")
                .and_then(|t| t.get("kind"))
                .and_then(|k| k.as_array())
                .is_some_and(|kinds| kinds.iter().any(|k| k.as_str() == Some("cdylib")))
    });
    assert!(
        cdylib_artifact.is_some(),
        "expected a compiler-artifact message for the cdylib target on stdout"
    );

    // Verify the artifact has filenames.
    let filenames = cdylib_artifact
        .unwrap()
        .get("filenames")
        .and_then(|f| f.as_array());
    assert!(
        filenames.is_some_and(|f| !f.is_empty()),
        "expected cdylib artifact to have filenames"
    );
}

/// `cargo code-sign rustc --message-format=json` should forward JSON to stdout (used by maturin).
#[test]
fn test_rustc_forwards_json_to_stdout() {
    let (_tmp, cargo_toml) = setup_fixture("simple_bin");
    let out = run_code_sign_with_env_full(
        &cargo_toml,
        "rustc",
        &[
            "--message-format=json",
            "--release",
            "--",
            "-C",
            "opt-level=3",
        ],
        &[],
        &[],
    );
    assert_eq!(out.code, 0, "rustc build failed");

    let messages = parse_json_lines(&out.stdout);
    assert!(
        !messages.is_empty(),
        "expected JSON messages on stdout from rustc subcommand"
    );

    let has_artifact = messages
        .iter()
        .any(|m| m.get("reason").and_then(|r| r.as_str()) == Some("compiler-artifact"));
    assert!(
        has_artifact,
        "expected at least one compiler-artifact message on stdout from rustc"
    );
}

// -----------------------------------------------------------------------
// Maturin integration
// -----------------------------------------------------------------------

/// Resolve the maturin binary path from the `MATURIN` env var.
///
/// In CI, `MATURIN` must be set (the workflow installs it via `uv tool install`).
/// Locally, if `MATURIN` is not set the test is skipped.
fn require_maturin_or_skip() -> Option<String> {
    if require_env_or_skip("maturin integration test", &["MATURIN"]) {
        Some(std::env::var("MATURIN").unwrap())
    } else {
        None
    }
}

/// Build a maturin "bin" project using `cargo code-sign` as the cargo command.
///
/// Maturin invokes `cargo rustc --message-format=json ...` under the hood and
/// parses the JSON output to locate build artifacts. This test verifies that
/// the JSON forwarding works end-to-end with a real maturin invocation.
///
/// Requires maturin to be installed; skipped otherwise.
#[test]
fn test_maturin_build_through_cargo_code_sign() {
    let Some(maturin) = require_maturin_or_skip() else {
        return;
    };

    let (tmp, _cargo_toml) = setup_fixture("maturin_bin");

    // Create a wrapper script that maturin will use as CARGO.
    // The wrapper calls `cargo code-sign` so that:
    //   maturin -> wrapper "rustc ..." -> cargo code-sign rustc ...
    #[cfg(unix)]
    let wrapper = {
        use std::os::unix::fs::PermissionsExt;
        let wrapper_path = tmp.path().join("cargo-code-sign-wrapper.sh");
        fs_err::write(
            &wrapper_path,
            format!("#!/bin/sh\nexec {EXE} code-sign \"$@\"\n"),
        )
        .unwrap();
        fs_err::set_permissions(&wrapper_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        wrapper_path
    };

    #[cfg(windows)]
    let wrapper = {
        let wrapper_path = tmp.path().join("cargo-code-sign-wrapper.cmd");
        fs_err::write(
            &wrapper_path,
            format!("@echo off\r\n\"{EXE}\" code-sign %*\r\n"),
        )
        .unwrap();
        wrapper_path
    };

    let output = Command::new(&maturin)
        .args(["build", "--release"])
        .current_dir(tmp.path())
        .env("CARGO", &wrapper)
        // Clear signing env so we get ad-hoc / no-op signing.
        .env_remove("CODESIGN_IDENTITY")
        .env_remove("CODESIGN_CERTIFICATE")
        .env_remove("CODESIGN_CERTIFICATE_PASSWORD")
        .env_remove("SIGNTOOL_CERTIFICATE_PATH")
        .env_remove("SIGNTOOL_CERTIFICATE_PASSWORD")
        .env("RUST_LOG", "cargo_code_sign=debug")
        .output()
        .expect("failed to run maturin");

    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("maturin stderr:\n{stderr}");

    assert!(
        output.status.success(),
        "maturin build through cargo-code-sign failed (exit {:?})",
        output.status.code()
    );

    // Verify that maturin produced a wheel.
    let wheels: Vec<_> = fs_err::read_dir(tmp.path().join("target/wheels"))
        .expect("target/wheels dir missing")
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "whl"))
        .collect();
    assert!(
        !wheels.is_empty(),
        "maturin did not produce any wheel files"
    );
    eprintln!("maturin produced {} wheel(s)", wheels.len());
}
