//! Integration tests for native-code-sign.
//!
//! These test the library's signing API directly (without the cargo CLI wrapper).

use native_code_sign::Signer;

#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::path::Path;
#[cfg(target_os = "macos")]
use std::process::Command;

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn in_ci() -> bool {
    std::env::var("CI")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
        || std::env::var("GITHUB_ACTIONS")
            .map(|v| v == "true")
            .unwrap_or(false)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
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

/// Copy a real binary to a tempdir for signing tests.
///
/// On macOS, copies `/usr/bin/true`. On Windows, copies a small system executable.
/// Returns the tempdir (keep alive!) and the path to the copied binary.
#[cfg(target_os = "macos")]
fn copy_test_binary() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().expect("failed to create tempdir");
    let dest = tmp.path().join("test_binary");
    fs_err::copy("/usr/bin/true", &dest).expect("failed to copy /usr/bin/true");
    (tmp, dest)
}

#[cfg(target_os = "windows")]
fn copy_test_binary() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().expect("failed to create tempdir");
    let dest = tmp.path().join("test_binary.exe");
    // whoami.exe is small and always present.
    fs_err::copy(r"C:\Windows\System32\whoami.exe", &dest).expect("failed to copy whoami.exe");
    (tmp, dest)
}

// ---------------------------------------------------------------------------
// macOS tests
// ---------------------------------------------------------------------------

/// Ad-hoc signing via the public `Signer` API.
#[cfg(target_os = "macos")]
#[test]
fn test_adhoc_sign_via_signer_api() {
    let (_tmp, binary) = copy_test_binary();

    // With no identity env vars, macOS targets get ad-hoc signing.
    let signer = temp_env::with_vars_unset(
        [
            "CODESIGN_IDENTITY",
            "CODESIGN_CERTIFICATE",
            "CODESIGN_CERTIFICATE_PASSWORD",
        ],
        || Signer::from_env("aarch64-apple-darwin"),
    )
    .expect("from_env failed")
    .expect("expected ad-hoc signer for apple target");

    let session = signer.begin_session().expect("begin_session failed");
    session.sign(&binary).expect("sign failed");

    assert_codesigned(&binary);
    assert_adhoc_signed(&binary);
}

/// Identity signing via the public `Signer` API.
#[cfg(target_os = "macos")]
#[test]
fn test_identity_sign_via_signer_api() {
    if !require_env_or_skip(
        "macOS identity signing",
        &[
            "CODESIGN_IDENTITY",
            "CODESIGN_CERTIFICATE",
            "CODESIGN_CERTIFICATE_PASSWORD",
        ],
    ) {
        return;
    }

    let (_tmp, binary) = copy_test_binary();

    let signer = Signer::from_env("aarch64-apple-darwin")
        .expect("from_env failed")
        .expect("expected identity signer");

    let session = signer.begin_session().expect("begin_session failed");
    session.sign(&binary).expect("sign failed");

    assert_codesigned(&binary);
    assert_identity_signed(&binary);
}

/// Identity signing multiple files in one session reuses the keychain.
#[cfg(target_os = "macos")]
#[test]
fn test_identity_sign_multiple_files_one_session() {
    if !require_env_or_skip(
        "macOS identity signing (multi-file)",
        &[
            "CODESIGN_IDENTITY",
            "CODESIGN_CERTIFICATE",
            "CODESIGN_CERTIFICATE_PASSWORD",
        ],
    ) {
        return;
    }

    let tmp = tempfile::tempdir().expect("failed to create tempdir");
    let bin_a = tmp.path().join("binary_a");
    let bin_b = tmp.path().join("binary_b");
    fs_err::copy("/usr/bin/true", &bin_a).unwrap();
    fs_err::copy("/usr/bin/true", &bin_b).unwrap();

    let signer = Signer::from_env("aarch64-apple-darwin")
        .expect("from_env failed")
        .expect("expected identity signer");

    let session = signer.begin_session().expect("begin_session failed");
    session.sign(&bin_a).expect("sign first failed");
    session.sign(&bin_b).expect("sign second failed");

    assert_codesigned(&bin_a);
    assert_codesigned(&bin_b);
    assert_identity_signed(&bin_a);
    assert_identity_signed(&bin_b);
}

/// The default keychain must not be changed after an identity signing session.
#[cfg(target_os = "macos")]
#[test]
fn test_default_keychain_preserved_after_session() {
    if !require_env_or_skip(
        "macOS keychain preservation",
        &[
            "CODESIGN_IDENTITY",
            "CODESIGN_CERTIFICATE",
            "CODESIGN_CERTIFICATE_PASSWORD",
        ],
    ) {
        return;
    }

    let before = Command::new("security")
        .arg("default-keychain")
        .output()
        .unwrap();
    let before_kc = String::from_utf8_lossy(&before.stdout).trim().to_string();

    let (_tmp, binary) = copy_test_binary();
    let signer = Signer::from_env("aarch64-apple-darwin")
        .expect("from_env failed")
        .expect("expected identity signer");

    let session = signer.begin_session().expect("begin_session failed");
    session.sign(&binary).expect("sign failed");
    drop(session);

    let after = Command::new("security")
        .arg("default-keychain")
        .output()
        .unwrap();
    let after_kc = String::from_utf8_lossy(&after.stdout).trim().to_string();

    assert_eq!(
        before_kc, after_kc,
        "default keychain was changed by signing session!"
    );
}

/// The keychain search list must not retain the ephemeral keychain after the session is dropped.
#[cfg(target_os = "macos")]
#[test]
fn test_ephemeral_keychain_removed_from_search_list() {
    if !require_env_or_skip(
        "macOS keychain cleanup",
        &[
            "CODESIGN_IDENTITY",
            "CODESIGN_CERTIFICATE",
            "CODESIGN_CERTIFICATE_PASSWORD",
        ],
    ) {
        return;
    }

    let search_list_before = keychain_search_list();

    let (_tmp, binary) = copy_test_binary();
    let signer = Signer::from_env("aarch64-apple-darwin")
        .expect("from_env failed")
        .expect("expected identity signer");

    let session = signer.begin_session().expect("begin_session failed");
    session.sign(&binary).expect("sign failed");
    drop(session);

    let search_list_after = keychain_search_list();

    assert_eq!(
        search_list_before, search_list_after,
        "keychain search list was modified by signing session"
    );
}

/// `Signer::from_env` returns `None` for non-apple, non-windows targets.
#[test]
fn test_from_env_returns_none_for_linux() {
    let result = Signer::from_env("x86_64-unknown-linux-gnu").expect("from_env failed");
    assert!(result.is_none(), "expected None for linux target");
}

/// `Signer::from_env` returns `None` when cross-compiling to windows from non-windows.
#[cfg(not(target_os = "windows"))]
#[test]
fn test_from_env_returns_none_for_windows_cross_compile() {
    let result = Signer::from_env("x86_64-pc-windows-msvc").expect("from_env failed");
    assert!(
        result.is_none(),
        "expected None for windows target on non-windows host"
    );
}

/// `Signer::from_env` returns `None` when cross-compiling to apple from non-macOS.
#[cfg(not(target_os = "macos"))]
#[test]
fn test_from_env_returns_none_for_apple_cross_compile() {
    let result = temp_env::with_vars_unset(
        [
            "CODESIGN_IDENTITY",
            "CODESIGN_CERTIFICATE",
            "CODESIGN_CERTIFICATE_PASSWORD",
        ],
        || Signer::from_env("aarch64-apple-darwin"),
    )
    .expect("from_env failed");
    assert!(
        result.is_none(),
        "expected None for apple target on non-macOS host"
    );
}

// ---------------------------------------------------------------------------
// Windows tests
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
fn test_windows_sign_via_signer_api() {
    if !require_env_or_skip(
        "Windows signing",
        &["SIGNTOOL_CERTIFICATE_PATH", "SIGNTOOL_CERTIFICATE_PASSWORD"],
    ) {
        return;
    }

    let (_tmp, binary) = copy_test_binary();

    let signer = Signer::from_env("x86_64-pc-windows-msvc")
        .expect("from_env failed")
        .expect("expected windows signer");

    let session = signer.begin_session().expect("begin_session failed");
    session.sign(&binary).expect("sign failed");

    assert_windows_signed(&binary);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn assert_codesigned(path: &Path) {
    assert!(path.exists(), "binary not found: {}", path.display());
    let output = Command::new("codesign")
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

#[cfg(target_os = "macos")]
fn assert_adhoc_signed(path: &Path) {
    let output = Command::new("codesign")
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
    let output = Command::new("codesign")
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
    let details = String::from_utf8_lossy(&output.stderr);
    assert!(
        !details.contains("Signature=adhoc"),
        "expected identity signature (not ad-hoc) for {}",
        path.display()
    );
}

#[cfg(target_os = "macos")]
fn keychain_search_list() -> String {
    let output = Command::new("security")
        .arg("list-keychains")
        .output()
        .expect("failed to run security list-keychains");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// On Windows, verify that a PE file has an Authenticode certificate table.
#[cfg(target_os = "windows")]
fn assert_windows_signed(path: &Path) {
    assert!(path.exists(), "artifact not found: {}", path.display());
    let bytes = fs_err::read(path).expect("failed to read PE file");
    assert!(bytes.len() >= 0x40, "file too small to be a PE");

    let pe_offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    assert!(
        bytes.len() >= pe_offset + 4 + 20 + 2,
        "truncated PE headers"
    );
    assert_eq!(
        &bytes[pe_offset..pe_offset + 4],
        b"PE\0\0",
        "missing PE signature"
    );

    let optional_header = pe_offset + 24;
    let magic = u16::from_le_bytes(
        bytes[optional_header..optional_header + 2]
            .try_into()
            .unwrap(),
    );
    let data_dirs_offset = match magic {
        0x10b => optional_header + 96,
        0x20b => optional_header + 112,
        _ => panic!("unknown PE optional header magic {magic:#x}"),
    };

    let security_dir = data_dirs_offset + (4 * 8);
    assert!(
        bytes.len() >= security_dir + 8,
        "missing PE security directory"
    );
    let cert_offset = u32::from_le_bytes(bytes[security_dir..security_dir + 4].try_into().unwrap());
    let cert_size = u32::from_le_bytes(
        bytes[security_dir + 4..security_dir + 8]
            .try_into()
            .unwrap(),
    );

    assert!(
        cert_offset > 0 && cert_size > 0,
        "artifact is not Authenticode-signed: {}",
        path.display()
    );
}
