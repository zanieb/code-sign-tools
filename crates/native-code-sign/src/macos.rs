//! macOS code signing using Apple's `codesign` tool.
//!
//! Environment variables:
//! - `CODESIGN_IDENTITY`: signing identity (e.g. "Developer ID Application: ...")
//! - `CODESIGN_CERTIFICATE`: base64-encoded `.p12` certificate
//! - `CODESIGN_CERTIFICATE_PASSWORD`: password for the `.p12`
//! - `CODESIGN_OPTIONS`: (optional) extra `--options` value (e.g. `"runtime"`)
//! - `CODESIGN_ALLOW_UNTRUSTED`: (optional) set to `1` or `true` to allow
//!   self-signed certificates that are not in the system trust store.
//!
//! Supports two modes:
//! 1. **Identity signing**: if `CODESIGN_IDENTITY`, `CODESIGN_CERTIFICATE`, and
//!    `CODESIGN_CERTIFICATE_PASSWORD` are all set, creates an ephemeral keychain,
//!    imports the certificate, and signs with the named identity.
//! 2. **Ad-hoc signing**: if no identity certificate config is provided, uses
//!    `codesign --force --sign -` (local development).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::{fmt, io};

use base64::Engine;
use thiserror::Error;
use zeroize::Zeroize;

use crate::secret::Secret;

const CODESIGN_BIN: &str = "codesign";
const SECURITY_BIN: &str = "security";

#[derive(Debug, Error)]
pub enum CodesignError {
    #[error("codesign failed for `{}`: {source}", path.display())]
    Sign {
        path: PathBuf,
        #[source]
        source: crate::CommandError,
    },
    #[error("failed to create ephemeral keychain: {source}")]
    KeychainSetup {
        step: KeychainStep,
        #[source]
        source: KeychainSetupError,
    },
    #[error(
        "signing identity `{identity}` not found in keychain after certificate import\n\
         available identities:\n{}",
        format_available_identities(available)
    )]
    IdentityNotFound {
        identity: String,
        available: Vec<String>,
    },
}

fn format_available_identities(identities: &[String]) -> String {
    if identities.is_empty() {
        return "  (none)".to_string();
    }
    identities
        .iter()
        .map(|id| format!("  - {id}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The step during ephemeral keychain setup that failed.
#[derive(Debug, Clone, Copy)]
pub enum KeychainStep {
    AcquireLock,
    CreateTempdir,
    CreateKeychain,
    SetSettings,
    Unlock,
    SetSearchList,
    GetSearchList,
    WriteCertificate,
    ImportCertificate,
    SetPartitionList,
    GeneratePassword,
    VerifyIdentity,
}

impl fmt::Display for KeychainStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AcquireLock => write!(f, "acquire keychain lock"),
            Self::CreateTempdir => write!(f, "create tempdir"),
            Self::CreateKeychain => write!(f, "create keychain"),
            Self::SetSettings => write!(f, "set keychain settings"),
            Self::Unlock => write!(f, "unlock keychain"),
            Self::SetSearchList => write!(f, "set keychain search list"),
            Self::GetSearchList => write!(f, "get keychain search list"),
            Self::WriteCertificate => write!(f, "write certificate"),
            Self::ImportCertificate => write!(f, "import certificate"),
            Self::SetPartitionList => write!(f, "set key partition list"),
            Self::GeneratePassword => write!(f, "generate password"),
            Self::VerifyIdentity => write!(f, "verify signing identity"),
        }
    }
}

/// The underlying error during a keychain setup step.
#[derive(Debug, Error)]
pub enum KeychainSetupError {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Command(#[from] crate::CommandError),
    #[error("failed to generate random bytes: {0}")]
    Getrandom(#[from] getrandom::Error),
    #[error("path contains non-UTF-8 characters: {}", path.display())]
    NonUtf8Path { path: PathBuf },
}

impl CodesignError {
    fn keychain(step: KeychainStep, source: impl Into<KeychainSetupError>) -> Self {
        Self::KeychainSetup {
            step,
            source: source.into(),
        }
    }

    fn non_utf8_path(step: KeychainStep, path: &Path) -> Self {
        Self::KeychainSetup {
            step,
            source: KeychainSetupError::NonUtf8Path {
                path: path.to_path_buf(),
            },
        }
    }
}

#[derive(Debug, Error)]
pub enum CodesignConfigError {
    #[error(
        "incomplete macOS signing configuration: all of CODESIGN_IDENTITY, CODESIGN_CERTIFICATE, and CODESIGN_CERTIFICATE_PASSWORD are required (missing: {missing})"
    )]
    IncompleteConfiguration { missing: String },
    #[error("CODESIGN_CERTIFICATE is not valid base64: {0}")]
    InvalidCertificate(#[source] base64::DecodeError),
}

/// Configuration for identity-based macOS signing.
#[derive(Debug)]
pub struct MacOsSigner {
    identity: String,
    certificate: Secret<Vec<u8>>,
    certificate_password: Secret<String>,
    /// Extra `--options` value for codesign, parsed from `CODESIGN_OPTIONS`
    options: Option<String>,
    /// When `true`, skip the trust check when verifying the signing identity
    /// exists in the keychain. This is useful for self-signed certificates
    /// (e.g. in CI) that are not in the system trust store.
    ///
    /// Controlled by `CODESIGN_ALLOW_UNTRUSTED=1`.
    allow_untrusted: bool,
}

impl MacOsSigner {
    /// Construct from environment variables.
    ///
    /// # Errors
    ///
    /// - [`CodesignConfigError::IncompleteConfiguration`] when some but not all of
    ///   `CODESIGN_IDENTITY`, `CODESIGN_CERTIFICATE`, and `CODESIGN_CERTIFICATE_PASSWORD` are set.
    /// - [`CodesignConfigError::InvalidCertificate`] when `CODESIGN_CERTIFICATE` is not valid
    ///   base64.
    ///
    /// Returns [`Ok(None)`] when none of the identity variables are set.
    pub fn from_env() -> Result<Option<Self>, CodesignConfigError> {
        let identity = std::env::var("CODESIGN_IDENTITY").ok();
        let cert_b64 = std::env::var("CODESIGN_CERTIFICATE").ok();
        let password = std::env::var("CODESIGN_CERTIFICATE_PASSWORD").ok();

        match (identity, cert_b64, password) {
            (None, None, None) => Ok(None),
            (Some(identity), Some(cert_b64), Some(password)) => {
                // Strip whitespace before decoding — base64 output from `openssl base64`
                // and similar tools commonly contains line breaks every 76 characters.
                // See: https://github.com/marshallpierce/rust-base64/issues/105
                let cert_b64_clean: String = cert_b64
                    .chars()
                    .filter(|c| !c.is_ascii_whitespace())
                    .collect();
                let certificate = base64::engine::general_purpose::STANDARD
                    .decode(&cert_b64_clean)
                    .map_err(CodesignConfigError::InvalidCertificate)?;
                let options = std::env::var("CODESIGN_OPTIONS").ok();
                let allow_untrusted = std::env::var("CODESIGN_ALLOW_UNTRUSTED")
                    .ok()
                    .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));

                Ok(Some(Self {
                    identity,
                    certificate: Secret::new(certificate),
                    certificate_password: Secret::new(password),
                    options,
                    allow_untrusted,
                }))
            }
            (identity, cert_b64, password) => {
                let mut missing = Vec::new();
                if identity.is_none() {
                    missing.push("CODESIGN_IDENTITY");
                }
                if cert_b64.is_none() {
                    missing.push("CODESIGN_CERTIFICATE");
                }
                if password.is_none() {
                    missing.push("CODESIGN_CERTIFICATE_PASSWORD");
                }
                Err(CodesignConfigError::IncompleteConfiguration {
                    missing: missing.join(", "),
                })
            }
        }
    }

    /// Create a signing session with a shared ephemeral keychain.
    ///
    /// The session creates one ephemeral keychain, imports the certificate into it, and holds an
    /// exclusive file lock to prevent concurrent processes from racing on the macOS keychain search
    /// list. Use [`MacOsSigningSession::sign`] to sign individual files.
    ///
    /// # Errors
    ///
    /// - [`CodesignError::KeychainSetup`] if the ephemeral keychain cannot be created, unlocked, or
    ///   if certificate import fails.
    pub fn begin_session(&self) -> Result<MacOsSigningSession, CodesignError> {
        let keychain = EphemeralKeychain::create()?;
        keychain.import_certificate(
            self.certificate.expose(),
            self.certificate_password.expose(),
        )?;
        keychain.verify_identity(&self.identity, self.allow_untrusted)?;

        Ok(MacOsSigningSession {
            identity: self.identity.clone(),
            options: self.options.clone(),
            keychain,
        })
    }
}

/// An active identity-signing session backed by a shared ephemeral keychain.
///
/// Created via [`MacOsSigner::begin_session`]. The keychain (and its file lock) are held for the
/// lifetime of this value, so signing multiple files reuses the same keychain and certificate
/// import.
#[derive(Debug)]
pub struct MacOsSigningSession {
    identity: String,
    options: Option<String>,
    keychain: EphemeralKeychain,
}

impl MacOsSigningSession {
    /// Sign a single file using the session's ephemeral keychain.
    ///
    /// # Errors
    ///
    /// - [`CodesignError::Io`] if the `codesign` process cannot be spawned.
    /// - [`CodesignError::Failed`] if `codesign` exits with a non-zero status.
    pub fn sign(&self, path: &Path) -> Result<(), CodesignError> {
        let keychain_str = self.keychain.path_str()?;

        let mut cmd = Command::new(CODESIGN_BIN);
        cmd.args(["--force", "--sign", &self.identity]);
        if let Some(options) = &self.options {
            cmd.args(["--options", options]);
        }
        cmd.args(["--keychain", keychain_str]);
        cmd.arg(path);
        run_codesign(&mut cmd, path)?;

        tracing::debug!("identity-signed {}", path.display());
        Ok(())
    }
}

/// Sign a file with an ad-hoc identity (no certificate needed).
///
/// # Errors
///
/// - [`CodesignError::Io`] if the `codesign` process cannot be spawned.
/// - [`CodesignError::Failed`] if `codesign` exits with a non-zero status.
pub fn adhoc_sign(path: &Path) -> Result<(), CodesignError> {
    let mut cmd = Command::new(CODESIGN_BIN);
    cmd.args(["--force", "--sign", "-"]);
    cmd.arg(path);
    run_codesign(&mut cmd, path)?;

    tracing::debug!("ad-hoc signed {}", path.display());
    Ok(())
}

/// An ephemeral macOS keychain.
///
/// # Drop order
///
/// Fields are dropped in declaration order after the manual `Drop` impl runs.
/// The intended sequence is:
///
/// 1. Manual `Drop`: `security delete-keychain` (removes keychain from search list AND deletes
///    the file).
/// 2. `temp_dir`: removes the temporary directory (the keychain file is already gone).
/// 3. `_lock`: releases the exclusive file lock so other processes can proceed.
#[derive(Debug)]
struct EphemeralKeychain {
    temp_dir: tempfile::TempDir,
    path: PathBuf,
    password: Secret<String>,
    /// Exclusive file lock held while the keychain search list is modified.
    ///
    /// This prevents concurrent `cargo-code-sign` processes from racing on the global per-user
    /// keychain search list. The lock is acquired before we modify the search list and released
    /// when this struct is dropped (after the keychain is deleted in [`Drop`]).
    _lock: fs_err::File,
}

impl Drop for EphemeralKeychain {
    fn drop(&mut self) {
        // `security delete-keychain` both removes the keychain from the search list AND deletes
        // the keychain file on disk. This is a single atomic operation that avoids the
        // stale-snapshot problem of manually restoring a saved search list.
        let result = Command::new(SECURITY_BIN)
            .args(["delete-keychain"])
            .arg(&self.path)
            .output();

        match result {
            Ok(output) if output.status.success() => {
                tracing::debug!("deleted ephemeral keychain {}", self.path.display());
            }
            Ok(output) => {
                tracing::warn!(
                    "failed to delete ephemeral keychain {}: {}",
                    self.path.display(),
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            Err(e) => {
                tracing::warn!(
                    "failed to run `security delete-keychain` for {}: {e}",
                    self.path.display()
                );
            }
        }
    }
}

impl EphemeralKeychain {
    fn create() -> Result<Self, CodesignError> {
        // Acquire an exclusive file lock before touching the keychain search list.
        //
        // This serialises concurrent `cargo-code-sign` processes so they don't clobber each
        // other's search list changes. The lock is held until this struct is dropped (after
        // `delete-keychain` has cleaned up).
        let lock = acquire_keychain_lock()?;

        let temp_dir = tempfile::tempdir()
            .map_err(|e| CodesignError::keychain(KeychainStep::CreateTempdir, e))?;
        let path = temp_dir.path().join("signing.keychain-db");

        // Use a random password for the ephemeral keychain.
        let password = random_hex_password()?;

        let path_str = path
            .to_str()
            .ok_or_else(|| CodesignError::non_utf8_path(KeychainStep::CreateKeychain, &path))?;

        // Create keychain
        run_security(
            KeychainStep::CreateKeychain,
            &["create-keychain", "-p", password.expose(), path_str],
        )?;

        // Set timeout so the keychain stays unlocked during the build.
        // `-u` locks after the timeout; `-t` sets the interval in seconds.
        // We intentionally omit `-l` (lock on sleep) — on developer laptops a sleep/wake
        // mid-build would otherwise lock the keychain and cause signing to fail.
        run_security(
            KeychainStep::SetSettings,
            &["set-keychain-settings", "-t", "21600", "-u", path_str],
        )?;

        // Unlock
        run_security(
            KeychainStep::Unlock,
            &["unlock-keychain", "-p", password.expose(), path_str],
        )?;

        // Read the current search list so we can prepend our keychain to it.
        let current_search_list = get_keychain_search_list()?;

        // Add the ephemeral keychain to the search list (without modifying the default keychain).
        // This allows codesign to find the imported certificate. On Drop,
        // `security delete-keychain` will atomically remove it from the search list.
        {
            let mut args = vec!["list-keychains", "-d", "user", "-s", path_str];
            let prev_strs: Vec<&str> = current_search_list
                .iter()
                .filter_map(|p| p.to_str())
                .collect();
            args.extend(prev_strs);
            run_security(KeychainStep::SetSearchList, &args)?;
        }

        Ok(Self {
            temp_dir,
            path,
            password,
            _lock: lock,
        })
    }

    /// Return the keychain path as a UTF-8 string.
    fn path_str(&self) -> Result<&str, CodesignError> {
        self.path
            .to_str()
            .ok_or_else(|| CodesignError::non_utf8_path(KeychainStep::CreateKeychain, &self.path))
    }

    /// Verify that the given signing identity exists in this keychain.
    ///
    /// Runs `security find-identity -p codesigning` and checks that the output
    /// contains the requested identity string. This catches typos, expired certificates,
    /// and wrong certificate types early — before `codesign` fails with a cryptic error.
    ///
    /// When `allow_untrusted` is `false` (the default), the `-v` flag is passed to
    /// filter to valid (trusted) identities only. Set `CODESIGN_ALLOW_UNTRUSTED=1`
    /// to skip the trust check, which is useful for self-signed certificates in CI.
    fn verify_identity(&self, identity: &str, allow_untrusted: bool) -> Result<(), CodesignError> {
        let keychain_str = self.path_str()?;

        let mut cmd = Command::new(SECURITY_BIN);
        cmd.arg("find-identity");
        if !allow_untrusted {
            cmd.arg("-v");
        }
        cmd.args(["-p", "codesigning", keychain_str]);

        let output = cmd
            .output()
            .map_err(|e| CodesignError::keychain(KeychainStep::VerifyIdentity, e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        if stdout.contains(identity) {
            tracing::debug!("verified identity `{identity}` exists in keychain");
            return Ok(());
        }

        // Collect available identities for the error message.
        // Output lines look like:
        //   1) AABBCCDD... "Developer ID Application: Example (TEAM1234)"
        let available: Vec<String> = stdout
            .lines()
            .filter(|line| line.contains('"'))
            .map(|line| {
                line.trim()
                    .split_once(") ")
                    .map_or(line.trim(), |x| x.1)
                    .to_string()
            })
            .collect();

        Err(CodesignError::IdentityNotFound {
            identity: identity.to_string(),
            available,
        })
    }

    fn import_certificate(
        &self,
        certificate: &[u8],
        passphrase: &str,
    ) -> Result<(), CodesignError> {
        let keychain_str = self.path_str()?;

        // Write cert to temp file with restrictive permissions.
        let cert_path = self.temp_dir.path().join("cert.p12");
        {
            use std::io::Write;
            let mut opts = fs_err::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use fs_err::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = opts
                .open(&cert_path)
                .map_err(|e| CodesignError::keychain(KeychainStep::WriteCertificate, e))?;
            file.write_all(certificate)
                .map_err(|e| CodesignError::keychain(KeychainStep::WriteCertificate, e))?;
        }

        let cert_path_str = cert_path.to_str().ok_or_else(|| {
            CodesignError::non_utf8_path(KeychainStep::ImportCertificate, &cert_path)
        })?;

        // Import into keychain.
        //
        // Use explicit `-T` entries with absolute paths rather than the overly broad `-A` flag
        // (which would grant all applications access to the key). The `set-key-partition-list`
        // call below is what actually controls access on modern macOS, but correct `-T` entries
        // are still important for the legacy ACL layer.
        //
        // The `-T` flag registers a specific binary in the keychain item's access control list.
        // Absolute paths are required because the Keychain Services ACL matches on the exact
        // path — bare names like "codesign" won't resolve and can silently fail to grant access.
        run_security(
            KeychainStep::ImportCertificate,
            &[
                "import",
                cert_path_str,
                "-k",
                keychain_str,
                "-P",
                passphrase,
                "-f",
                "pkcs12",
                "-T",
                "/usr/bin/codesign",
                "-T",
                "/usr/bin/security",
                "-T",
                "/usr/bin/productbuild",
                "-T",
                "/usr/bin/pkgbuild",
            ],
        )?;

        // Set key partition list for signing keys (`-s`).
        //
        // This is the modern access control mechanism on macOS. The partition list must include
        // "apple:" for `/usr/bin/codesign` to access the key.
        run_security(
            KeychainStep::SetPartitionList,
            &[
                "set-key-partition-list",
                "-S",
                "apple-tool:,apple:,codesign:",
                "-s",
                "-k",
                self.password.expose(),
                keychain_str,
            ],
        )?;

        Ok(())
    }
}

/// Acquire an exclusive file lock to serialise access to the keychain search list.
///
/// The lock file lives in the system temp directory so all `cargo-code-sign` processes for the same
/// user converge on the same path.
fn acquire_keychain_lock() -> Result<fs_err::File, CodesignError> {
    let lock_path = std::env::temp_dir().join("cargo-code-sign-keychain.lock");
    let file = fs_err::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| CodesignError::keychain(KeychainStep::AcquireLock, e))?;
    tracing::debug!("waiting for keychain lock at {}", lock_path.display());
    file.lock()
        .map_err(|e| CodesignError::keychain(KeychainStep::AcquireLock, e))?;
    tracing::debug!("acquired keychain lock");
    Ok(file)
}

/// Query the current keychain search list.
fn get_keychain_search_list() -> Result<Vec<PathBuf>, CodesignError> {
    let output = Command::new(SECURITY_BIN)
        .args(["list-keychains", "-d", "user"])
        .output()
        .map_err(|e| CodesignError::keychain(KeychainStep::GetSearchList, e))?;

    if !output.status.success() {
        return Err(CodesignError::keychain(
            KeychainStep::GetSearchList,
            crate::CommandError::Failed {
                status: output.status,
                stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            },
        ));
    }

    // Output is one quoted path per line, e.g.:
    //     "/Users/foo/Library/Keychains/login.keychain-db"
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| line.trim().trim_matches('"'))
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect())
}

/// Run a `codesign` command and translate failures into [`CodesignError`].
fn run_codesign(cmd: &mut Command, path: &Path) -> Result<(), CodesignError> {
    crate::run_command(cmd).map_err(|source| CodesignError::Sign {
        path: path.to_path_buf(),
        source,
    })
}

/// Run a `security` command and map failures to keychain-specific errors.
fn run_security(step: KeychainStep, args: &[&str]) -> Result<(), CodesignError> {
    crate::run_command(Command::new(SECURITY_BIN).args(args))
        .map_err(|e| CodesignError::keychain(step, e))
}

/// Generate a random hex string for ephemeral keychain passwords.
fn random_hex_password() -> Result<Secret<String>, CodesignError> {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf)
        .map_err(|e| CodesignError::keychain(KeychainStep::GeneratePassword, e))?;
    let mut hex = String::with_capacity(64);
    for b in &buf {
        use fmt::Write;
        write!(hex, "{b:02x}").unwrap();
    }
    buf.zeroize();
    Ok(Secret::new(hex))
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    fn require_command_or_skip(context: &str, command: &str) -> bool {
        if Command::new(command).arg("--help").output().is_ok() {
            return true;
        }
        eprintln!("skipping {context}: required command not found in PATH: {command}");
        false
    }

    #[cfg(unix)]
    #[test]
    fn test_random_hex_password() {
        let a = random_hex_password().unwrap();
        let b = random_hex_password().unwrap();
        let a = a.expose();
        let b = b.expose();
        assert_eq!(a.len(), 64, "expected 32 bytes = 64 hex chars");
        assert_ne!(a, b, "two random passwords should differ");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_adhoc_sign_real_binary() {
        if !require_command_or_skip("adhoc signing real binary", CODESIGN_BIN) {
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("true_copy");
        fs_err::copy("/usr/bin/true", &path).unwrap();
        adhoc_sign(&path).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_adhoc_sign_nonexistent_fails() {
        if !require_command_or_skip("adhoc signing nonexistent file", CODESIGN_BIN) {
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nope");
        // This should fail because the file doesn't exist.
        assert!(adhoc_sign(&path).is_err());
    }
}
