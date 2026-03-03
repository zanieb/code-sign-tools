//! Platform-native code signing.
//!
//! Wraps native platform tools to sign binaries:
//! - [`macos`]: Apple `codesign` via ephemeral keychain (for CI) or ad-hoc signing.
//! - [`windows`]: Microsoft `signtool.exe` with local certificate or Azure Trusted Signing.

pub(crate) mod macos;
pub(crate) mod secret;
pub(crate) mod windows;

use std::io;
use std::path::Path;
use std::process::{Command, ExitStatus};

use thiserror::Error;

pub use macos::{
    adhoc_sign, CodesignConfigError, CodesignError, KeychainSetupError, KeychainStep, MacOsSigner,
    MacOsSigningSession,
};
pub use windows::{SigntoolConfigError, SigntoolError, WindowsSigner};

/// Error from running an external command (codesign, security, signtool).
#[derive(Debug, Error)]
pub enum CommandError {
    #[error("failed to spawn: {0}")]
    Spawn(#[source] io::Error),
    #[error("exited with {status}\nstdout: {stdout}\nstderr: {stderr}")]
    Failed {
        status: ExitStatus,
        stdout: String,
        stderr: String,
    },
}

/// Run a command, returning a [`CommandError`] on spawn failure or non-zero exit.
pub(crate) fn run_command(cmd: &mut Command) -> Result<(), CommandError> {
    let output = cmd.output().map_err(CommandError::Spawn)?;
    if !output.status.success() {
        return Err(CommandError::Failed {
            status: output.status,
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum SignError {
    #[error("codesign failed: {0}")]
    Codesign(#[from] macos::CodesignError),
    #[error("signtool failed: {0}")]
    Signtool(#[from] windows::SigntoolError),
}

#[derive(Debug, Error)]
pub enum SignConfigError {
    #[error("invalid macOS signing configuration: {0}")]
    MacOs(#[from] macos::CodesignConfigError),
    #[error("invalid Windows signing configuration: {0}")]
    Windows(#[from] windows::SigntoolConfigError),
}

/// A configured signer, determined from the environment and target triple.
#[derive(Debug)]
pub enum Signer {
    MacOsIdentity(MacOsSigner),
    MacOsAdHoc,
    Windows(WindowsSigner),
}

impl Signer {
    /// Detect signing configuration from environment variables and target triple.
    ///
    /// # Errors
    ///
    /// - [`SignConfigError::MacOs`] when macOS signing env vars are partially set
    ///   or the certificate is invalid base64.
    /// - [`SignConfigError::Windows`] when Windows signing env vars are partially set.
    ///
    /// Returns `Ok(None)` when signing is intentionally unavailable for this
    /// target (e.g., no credentials configured, or an unsupported platform).
    pub fn from_env(target_triple: &str) -> Result<Option<Self>, SignConfigError> {
        if target_triple.contains("apple") {
            if let Some(signer) = MacOsSigner::from_env()? {
                return Ok(Some(Self::MacOsIdentity(signer)));
            }
            // Fall back to ad-hoc signing, but only when running on macOS.
            // Cross-compiling to apple targets from other hosts can't use codesign.
            if cfg!(target_os = "macos") {
                return Ok(Some(Self::MacOsAdHoc));
            }
            tracing::warn!(
                target = %target_triple,
                "skipping Apple signing on non-macOS host"
            );
            return Ok(None);
        }

        if target_triple.contains("windows") {
            // Cross-compiling to Windows from non-Windows hosts cannot run signtool.exe.
            if !cfg!(target_os = "windows") {
                tracing::warn!(
                    target = %target_triple,
                    "skipping Windows signing on non-Windows host"
                );
                return Ok(None);
            }

            if let Some(signer) = WindowsSigner::from_env()? {
                return Ok(Some(Self::Windows(signer)));
            }
            // No Windows signing credentials configured.
            return Ok(None);
        }

        // Linux/other: no signing support.
        Ok(None)
    }

    /// Prepare a signing session.
    ///
    /// For macOS identity signing this creates a shared ephemeral keychain
    /// (with an exclusive file lock) that is reused for every file signed
    /// during the session. Call [`SigningSession::sign`] for each artifact.
    ///
    /// # Errors
    ///
    /// - [`SignError::Codesign`] if the macOS ephemeral keychain cannot be
    ///   created or the certificate cannot be imported.
    pub fn begin_session(self) -> Result<SigningSession, SignError> {
        match self {
            Self::MacOsIdentity(s) => {
                let session = s.begin_session()?;
                Ok(SigningSession::MacOsIdentity(session))
            }
            Self::MacOsAdHoc => Ok(SigningSession::MacOsAdHoc),
            Self::Windows(s) => Ok(SigningSession::Windows(s)),
        }
    }
}

/// An active signing session.
///
/// For macOS identity signing the session holds a shared ephemeral keychain
/// and an exclusive file lock on the keychain search list, amortising the
/// setup cost across all artifacts and preventing races with concurrent
/// processes.
#[derive(Debug)]
pub enum SigningSession {
    MacOsIdentity(MacOsSigningSession),
    MacOsAdHoc,
    Windows(WindowsSigner),
}

impl SigningSession {
    /// Sign a single file.
    ///
    /// # Errors
    ///
    /// - [`SignError::Codesign`] if macOS `codesign` fails (identity or ad-hoc).
    /// - [`SignError::Signtool`] if Windows `signtool` fails.
    pub fn sign(&self, path: &Path) -> Result<(), SignError> {
        match self {
            Self::MacOsIdentity(s) => s.sign(path).map_err(SignError::from),
            Self::MacOsAdHoc => adhoc_sign(path).map_err(SignError::from),
            Self::Windows(s) => s.sign(path).map_err(SignError::from),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    #[test]
    fn signer_is_send_and_sync() {
        assert_send::<Signer>();
        assert_sync::<Signer>();
    }

    #[test]
    fn errors_are_send_and_sync() {
        assert_send::<SignError>();
        assert_sync::<SignError>();
        assert_send::<SignConfigError>();
        assert_sync::<SignConfigError>();
    }
}
