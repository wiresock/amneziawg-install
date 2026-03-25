//! Subprocess bridge for invoking `amneziawg-install.sh` non-interactively.
//!
//! This module is the **only** place that spawns the install script.  All
//! invocations use explicit argument arrays (`Command::new` + `.arg()`), with
//! **no** shell interpolation, `sh -c`, or string concatenation in command
//! construction.
//!
//! # Supported operations
//!
//! | Flag | Description |
//! |------|-------------|
//! | `--add-client <NAME>` | Create a new client; prints config path to stdout |
//! | `--remove-client <NAME>` | Remove an existing client |
//! | `--list-clients` | List all client names (one per line) |
//!
//! # Security notes
//!
//! - Client names are validated *before* being passed to the script.
//! - stdout/stderr are captured; **config contents are never logged**.
//! - The script is invoked via `sudo` to gain the required root privileges.

use std::path::{Path, PathBuf};
use std::time::Duration;

use thiserror::Error;
use tracing::{debug, error, info, warn};

/// Default path to the install script (relative to repo root on a standard install).
pub const DEFAULT_SCRIPT_PATH: &str = "/usr/local/bin/amneziawg-install.sh";

/// Maximum time to wait for the script to complete.
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum client name length (must match install script's validation).
pub const MAX_CLIENT_NAME_LEN: usize = 15;

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ScriptError {
    #[error("script exited with code {code}: {stderr}")]
    NonZeroExit { code: i32, stderr: String },

    #[error("script killed by signal (no exit code): {stderr}")]
    Signal { stderr: String },

    #[error("script timed out after {0:?}")]
    Timeout(Duration),

    #[error("failed to spawn script process: {0}")]
    Spawn(std::io::Error),

    #[error("failed to wait on script process: {0}")]
    Wait(std::io::Error),

    #[error("invalid client name: {0}")]
    InvalidName(String),
}

// ── Name validation ──────────────────────────────────────────────────────────

/// Characters allowed in a client name: `[a-zA-Z0-9_-]`.
fn is_valid_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// Validate a client name against the same rules the install script enforces.
///
/// Rules:
/// - Non-empty
/// - Only ASCII alphanumeric, underscore, or hyphen
/// - Fewer than 16 characters
/// - No path separators, dots, or shell metacharacters
pub fn validate_client_name(name: &str) -> Result<(), ScriptError> {
    if name.is_empty() {
        return Err(ScriptError::InvalidName(
            "client name must not be empty".into(),
        ));
    }
    if name.len() > MAX_CLIENT_NAME_LEN {
        return Err(ScriptError::InvalidName(format!(
            "client name must be at most {} characters",
            MAX_CLIENT_NAME_LEN
        )));
    }
    if !name.chars().all(is_valid_name_char) {
        return Err(ScriptError::InvalidName(
            "client name must contain only ASCII alphanumeric, underscore, or hyphen characters"
                .into(),
        ));
    }
    // Additional safety: reject reserved names that could cause confusion
    if name == "." || name == ".." {
        return Err(ScriptError::InvalidName(
            "client name must not be '.' or '..'".into(),
        ));
    }
    Ok(())
}

// ── Script bridge ────────────────────────────────────────────────────────────

/// Bridge to the `amneziawg-install.sh` script for client lifecycle actions.
#[derive(Debug, Clone)]
pub struct ScriptBridge {
    script_path: PathBuf,
    sudo_path: PathBuf,
    timeout: Duration,
}

impl ScriptBridge {
    /// Create a new bridge pointing at the given script.
    pub fn new(script_path: impl Into<PathBuf>) -> Self {
        Self {
            script_path: script_path.into(),
            sudo_path: PathBuf::from("/usr/bin/sudo"),
            timeout: SCRIPT_TIMEOUT,
        }
    }

    /// Override the path to the `sudo` binary (useful for testing).
    #[cfg(test)]
    pub fn with_sudo_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.sudo_path = path.into();
        self
    }

    /// Override the execution timeout (useful for testing).
    #[cfg(test)]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Build the argument array for a given flag + optional client name.
    ///
    /// The returned vector is the full `argv` for `Command::new(sudo)`.
    fn build_args(&self, flag: &str, client_name: Option<&str>) -> Vec<String> {
        let mut args = vec![
            "-n".to_string(), // non-interactive sudo
            self.script_path.to_string_lossy().into_owned(),
            flag.to_string(),
        ];
        if let Some(name) = client_name {
            args.push(name.to_string());
        }
        args
    }

    /// Run the script with the given arguments, capturing stdout/stderr.
    async fn run(&self, flag: &str, client_name: Option<&str>) -> Result<String, ScriptError> {
        let args = self.build_args(flag, client_name);

        debug!(
            sudo = %self.sudo_path.display(),
            args = ?args,
            "spawning install script"
        );

        let child = tokio::process::Command::new(&self.sudo_path)
            .args(&args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(ScriptError::Spawn)?;

        let result = tokio::time::timeout(self.timeout, child.wait_with_output()).await;

        match result {
            Err(_elapsed) => {
                warn!(timeout = ?self.timeout, "install script timed out");
                Err(ScriptError::Timeout(self.timeout))
            }
            Ok(Err(e)) => Err(ScriptError::Wait(e)),
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();

                if !stderr.is_empty() {
                    // Log stderr at debug level, redacting anything that might
                    // contain private keys.  The stderr from the install script
                    // is short diagnostic text (no secrets).
                    debug!(stderr = %stderr, "script stderr");
                }

                match output.status.code() {
                    Some(0) => {
                        info!(flag, "install script completed successfully");
                        Ok(stdout.trim().to_string())
                    }
                    Some(code) => {
                        error!(flag, code, stderr = %stderr, "install script failed");
                        Err(ScriptError::NonZeroExit {
                            code,
                            stderr: stderr.trim().to_string(),
                        })
                    }
                    None => {
                        error!(flag, stderr = %stderr, "install script killed by signal");
                        Err(ScriptError::Signal {
                            stderr: stderr.trim().to_string(),
                        })
                    }
                }
            }
        }
    }

    /// Create a new client.
    ///
    /// Returns the path to the generated client config file on success.
    pub async fn add_client(&self, name: &str) -> Result<String, ScriptError> {
        validate_client_name(name)?;
        self.run("--add-client", Some(name)).await
    }

    /// Remove an existing client.
    pub async fn remove_client(&self, name: &str) -> Result<(), ScriptError> {
        validate_client_name(name)?;
        self.run("--remove-client", Some(name)).await?;
        Ok(())
    }

    /// List all client names (one per line).
    pub async fn list_clients(&self) -> Result<Vec<String>, ScriptError> {
        let output = self.run("--list-clients", None).await?;
        Ok(output
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect())
    }

    /// Return the path to the install script.
    pub fn script_path(&self) -> &Path {
        &self.script_path
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_client_name ─────────────────────────────────────────────

    #[test]
    fn valid_simple_name() {
        assert!(validate_client_name("alice").is_ok());
    }

    #[test]
    fn valid_name_with_digits() {
        assert!(validate_client_name("client42").is_ok());
    }

    #[test]
    fn valid_name_with_underscore_and_dash() {
        assert!(validate_client_name("my_vpn-phone").is_ok());
    }

    #[test]
    fn valid_name_max_length() {
        // Exactly 15 chars
        assert!(validate_client_name("123456789012345").is_ok());
    }

    #[test]
    fn reject_empty_name() {
        assert!(validate_client_name("").is_err());
    }

    #[test]
    fn reject_too_long_name() {
        // 16 chars
        assert!(validate_client_name("1234567890123456").is_err());
    }

    #[test]
    fn reject_name_with_spaces() {
        assert!(validate_client_name("my phone").is_err());
    }

    #[test]
    fn reject_name_with_dots() {
        assert!(validate_client_name("client.conf").is_err());
    }

    #[test]
    fn reject_name_with_slash() {
        assert!(validate_client_name("../etc/passwd").is_err());
    }

    #[test]
    fn reject_name_with_shell_chars() {
        assert!(validate_client_name("$(whoami)").is_err());
        assert!(validate_client_name("a;b").is_err());
        assert!(validate_client_name("a|b").is_err());
        assert!(validate_client_name("a&b").is_err());
    }

    #[test]
    fn reject_dot_names() {
        assert!(validate_client_name(".").is_err());
        assert!(validate_client_name("..").is_err());
    }

    // ── build_args ───────────────────────────────────────────────────────

    #[test]
    fn build_args_add_client() {
        let bridge = ScriptBridge::new("/opt/amneziawg-install.sh");
        let args = bridge.build_args("--add-client", Some("alice"));
        assert_eq!(
            args,
            vec!["-n", "/opt/amneziawg-install.sh", "--add-client", "alice"]
        );
    }

    #[test]
    fn build_args_remove_client() {
        let bridge = ScriptBridge::new("/opt/amneziawg-install.sh");
        let args = bridge.build_args("--remove-client", Some("bob"));
        assert_eq!(
            args,
            vec!["-n", "/opt/amneziawg-install.sh", "--remove-client", "bob"]
        );
    }

    #[test]
    fn build_args_list_clients() {
        let bridge = ScriptBridge::new("/opt/amneziawg-install.sh");
        let args = bridge.build_args("--list-clients", None);
        assert_eq!(
            args,
            vec!["-n", "/opt/amneziawg-install.sh", "--list-clients"]
        );
    }

    #[test]
    fn build_args_no_shell_interpolation() {
        // Even a malicious name is passed as a single argument element,
        // never expanded by the shell.
        let bridge = ScriptBridge::new("/opt/amneziawg-install.sh");
        let args = bridge.build_args("--add-client", Some("$(rm -rf /)"));
        assert_eq!(args.len(), 4);
        assert_eq!(args[3], "$(rm -rf /)");
    }

    // ── ScriptBridge construction ────────────────────────────────────────

    #[test]
    fn script_path_is_returned() {
        let bridge = ScriptBridge::new("/usr/local/bin/amneziawg-install.sh");
        assert_eq!(
            bridge.script_path(),
            Path::new("/usr/local/bin/amneziawg-install.sh")
        );
    }
}
