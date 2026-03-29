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

use tokio::io::AsyncReadExt;
use thiserror::Error;
use tracing::{debug, error, info, warn};

/// Default absolute path to the install script on a standard system-wide install.
pub const DEFAULT_SCRIPT_PATH: &str = "/usr/local/bin/amneziawg-install.sh";

/// Maximum time to wait for the script to complete.
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum client name length (must match install script's validation).
pub const MAX_CLIENT_NAME_LEN: usize = 15;

/// Maximum number of chars to keep when logging stderr output.
const STDERR_LOG_LIMIT: usize = 512;

/// Maximum number of bytes to capture from stdout/stderr pipes.
///
/// Prevents unbounded memory usage if the script produces excessive output.
/// The value is generous enough for all expected output while still bounding
/// memory consumption (and the size of strings stored in error variants /
/// audit-event records).
const PIPE_CAPTURE_LIMIT: usize = 64 * 1024; // 64 KiB

/// Truncate stderr to [`STDERR_LOG_LIMIT`] chars for safe logging.
fn truncate_for_log(s: &str) -> String {
    s.chars().take(STDERR_LOG_LIMIT).collect()
}

/// Drain a pipe fully so the child process never gets a broken-pipe error.
///
/// Only the first [`PIPE_CAPTURE_LIMIT`] bytes are stored in `buf`; any excess
/// is read and discarded so the child can finish writing without blocking.
async fn drain_pipe<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> std::io::Result<()> {
    // Phase 1: read up to the capture limit into buf.
    let mut limited = reader.take(PIPE_CAPTURE_LIMIT as u64);
    limited.read_to_end(buf).await?;

    // Phase 2: if we hit the limit, the child may have more output.
    // Drain the remainder into a sink so the pipe stays open and the
    // child doesn't get a broken-pipe error.
    if buf.len() >= PIPE_CAPTURE_LIMIT {
        let inner = limited.into_inner();
        tokio::io::copy(inner, &mut tokio::io::sink()).await?;
    }
    Ok(())
}

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ScriptError {
    #[error("script exited with code {code}: {stderr}")]
    NonZeroExit { code: i32, stderr: String },

    #[error("script killed by signal (no exit code): {stderr}")]
    Signal { stderr: String },

    #[error("script timed out after {0:?}")]
    Timeout(Duration),

    #[error("another add/remove operation is already in progress")]
    LockBusy,

    #[error("lock I/O failure: {0}")]
    LockFailed(String),

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
/// - At most 15 characters
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
            sudo_path: PathBuf::from(crate::awg::SUDO_BIN),
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
    /// Uses `OsString` to preserve the exact script path bytes (no lossy
    /// UTF-8 conversion), which also ensures sudoers matching works for
    /// non-ASCII paths.
    fn build_args(&self, flag: &str, client_name: Option<&str>) -> Vec<std::ffi::OsString> {
        let mut args: Vec<std::ffi::OsString> = vec![
            "-n".into(), // non-interactive sudo
            self.script_path.as_os_str().to_owned(),
            flag.into(),
        ];
        if let Some(name) = client_name {
            args.push(name.into());
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

        let mut child = tokio::process::Command::new(&self.sudo_path)
            .args(&args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(ScriptError::Spawn)?;

        // Take ownership of stdout/stderr handles before the select! so we
        // can still kill the child on timeout.
        let stdout_handle = child.stdout.take();
        let stderr_handle = child.stderr.take();

        // Read stdout/stderr concurrently with waiting on the child process
        // to avoid deadlocks on full OS pipe buffers.
        //
        // We drain the pipes fully so the child process never gets a broken
        // pipe error, but only *store* up to PIPE_CAPTURE_LIMIT bytes.
        let stdout_fut = async move {
            let mut buf = Vec::new();
            if let Some(mut h) = stdout_handle {
                if let Err(e) = drain_pipe(&mut h, &mut buf).await {
                    warn!(error = %e, "failed to read child stdout");
                }
            }
            buf
        };

        let stderr_fut = async move {
            let mut buf = Vec::new();
            if let Some(mut h) = stderr_handle {
                if let Err(e) = drain_pipe(&mut h, &mut buf).await {
                    warn!(error = %e, "failed to read child stderr");
                }
            }
            buf
        };

        let timeout = self.timeout;
        tokio::select! {
            joined = async { tokio::join!(child.wait(), stdout_fut, stderr_fut) } => {
                let (status_result, stdout_buf, stderr_buf) = joined;
                let status = status_result.map_err(ScriptError::Wait)?;

                let stdout = String::from_utf8_lossy(&stdout_buf).to_string();
                let stderr = String::from_utf8_lossy(&stderr_buf).to_string();

                if !stderr.is_empty() {
                    // Log stderr at debug level.  The install script is
                    // expected to emit only short diagnostic text (no secrets).
                    // Truncate as a safety measure.
                    debug!(stderr = %truncate_for_log(&stderr), "script stderr");
                }

                match status.code() {
                    Some(0) => {
                        info!(flag, "install script completed successfully");
                        Ok(stdout.trim().to_string())
                    }
                    Some(code) => {
                        error!(flag, code, stderr = %truncate_for_log(&stderr), "install script failed");
                        Err(ScriptError::NonZeroExit {
                            code,
                            stderr: truncate_for_log(stderr.trim()),
                        })
                    }
                    None => {
                        error!(flag, stderr = %truncate_for_log(&stderr), "install script killed by signal");
                        Err(ScriptError::Signal {
                            stderr: truncate_for_log(stderr.trim()),
                        })
                    }
                }
            }
            _ = tokio::time::sleep(timeout) => {
                warn!(timeout = ?timeout, "install script timed out – killing child process");
                // Best-effort kill and reap; ignore errors (process may have already exited).
                let _ = child.kill().await;
                let _ = child.wait().await;
                Err(ScriptError::Timeout(timeout))
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
    use std::ffi::OsString;

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
        let expected: Vec<OsString> = vec![
            "-n".into(),
            "/opt/amneziawg-install.sh".into(),
            "--add-client".into(),
            "alice".into(),
        ];
        assert_eq!(args, expected);
    }

    #[test]
    fn build_args_remove_client() {
        let bridge = ScriptBridge::new("/opt/amneziawg-install.sh");
        let args = bridge.build_args("--remove-client", Some("bob"));
        let expected: Vec<OsString> = vec![
            "-n".into(),
            "/opt/amneziawg-install.sh".into(),
            "--remove-client".into(),
            "bob".into(),
        ];
        assert_eq!(args, expected);
    }

    #[test]
    fn build_args_list_clients() {
        let bridge = ScriptBridge::new("/opt/amneziawg-install.sh");
        let args = bridge.build_args("--list-clients", None);
        let expected: Vec<OsString> = vec![
            "-n".into(),
            "/opt/amneziawg-install.sh".into(),
            "--list-clients".into(),
        ];
        assert_eq!(args, expected);
    }

    #[test]
    fn build_args_no_shell_interpolation() {
        // Even a malicious name is passed as a single argument element,
        // never expanded by the shell.
        let bridge = ScriptBridge::new("/opt/amneziawg-install.sh");
        let args = bridge.build_args("--add-client", Some("$(rm -rf /)"));
        assert_eq!(args.len(), 4);
        assert_eq!(args[3], OsString::from("$(rm -rf /)"));
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
