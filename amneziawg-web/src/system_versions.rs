//! Best-effort system version detection for the web panel.
//!
//! Probes use fixed binaries and explicit argv arrays only. The web UI treats
//! every value as informational: failures are reported as unavailable/unknown
//! without exposing raw stderr.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::Serialize;
use tokio::process::Command;

const AWG_BIN: &str = "/usr/bin/awg";
const PROXY_BIN: &str = "/usr/local/bin/amneziawg-proxy";
const PROXY_SERVICE: &str = "/etc/systemd/system/amneziawg-proxy.service";
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_VERSION_LEN: usize = 160;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VersionInfo {
    pub name: String,
    pub status: String,
    pub version: Option<String>,
    pub source: Option<String>,
    pub error: Option<String>,
}

impl VersionInfo {
    fn installed(name: &str, version: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            name: name.to_string(),
            status: "installed".to_string(),
            version: Some(version.into()),
            source: Some(source.into()),
            error: None,
        }
    }

    fn not_installed(name: &str) -> Self {
        Self {
            name: name.to_string(),
            status: "not_installed".to_string(),
            version: None,
            source: None,
            error: None,
        }
    }

    fn unknown(name: &str, source: impl Into<String>, error: &str) -> Self {
        Self {
            name: name.to_string(),
            status: "unknown".to_string(),
            version: None,
            source: Some(source.into()),
            error: Some(error.to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SystemVersions {
    pub amneziawg: VersionInfo,
    pub web_panel: VersionInfo,
    pub proxy: VersionInfo,
}

pub async fn detect() -> SystemVersions {
    let (amneziawg, proxy) = tokio::join!(detect_amneziawg(), detect_proxy());
    SystemVersions {
        amneziawg,
        web_panel: VersionInfo::installed(
            "AmneziaWG Web Panel",
            env!("CARGO_PKG_VERSION"),
            "amneziawg-web",
        ),
        proxy,
    }
}

async fn detect_amneziawg() -> VersionInfo {
    for modinfo in ["/usr/sbin/modinfo", "/sbin/modinfo"] {
        let modinfo_path = Path::new(modinfo);
        if !modinfo_path.is_file() {
            continue;
        }
        for module in ["amneziawg", "wireguard"] {
            match command_output(modinfo_path, &[module]).await {
                ProbeResult::Version(output) => {
                    if let Some(version) = parse_modinfo_version(&output) {
                        return VersionInfo::installed(
                            "AmneziaWG Module",
                            version,
                            format!("{modinfo} {module}"),
                        );
                    }
                }
                ProbeResult::Failed(_) => {
                    // Try the next module/path before reporting not installed.
                }
            }
        }
    }

    let awg_path = Path::new(AWG_BIN);
    if awg_path.is_file() {
        match command_first_line(awg_path, &["--version"]).await {
            ProbeResult::Version(line) => {
                return VersionInfo::installed("AmneziaWG", normalize_awg_version(&line), AWG_BIN);
            }
            ProbeResult::Failed(error) => {
                return VersionInfo::unknown("AmneziaWG", AWG_BIN, error);
            }
        }
    }

    VersionInfo::not_installed("AmneziaWG Module")
}

async fn detect_proxy() -> VersionInfo {
    let candidates = proxy_binary_candidates();
    if candidates.is_empty() {
        return VersionInfo::not_installed("AmneziaWG Proxy");
    }

    let mut first_error = None;
    for path in candidates {
        match command_first_line(&path, &["--version"]).await {
            ProbeResult::Version(line) => {
                return VersionInfo::installed(
                    "AmneziaWG Proxy",
                    normalize_proxy_version(&line),
                    path.display().to_string(),
                );
            }
            ProbeResult::Failed(error) => {
                if first_error.is_none() {
                    first_error = Some((path.display().to_string(), error));
                }
            }
        }
    }

    if let Some((source, error)) = first_error {
        return VersionInfo::unknown("AmneziaWG Proxy", source, error);
    }

    VersionInfo::not_installed("AmneziaWG Proxy")
}

fn proxy_binary_candidates() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let default = PathBuf::from(PROXY_BIN);
    if default.is_file() {
        paths.push(default);
    }

    if let Ok(service) = std::fs::read_to_string(PROXY_SERVICE) {
        if let Some(path) = parse_proxy_exec_start(&service) {
            if path.is_file() && !paths.iter().any(|existing| existing == &path) {
                paths.push(path);
            }
        }
    }

    paths
}

enum ProbeResult {
    Version(String),
    Failed(&'static str),
}

async fn command_first_line(path: &Path, args: &[&str]) -> ProbeResult {
    match command_output(path, args).await {
        ProbeResult::Version(output) => first_non_empty_line(&output)
            .map(ProbeResult::Version)
            .unwrap_or(ProbeResult::Failed("version not reported")),
        ProbeResult::Failed(error) => ProbeResult::Failed(error),
    }
}

async fn command_output(path: &Path, args: &[&str]) -> ProbeResult {
    let child = Command::new(path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn();

    let child = match child {
        Ok(child) => child,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return ProbeResult::Failed("not found");
        }
        Err(_) => return ProbeResult::Failed("failed to start"),
    };

    let output = match tokio::time::timeout(PROBE_TIMEOUT, child.wait_with_output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(_)) => return ProbeResult::Failed("failed to read output"),
        Err(_) => return ProbeResult::Failed("timed out"),
    };

    if !output.status.success() {
        return ProbeResult::Failed("command failed");
    }

    ProbeResult::Version(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn first_non_empty_line(output: &str) -> Option<String> {
    output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(truncate_version)
}

fn truncate_version(value: &str) -> String {
    value.chars().take(MAX_VERSION_LEN).collect()
}

fn normalize_proxy_version(line: &str) -> String {
    line.strip_prefix("amneziawg-proxy ")
        .unwrap_or(line)
        .trim()
        .to_string()
}

fn normalize_awg_version(line: &str) -> String {
    truncate_version(line.trim())
}

fn parse_modinfo_version(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim() == "version" {
            let value = value.trim();
            if !value.is_empty() {
                return Some(truncate_version(value));
            }
        }
        None
    })
}

fn parse_proxy_exec_start(service: &str) -> Option<PathBuf> {
    for line in service.lines() {
        let trimmed = line.trim();
        let Some(value) = trimmed.strip_prefix("ExecStart=") else {
            continue;
        };
        let value = value.strip_prefix('-').unwrap_or(value).trim_start();
        let Some(binary) = parse_first_exec_token(value) else {
            continue;
        };
        let path = PathBuf::from(&binary);
        if is_absolute_proxy_path(&binary, &path) {
            return Some(path);
        }
    }
    None
}

fn is_absolute_proxy_path(raw: &str, path: &Path) -> bool {
    (path.is_absolute() || raw.starts_with('/'))
        && path.file_name().and_then(|n| n.to_str()) == Some("amneziawg-proxy")
}

fn parse_first_exec_token(value: &str) -> Option<String> {
    let mut chars = value.chars();
    match chars.next()? {
        '"' => Some(chars.take_while(|c| *c != '"').collect()),
        '\'' => Some(chars.take_while(|c| *c != '\'').collect()),
        first => {
            let mut token = String::new();
            token.push(first);
            token.extend(chars.take_while(|c| !c.is_whitespace()));
            Some(token)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_modinfo_version_extracts_version() {
        let output = "filename: /lib/modules/amneziawg.ko\nversion: 2.0.0\nlicense: GPL\n";
        assert_eq!(parse_modinfo_version(output).as_deref(), Some("2.0.0"));
    }

    #[test]
    fn parse_modinfo_version_missing_returns_none() {
        assert_eq!(parse_modinfo_version("filename: x\nlicense: GPL\n"), None);
    }

    #[test]
    fn normalize_proxy_version_strips_binary_name() {
        assert_eq!(normalize_proxy_version("amneziawg-proxy 0.1.2"), "0.1.2");
    }

    #[test]
    fn parse_proxy_exec_start_accepts_absolute_proxy_path() {
        let service = "ExecStart=/usr/local/bin/amneziawg-proxy /etc/amneziawg-proxy/proxy.toml\n";
        assert_eq!(
            parse_proxy_exec_start(service).as_deref(),
            Some(Path::new("/usr/local/bin/amneziawg-proxy"))
        );
    }

    #[test]
    fn parse_proxy_exec_start_accepts_quoted_path() {
        let service = "ExecStart=\"/opt/proxy bin/amneziawg-proxy\" /etc/proxy.toml\n";
        assert_eq!(
            parse_proxy_exec_start(service).as_deref(),
            Some(Path::new("/opt/proxy bin/amneziawg-proxy"))
        );
    }

    #[test]
    fn parse_proxy_exec_start_skips_empty_entries() {
        let service =
            "ExecStart=\nExecStart=/usr/local/bin/amneziawg-proxy /etc/amneziawg-proxy/proxy.toml\n";
        assert_eq!(
            parse_proxy_exec_start(service).as_deref(),
            Some(Path::new("/usr/local/bin/amneziawg-proxy"))
        );
    }

    #[test]
    fn parse_proxy_exec_start_rejects_other_binary() {
        let service = "ExecStart=/usr/local/bin/not-proxy /etc/proxy.toml\n";
        assert_eq!(parse_proxy_exec_start(service), None);
    }

    #[test]
    fn first_non_empty_line_trims_output() {
        assert_eq!(
            first_non_empty_line("\n  amneziawg-proxy 0.1.0\nextra").as_deref(),
            Some("amneziawg-proxy 0.1.0")
        );
    }
}
