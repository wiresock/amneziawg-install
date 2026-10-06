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
const PRIVILEGED_HELPER: &str = "/usr/local/libexec/amneziawg-web-privileged";
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
    pub runtime: RuntimeInfo,
    pub summary: String,
}

/// Only installed component versions may be cached. Runtime status must be
/// inspected again on every request, including after a failed probe.
#[derive(Debug, Clone)]
pub(crate) struct ComponentVersions {
    pub amneziawg: VersionInfo,
    pub web_panel: VersionInfo,
    pub proxy: VersionInfo,
}

impl ComponentVersions {
    pub(crate) fn with_runtime(self, runtime: RuntimeInfo) -> SystemVersions {
        let summary = header_summary(&runtime, env!("CARGO_PKG_VERSION"), &self.proxy);
        SystemVersions {
            amneziawg: self.amneziawg,
            web_panel: self.web_panel,
            proxy: self.proxy,
            runtime,
            summary,
        }
    }
}

/// Protocol configuration and the backend actually serving it are independent
/// of the version of any installed kernel module or command-line tools.
#[derive(Debug, Default, Clone, Serialize, PartialEq, Eq)]
pub struct RuntimeInfo {
    pub protocol: Option<String>,
    pub backend: Option<String>,
    pub service_state: Option<String>,
    pub module_state: Option<String>,
    pub daemon_state: Option<String>,
    pub version: Option<String>,
    pub release: Option<String>,
    pub imitation: Option<crate::imitation::Settings>,
    pub daemon_imitation: Option<crate::imitation::Settings>,
}

impl RuntimeInfo {
    fn parse(output: &str) -> Self {
        let fields: std::collections::HashMap<_, _> = output
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect();
        let value = |key| fields.get(key).copied().unwrap_or("");
        let mut info = Self {
            protocol: match value("awg_protocol") {
                "2" | "2.0" => Some("2.0".into()),
                "3" | "3.0" => Some("3.0".into()),
                "3.1" => Some("3.1".into()),
                _ => None,
            },
            backend: match value("backend") {
                "kernel" | "boringtun" => Some(value("backend").into()),
                _ => None,
            },
            service_state: match value("service_state") {
                "active" | "inactive" | "failed" | "activating" | "deactivating" => {
                    Some(value("service_state").into())
                }
                _ => None,
            },
            daemon_state: match value("daemon_state") {
                "running" | "stopped" | "unverified" => Some(value("daemon_state").into()),
                _ => None,
            },
            module_state: match value("module_state") {
                "loaded" | "not-loaded" => Some(value("module_state").into()),
                _ => None,
            },
            ..Self::default()
        };
        // An installed/current release can differ from the running executable.
        if info.backend.as_deref() == Some("boringtun") {
            info.imitation = crate::imitation::Settings::parse(
                value("imitation_protocol"),
                value("imitation_domain"),
            )
            .ok();
        }
        // Report only the release verified by the installer's live-daemon check.
        if info.backend.as_deref() == Some("boringtun")
            && info.service_state.as_deref() == Some("active")
            && info.daemon_state.as_deref() == Some("running")
        {
            info.daemon_imitation = crate::imitation::Settings::parse(
                value("daemon_imitation_protocol"),
                value("daemon_imitation_domain"),
            )
            .ok();
            let release = value("daemon_release");
            if let Some((version, _)) = release
                .strip_prefix("boringtun-cli-")
                .and_then(|s| s.split_once("-g"))
            {
                if version.split('.').count() == 3
                    && version
                        .split('.')
                        .all(|part| !part.is_empty() && part.bytes().all(|c| c.is_ascii_digit()))
                    && release.len() <= MAX_VERSION_LEN
                    && release
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b".-_".contains(&c))
                {
                    info.version = Some(version.into());
                    info.release = Some(release.into());
                }
            }
        }
        info
    }
}

fn header_summary(runtime: &RuntimeInfo, web_version: &str, proxy: &VersionInfo) -> String {
    let protocol = runtime
        .protocol
        .as_ref()
        .map(|p| format!("AWG {p}"))
        .unwrap_or_else(|| "unknown".into());
    let backend = match runtime.backend.as_deref() {
        Some("boringtun") => match runtime.version.as_deref() {
            Some(version) => format!("BoringTun {version}"),
            None => format!(
                "BoringTun ({})",
                match runtime.service_state.as_deref() {
                    Some("active" | "inactive") =>
                        runtime.daemon_state.as_deref().unwrap_or("unknown"),
                    state => state.unwrap_or("unknown"),
                }
            ),
        },
        Some("kernel") => match (
            runtime.service_state.as_deref(),
            runtime.module_state.as_deref(),
        ) {
            (Some("active"), Some("loaded")) => "AWG kernel".into(),
            (Some("active"), _) => "AWG kernel (unverified)".into(),
            (state, _) => format!("AWG kernel ({})", state.unwrap_or("unknown")),
        },
        _ => "unknown".into(),
    };
    let mut summary = format!("Protocol: {protocol} · Backend: {backend} · Panel: {web_version}");
    if runtime.backend.as_deref() == Some("kernel") && proxy.status != "not_installed" {
        summary.push_str(&format!(
            " · Proxy: {}",
            proxy.version.as_deref().unwrap_or("unknown")
        ));
    }
    summary
}

pub(crate) async fn detect_components() -> ComponentVersions {
    let (amneziawg, proxy) = tokio::join!(detect_amneziawg(), detect_proxy());
    ComponentVersions {
        amneziawg,
        web_panel: VersionInfo::installed(
            "AmneziaWG Web Panel",
            env!("CARGO_PKG_VERSION"),
            "amneziawg-web",
        ),
        proxy,
    }
}

pub(crate) async fn detect_runtime() -> RuntimeInfo {
    let sudo = Path::new(crate::awg::SUDO_BIN);
    match command_output(sudo, &["-n", PRIVILEGED_HELPER, "backend-status"]).await {
        ProbeResult::Version(output) => RuntimeInfo::parse(&output),
        ProbeResult::Failed(_) => {
            // Older helpers can still report the protocol, but a failure must
            // never be interpreted as evidence that the kernel backend is used.
            match command_first_line(sudo, &["-n", PRIVILEGED_HELPER, "protocol-status"]).await {
                ProbeResult::Version(protocol) => {
                    RuntimeInfo::parse(&format!("awg_protocol={protocol}"))
                }
                ProbeResult::Failed(_) => RuntimeInfo::default(),
            }
        }
    }
}

async fn detect_amneziawg() -> VersionInfo {
    for modinfo in ["/usr/sbin/modinfo", "/sbin/modinfo"] {
        let modinfo_path = Path::new(modinfo);
        if !modinfo_path.is_file() {
            continue;
        }
        for module in ["amneziawg"] {
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
    let candidates = match tokio::task::spawn_blocking(proxy_binary_candidates).await {
        Ok(candidates) => candidates,
        Err(_) => {
            return VersionInfo::unknown(
                "AmneziaWG Proxy",
                PROXY_SERVICE,
                "failed to inspect install paths",
            );
        }
    };
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

    const BORINGTUN_STATUS: &str = "backend=boringtun\nawg_protocol=2.0\nservice_state=active\ndaemon_state=running\ndaemon_release=boringtun-cli-0.7.1-gae2ab44e9a68-linux-x86_64-musl\ninstalled_release=boringtun-cli-9.9.9-gabcdef-linux-x86_64-musl\n";

    #[test]
    fn boringtun_header_separates_protocol_from_verified_running_release() {
        let runtime = RuntimeInfo::parse(BORINGTUN_STATUS);
        assert_eq!(runtime.protocol.as_deref(), Some("2.0"));
        assert_eq!(runtime.version.as_deref(), Some("0.7.1"));
        // Even stale proxy files must not add a proxy to a BoringTun header.
        let proxy = VersionInfo::installed("Proxy", "0.1.3", PROXY_BIN);
        assert_eq!(
            header_summary(&runtime, "0.1.21", &proxy),
            "Protocol: AWG 2.0 · Backend: BoringTun 0.7.1 · Panel: 0.1.21"
        );
    }

    #[test]
    fn boringtun_header_distinguishes_service_failure_from_stopped_daemon() {
        for (service, daemon, expected) in [
            ("inactive", "stopped", "stopped"),
            ("failed", "stopped", "failed"),
            ("activating", "stopped", "activating"),
            ("deactivating", "stopped", "deactivating"),
            ("active", "unverified", "unverified"),
            ("", "stopped", "unknown"),
        ] {
            let runtime = RuntimeInfo::parse(
                &BORINGTUN_STATUS
                    .replace("service_state=active", &format!("service_state={service}"))
                    .replace("daemon_state=running", &format!("daemon_state={daemon}")),
            );
            assert_eq!(runtime.version, None);
            assert_eq!(runtime.release, None);
            let summary = header_summary(&runtime, "0.1.21", &VersionInfo::not_installed("Proxy"));
            assert!(
                summary.contains(&format!("BoringTun ({expected})")),
                "{summary}"
            );
            assert!(!summary.contains("0.7.1"));
            assert!(!summary.contains("Proxy:"));
        }
    }

    #[test]
    fn kernel_header_shows_configured_protocol_and_only_relevant_proxy() {
        let runtime = RuntimeInfo::parse(
            "backend=kernel\nawg_protocol=3.1\nservice_state=active\nmodule_state=loaded\n",
        );
        assert_eq!(
            header_summary(
                &runtime,
                "0.1.21",
                &VersionInfo::installed("Proxy", "0.1.3", PROXY_BIN)
            ),
            "Protocol: AWG 3.1 · Backend: AWG kernel · Panel: 0.1.21 · Proxy: 0.1.3"
        );
        assert!(
            !header_summary(&runtime, "0.1.21", &VersionInfo::not_installed("Proxy"))
                .contains("Proxy:")
        );
    }

    #[test]
    fn kernel_header_distinguishes_service_and_module_state() {
        for (state, module, expected) in [
            ("active", "loaded", "AWG kernel"),
            ("inactive", "loaded", "AWG kernel (inactive)"),
            ("failed", "not-loaded", "AWG kernel (failed)"),
            ("activating", "loaded", "AWG kernel (activating)"),
            ("deactivating", "loaded", "AWG kernel (deactivating)"),
            ("active", "not-loaded", "AWG kernel (unverified)"),
            ("active", "", "AWG kernel (unverified)"),
            ("", "loaded", "AWG kernel (unknown)"),
        ] {
            let runtime = RuntimeInfo::parse(&format!(
                "backend=kernel\nawg_protocol=2\nservice_state={state}\nmodule_state={module}\n"
            ));
            assert_eq!(
                header_summary(&runtime, "0.1.21", &VersionInfo::not_installed("Proxy")),
                format!("Protocol: AWG 2.0 · Backend: {expected} · Panel: 0.1.21")
            );
        }
    }

    #[test]
    fn unknown_status_never_falls_back_to_a_module_version() {
        let runtime = RuntimeInfo::parse("backend=unexpected\nawg_protocol=1.0.0\n");
        assert_eq!(
            header_summary(
                &runtime,
                "0.1.21",
                &VersionInfo::unknown("Proxy", PROXY_BIN, "failed")
            ),
            "Protocol: unknown · Backend: unknown · Panel: 0.1.21"
        );
    }

    #[test]
    fn malformed_release_is_not_reported_as_a_backend_version() {
        for release in [
            "invalid",
            "boringtun-cli-<script>-g123",
            "boringtun-cli-0..1-g123",
        ] {
            let output = format!("backend=boringtun\nawg_protocol=2\nservice_state=active\ndaemon_state=running\ndaemon_release={release}\n");
            let runtime = RuntimeInfo::parse(&output);
            assert_eq!(runtime.version, None);
            assert_eq!(runtime.protocol.as_deref(), Some("2.0"));
        }
    }

    #[test]
    fn parse_modinfo_version_extracts_version() {
        let output = "filename: /lib/modules/amneziawg.ko\nversion: 2.0.0\nlicense: GPL\n";
        assert_eq!(parse_modinfo_version(output).as_deref(), Some("2.0.0"));
    }

    #[test]
    fn imitation_status_separates_configured_from_verified_running_settings() {
        let configured =
            "backend=boringtun\nimitation_protocol=quic\nimitation_domain=example.com\n";
        let live = "daemon_imitation_protocol=dns\ndaemon_imitation_domain=\n";
        for state in ["inactive", "failed", "active"] {
            let runtime = RuntimeInfo::parse(&format!(
                "{configured}{live}service_state={state}\ndaemon_state=running\n"
            ));
            assert_eq!(runtime.imitation.unwrap().protocol, "quic");
            assert_eq!(runtime.daemon_imitation.is_some(), state == "active");
        }
        let runtime = RuntimeInfo::parse(&format!(
            "{configured}{live}service_state=active\ndaemon_state=unverified\n"
        ));
        assert!(runtime.daemon_imitation.is_none());
        let runtime = RuntimeInfo::parse(&format!(
            "{configured}{live}service_state=active\ndaemon_state=running\n"
        ));
        assert_eq!(runtime.daemon_imitation.unwrap().protocol, "dns");
        let runtime = RuntimeInfo::parse("backend=kernel\nimitation_protocol=none\n");
        assert!(runtime.imitation.is_none());
        let runtime = RuntimeInfo::parse(
            "backend=boringtun\nimitation_protocol=quic\nimitation_domain=<script>\n",
        );
        assert!(runtime.imitation.is_none());
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
