//! Selection of the AmneziaWG interface the panel follows, and what it may do
//! with it.
//!
//! The installer supports one interface per host and records its name as
//! `SERVER_AWG_NIC` in the params file.  A host may still carry further,
//! hand-made AWG interfaces (for example `awg1` next to the managed `awg0`),
//! and `awg show all dump` reports all of them.  Without scoping, the poller
//! would record those foreign peers as if they were remnants of the panel's
//! own interface, and the enforcement helpers would act on interfaces the
//! panel does not own.
//!
//! [`InterfaceSelector`] resolves the followed interface, either from the
//! optional `AWG_INTERFACE` override or from the installer params, and
//! [`scope_to_interface`] narrows a parsed dump to that interface.
//!
//! Client creation and removal, expiration cleanup, peer enforcement and the
//! protocol and imitation controls all work through the installer's params,
//! server config and scripts, which only ever describe `SERVER_AWG_NIC`.  So
//! the selector also yields a [`PanelMode`]: following the installer's own
//! interface allows full management, while an override that names any other
//! interface (or unreadable params) puts the panel into monitoring-only mode,
//! in which it records the interface but never changes it, the installer's
//! interface, or the protocol.

use std::collections::HashSet;
use std::fmt;
use std::sync::{Arc, RwLock};

use crate::admin::client_manager::{parse_params, validate_interface_name_for};
use crate::awg::{self, AwgInterface};

/// Reads the installer params; normally the privileged helper's `read-params`.
type ParamsReader = Arc<dyn Fn() -> Result<String, awg::AwgError> + Send + Sync>;

/// Errors raised while determining the followed interface.
#[derive(Debug, thiserror::Error)]
pub enum ManagedInterfaceError {
    /// `AWG_INTERFACE` is set but is not a safe interface name.
    #[error("{0}")]
    InvalidOverride(String),

    /// The installer params could not be read through the privileged helper.
    #[error("failed to read installer params: {0}")]
    ParamsRead(#[source] awg::AwgError),

    /// The installer params do not describe a usable interface.
    #[error("failed to parse installer params: {0}")]
    ParamsParse(String),

    /// The blocking resolution task panicked or was cancelled.
    #[error("interface resolution task failed: {0}")]
    Task(String),
}

/// What this panel instance may do with the interface it follows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PanelMode {
    /// The followed interface is the installer's own: clients, peers and the
    /// protocol can be managed.
    Managing { interface: String },
    /// `AWG_INTERFACE` names an interface the installer does not manage, or
    /// the installer params cannot be read.  The panel records the interface
    /// but refuses every change to it, to the installer's interface, and to
    /// the protocol.
    MonitoringOnly {
        monitored: String,
        /// `SERVER_AWG_NIC` from the params, or `None` when they are unreadable.
        installer: Option<String>,
    },
}

impl PanelMode {
    /// The interface this panel instance follows.
    pub fn interface(&self) -> &str {
        match self {
            PanelMode::Managing { interface } => interface,
            PanelMode::MonitoringOnly { monitored, .. } => monitored,
        }
    }

    /// Whether clients, peers and the protocol may be managed.
    pub fn is_managing(&self) -> bool {
        matches!(self, PanelMode::Managing { .. })
    }

    /// Why management requests are refused, or `None` when managing.
    ///
    /// The text is shown to operators in error responses and page banners.
    pub fn management_unavailable(&self) -> Option<String> {
        match self {
            PanelMode::Managing { .. } => None,
            PanelMode::MonitoringOnly {
                monitored,
                installer: Some(installer),
            } => Some(format!(
                "this panel instance monitors {monitored} but the installer manages {installer}; \
                 client, peer and protocol management are unavailable (monitoring-only mode)"
            )),
            PanelMode::MonitoringOnly {
                monitored,
                installer: None,
            } => Some(format!(
                "this panel instance monitors {monitored} but the installer params could not be read; \
                 client, peer and protocol management are unavailable (monitoring-only mode)"
            )),
        }
    }
}

/// Decides which AWG interface the panel follows and in which [`PanelMode`].
///
/// Clones share one cache of the last resolved mode, so the poller's
/// per-cycle resolution is visible to the web handlers without another
/// privileged call.  The params are re-read on every resolution, so an
/// interface renamed by re-running the installer is picked up without a
/// restart.
#[derive(Clone)]
pub struct InterfaceSelector {
    /// Interface name pinned by `AWG_INTERFACE`; `None` defers to the params.
    override_name: Option<String>,
    read_params: ParamsReader,
    last_mode: Arc<RwLock<Option<ResolvedInterface>>>,
}

#[derive(Clone)]
struct ResolvedInterface {
    mode: PanelMode,
    installer_public_key: Option<String>,
    observed: Option<AwgInterface>,
}

/// Evidence tying client files to the selected server, shared by discovery
/// and exports. Monitoring requires a successful observation of that server.
pub(crate) struct ConfigScope {
    pub mode: PanelMode,
    pub server_public_key: String,
    monitored_peer_keys: Option<HashSet<String>>,
}

impl ConfigScope {
    pub fn permits_peer(&self, public_key: &str) -> bool {
        self.monitored_peer_keys
            .as_ref()
            .map_or(true, |keys| keys.contains(public_key))
    }
}

impl fmt::Debug for InterfaceSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InterfaceSelector")
            .field("override_name", &self.override_name)
            .field("last_mode", &self.last_mode())
            .finish()
    }
}

impl Default for InterfaceSelector {
    fn default() -> Self {
        Self::from_params()
    }
}

impl InterfaceSelector {
    fn new(override_name: Option<String>) -> Self {
        Self {
            override_name,
            read_params: Arc::new(awg::read_params_via_sudo),
            last_mode: Arc::new(RwLock::new(None)),
        }
    }

    /// Follow `SERVER_AWG_NIC` from the installer params.
    pub fn from_params() -> Self {
        Self::new(None)
    }

    /// Build a selector from the optional `AWG_INTERFACE` value.
    ///
    /// Surrounding whitespace is ignored and an empty value counts as unset,
    /// so a blank `AWG_INTERFACE=` line in the env file falls back to the
    /// params.  Any other value must pass the same validation as
    /// `SERVER_AWG_NIC`, because it is handed to the privileged helper.
    pub fn from_override(value: Option<&str>) -> Result<Self, ManagedInterfaceError> {
        let name = match value.map(str::trim).filter(|name| !name.is_empty()) {
            Some(name) => name,
            None => return Ok(Self::from_params()),
        };
        validate_interface_name_for("AWG_INTERFACE", name)
            .map_err(ManagedInterfaceError::InvalidOverride)?;
        Ok(Self::new(Some(name.to_string())))
    }

    /// Replace the installer-params reader (tests never run the helper).
    #[cfg(test)]
    pub fn with_params_reader<F>(mut self, read_params: F) -> Self
    where
        F: Fn() -> Result<String, awg::AwgError> + Send + Sync + 'static,
    {
        self.read_params = Arc::new(read_params);
        self
    }

    /// The `AWG_INTERFACE` override, if one is set.
    pub fn override_name(&self) -> Option<&str> {
        self.override_name.as_deref()
    }

    /// Where the followed interface name comes from, for log lines.
    pub fn source(&self) -> &'static str {
        if self.override_name.is_some() {
            "AWG_INTERFACE"
        } else {
            "SERVER_AWG_NIC"
        }
    }

    /// Resolve the panel mode and remember it.
    ///
    /// This reads the installer params through the privileged helper – a
    /// blocking `sudo` call – so run it off the async executor.  Without an
    /// override the params are required; with one, unreadable params merely
    /// mean monitoring-only mode.
    pub fn resolve_mode(&self) -> Result<PanelMode, ManagedInterfaceError> {
        let params = (self.read_params)();
        let installer_public_key = params
            .as_ref()
            .ok()
            .and_then(|content| parse_params(content).ok())
            .map(|params| params.server_pub_key);
        let mode = self.classify(params)?;
        let mut guard = self.last_mode.write().unwrap_or_else(|e| e.into_inner());
        let observed = guard
            .as_ref()
            .filter(|previous| {
                previous.mode == mode && previous.installer_public_key == installer_public_key
            })
            .and_then(|previous| previous.observed.clone());
        *guard = Some(ResolvedInterface {
            mode: mode.clone(),
            installer_public_key,
            observed,
        });
        Ok(mode)
    }

    /// [`resolve_mode`](Self::resolve_mode) on the blocking pool.
    pub async fn resolve_mode_off_thread(&self) -> Result<PanelMode, ManagedInterfaceError> {
        let selector = self.clone();
        match tokio::task::spawn_blocking(move || selector.resolve_mode()).await {
            Ok(result) => result,
            Err(e) => Err(ManagedInterfaceError::Task(e.to_string())),
        }
    }

    /// The last resolved mode, or a fresh resolution when none is cached yet
    /// (only before the poller's first cycle has completed).
    pub async fn current_mode(&self) -> Result<PanelMode, ManagedInterfaceError> {
        if let Some(mode) = self.last_mode() {
            return Ok(mode);
        }
        self.resolve_mode_off_thread().await
    }

    /// The last successfully resolved mode, if any.
    pub fn last_mode(&self) -> Option<PanelMode> {
        match self.last_mode.read() {
            Ok(guard) => guard.as_ref().map(|resolved| resolved.mode.clone()),
            Err(poisoned) => poisoned
                .into_inner()
                .as_ref()
                .map(|resolved| resolved.mode.clone()),
        }
    }

    /// Replace the live evidence after each successful dump, including an
    /// empty dump: an absent monitored interface must revoke old exports.
    pub(crate) fn observe_interfaces(&self, interfaces: &[AwgInterface]) {
        let mut guard = self.last_mode.write().unwrap_or_else(|e| e.into_inner());
        if let Some(resolved) = guard.as_mut() {
            resolved.observed = interfaces
                .iter()
                .find(|iface| iface.name == resolved.mode.interface())
                .cloned();
        }
    }

    pub(crate) async fn config_scope(&self) -> Result<Option<ConfigScope>, ManagedInterfaceError> {
        self.current_mode().await?;
        let guard = self.last_mode.read().unwrap_or_else(|e| e.into_inner());
        let Some(resolved) = guard.as_ref() else {
            return Ok(None);
        };
        let key = resolved
            .observed
            .as_ref()
            .map(|iface| &iface.public_key.0)
            // BoringTun does not expose its private key, so awg can report
            // "(none)" here. Only a usable live key overrides installer identity.
            .filter(|key| !key.is_empty() && key.as_str() != "(none)")
            .or_else(|| {
                resolved
                    .mode
                    .is_managing()
                    .then_some(resolved.installer_public_key.as_ref())
                    .flatten()
            });
        let Some(key) = key.filter(|key| !key.is_empty() && key.as_str() != "(none)") else {
            return Ok(None);
        };
        Ok(Some(ConfigScope {
            mode: resolved.mode.clone(),
            server_public_key: key.clone(),
            monitored_peer_keys: (!resolved.mode.is_managing()).then(|| {
                resolved
                    .observed
                    .iter()
                    .flat_map(|iface| &iface.peers)
                    .map(|peer| peer.public_key.0.clone())
                    .collect()
            }),
        }))
    }

    fn classify(
        &self,
        params: Result<String, awg::AwgError>,
    ) -> Result<PanelMode, ManagedInterfaceError> {
        let installer = params
            .map_err(ManagedInterfaceError::ParamsRead)
            .and_then(|content| {
                parse_params(&content)
                    .map(|params| params.server_awg_nic)
                    .map_err(|e| ManagedInterfaceError::ParamsParse(e.to_string()))
            });
        match (&self.override_name, installer) {
            (None, Ok(interface)) => Ok(PanelMode::Managing { interface }),
            (None, Err(e)) => Err(e),
            (Some(monitored), Ok(installer)) if installer == *monitored => {
                Ok(PanelMode::Managing {
                    interface: installer,
                })
            }
            (Some(monitored), Ok(installer)) => Ok(PanelMode::MonitoringOnly {
                monitored: monitored.clone(),
                installer: Some(installer),
            }),
            (Some(monitored), Err(e)) => {
                tracing::debug!(
                    error = %e,
                    monitored = %monitored,
                    "installer params unavailable – AWG_INTERFACE runs in monitoring-only mode"
                );
                Ok(PanelMode::MonitoringOnly {
                    monitored: monitored.clone(),
                    installer: None,
                })
            }
        }
    }
}

/// A parsed dump narrowed to the followed interface.
#[derive(Debug, Default)]
pub struct ScopedInterfaces {
    /// The followed interface when the dump contained it (at most one entry).
    pub matched: Vec<AwgInterface>,
    /// Names of the other interfaces in the dump, sorted.
    pub ignored: Vec<String>,
}

/// Keep only the interface named `managed`, reporting the others by name.
pub fn scope_to_interface(interfaces: Vec<AwgInterface>, managed: &str) -> ScopedInterfaces {
    let mut scoped = ScopedInterfaces::default();
    for iface in interfaces {
        if iface.name == managed {
            scoped.matched.push(iface);
        } else {
            scoped.ignored.push(iface.name);
        }
    }
    scoped.ignored.sort();
    scoped
}

/// Minimal AWG 2.0 installer params naming `nic`, for tests across the crate.
#[cfg(test)]
pub(crate) fn test_params(nic: &str) -> String {
    format!(
        "SERVER_PUB_IP='198.51.100.1'\nSERVER_AWG_NIC='{nic}'\nSERVER_AWG_IPV4='10.66.66.1'\n\
         SERVER_AWG_IPV6='fd42:42:42::1'\nSERVER_PORT='51820'\nSERVER_PUB_KEY='PUB'\n\
         CLIENT_DNS_1='1.1.1.1'\nALLOWED_IPS='0.0.0.0/0, ::/0'\nSERVER_AWG_JC='4'\n\
         SERVER_AWG_JMIN='50'\nSERVER_AWG_JMAX='1000'\nSERVER_AWG_S1='30'\nSERVER_AWG_S2='100'\n\
         SERVER_AWG_S3='45'\nSERVER_AWG_S4='120'\nSERVER_AWG_H1='5-10'\nSERVER_AWG_H2='11-20'\n\
         SERVER_AWG_H3='21-30'\nSERVER_AWG_H4='31-40'\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::PublicKey;

    fn unreadable_params() -> Result<String, awg::AwgError> {
        Err(awg::AwgError::NonZeroExit {
            status: 1,
            stderr: "sudo: a password is required".into(),
        })
    }

    fn iface(name: &str, peer_keys: &[&str]) -> AwgInterface {
        AwgInterface {
            name: name.to_string(),
            public_key: PublicKey(format!("{name}_SERVER_KEY=")),
            listen_port: Some(51820),
            peers: peer_keys
                .iter()
                .map(|key| awg::AwgPeer {
                    public_key: PublicKey((*key).to_string()),
                    endpoint: None,
                    allowed_ips: Vec::new(),
                    last_handshake: None,
                    rx_bytes: 0,
                    tx_bytes: 0,
                })
                .collect(),
        }
    }

    #[test]
    fn override_is_trimmed_and_blank_means_unset() {
        let trimmed = InterfaceSelector::from_override(Some("  awg1\n")).expect("trimmed");
        assert_eq!(trimmed.override_name(), Some("awg1"));
        assert_eq!(trimmed.source(), "AWG_INTERFACE");

        for blank in [None, Some(""), Some("   ")] {
            let selector = InterfaceSelector::from_override(blank).expect("blank is unset");
            assert!(selector.override_name().is_none());
            assert_eq!(selector.source(), "SERVER_AWG_NIC");
        }
    }

    #[test]
    fn override_is_validated_like_server_awg_nic() {
        for invalid in [
            "-awg0",
            "../etc",
            "awg0/conf",
            "awg 0",
            "1234567890123456",
            "awg0;id",
        ] {
            let error = InterfaceSelector::from_override(Some(invalid)).expect_err(invalid);
            assert!(
                matches!(error, ManagedInterfaceError::InvalidOverride(_)),
                "{invalid}: {error}"
            );
            assert!(
                error.to_string().contains("AWG_INTERFACE"),
                "{invalid}: {error}"
            );
        }
    }

    #[test]
    fn params_alone_select_the_installer_interface_for_management() {
        let selector =
            InterfaceSelector::from_params().with_params_reader(|| Ok(test_params("awg0")));
        assert_eq!(
            selector.resolve_mode().expect("resolve"),
            PanelMode::Managing {
                interface: "awg0".into()
            }
        );
    }

    #[test]
    fn override_matching_the_params_keeps_management() {
        let selector = InterfaceSelector::from_override(Some("awg0"))
            .expect("valid override")
            .with_params_reader(|| Ok(test_params("awg0")));
        let mode = selector.resolve_mode().expect("resolve");
        assert!(mode.is_managing());
        assert_eq!(mode.interface(), "awg0");
        assert!(mode.management_unavailable().is_none());
    }

    #[test]
    fn override_naming_another_interface_is_monitoring_only() {
        let selector = InterfaceSelector::from_override(Some("awg1"))
            .expect("valid override")
            .with_params_reader(|| Ok(test_params("awg0")));
        let mode = selector.resolve_mode().expect("resolve");
        assert_eq!(
            mode,
            PanelMode::MonitoringOnly {
                monitored: "awg1".into(),
                installer: Some("awg0".into()),
            }
        );
        assert_eq!(mode.interface(), "awg1");

        let reason = mode.management_unavailable().expect("reason");
        assert!(reason.contains("monitors awg1"), "{reason}");
        assert!(reason.contains("installer manages awg0"), "{reason}");
    }

    #[test]
    fn override_with_unreadable_params_is_monitoring_only() {
        let selector = InterfaceSelector::from_override(Some("awg1"))
            .expect("valid override")
            .with_params_reader(unreadable_params);
        let mode = selector.resolve_mode().expect("override needs no params");
        assert_eq!(
            mode,
            PanelMode::MonitoringOnly {
                monitored: "awg1".into(),
                installer: None,
            }
        );
        let reason = mode.management_unavailable().expect("reason");
        assert!(reason.contains("params could not be read"), "{reason}");

        let unparseable = InterfaceSelector::from_override(Some("awg1"))
            .expect("valid override")
            .with_params_reader(|| Ok("SERVER_AWG_NIC='awg0'\n".to_string()));
        assert!(!unparseable.resolve_mode().expect("resolve").is_managing());
    }

    #[test]
    fn params_failures_are_errors_without_an_override() {
        let unreadable = InterfaceSelector::from_params().with_params_reader(unreadable_params);
        let error = unreadable.resolve_mode().expect_err("read failure");
        assert!(matches!(error, ManagedInterfaceError::ParamsRead(_)));
        assert!(error.to_string().contains("a password is required"));
        assert!(unreadable.last_mode().is_none());

        let missing_keys = InterfaceSelector::from_params()
            .with_params_reader(|| Ok("SERVER_AWG_NIC='awg0'\n".to_string()));
        assert!(matches!(
            missing_keys.resolve_mode().expect_err("missing keys"),
            ManagedInterfaceError::ParamsParse(_)
        ));

        let unsafe_nic = InterfaceSelector::from_params()
            .with_params_reader(|| Ok(test_params("awg0").replace("'awg0'", "'../etc'")));
        assert!(matches!(
            unsafe_nic.resolve_mode().expect_err("unsafe nic"),
            ManagedInterfaceError::ParamsParse(_)
        ));
    }

    #[test]
    fn resolved_mode_is_shared_between_clones() {
        let selector = InterfaceSelector::from_override(Some("awg1"))
            .expect("valid override")
            .with_params_reader(|| Ok(test_params("awg0")));
        let clone = selector.clone();
        assert!(selector.last_mode().is_none());

        let mode = clone.resolve_mode().expect("resolve");
        assert_eq!(selector.last_mode(), Some(mode));
    }

    #[tokio::test]
    async fn current_mode_resolves_once_and_then_serves_the_cache() {
        let selector = InterfaceSelector::from_override(Some("awg1"))
            .expect("valid override")
            .with_params_reader(|| Ok(test_params("awg0")));
        let first = selector.current_mode().await.expect("first resolution");
        assert!(!first.is_managing());

        let off_thread = selector
            .resolve_mode_off_thread()
            .await
            .expect("off-thread resolution");
        assert_eq!(off_thread, first);
        assert_eq!(selector.current_mode().await.expect("cached"), first);
    }

    #[tokio::test]
    async fn config_scope_uses_installer_key_when_managed_dump_omits_public_key() {
        for unavailable in ["(none)", ""] {
            let selector =
                InterfaceSelector::from_params().with_params_reader(|| Ok(test_params("awg0")));
            selector.resolve_mode().expect("managed interface");
            let mut observed = iface("awg0", &["CLIENT="]);
            observed.public_key = PublicKey(unavailable.into());
            selector.observe_interfaces(&[observed]);

            let scope = selector
                .config_scope()
                .await
                .expect("scope lookup")
                .expect("managed BoringTun interface must retain its installer identity");
            assert_eq!(scope.server_public_key, "PUB");
            let config = crate::config_store::ClientConfig::from_content(
                "/clients/awg0-client-alice.conf".into(),
                "[Interface]\nAddress = 10.66.66.2/32\n[Peer]\nPublicKey = PUB\n",
            );
            assert!(
                config.belongs_to(&scope),
                "{unavailable}: own client stays linked"
            );
        }
    }

    #[tokio::test]
    async fn config_scope_does_not_lend_installer_key_to_unidentified_monitored_interface() {
        for unavailable in ["(none)", ""] {
            let selector = InterfaceSelector::from_override(Some("awg1"))
                .expect("valid override")
                .with_params_reader(|| Ok(test_params("awg0")));
            selector.resolve_mode().expect("monitoring interface");
            let mut observed = iface("awg1", &["FOREIGN="]);
            observed.public_key = PublicKey(unavailable.into());
            selector.observe_interfaces(&[observed]);
            assert!(selector
                .config_scope()
                .await
                .expect("scope lookup")
                .is_none());
        }
    }

    #[tokio::test]
    async fn config_scope_prefers_observed_key_over_installer_key() {
        let selector =
            InterfaceSelector::from_params().with_params_reader(|| Ok(test_params("awg0")));
        selector.resolve_mode().expect("managed interface");
        selector.observe_interfaces(&[iface("awg0", &["CLIENT="])]);
        let scope = selector
            .config_scope()
            .await
            .expect("scope lookup")
            .expect("live identity");
        assert_eq!(scope.server_public_key, "awg0_SERVER_KEY=");
        let stale = crate::config_store::ClientConfig::from_content(
            "/clients/awg0-client-alice.conf".into(),
            "[Interface]\nAddress = 10.66.66.2/32\n[Peer]\nPublicKey = PUB\n",
        );
        assert!(
            !stale.belongs_to(&scope),
            "a real observed key must remain authoritative"
        );
    }

    #[test]
    fn scope_keeps_only_the_managed_interface() {
        let dump = vec![
            iface("awg1", &["FOREIGN="]),
            iface("awg0", &["A=", "B="]),
            iface("wg0", &[]),
        ];
        let scoped = scope_to_interface(dump, "awg0");
        assert_eq!(scoped.matched.len(), 1);
        assert_eq!(scoped.matched[0].name, "awg0");
        assert_eq!(scoped.matched[0].peers.len(), 2);
        assert_eq!(scoped.ignored, vec!["awg1".to_string(), "wg0".to_string()]);
    }

    #[test]
    fn scope_reports_a_missing_managed_interface() {
        let scoped = scope_to_interface(vec![iface("awg1", &["FOREIGN="])], "awg0");
        assert!(scoped.matched.is_empty());
        assert_eq!(scoped.ignored, vec!["awg1".to_string()]);

        let empty = scope_to_interface(Vec::new(), "awg0");
        assert!(empty.matched.is_empty());
        assert!(empty.ignored.is_empty());
    }
}
