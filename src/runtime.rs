//! Unified service assembly. One identity, one Node and one bounded service dispatcher.
use crate::{ai_worker, ops, rooms};
use anyhow::{Context, Result, ensure};
use authority::authority::Authority;
use authority::events::PROTOCOL as EVENTS_PROTOCOL;
use authority::journal::{Journal, PROTOCOL as GOVERNANCE_PROTOCOL};
use node::{AccessPolicy, Identity, Node, NodeConfig, PeerId, Service, ServiceId};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    sync::{Mutex, mpsc},
    task::JoinSet,
};

pub use crate::ai_worker::Config as AiWorkerConfig;
pub use client::application::Application;
const SERVICE_QUEUE: usize = 32;
const MAX_ROOMS: usize = 8;
const CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub node: Network,
    #[serde(default)]
    pub services: Services,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub key: PathBuf,
    #[serde(default)]
    pub listen: Vec<String>,
    #[serde(default)]
    pub external: Vec<String>,
    #[serde(default)]
    pub bootstrap: Vec<String>,
    #[serde(default)]
    pub reserve: Vec<String>,
    #[serde(default)]
    pub lan_discovery: bool,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Services {
    pub identity: Option<IdentityService>,
    pub league_proxy: Option<LeagueProxy>,
    pub scoring: Option<Scoring>,
    pub directory: bool,
    pub relay: RelayService,
    pub governance: Option<Governance>,
    pub ai_worker: Option<AiWorkerConfig>,
    pub activity_oracle: Option<crate::activity::Config>,
    pub workflow_worker: Option<crate::workflow_worker::Config>,
    pub notifications: Option<crate::notifications::Config>,
    pub report_board: Option<crate::report_board::Config>,
    pub operations: Option<Operations>,
    pub member_rooms: Vec<rooms::HostConfig>,
    pub documents: Option<Documents>,
}

/// Relay service toggle: `true`/`false` keeps the default circuit limits, a table overrides them.
/// Manual deserialization keeps `deny_unknown_fields` on `RelayLimits` effective (untagged enums would ignore it).
#[derive(Debug)]
pub enum RelayService {
    Toggle(bool),
    Limits(RelayLimits),
}

impl Default for RelayService {
    fn default() -> Self {
        Self::Toggle(false)
    }
}

impl<'de> Deserialize<'de> for RelayService {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        match serde_json::Value::deserialize(deserializer)? {
            serde_json::Value::Bool(enabled) => Ok(Self::Toggle(enabled)),
            value @ serde_json::Value::Object(_) => RelayLimits::deserialize(value)
                .map(Self::Limits)
                .map_err(serde::de::Error::custom),
            _ => Err(serde::de::Error::custom(
                "relay must be a boolean or a limits table",
            )),
        }
    }
}

impl RelayService {
    fn config(&self) -> Option<node::RelayConfig> {
        match self {
            Self::Toggle(true) => Some(node::RelayConfig::default()),
            Self::Toggle(false) => None,
            Self::Limits(limits) => Some(limits.config()),
        }
    }
    fn enabled(&self) -> bool {
        !matches!(self, Self::Toggle(false))
    }
}

/// Relay circuit limits; every field falls back to `node::RelayConfig::default()`.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RelayLimits {
    pub max_reservations: usize,
    pub max_circuits: usize,
    pub max_circuit_bytes: u64,
    pub max_circuit_duration_seconds: u64,
}

impl Default for RelayLimits {
    fn default() -> Self {
        let defaults = node::RelayConfig::default();
        Self {
            max_reservations: defaults.max_reservations,
            max_circuits: defaults.max_circuits,
            max_circuit_bytes: defaults.max_circuit_bytes,
            max_circuit_duration_seconds: defaults.max_circuit_duration.as_secs(),
        }
    }
}

impl RelayLimits {
    fn config(&self) -> node::RelayConfig {
        node::RelayConfig {
            max_reservations: self.max_reservations,
            max_circuits: self.max_circuits,
            max_circuit_bytes: self.max_circuit_bytes,
            max_circuit_duration: std::time::Duration::from_secs(self.max_circuit_duration_seconds),
        }
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.max_reservations > 0
                && self.max_circuits > 0
                && self.max_circuit_bytes > 0
                && self.max_circuit_duration_seconds > 0,
            "relay limits must be positive"
        );
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeagueProxy {
    pub config: crate::native::Config,
    pub key: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scoring {
    pub bind: std::net::SocketAddr,
    pub key: PathBuf,
    pub token: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityService {
    #[serde(default)]
    pub genesis: PathBuf,
    #[serde(default)]
    pub genesis_hash: String,
    #[serde(skip)]
    root: Option<node::protocol::TrustGenesis>,
    pub log: PathBuf,
    pub writer: bool,
    pub source: Option<IdentitySource>,
    pub max_staleness_seconds: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySource {
    pub peer: String,
    pub address: String,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Governance {
    #[serde(default)]
    pub replication: Option<Replication>,
    pub genesis: PathBuf,
    pub journal: PathBuf,
    #[serde(default)]
    pub binding: Option<node::protocol::TrustBusinessBinding>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Replication {
    pub id: u64,
    #[serde(default)]
    pub initialize: bool,
    pub peers: std::collections::BTreeMap<u64, state::governance::ConsensusPeer>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operations {
    pub service: String,
    pub instances: Vec<rooms::InstanceConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Documents {
    pub service: String,
    pub directory: PathBuf,
}
fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    ensure!(
        std::fs::metadata(path)?.len() <= CONFIG_BYTES,
        "configuration file too large"
    );
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}
fn relative(base: &Path, path: &mut PathBuf) {
    if path.is_relative() {
        *path = base.join(&*path);
    }
}
impl Config {
    /// Identity services require the caller's root; directory and relay nodes do not.
    pub fn load(
        path: &Path,
        genesis: Option<&node::protocol::TrustGenesis>,
    ) -> crate::Result<Self> {
        Self::load_inner(path, genesis).map_err(crate::operation_error)
    }
    fn load_inner(path: &Path, genesis: Option<&node::protocol::TrustGenesis>) -> Result<Self> {
        let path = path.canonicalize()?;
        let base = path.parent().context("configuration directory missing")?;
        let mut config: Self = read(&path)?;
        relative(base, &mut config.node.key);
        if let Some(identity) = &mut config.services.identity {
            let genesis = genesis.context("identity service requires an explicit trust root")?;
            let pin = crate::bootstrap::validate_genesis(genesis)?;
            ensure!(
                identity.genesis_hash.is_empty() || identity.genesis_hash == pin,
                "identity genesis does not match the supplied trust root"
            );
            identity.genesis_hash = pin;
            identity.root = Some(genesis.clone());
            if !identity.genesis.as_os_str().is_empty() {
                relative(base, &mut identity.genesis);
                let configured: node::protocol::TrustGenesis = read(&identity.genesis)?;
                ensure!(
                    configured == *genesis,
                    "identity genesis file does not match the supplied trust root"
                );
            }
            relative(base, &mut identity.log);
        }
        if let Some(proxy) = &mut config.services.league_proxy {
            relative(base, &mut proxy.key);
            relative(base, &mut proxy.config.waiting.forwarding_secret);
            relative(base, &mut proxy.config.arena.forwarding_secret);
        }
        if let Some(scoring) = &mut config.services.scoring {
            relative(base, &mut scoring.key);
            relative(base, &mut scoring.token);
        }
        if let Some(board) = &mut config.services.report_board {
            relative(base, &mut board.key);
        }
        for g in config.services.governance.iter_mut() {
            relative(base, &mut g.genesis);
            relative(base, &mut g.journal);
        }
        if let Some(p) = &mut config.services.notifications {
            relative(base, &mut p.key);
            relative(base, &mut p.store);
            relative(base, &mut p.vapid_key);
        }
        if let Some(a) = &mut config.services.workflow_worker {
            relative(base, &mut a.key);
        }
        if let Some(oracle) = &mut config.services.activity_oracle {
            relative(base, &mut oracle.key);
            relative(base, &mut oracle.spool);
            relative(base, &mut oracle.evidence_directory);
            for probe in &mut oracle.probes {
                relative(base, &mut probe.token);
            }
        }
        if let Some(a) = &mut config.services.ai_worker {
            relative(base, &mut a.key);
            for provider in &mut a.providers {
                if let Some(path) = &mut provider.key_file {
                    relative(base, path);
                }
            }
        }
        if let Some(o) = &mut config.services.operations {
            for instance in &mut o.instances {
                relative(base, &mut instance.directory);
            }
        }
        for room in &mut config.services.member_rooms {
            relative(base, &mut room.instance.directory);
            relative(base, &mut room.forwarding_secret);
        }

        if let Some(d) = &mut config.services.documents {
            relative(base, &mut d.directory);
        }
        config.validate_inner()?;
        Ok(config)
    }
    pub fn validate(&self) -> crate::Result<()> {
        self.validate_inner().map_err(crate::operation_error)
    }
    fn network(&self) -> Result<NodeConfig> {
        fn addresses(values: &[String]) -> Result<Vec<node::Multiaddr>> {
            ensure!(
                values.len() <= node::protocol::MAX_DIRECTORY_ADDRESSES,
                "too many network addresses"
            );
            values.iter().map(|v| Ok(v.parse()?)).collect()
        }
        let mut network = NodeConfig {
            external_addresses: addresses(&self.node.external)?,
            bootstrap: addresses(&self.node.bootstrap)?,
            relay: self.services.relay.config(),
            discovery_server: self.services.directory,
            lan_discovery: self.node.lan_discovery,
            ..Default::default()
        };
        if !self.node.listen.is_empty() {
            network.listen = addresses(&self.node.listen)?;
        }
        // Validate reserve relay addresses early so `Config::validate` catches
        // unparseable entries before `start_inner` reparses them for dialing.
        addresses(&self.node.reserve).context("invalid reserve relay address")?;
        Ok(network)
    }
    fn validate_inner(&self) -> Result<()> {
        self.network()?;
        if let RelayService::Limits(limits) = &self.services.relay {
            limits.validate()?;
        }
        let protected = self.services.governance.is_some()
            || self.services.operations.is_some()
            || self.services.documents.is_some()
            || !self.services.member_rooms.is_empty();
        ensure!(
            !protected || self.services.identity.is_some(),
            "protected services require unified identity"
        );
        if let Some(identity) = &self.services.identity {
            ensure!(
                identity.writer != identity.source.is_some(),
                "configure either an identity writer or a source"
            );
            ensure!(
                identity.max_staleness_seconds >= 3 && identity.max_staleness_seconds <= 3600,
                "identity freshness must be 3..3600 seconds"
            );
            ensure!(
                identity.genesis_hash.len() == 64,
                "pinned identity genesis required"
            );
            if let Some(source) = &identity.source {
                let peer: PeerId = source.peer.parse()?;
                let address: node::Multiaddr = source.address.parse()?;
                ensure!(
                    matches!(address.iter().last(),Some(node::AddressProtocol::P2p(id)) if id==peer),
                    "identity source peer mismatch"
                );
            }
        }
        ensure!(
            self.services.member_rooms.len() <= MAX_ROOMS,
            "too many rooms"
        );
        ensure!(
            self.services.member_rooms.is_empty() || self.services.identity.is_some(),
            "member rooms require unified identity"
        );
        if self.services.league_proxy.is_some() || self.services.scoring.is_some() {
            ensure!(
                self.services.identity.is_some() && self.services.governance.is_some(),
                "game adapters require application governance"
            );
        }
        if let Some(scoring) = &self.services.scoring {
            ensure!(
                scoring.bind.ip().is_loopback(),
                "scoring adapter must bind loopback"
            );
        }
        let needs_governance = self.services.ai_worker.is_some()
            || self.services.activity_oracle.is_some()
            || (self.services.identity.is_none()
                && (self.services.operations.is_some() || self.services.documents.is_some()));
        ensure!(
            !needs_governance || self.services.governance.is_some(),
            "service requires live governance"
        );
        ensure!(
            (self.services.ai_worker.is_none()
                && self.services.workflow_worker.is_none()
                && self.services.notifications.is_none()
                && self.services.report_board.is_none())
                || self.services.governance.is_some(),
            "workflow services require application governance"
        );
        if let Some(worker) = &self.services.ai_worker {
            ensure!(!worker.providers.is_empty(), "AI worker needs providers");
        }
        if let Some(oracle) = &self.services.activity_oracle {
            ensure!(
                oracle.bind.ip().is_loopback(),
                "activity adapter must bind loopback"
            );
        }
        let mut ids = HashSet::new();
        let mut register = |id: &str| -> Result<()> {
            ensure!(ids.insert(id.parse::<ServiceId>()?), "duplicate service ID");
            Ok(())
        };
        if let Some(proxy) = &self.services.league_proxy {
            register(&proxy.config.service)?;
        }
        if let Some(o) = &self.services.operations {
            register(&o.service)?;
        }
        if let Some(d) = &self.services.documents {
            register(&d.service)?;
        }
        if let Some(p) = &self.services.notifications {
            register(&p.service)?;
        }
        let mut directories = HashSet::new();
        let mut backends = HashSet::new();
        let mut instance_ids = HashSet::new();
        let mut instance = |i: &rooms::InstanceConfig| -> Result<()> {
            i.validate()?;
            ensure!(
                directories.insert(i.directory.canonicalize()?)
                    && backends.insert(i.backend)
                    && instance_ids.insert(i.id.clone()),
                "instances must have unique directories, ports and IDs"
            );
            Ok(())
        };
        if let Some(o) = &self.services.operations {
            ensure!(
                o.instances.len() <= ops::MAX_INSTANCES,
                "too many managed instances"
            );
            for i in &o.instances {
                instance(i)?;
            }
        }
        for room in &self.services.member_rooms {
            register(&room.service)?;
            instance(&room.instance)?;
        }

        Ok(())
    }
}
#[derive(Serialize)]
pub struct Status {
    pub peer: String,
    pub addresses: Vec<String>,
    pub services: Vec<String>,
}
pub struct Host {
    node: Option<Arc<Node>>,
    tasks: JoinSet<Result<()>>,
    routes: HashMap<ServiceId, mpsc::Sender<node::IncomingSession>>,
    rooms: Vec<rooms::LocalRoom>,
    witnesses: crate::activity::Witnesses,
    oracle: Option<crate::activity::Oracle>,
    fleet: Option<Arc<ops::Fleet>>,
    services: Vec<String>,
    pending_ai: Option<(Authority<Application>, ai_worker::Prepared)>,
    pending_workflows: Option<(Authority<Application>, crate::workflow_worker::Config)>,
    #[cfg(feature = "server")]
    raft: Vec<authority::consensus::Raft>,
    identity: Option<(
        Arc<Mutex<authority::trust::TrustLog>>,
        authority::trust::TrustView,
    )>,
}
impl Host {
    pub async fn start(config: Config) -> crate::Result<Self> {
        let identity = Identity::load(&config.node.key)?;
        Self::start_inner(config, identity)
            .await
            .map_err(crate::operation_error)
    }
    pub async fn start_with_identity(config: Config, identity: Identity) -> crate::Result<Self> {
        Self::start_inner(config, identity)
            .await
            .map_err(crate::operation_error)
    }
    pub fn room_status(&self) -> Option<rooms::HostStatus> {
        self.rooms.iter().find_map(|r| r.status())
    }
    async fn start_inner(config: Config, identity: Identity) -> Result<Self> {
        config.validate_inner()?;
        let mut node = Node::start(identity, config.network()?).await?;
        let reserve = config
            .node
            .reserve
            .iter()
            .map(|s| s.parse())
            .collect::<std::result::Result<Vec<node::Multiaddr>, _>>()?;
        terminal_runtime::reserve_relays(&node, &reserve).await?;
        let incoming = node.take_incoming()?;
        let mut host = Self {
            node: Some(Arc::new(node)),
            tasks: JoinSet::new(),
            routes: HashMap::new(),
            rooms: Vec::new(),
            witnesses: crate::activity::Witnesses::default(),
            oracle: None,
            fleet: None,
            services: Vec::new(),
            pending_ai: None,
            pending_workflows: None,
            #[cfg(feature = "server")]
            raft: Vec::new(),
            identity: None,
        };
        if let Err(error) = host.prepare(config.services).await {
            let _ = host.close_inner().await;
            return Err(error);
        }
        let routes = host.routes.clone();
        host.tasks.spawn(async move {
            let mut incoming = incoming;
            while let Some(session) = incoming.recv().await {
                if let Some(route) = routes.get(&session.service)
                    && let Err(error) = route.try_send(session) {
                        let rejected = error.into_inner();
                        tracing::warn!(peer = %rejected.peer, service = %rejected.service, "service unavailable; closing rejected stream");
                        // Routes carry different application protocols, including raw Minecraft.
                        // Do not inject a JSON error into an unknown protocol; close explicitly.
                        let mut stream = tokio_util::compat::FuturesAsyncReadCompatExt::compat(rejected.stream);
                 if let Err(error) = tokio::io::AsyncWriteExt::shutdown(&mut stream).await {
                            tracing::debug!(%error, "dispatcher rejection close failed");
                        }
                }
            }
            anyhow::bail!("node dispatcher stopped")
        });
        if let Some((authority, config)) = host.pending_workflows.take() {
            host.tasks
                .spawn(crate::workflow_worker::serve(authority, config));
        }
        if let Some((authority, config)) = host.pending_ai.take() {
            host.tasks.spawn(ai_worker::serve(authority, config));
        }
        Ok(host)
    }
    fn node(&self) -> Result<Arc<Node>> {
        self.node.clone().context("node closed")
    }
    fn route(&mut self, service: ServiceId) -> mpsc::Receiver<node::IncomingSession> {
        let (sender, receiver) = mpsc::channel(SERVICE_QUEUE);
        self.routes.insert(service, sender);
        receiver
    }
    async fn prepare(&mut self, mut services: Services) -> Result<()> {
        if let Some(config) = services.identity.take() {
            let genesis = match config.root {
                Some(genesis) => genesis,
                None => {
                    let genesis = read(&config.genesis)?;
                    crate::bootstrap::validate_genesis(&genesis)?;
                    genesis
                }
            };
            let log = Arc::new(Mutex::new(authority::trust::TrustLog::open(
                &config.log,
                &genesis,
                &config.genesis_hash,
            )?));
            let view = log
                .lock()
                .await
                .view(std::time::Duration::from_secs(config.max_staleness_seconds))?;
            let node = self.node()?;
            if let Some(source) = &config.source {
                node.dial(source.address.parse()?).await?;
                authority::trust::synchronize(&node, source.peer.parse()?, &log).await?;
            } else {
                log.lock().await.mark_current()?;
            }
            self.identity = Some((log.clone(), view));
            let publisher = log.clone();
            let network = node.clone();
            let writable = config.writer;
            let serving_view = self
                .identity
                .as_ref()
                .context("identity missing")?
                .1
                .clone();
            self.tasks.spawn(async move {
                authority::trust::serve_with_view(&network, publisher, writable, serving_view)
                    .await
                    .map_err(Into::into)
            });
            self.tasks.spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                    config.max_staleness_seconds / 3,
                ));
                loop {
                    interval.tick().await;
                    if let Some(source) = &config.source {
                        let result = async {
                            node.dial(source.address.parse()?).await?;
                            authority::trust::synchronize(&node, source.peer.parse()?, &log)
                                .await?;
                            Ok::<(), anyhow::Error>(())
                        }
                        .await;
                        if result.is_err() {
                            log.lock().await.mark_stale();
                            tracing::debug!("identity source unavailable");
                        }
                    } else {
                        log.lock().await.mark_current()?;
                    }
                }
            });
            self.services.push("identity".into());
        }
        if services.directory {
            self.services.push("directory".into());
        }
        if services.relay.enabled() {
            self.services.push("relay".into());
        }
        if let Some(governance) = services.governance.take() {
            self.start_governance(&governance, &mut services).await?;
        }
        self.other_services(&mut services).await?;
        for config in services.member_rooms {
            let service = config.service.parse()?;
            let incoming = self.route(service);
            let view = self
                .identity
                .as_ref()
                .context("identity missing")?
                .1
                .clone();
            self.rooms.push(
                rooms::LocalRoom::start(
                    self.node()?,
                    incoming,
                    config,
                    view,
                    Some(self.witnesses.clone()),
                )
                .await?,
            );
            self.services.push(format!("room:{service}"));
        }

        Ok(())
    }
    async fn game_adapters(
        &mut self,
        authority: Authority<Application>,
        services: &mut Services,
    ) -> Result<()> {
        if services.league_proxy.is_none() && services.scoring.is_none() {
            return Ok(());
        }
        let view = authority.identity_view();
        let club = authority.stored_state().await.core.identity.club.clone();
        if let Some(proxy) = services.league_proxy.take() {
            let id = proxy.config.service.parse()?;
            let key = Identity::load(&proxy.key)?;
            self.node()?
                .publish(Service {
                    id,
                    name: proxy.config.league.clone(),
                    protocol: "minecraft/java/26.3".into(),
                    metadata: Vec::new(),
                    access: AccessPolicy::Trust {
                        view,
                        requirement: node::protocol::TrustRequirement {
                            clubs: [club].into(),
                            permission: None,
                        },
                    },
                })
                .await?;
            let incoming = self.route(id);
            self.tasks.spawn(crate::native::serve_scheduled(
                proxy.config,
                self.node()?,
                authority.clone(),
                key,
                incoming,
                Some(self.witnesses.clone()),
            ));
            self.services.push(format!("league_proxy:{id}"));
        }
        if let Some(scoring) = services.scoring.take() {
            ensure!(
                std::fs::metadata(&scoring.token)?.len() <= 258,
                "scoring token too large"
            );
            let token = std::fs::read_to_string(&scoring.token)?.trim().to_owned();
            let key = Identity::load(&scoring.key)?;
            self.tasks
                .spawn(crate::scoring::serve(scoring.bind, authority, key, token));
            self.services.push("scoring".into());
        }
        Ok(())
    }
    async fn open_authority<D: state::Domain>(
        &mut self,
        config: &Governance,
    ) -> Result<Authority<D>> {
        let genesis = read(&config.genesis)?;
        let authority = if let Some(replication) = &config.replication {
            #[cfg(feature = "server")]
            {
                ensure!(
                    self.identity.is_some(),
                    "replicated services require unified identity"
                );
                let cluster = authority::consensus::Cluster::start(
                    replication.id,
                    self.node()?,
                    &config.journal,
                    genesis,
                    replication.peers.clone(),
                    self.identity.clone().context("identity service required")?,
                )
                .await?;
                self.raft.push(cluster.raft.clone());
                if replication.initialize {
                    cluster.initialize().await?;
                }
                Authority::Replicated(cluster)
            }
            #[cfg(not(feature = "server"))]
            {
                let _ = replication;
                anyhow::bail!("Raft hosting requires the server feature");
            }
        } else {
            let journal = Arc::new(Mutex::new(Journal::<D>::open(&config.journal, genesis)?));
            let (log, view) = self
                .identity
                .as_ref()
                .context("identity service required")?;
            Authority::Local {
                journal,
                log: log.clone(),
                view: view.clone(),
            }
        };
        let state = authority.stored_state().await;
        let (_, view) = self
            .identity
            .as_ref()
            .context("identity service required")?;
        let current = view.state()?;
        let binding = &state.core.identity;
        // Replicated business logs pin a shared logical audience in genesis. It need not
        // equal every replica transport PeerId. Raft membership authenticates replication
        // peers, while business authorization still checks this pinned audience/service.
        ensure!(
            binding.genesis == current.checkpoint().genesis
                && (config.replication.is_some()
                    || binding.audience == self.node()?.peer_id().to_string()),
            "business identity binding mismatch"
        );
        Ok(authority)
    }
    async fn governance<D: state::Domain>(&mut self, authority: Authority<D>) -> Result<()> {
        let node = self.node()?;
        let serving = authority.clone();
        self.tasks.spawn(async move {
            serving
                .serve(node, GOVERNANCE_PROTOCOL)
                .await
                .map_err(Into::into)
        });
        let node = self.node()?;
        let events = authority.clone();
        self.tasks.spawn(async move {
            authority::events::serve_authority(node, events, EVENTS_PROTOCOL)
                .await
                .map_err(Into::into)
        });
        self.services.push("application".into());
        Ok(())
    }
    async fn start_governance(&mut self, g: &Governance, services: &mut Services) -> Result<()> {
        let authority = self.open_authority::<Application>(g).await?;
        if let Some(config) = services.activity_oracle.take() {
            self.oracle = Some(
                crate::activity::Oracle::start(config, authority.clone(), self.witnesses.clone())
                    .await?,
            );
            self.services.push("activity_oracle".into());
        }
        self.game_adapters(authority.clone(), services).await?;
        if let Some(config) = services.report_board.take() {
            self.tasks
                .spawn(crate::report_board::serve(authority.clone(), config));
            self.services.push("report_board".into());
        }
        if let Some(config) = services.notifications.take() {
            let service = config.service.parse()?;
            self.node()?
                .publish(Service {
                    id: service,
                    name: "Application notifications".into(),
                    protocol: node::protocol::APPLICATION_PUSH_PROTOCOL.into(),
                    metadata: vec![],
                    access: self.access("use")?,
                })
                .await?;
            let incoming = self.route(service);
            self.tasks.spawn(crate::notifications::serve(
                authority.clone(),
                config,
                incoming,
            ));
            self.services.push("notifications".into());
        }

        if let Some(config) = services.workflow_worker.take() {
            Identity::load(&config.key)?;
            self.pending_workflows = Some((authority.clone(), config));
            self.services.push("workflow_worker".into());
        }
        if let Some(config) = services.ai_worker.take() {
            self.pending_ai = Some((authority.clone(), ai_worker::prepare(config)?));
            self.services.push("ai_worker".into());
        }
        self.governance(authority).await?;
        Ok(())
    }
    async fn other_services(&mut self, services: &mut Services) -> Result<()> {
        if let Some(o) = services.operations.take() {
            let service = o.service.parse()?;
            let fleet = Arc::new(ops::Fleet::new(ops::Config {
                instances: o.instances,
            })?);
            self.fleet = Some(fleet.clone());
            self.node()?
                .publish(Service {
                    id: service,
                    name: "Operations".into(),
                    protocol: node::protocol::OPS_PROTOCOL.into(),
                    metadata: vec![],
                    access: self.access("manage")?,
                })
                .await?;
            let incoming = self.route(service);
            let node = self.node()?;
            self.tasks
                .spawn(async move { ops::serve(&node, incoming, service, fleet).await });
            self.services.push(format!("operations:{service}"));
        }
        if let Some(d) = services.documents.take() {
            let service = d.service.parse()?;
            self.node()?
                .publish(Service {
                    id: service,
                    name: "Documents".into(),
                    protocol: node::protocol::DOCUMENT_PROTOCOL.into(),
                    metadata: vec![],
                    access: self.access("read")?,
                })
                .await?;
            let incoming = self.route(service);
            self.tasks.spawn(async move {
                events::documents::serve(incoming, service, d.directory)
                    .await
                    .map_err(Into::into)
            });
            self.services.push(format!("documents:{service}"));
        }
        Ok(())
    }
    fn access(&self, permission: &str) -> Result<AccessPolicy> {
        let (_, view) = self
            .identity
            .as_ref()
            .context("unified identity required")?;
        Ok(AccessPolicy::Trust {
            view: view.clone(),
            requirement: node::protocol::TrustRequirement {
                clubs: Default::default(),
                permission: Some(permission.into()),
            },
        })
    }
    pub fn status(&self) -> crate::Result<Status> {
        let node = self.node().map_err(crate::operation_error)?;
        let mut services = self.services.clone();
        services.retain(|s| {
            !s.starts_with("room:")
                || self.rooms.iter().any(|room| {
                    room.status()
                        .is_some_and(|r| s == &format!("room:{}", r.service))
                })
        });
        Ok(Status {
            peer: node.peer_id().to_string(),
            addresses: node.addresses().iter().map(ToString::to_string).collect(),
            services,
        })
    }
    pub async fn wait(&mut self) -> crate::Result<()> {
        let next = if let Some(oracle) = &self.oracle {
            tokio::select! {result=self.tasks.join_next()=>result,_=oracle.closed()=>return Err(node::Error::Protocol("activity adapter stopped".into()))}
        } else {
            self.tasks.join_next().await
        };
        match next {
            Some(Ok(Err(error))) => Err(crate::operation_error(error)),
            Some(Err(error)) => Err(crate::operation_error(error.into())),
            _ => Err(node::Error::Protocol("host service stopped".into())),
        }
    }
    pub async fn close(self) -> crate::Result<()> {
        self.close_inner().await.map_err(crate::operation_error)
    }
    async fn close_inner(mut self) -> Result<()> {
        if let Some(node) = &self.node {
            for service in self.routes.keys() {
                node.withdraw(*service).await;
            }
        }
        let mut error = None;
        for room in self.rooms.drain(..) {
            if let Err(e) = room.stop().await {
                error = Some(anyhow::Error::from(e));
            }
        }
        if let Some(fleet) = self.fleet.take()
            && let Err(e) = fleet.shutdown().await
        {
            error = Some(anyhow::Error::from(e));
        }
        if let Some(oracle) = self.oracle.take()
            && let Err(e) = oracle.stop().await
        {
            error = Some(e);
        }
        #[cfg(feature = "server")]
        for raft in self.raft.drain(..) {
            raft.shutdown().await?;
        }
        self.tasks.shutdown().await;
        self.routes.clear();
        self.pending_ai.take();
        self.pending_workflows.take();
        self.identity.take();
        if let Some(node) = self.node.take() {
            Arc::try_unwrap(node)
                .map_err(|_| anyhow::anyhow!("node still referenced"))?
                .shutdown()
                .await?;
        }
        if let Some(error) = error {
            return Err(error);
        }
        Ok(())
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let Some(node) = self.node.take() else {
            return;
        };
        let mut tasks = std::mem::replace(&mut self.tasks, JoinSet::new());
        let rooms = std::mem::take(&mut self.rooms);
        let fleet = self.fleet.take();
        let oracle = self.oracle.take();
        self.pending_ai.take();
        self.pending_workflows.take();
        self.identity.take();
        self.routes.clear();
        #[cfg(feature = "server")]
        let raft = std::mem::take(&mut self.raft);
        tasks.abort_all();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                for room in rooms {
                    let _ = room.stop().await;
                }
                if let Some(fleet) = fleet {
                    let _ = fleet.shutdown().await;
                }
                if let Some(oracle) = oracle {
                    let _ = oracle.stop().await;
                }
                #[cfg(feature = "server")]
                for raft in raft {
                    let _ = raft.shutdown().await;
                }
                tasks.shutdown().await;
                if let Ok(node) = Arc::try_unwrap(node) {
                    let _ = node.shutdown().await;
                }
            });
        }
    }
}
