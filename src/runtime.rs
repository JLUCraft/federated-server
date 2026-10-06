//! Unified service assembly. One identity, one Node and one bounded service dispatcher.
use crate::{office_ai, ops, rooms};
use anyhow::{Context, Result, ensure};
use authority::authority::Authority;
use authority::journal::Journal;
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

pub use crate::office_ai::Config as AiWorkerConfig;
pub type Office = flows::Flows<events::EventsDomain>;
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
    pub relay: bool,
    pub governance: Option<Governance>,
    pub gateway: Option<Gateway>,
    pub ai_worker: Option<AiWorkerConfig>,
    pub operations: Option<Operations>,
    pub member_rooms: Vec<rooms::HostConfig>,
    pub documents: Option<Documents>,
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
    embedded_genesis: Option<node::protocol::TrustGenesis>,
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
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Domain {
    Identity,
    League,
    Office,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Governance {
    #[serde(default)]
    pub replication: Option<Replication>,
    pub domain: Domain,
    pub genesis: PathBuf,
    pub journal: PathBuf,
    #[serde(default)]
    pub binding: Option<node::protocol::TrustBusinessBinding>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Replication {
    pub id: u64,
    #[serde(default)]
    pub initialize: bool,
    pub peers: std::collections::BTreeMap<u64, state::governance::ConsensusPeer>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gateway {
    pub service: String,
    pub config: PathBuf,
    pub ledger: PathBuf,
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
    pub fn load(path: &Path) -> crate::Result<Self> {
        Self::load_inner(path).map_err(crate::operation_error)
    }
    fn load_inner(path: &Path) -> Result<Self> {
        let path = path.canonicalize()?;
        let base = path.parent().context("configuration directory missing")?;
        let mut config: Self = read(&path)?;
        relative(base, &mut config.node.key);
        if let Some(identity) = &mut config.services.identity {
            if identity.genesis.as_os_str().is_empty() {
                let genesis = crate::bootstrap::genesis()?;
                let pin = client::trust::TrustState::genesis_digest(&genesis)?;
                ensure!(
                    identity.genesis_hash.is_empty() || identity.genesis_hash == pin,
                    "identity genesis does not match this server build"
                );
                identity.genesis_hash = pin;
                identity.embedded_genesis = Some(genesis);
            } else {
                relative(base, &mut identity.genesis);
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
        if let Some(g) = &mut config.services.governance {
            relative(base, &mut g.genesis);
            relative(base, &mut g.journal);
        }
        if let Some(g) = &mut config.services.gateway {
            relative(base, &mut g.config);
            relative(base, &mut g.ledger);
        }
        if let Some(a) = &mut config.services.ai_worker {
            relative(base, &mut a.key);
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
            relay: self.services.relay.then(node::RelayConfig::default),
            discovery_server: self.services.directory,
            lan_discovery: self.node.lan_discovery,
            ..Default::default()
        };
        if !self.node.listen.is_empty() {
            network.listen = addresses(&self.node.listen)?;
        }
        addresses(&self.node.reserve)?;
        Ok(network)
    }
    fn validate_inner(&self) -> Result<()> {
        self.network()?;
        let protected = self.services.governance.is_some()
            || self.services.gateway.is_some()
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
                self.services.identity.is_some()
                    && self
                        .services
                        .governance
                        .as_ref()
                        .is_some_and(|g| matches!(g.domain, Domain::League)),
                "league adapters require unified league governance"
            );
        }
        if let Some(scoring) = &self.services.scoring {
            ensure!(
                scoring.bind.ip().is_loopback(),
                "scoring adapter must bind loopback"
            );
        }
        let needs_governance = self.services.gateway.is_some()
            || self.services.ai_worker.is_some()
            || (self.services.identity.is_none()
                && (self.services.operations.is_some() || self.services.documents.is_some()));
        ensure!(
            !needs_governance || self.services.governance.is_some(),
            "service requires live governance"
        );
        ensure!(
            self.services.ai_worker.is_none()
                || self
                    .services
                    .governance
                    .as_ref()
                    .is_some_and(|g| matches!(g.domain, Domain::Office)),
            "AI worker requires office governance"
        );
        if let Some(worker) = &self.services.ai_worker {
            let local =
                worker.address.is_empty() && worker.peer.is_empty() && worker.service.is_empty();
            ensure!(
                (local && self.services.gateway.is_some())
                    || (!worker.address.is_empty()
                        && !worker.peer.is_empty()
                        && !worker.service.is_empty()),
                "AI worker needs a local gateway or a complete remote target"
            );
            if !local {
                let peer: PeerId = worker.peer.parse()?;
                let address: node::Multiaddr = worker.address.parse()?;
                let _: ServiceId = worker.service.parse()?;
                ensure!(
                    matches!(address.iter().last(), Some(node::AddressProtocol::P2p(id)) if id == peer),
                    "AI target address must match peer"
                );
            }
        }
        let mut ids = HashSet::new();
        let mut register = |id: &str| -> Result<()> {
            ensure!(ids.insert(id.parse::<ServiceId>()?), "duplicate service ID");
            Ok(())
        };
        if let Some(proxy) = &self.services.league_proxy {
            register(&proxy.config.service)?;
        }
        if let Some(g) = &self.services.gateway {
            register(&g.service)?;
        }
        if let Some(o) = &self.services.operations {
            register(&o.service)?;
        }
        if let Some(d) = &self.services.documents {
            register(&d.service)?;
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
    fleet: Option<Arc<ops::Fleet>>,
    services: Vec<String>,
    pending_ai: Option<(Authority<Office>, AiWorkerConfig)>,
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
            fleet: None,
            services: Vec::new(),
            pending_ai: None,
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
        if let Some((authority, config)) = host.pending_ai.take() {
            host.tasks.spawn(office_ai::serve(authority, config));
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
            let genesis = match config.embedded_genesis {
                Some(genesis) => genesis,
                None => read(&config.genesis)?,
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
        if services.relay {
            self.services.push("relay".into());
        }
        if let Some(g) = services.governance.take() {
            match g.domain {
                Domain::Identity => {
                    let authority = self.open_authority::<state::EmptyDomain>(&g).await?;
                    self.governance(authority, &mut services).await?;
                }
                Domain::League => {
                    let authority = self.open_authority::<league::LeagueDomain>(&g).await?;
                    self.league_adapters(authority.clone(), &mut services)
                        .await?;
                    self.governance(authority, &mut services).await?;
                }
                Domain::Office => {
                    let authority = self.open_authority::<Office>(&g).await?;
                    if let Some(mut config) = services.ai_worker.take() {
                        if config.address.is_empty() {
                            let node = self.node()?;
                            let address = node
                                .addresses()
                                .into_iter()
                                .find(|a| {
                                    !a.iter()
                                        .any(|p| matches!(p, node::AddressProtocol::P2pCircuit))
                                })
                                .context("local gateway has no direct listener")?;
                            let address: node::Multiaddr = address
                                .iter()
                                .map(|p| match p {
                                    node::AddressProtocol::Ip4(ip) if ip.is_unspecified() => {
                                        node::AddressProtocol::Ip4(std::net::Ipv4Addr::LOCALHOST)
                                    }
                                    node::AddressProtocol::Ip6(ip) if ip.is_unspecified() => {
                                        node::AddressProtocol::Ip6(std::net::Ipv6Addr::LOCALHOST)
                                    }
                                    p => p,
                                })
                                .collect();
                            config.address = address.to_string();
                            config.peer = node.peer_id().to_string();
                            config.service = services
                                .gateway
                                .as_ref()
                                .context("local gateway missing")?
                                .service
                                .clone();
                        }
                        Identity::load(&config.key)?;
                        self.pending_ai = Some((authority.clone(), config));
                        self.services.push("ai_worker".into());
                    }
                    self.governance(authority, &mut services).await?;
                }
            }
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
            self.rooms
                .push(rooms::LocalRoom::start(self.node()?, incoming, config, view).await?);
            self.services.push(format!("room:{service}"));
        }

        Ok(())
    }
    async fn league_adapters(
        &mut self,
        authority: Authority<league::LeagueDomain>,
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
    async fn governance<D: state::Domain>(
        &mut self,
        authority: Authority<D>,
        services: &mut Services,
    ) -> Result<()> {
        let node = self.node()?;
        let serving = authority.clone();
        self.tasks
            .spawn(async move { serving.serve(node).await.map_err(Into::into) });
        let node = self.node()?;
        let events = authority.clone();
        self.tasks.spawn(async move {
            authority::events::serve_authority(node, events)
                .await
                .map_err(Into::into)
        });
        self.services.push("governance".into());
        if let Some(g) = services.gateway.take() {
            let service = g.service.parse()?;
            let club = authority.stored_state().await.core.identity.club.clone();
            let gateway = llm_gateway::Gateway::new(
                read(&g.config)?,
                llm_gateway::Ledger::open(g.ledger)?,
                authority,
            )?;
            let gateway = Arc::new(gateway);
            let mut access = self.access("use")?;
            if let AccessPolicy::Trust { requirement, .. } = &mut access {
                requirement.clubs.insert(club);
            }
            self.node()?
                .publish(Service {
                    id: service,
                    name: "LLM".into(),
                    protocol: node::protocol::LLM_PROTOCOL.into(),
                    metadata: vec![],
                    access,
                })
                .await?;
            let mut incoming = self.route(service);
            self.tasks.spawn(async move {
                let mut tasks = JoinSet::new();
                loop { tokio::select! {
                    session = incoming.recv() => { let Some(session) = session else { break; }; let gateway = gateway.clone(); tasks.spawn(async move {gateway.serve(session).await}); }
                    Some(result) = tasks.join_next(), if !tasks.is_empty() => { if !matches!(result, Ok(Ok(()))) { tracing::debug!("gateway session ended"); } }
                }}
                tasks.shutdown().await;
                Ok(())
            });
            self.services.push(format!("gateway:{service}"));
        }
        self.other_services(services).await?;
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
        match self.tasks.join_next().await {
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
        #[cfg(feature = "server")]
        for raft in self.raft.drain(..) {
            raft.shutdown().await?;
        }
        self.tasks.shutdown().await;
        self.routes.clear();
        self.pending_ai.take();
        self.identity.take();
        let mut error = None;
        for room in self.rooms.drain(..) {
            if let Err(e) = room.stop().await {
                error = Some(e);
            }
        }
        if let Some(fleet) = self.fleet.take()
            && let Err(e) = fleet.shutdown().await
        {
            error = Some(e);
        }
        if let Some(node) = self.node.take() {
            Arc::try_unwrap(node)
                .map_err(|_| anyhow::anyhow!("node still referenced"))?
                .shutdown()
                .await?;
        }
        if let Some(error) = error {
            return Err(error.into());
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
        self.pending_ai.take();
        self.identity.take();
        self.routes.clear();
        #[cfg(feature = "server")]
        let raft = std::mem::take(&mut self.raft);
        tasks.abort_all();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                #[cfg(feature = "server")]
                for raft in raft {
                    let _ = raft.shutdown().await;
                }
                tasks.shutdown().await;
                for room in rooms {
                    let _ = room.stop().await;
                }
                if let Some(fleet) = fleet {
                    let _ = fleet.shutdown().await;
                }
                if let Ok(node) = Arc::try_unwrap(node) {
                    let _ = node.shutdown().await;
                }
            });
        }
    }
}
