//! Member-owned rooms: local instance lifecycle and delegated game admission.
use crate::wire::{self, Fields, Packet};
use anyhow::{Context, Result, ensure};
use minecraftd::{
    core::{event::TokioBroadcastBus, state::InstanceState},
    instance::{builder::InstanceBuilder, path::InstancePath, server::ServerConfig},
    process::local::LocalSpawner,
    service::{instance::InstanceService, restart::RestartPolicy},
};
use node::protocol::{ROOM_PROTOCOL, RoomMetadata};
use node::{AccessPolicy, IncomingSession, Node, Service, ServiceId};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    net::TcpStream,
    sync::{oneshot, watch},
    task::JoinSet,
    time::timeout,
};
use tokio_util::compat::FuturesAsyncReadCompatExt;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const START_TIMEOUT: Duration = Duration::from_secs(120);
const MIN_UUID_LOGIN_PROTOCOL: i32 = 764;
const STOP_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceConfig {
    pub id: String,
    pub directory: PathBuf,
    pub backend: SocketAddr,
    pub server: ServerConfig,
}
impl InstanceConfig {
    pub fn validate(&self) -> crate::Result<()> {
        self.validate_inner().map_err(crate::operation_error)
    }
    fn validate_inner(&self) -> Result<()> {
        ensure!(
            !self.id.is_empty() && self.id.len() <= 128,
            "invalid instance id"
        );
        ensure!(self.directory.is_dir(), "instance directory is missing");
        ensure!(
            self.backend.ip().is_loopback() && self.backend.port() != 0,
            "backend must use a fixed loopback port"
        );
        ensure!(
            !self.server.start_command.trim().is_empty(),
            "start command is missing"
        );
        Ok(())
    }
    pub fn create(&self) -> crate::Result<InstanceService> {
        self.create_inner().map_err(crate::operation_error)
    }
    fn create_inner(&self) -> Result<InstanceService> {
        self.validate()?;
        Ok(InstanceService::new(
            InstanceBuilder::new(self.id.clone(), InstancePath::new(&self.directory))
                .spawner(LocalSpawner::new())
                .event_bus(TokioBroadcastBus::new())
                .build_server(self.server.clone()),
            RestartPolicy::never(),
        ))
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    pub service: String,
    pub name: String,
    pub instance: InstanceConfig,
    pub forwarding_secret: PathBuf,
    pub club: String,
    pub join_clubs: std::collections::BTreeSet<String>,
}
struct RoomSettings {
    service: String,
    name: String,
    instance: InstanceConfig,
    forwarding_secret: PathBuf,
}
#[derive(Clone, Debug, Serialize)]
pub struct HostStatus {
    pub peer: String,
    pub service: String,
    pub name: String,
    pub addresses: Vec<String>,
    pub metadata: RoomMetadata,
}

fn validate_backend(config: &InstanceConfig) -> Result<()> {
    let path = config.directory.join("server.properties");
    ensure!(
        std::fs::metadata(&path)?.len() <= 65536,
        "server properties too large"
    );
    let text = std::fs::read_to_string(path)?;
    let mut properties = std::collections::BTreeMap::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with(['#', '!']))
    {
        let (key, value) = line
            .split_once('=')
            .context("server properties must use key=value syntax")?;
        ensure!(
            !key.contains('\\'),
            "escaped property keys are not supported"
        );
        properties.insert(key.trim(), value.trim());
    }
    let ip: std::net::IpAddr = properties
        .get("server-ip")
        .context("set server-ip to loopback")?
        .parse()?;
    let port: u16 = properties
        .get("server-port")
        .context("set server-port explicitly")?
        .parse()?;
    ensure!(
        SocketAddr::new(ip, port) == config.backend,
        "server binding must match configured loopback backend"
    );
    ensure!(
        properties.get("online-mode") == Some(&"false"),
        "room backend must use authenticated identity forwarding, not online authentication"
    );
    Ok(())
}

/// Dropping the owner requests graceful cleanup, including during cancelled start.
pub struct LocalRoom {
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<()>>,
    status: Option<HostStatus>,
    addresses: watch::Receiver<Vec<node::Multiaddr>>,
    completion: watch::Receiver<()>,
}
impl LocalRoom {
    pub fn status(&self) -> Option<HostStatus> {
        if self.task.is_finished() {
            return None;
        }
        self.status.clone().map(|mut status| {
            status.addresses = self
                .addresses
                .borrow()
                .iter()
                .map(ToString::to_string)
                .collect();
            status
        })
    }
    pub async fn closed(&self) {
        let mut completion = self.completion.clone();
        let _ = completion.changed().await;
    }

    pub async fn start(
        node: Arc<Node>,
        incoming: tokio::sync::mpsc::Receiver<IncomingSession>,
        config: HostConfig,
        view: authority::trust::TrustView,
    ) -> crate::Result<Self> {
        let settings = RoomSettings {
            service: config.service,
            name: config.name,
            instance: config.instance,
            forwarding_secret: config.forwarding_secret,
        };
        Self::start_configured(
            node,
            incoming,
            settings,
            view,
            config.club,
            config.join_clubs,
        )
        .await
        .map_err(crate::operation_error)
    }
    async fn start_configured(
        node: Arc<Node>,
        mut incoming: tokio::sync::mpsc::Receiver<IncomingSession>,
        config: RoomSettings,
        mut identity_view: authority::trust::TrustView,
        school: String,
        clubs: std::collections::BTreeSet<String>,
    ) -> Result<Self> {
        config.instance.validate()?;
        validate_backend(&config.instance)?;
        crate::forwarding::read_secret(&config.forwarding_secret)?;
        ensure!(
            timeout(CONNECT_TIMEOUT, TcpStream::connect(config.instance.backend))
                .await
                .is_ok_and(|r| r.is_err()),
            "backend port is already in use or unreachable"
        );
        let state = identity_view.state()?;
        let member = state
            .member_for_device(&node.peer_id().to_string())
            .context("room host device is not bound to a member")?;
        ensure!(
            state.is_member(member, &school),
            "room host lacks club membership"
        );
        ensure!(
            !clubs.is_empty() && clubs.iter().all(|c| state.chairs().contains_key(c)),
            "room admission needs known clubs"
        );
        let access = AccessPolicy::Trust {
            view: identity_view.clone(),
            requirement: node::protocol::TrustRequirement {
                clubs,
                permission: None,
            },
        };
        let service: ServiceId = config.service.parse()?;
        let instance = config.instance.create()?;
        let mut states = instance.state_watch();
        let holder = node.peer_id();
        let addresses = node.watch_addresses();
        let (stop, mut stopping) = oneshot::channel();
        let (ready, started) = oneshot::channel();
        let (completed, completion) = watch::channel(());
        let task = tokio::spawn(async move {
            let _completed = completed;
            let result: Result<()> = async {
                let ping = tokio::select! {
                    _ = &mut stopping => return Ok(()),
                    result = async {
                instance.start().await?;
                timeout(START_TIMEOUT, async {
                    loop {
                        match states.borrow().clone() {
                            InstanceState::Running => break,
                            InstanceState::Error(error) => anyhow::bail!("instance start failed: {error}"),
                            _ => {}
                        }
                        states.changed().await.context("instance supervisor stopped")?;
                    }
                    Ok::<_, anyhow::Error>(())
                }).await.context("instance start timed out")??;
                timeout(START_TIMEOUT, async {
                    loop {
                        if let Ok(ping) = minecraftd::minecraft::ping::ping_java_server(config.instance.backend, CONNECT_TIMEOUT).await {
                            break Ok::<_, anyhow::Error>(ping);
                        }
                        ensure!(instance.state() == InstanceState::Running, "instance exited before readiness");
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                }).await.context("Minecraft readiness timed out")?
                    } => result?,
                };
                let current = identity_view.state()?;
                let member = current.member_for_device(&holder.to_string()).context("room host device revoked during startup")?;
                ensure!(current.is_member(member, &school), "room host membership revoked during startup");
                let metadata = RoomMetadata { school: school.clone(), version: ping.version,
                    players_max: u32::try_from(ping.max_players)? };
                metadata.validate()?;
                if stopping.try_recv().is_ok() { return Ok(()); }
                node.publish(Service { id: service, name: config.name.clone(), protocol: ROOM_PROTOCOL.into(),
                    metadata: serde_json::to_vec(&metadata)?, access }).await?;
                let status = HostStatus { peer: node.peer_id().to_string(), service: service.to_string(),
                    name: config.name, addresses: node.addresses().iter().map(ToString::to_string).collect(), metadata };
                if ready.send(status).is_err() { return Ok(()); }
                let forwarding_secret = Arc::new(config.forwarding_secret);
                let mut tasks = JoinSet::new();
                loop {
                    identity_view.mark_seen();
                    if let Ok(state) = identity_view.state() {
                        let member=state.member_for_device(&holder.to_string()).context("room host device revoked")?;
                        ensure!(state.is_member(member,&school),"room host membership revoked");
                    }
                    tokio::select! {
                        changed=async {if identity_view.state().is_err() {identity_view.changed().await?;} else {let remaining=identity_view.remaining();tokio::select!{r=identity_view.changed()=>{r?;},_=tokio::time::sleep(remaining)=>{}}} Ok::<(),node::Error>(())}=>{changed?;},
                        _ = &mut stopping => break,
                        update = states.changed() => {
                            if update.is_err() || *states.borrow() != InstanceState::Running { break; }
                        }
                        session = incoming.recv() => {
                            let Some(session) = session else { break; };
                            let backend = config.instance.backend;
                            let secret = forwarding_secret.clone();
                            tasks.spawn(async move {
                                if let Err(error) = bridge(session, backend, &secret).await {
                                    tracing::debug!(%error, "room session ended");
                                }
                            });
                        }
                        Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                            if let Err(error) = result { tracing::warn!(%error, "room task failed"); }
                        }
                    }
                }
                node.withdraw(service).await;
                tasks.shutdown().await;
                Ok(())
            }.await;
            node.withdraw(service).await;
            let cleanup = shutdown_instance(&instance).await;
            result?;
            cleanup?;
            Ok(())
        });
        let mut owner = Self {
            stop: Some(stop),
            task,
            status: None,
            addresses,
            completion,
        };
        // A cancellation drops owner, signalling cleanup; no detached running instance.
        match started.await {
            Ok(status) => {
                owner.status = Some(status);
                Ok(owner)
            }
            Err(_) => {
                (&mut owner.task).await??;
                anyhow::bail!("room stopped before publication")
            }
        }
    }
    pub async fn stop(self) -> crate::Result<()> {
        self.stop_inner().await.map_err(crate::operation_error)
    }
    async fn stop_inner(mut self) -> Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        (&mut self.task).await?
    }
}
impl Drop for LocalRoom {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

pub async fn shutdown_instance(instance: &InstanceService) -> crate::Result<()> {
    shutdown_instance_inner(instance)
        .await
        .map_err(crate::operation_error)
}
async fn shutdown_instance_inner(instance: &InstanceService) -> Result<()> {
    let mut states = instance.state_watch();
    instance.shutdown().await?;
    timeout(STOP_TIMEOUT, async {
        while states.changed().await.is_ok() {}
    })
    .await
    .context("instance shutdown timed out")?;
    Ok(())
}

/// Verify the actual login UUID before forwarding any login bytes to Minecraft.
async fn bridge(
    session: IncomingSession,
    backend: SocketAddr,
    secret: &std::path::Path,
) -> Result<()> {
    let claims = session
        .claims
        .as_deref()
        .context("verified member claims required")?;
    let admission = serde_json::from_slice::<node::protocol::TrustAdmission>(claims)?;
    let verified_profile = admission
        .game_profile
        .as_deref()
        .context("member has no verified game profile")?;
    let mut client = session.stream.compat();
    let (handshake, login) = timeout(CONNECT_TIMEOUT, async {
        let handshake = wire::read_frame(&mut client).await?;
        let packet = Packet::decode(&handshake, None)?;
        ensure!(packet.id == 0, "handshake required");
        let mut fields = Fields::new(&packet.body);
        let version = fields.int()?;
        fields.text(255)?;
        fields.bytes(2)?;
        let intention = fields.int()?;
        fields.finish()?;
        ensure!(intention == 1 || intention == 2, "unsupported intention");
        let login = if intention == 2 {
            // UUID-bearing Login Start is required; older clients cannot prove this binding.
            ensure!(
                version >= MIN_UUID_LOGIN_PROTOCOL,
                "Minecraft 1.20.2 or later required"
            );
            let raw = wire::read_frame(&mut client).await?;
            let packet = Packet::decode(&raw, None)?;
            ensure!(packet.id == 0, "login start required");
            let mut fields = Fields::new(&packet.body);
            let name = fields.text(16)?.to_owned();
            crate::forwarding::validate_name(&name)?;
            let profile = uuid::Uuid::from_slice(fields.bytes(16)?)?;
            fields.finish()?;
            ensure!(
                profile.simple().to_string() == verified_profile,
                "login UUID differs from verified credential"
            );
            tracing::info!(member = %admission.member, device = %session.peer, profile = %profile, display_name = %name, "verified room identity forwarding");
            Some((
                raw,
                crate::forwarding::Profile {
                    uuid: profile,
                    name,
                },
            ))
        } else {
            None
        };
        Ok::<_, anyhow::Error>((handshake, login))
    })
    .await??;
    let mut remote = timeout(CONNECT_TIMEOUT, TcpStream::connect(backend)).await??;
    remote.set_nodelay(true)?;
    wire::write_frame(&mut remote, &handshake).await?;
    if let Some((login, profile)) = login {
        wire::write_frame(&mut remote, &login).await?;
        // Complete and verify backend identity forwarding before exposing login success.
        timeout(CONNECT_TIMEOUT, async {
            let mut compression = None;
            let mut negotiation = crate::forwarding::LoginNegotiation::default();
            loop {
                let raw = wire::read_frame(&mut remote).await?;
                let packet = Packet::decode(&raw, compression)?;
                use crate::forwarding::LoginStep;
                match negotiation.receive(&packet, compression, &profile, || {
                    crate::forwarding::encode(secret, &profile)
                })? {
                    LoginStep::Compression(threshold) => {
                        wire::write_frame(&mut client, &raw).await?;
                        compression = Some(threshold);
                    }
                    LoginStep::Reply(reply) => {
                        wire::write_packet(&mut remote, reply, compression).await?
                    }
                    LoginStep::Ready => {
                        wire::write_frame(&mut client, &raw).await?;
                        return Ok::<_, anyhow::Error>(());
                    }
                    LoginStep::Forward => {
                        ensure!(packet.id != 0, "backend rejected member login");
                        wire::write_frame(&mut client, &raw).await?;
                    }
                }
            }
        })
        .await??;
    }
    tokio::io::copy_bidirectional(&mut client, &mut remote).await?;
    Ok(())
}

#[cfg(test)]
mod tests;
