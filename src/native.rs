//! Native union-authenticated Minecraft gateway. Backends are local sockets or
//! encrypted union services; neither a proxy server nor an auth plugin is used.
use crate::wire::{self, Fields, Packet};
use anyhow::{Result, bail, ensure};
use identity::Identity;
use league::{
    authority::Authority,
    governance::{Action, ConnectionHealth, Phase, Route},
    journal::now_ms,
};
use node::{IncomingSession, Node};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::{Mutex, RwLock, mpsc, watch},
    task::JoinSet,
    time::timeout,
};
use tokio_util::compat::FuturesAsyncReadCompatExt;
const MAX_NATIVE_SESSIONS: usize = 128;
/// Recovery-time ceiling reported in `ConnectionHealth`; mirrors the cap league
/// governance enforces on `reconnect_max_ms` and `recovery_ms` (600_000 ms).
const MAX_RECOVERY_MS: u128 = 600_000;
const STATUS_DESCRIPTION: &str = "高校联赛";

pub trait GameStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> GameStream for T {}
type Connection = Box<dyn GameStream>;
#[derive(Clone, Deserialize)]
#[serde(tag = "transport", rename_all = "snake_case", deny_unknown_fields)]
pub enum Endpoint {
    Local {
        address: SocketAddr,
    },
    Union {
        peer: String,
        addresses: Vec<String>,
        service: String,
    },
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backend {
    pub endpoint: Endpoint,
    pub forwarding_secret: PathBuf,
}
use crate::forwarding::Profile;
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub league: String,
    pub service: String,
    pub waiting: Backend,
    pub arena: Backend,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Room {
    Waiting,
    Arena(u64),
}
struct Active {
    id: u64,
    health: ConnectionHealth,
}
struct Runtime {
    journal: Authority,
    cache: RwLock<league::governance::State>,
    identity: Identity,
    config: Config,
    healthy: bool,
    active: BTreeMap<String, Active>,
    disconnected: BTreeMap<String, Instant>,
    next: u64,
}
type Shared = Arc<Mutex<Runtime>>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Login,
    LoginAck,
    Configuration,
    ConfigurationAck,
    Play,
    ReconfigurationAck,
}
impl Backend {
    async fn connect(&self, node: &Node) -> Result<Connection> {
        match &self.endpoint {
            Endpoint::Local { address } => {
                ensure!(
                    address.ip().is_loopback(),
                    "local backend must bind loopback; use union transport for remote rooms"
                );
                let stream = timeout(Duration::from_secs(5), TcpStream::connect(address)).await??;
                stream.set_nodelay(true)?;
                Ok(Box::new(stream))
            }
            Endpoint::Union {
                peer,
                addresses,
                service,
            } => {
                ensure!(
                    !addresses.is_empty() && addresses.len() <= 8,
                    "invalid backend routes"
                );
                let target = terminal_runtime::TargetArgs {
                    peer: peer.parse()?,
                    address: addresses
                        .iter()
                        .map(|a| a.parse())
                        .collect::<std::result::Result<Vec<_>, _>>()?,
                };
                target.connect(node).await?;
                Ok(Box::new(
                    node.open_service(target.peer, service.parse()?)
                        .await?
                        .compat(),
                ))
            }
        }
    }
    async fn healthy(&self, node: &Node) -> bool {
        timeout(Duration::from_secs(3), async {
            let mut stream = self.connect(node).await?;
            wire::write_packet(
                &mut stream,
                handshake("localhost", wire::DEFAULT_MC_PORT, 1)?,
                None,
            )
            .await?;
            wire::write_packet(
                &mut stream,
                Packet {
                    id: 0,
                    body: vec![],
                },
                None,
            )
            .await?;
            let status = Packet::decode(&wire::read_frame(&mut stream).await?, None)?;
            ensure!(status.id == 0, "invalid status");
            let mut fields = Fields::new(&status.body);
            let value: serde_json::Value = serde_json::from_str(fields.text(32767)?)?;
            fields.finish()?;
            ensure!(
                value["version"]["protocol"] == wire::VERSION,
                "backend protocol mismatch"
            );
            Ok::<(), anyhow::Error>(())
        })
        .await
        .is_ok_and(|v| v.is_ok())
    }
    fn forwarding(&self, profile: &Profile) -> Result<Vec<u8>> {
        crate::forwarding::encode(&self.forwarding_secret, profile)
    }
}
fn handshake(host: &str, port: u16, intention: u32) -> Result<Packet> {
    let mut body = vec![];
    wire::varint(wire::VERSION as u32, &mut body);
    wire::string(host, &mut body)?;
    body.extend(port.to_be_bytes());
    wire::varint(intention, &mut body);
    Ok(Packet { id: 0, body })
}
async fn action(runtime: &Runtime, action: Action) -> Result<()> {
    runtime.journal.apply(&runtime.identity, action).await?;
    *runtime.cache.write().await = runtime
        .journal
        .operational_state(runtime.identity.peer_id())
        .await?;
    Ok(())
}
async fn presence(
    runtime: &Runtime,
    member: &str,
    online: bool,
    health: ConnectionHealth,
) -> Result<()> {
    if !online
        && runtime.cache.read().await.domain.leagues[&runtime.config.league].phase
            == Phase::Finished
    {
        return Ok(());
    }
    action(
        runtime,
        Action::Domain(league::LeagueAction::Presence {
            league: runtime.config.league.clone(),
            member: member.into(),
            online,
            health,
        }),
    )
    .await
}
async fn room(runtime: &Runtime, member: &str) -> Result<Room> {
    let journal = runtime.cache.read().await;
    let league = &journal.domain.leagues[&runtime.config.league];
    ensure!(
        league
            .team_of(member)
            .is_some_and(|team| league.teams[team].registered),
        "player is not registered"
    );
    Ok(match league.route(member) {
        Route::Match { epoch, .. } if runtime.healthy && league.paused_since.is_none() => {
            Room::Arena(epoch)
        }
        _ => Room::Waiting,
    })
}
async fn finish(shared: &Shared, member: &str, id: u64) -> Result<()> {
    let mut runtime = shared.lock().await;
    if runtime.active.get(member).is_some_and(|s| s.id == id) {
        let active = runtime
            .active
            .remove(member)
            .ok_or_else(|| anyhow::anyhow!("session vanished"))?;
        runtime.disconnected.insert(member.into(), Instant::now());
        presence(&runtime, member, false, active.health).await?;
    }
    Ok(())
}
async fn monitor(shared: Shared, node: Arc<Node>, changed: watch::Sender<()>) -> Result<()> {
    let (waiting, arena) = {
        let runtime = shared.lock().await;
        (runtime.config.waiting.clone(), runtime.config.arena.clone())
    };
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let result: Result<()> = async {
            let (a, b) = tokio::join!(waiting.healthy(&node), arena.healthy(&node));
            let (authority, actor) = {
                let runtime = shared.lock().await;
                (runtime.journal.clone(), runtime.identity.peer_id())
            };
            let fresh = authority.operational_state(actor).await?;
            let mut runtime = shared.lock().await;
            *runtime.cache.write().await = fresh;
            let healthy = a && b;
            let (paused, expired) = {
                let j = runtime.cache.read().await;
                let l = &j.domain.leagues[&runtime.config.league];
                let now = now_ms()?;
                (
                    l.infrastructure_down,
                    l.phase == Phase::Playing
                        && l.seats
                            .values()
                            .flatten()
                            .any(|s| s.disconnected_until.is_some_and(|t| t <= now)),
                )
            };
            if paused == healthy {
                action(
                    &runtime,
                    Action::Domain(league::LeagueAction::Infrastructure {
                        league: runtime.config.league.clone(),
                        healthy,
                    }),
                )
                .await?;
            }
            runtime.healthy = healthy;
            if healthy && expired {
                action(
                    &runtime,
                    Action::Domain(league::LeagueAction::Tick {
                        league: runtime.config.league.clone(),
                    }),
                )
                .await?;
            }
            let missing = {
                let j = runtime.cache.read().await;
                j.domain.leagues[&runtime.config.league]
                    .online
                    .iter()
                    .filter(|m| !runtime.active.contains_key(*m))
                    .cloned()
                    .collect::<Vec<_>>()
            };
            for member in missing {
                presence(&runtime, &member, false, ConnectionHealth::default()).await?;
            }
            changed.send_replace(());
            Ok(())
        }
        .await;
        if let Err(error) = result {
            // Election/temporary quorum loss must not tear down all live game sockets.
            // No routing effect is emitted until the state read and commands commit again.
            tracing::warn!("governance monitor will retry: {error}");
        }
    }
}
async fn reader<R: AsyncRead + Unpin>(mut read: R, tx: mpsc::Sender<Result<Vec<u8>>>) {
    loop {
        let packet = wire::read_frame(&mut read).await;
        let failed = packet.is_err();
        if tx.send(packet).await.is_err() || failed {
            break;
        }
    }
}
async fn status<S: GameStream>(stream: &mut S) -> Result<()> {
    let request = Packet::decode(&wire::read_frame(stream).await?, None)?;
    ensure!(
        request.id == 0 && request.body.is_empty(),
        "invalid status request"
    );
    let value = serde_json::json!({
        "version": {"name": "26.3", "protocol": wire::VERSION},
        "players": {"max": 256, "online": 0},
        "description": {"text": STATUS_DESCRIPTION},
    })
    .to_string();
    let mut body = vec![];
    wire::string(&value, &mut body)?;
    wire::write_packet(stream, Packet { id: 0, body }, None).await?;
    let ping = Packet::decode(&wire::read_frame(stream).await?, None)?;
    ensure!(ping.id == 1 && ping.body.len() == 8, "invalid ping");
    wire::write_packet(stream, ping, None).await
}
async fn session(
    incoming: IncomingSession,
    shared: Shared,
    node: Arc<Node>,
    mut changed: watch::Receiver<()>,
) -> Result<()> {
    let claims = incoming
        .claims
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("identity required"))?;
    let admission: node::protocol::TrustAdmission = serde_json::from_slice(claims)?;
    let peer = incoming.peer.to_string();
    let mut client = incoming.stream.compat();
    let first = timeout(Duration::from_secs(10), wire::read_frame(&mut client)).await??;
    let first = Packet::decode(&first, None)?;
    ensure!(first.id == 0, "expected handshake");
    let mut fields = Fields::new(&first.body);
    let version = fields.int()?;
    let host = fields.text(255)?.to_owned();
    let port = u16::from_be_bytes(fields.bytes(2)?.try_into()?);
    let intention = fields.int()?;
    fields.finish()?;
    if intention == 1 {
        return timeout(Duration::from_secs(10), status(&mut client)).await?;
    }
    ensure!(
        version == wire::VERSION && (intention == 2 || intention == 3),
        "unsupported Minecraft version or intention"
    );
    ensure!(
        (host == "127.0.0.1" || host == "localhost") && port != 0,
        "client must connect through launcher loopback endpoint"
    );
    let login = Packet::decode(
        &timeout(Duration::from_secs(10), wire::read_frame(&mut client)).await??,
        None,
    )?;
    ensure!(login.id == 0, "expected login start");
    let mut fields = Fields::new(&login.body);
    let name = fields.text(16)?.to_owned();
    let uuid = uuid::Uuid::from_slice(fields.bytes(16)?)?;
    fields.finish()?;
    let (member, id, profile, selected, backend) = {
        let mut runtime = shared.lock().await;
        let member = {
            let j = runtime.cache.read().await;
            j.members
                .iter()
                .find(|(_, m)| m.owns(&peer))
                .map(|(id, _)| id.clone())
                .ok_or_else(|| anyhow::anyhow!("unknown device"))?
        };
        let profile = {
            ensure!(
                admission.game_profile.as_deref() == Some(uuid.simple().to_string().as_str()),
                "verified identity does not match Minecraft profile"
            );
            crate::forwarding::validate_name(&name)?;
            Profile {
                uuid,
                name: name.clone(),
            }
        };
        ensure!(
            !runtime.active.contains_key(&member),
            "member already connected"
        );
        let selected = room(&runtime, &member).await?;
        let backend = match selected {
            Room::Waiting => runtime.config.waiting.clone(),
            Room::Arena(_) => runtime.config.arena.clone(),
        };
        runtime.next = runtime
            .next
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("session id exhausted"))?;
        let id = runtime.next;
        let recovery_ms = runtime
            .disconnected
            .remove(&member)
            .map(|t| t.elapsed().as_millis().min(MAX_RECOVERY_MS) as u64)
            .unwrap_or(0);
        runtime.active.insert(
            member.clone(),
            Active {
                id,
                health: ConnectionHealth {
                    recovery_ms,
                    ..Default::default()
                },
            },
        );
        (member, id, profile, selected, backend)
    };
    tracing::info!(member = %member, device = %peer, profile = %profile.uuid, display_name = %profile.name, "verified game identity forwarding");
    let result = async {
        let mut remote = backend.connect(&node).await?;
        wire::write_packet(
            &mut remote,
            handshake("localhost", wire::DEFAULT_MC_PORT, 2)?,
            None,
        )
        .await?;
        wire::write_packet(&mut remote, login, None).await?;
        let (cr, mut cw) = tokio::io::split(client);
        let (br, mut bw) = tokio::io::split(remote);
        let (ct, mut cx) = mpsc::channel(1);
        let (bt, mut bx) = mpsc::channel(1);
        let mut readers = JoinSet::new();
        readers.spawn(reader(cr, ct));
        readers.spawn(reader(br, bt));
        let mut stage = Stage::Login;
        let mut compression = None;
        let mut negotiation = crate::forwarding::LoginNegotiation::default();
        let mut keepalive: Option<(Vec<u8>, Instant)> = None;
        let mut announced = false;
        let mut started = Instant::now();
        loop {
            {
                let runtime = shared.lock().await;
                let state = runtime.cache.read().await;
                ensure!(
                    state.members.get(&member).is_some_and(|m| m.owns(&peer)),
                    "device authorization revoked"
                );
            }
            if stage != Stage::Play && started.elapsed() > Duration::from_secs(120) {
                bail!("Minecraft login/configuration timed out");
            }
            if matches!(stage, Stage::Play | Stage::Configuration)
                && room(&*shared.lock().await, &member).await? != selected
            {
                // Fence the old connection before issuing transfer; a reconnect may race
                // this task's final cleanup, which is guarded by the session generation.
                finish(&shared, &member, id).await?;
                let mut body = vec![];
                wire::string("127.0.0.1", &mut body)?;
                wire::varint(u32::from(port), &mut body);
                wire::write_packet(
                    &mut cw,
                    Packet {
                        id: if stage == Stage::Play {
                            wire::PLAY_TRANSFER
                        } else {
                            wire::CONFIGURATION_TRANSFER
                        },
                        body,
                    },
                    compression,
                )
                .await?;
                return Ok(());
            }
            let (from_client, raw) = tokio::select! {
                update = changed.changed() => { update?; continue; },
                raw = cx.recv() => (true, raw),
                raw = bx.recv() => (false, raw),
            };
            if from_client {
                let raw = raw.ok_or_else(|| anyhow::anyhow!("client closed"))??;
                let p = Packet::decode(&raw, compression)?;
                match stage {
                    Stage::Login => ensure!(p.id == 4, "unexpected packet before login success"),
                    Stage::LoginAck => {
                        ensure!(
                            p.id == 3 && p.body.is_empty(),
                            "expected login acknowledgment"
                        );
                        stage = Stage::Configuration;
                    }
                    Stage::Configuration => {
                        ensure!(p.id != 3, "unsolicited configuration acknowledgment")
                    }
                    Stage::ConfigurationAck if p.id == 3 => {
                        ensure!(p.body.is_empty(), "invalid configuration acknowledgment");
                        stage = Stage::Play;
                        if !announced {
                            let runtime = shared.lock().await;
                            let health = runtime.active[&member].health.clone();
                            presence(&runtime, &member, true, health).await?;
                            announced = true;
                        }
                    }
                    Stage::ReconfigurationAck if p.id == wire::PLAY_RECONFIGURE_ACK => {
                        ensure!(p.body.is_empty(), "invalid reconfiguration acknowledgment");
                        stage = Stage::Configuration;
                    }
                    _ => {}
                }
                if stage == Stage::Play
                    && p.id == wire::PLAY_KEEPALIVE_REPLY
                    && let Some((expected, sent)) = keepalive.take()
                {
                    ensure!(p.body == expected, "unexpected keepalive reply");
                    let rtt = sent.elapsed().as_millis().min(60_000) as u64;
                    let mut runtime = shared.lock().await;
                    if let Some(active) = runtime.active.get_mut(&member) {
                        active.health.jitter_ms =
                            (active.health.jitter_ms * 3 + active.health.rtt_ms.abs_diff(rtt)) / 4;
                        active.health.rtt_ms = rtt;
                    }
                }
                wire::write_frame(&mut bw, &raw).await?;
            } else {
                let raw = raw.ok_or_else(|| anyhow::anyhow!("backend closed"))??;
                let p = Packet::decode(&raw, compression)?;
                match stage {
                    Stage::Login => {
                        use crate::forwarding::LoginStep;
                        match negotiation
                            .receive(&p, compression, &profile, || backend.forwarding(&profile))?
                        {
                            LoginStep::Compression(threshold) => {
                                wire::write_frame(&mut cw, &raw).await?;
                                compression = Some(threshold);
                                continue;
                            }
                            LoginStep::Reply(reply) => {
                                wire::write_packet(&mut bw, reply, compression).await?;
                                continue;
                            }
                            LoginStep::Ready => stage = Stage::LoginAck,
                            LoginStep::Forward => {}
                        }
                    }
                    Stage::Configuration if p.id == 3 => {
                        ensure!(p.body.is_empty(), "invalid finish configuration");
                        stage = Stage::ConfigurationAck;
                    }
                    Stage::Play if p.id == wire::PLAY_RECONFIGURE => {
                        ensure!(p.body.is_empty(), "invalid start configuration");
                        stage = Stage::ReconfigurationAck;
                        started = Instant::now();
                    }
                    Stage::Play if p.id == wire::PLAY_KEEPALIVE => {
                        ensure!(p.body.len() == 8, "invalid keepalive");
                        keepalive = Some((p.body.clone(), Instant::now()));
                    }
                    Stage::Play if p.id == wire::PLAY_TRANSFER => {
                        bail!("backend attempted unmanaged transfer")
                    }
                    Stage::Configuration if p.id == wire::CONFIGURATION_TRANSFER => {
                        bail!("backend attempted unmanaged transfer")
                    }
                    _ => {}
                }
                wire::write_frame(&mut cw, &raw).await?;
            }
        }
    }
    .await;
    finish(&shared, &member, id).await?;
    result
}
pub async fn serve(
    config: Config,
    node: Arc<Node>,
    journal: Authority,
    identity: Identity,
    mut incoming: mpsc::Receiver<IncomingSession>,
) -> Result<()> {
    {
        let j = journal.operational_state(identity.peer_id()).await?;
        let league = j
            .domain
            .leagues
            .get(&config.league)
            .ok_or_else(|| anyhow::anyhow!("league missing"))?;
        ensure!(
            league.host == identity.peer_id().to_string(),
            "not league host"
        );
    }
    let cached = journal.operational_state(identity.peer_id()).await?;
    let runtime = Runtime {
        cache: RwLock::new(cached),
        journal,
        identity,
        config,
        healthy: false,
        active: BTreeMap::new(),
        disconnected: BTreeMap::new(),
        next: 0,
    };
    action(
        &runtime,
        Action::Domain(league::LeagueAction::Infrastructure {
            league: runtime.config.league.clone(),
            healthy: false,
        }),
    )
    .await?;
    let online = runtime.cache.read().await.domain.leagues[&runtime.config.league]
        .online
        .clone();
    for member in online {
        presence(&runtime, &member, false, ConnectionHealth::default()).await?;
    }
    let shared = Arc::new(Mutex::new(runtime));
    let (changed, receiver) = watch::channel(());
    let monitor = monitor(shared.clone(), node.clone(), changed);
    tokio::pin!(monitor);
    let mut sessions = JoinSet::new();
    loop {
        tokio::select! {
         result=&mut monitor=>{result?;break;},
         incoming = incoming.recv() => {
             let Some(incoming) = incoming else { break };
             if sessions.len() >= MAX_NATIVE_SESSIONS {
                 tracing::warn!(peer = %incoming.peer, service = %incoming.service, "game session capacity reached; closing stream");
                 let mut stream = tokio_util::compat::FuturesAsyncReadCompatExt::compat(incoming.stream);
                 if let Err(error) = tokio::io::AsyncWriteExt::shutdown(&mut stream).await {
                     tracing::debug!(%error, "game overload close failed");
                 }
                 continue;
             }
             let (shared, node, changed) = (shared.clone(), node.clone(), receiver.clone());
             sessions.spawn(async move { session(incoming, shared, node, changed).await });
         },
         Some(result)=sessions.join_next(),if !sessions.is_empty()=>{match result{Ok(Ok(()))=>{},Ok(Err(error))=>tracing::debug!("game session ended: {error}"),Err(error)=>return Err(error.into())}}
        }
    }
    sessions.shutdown().await;
    Ok(())
}
#[cfg(test)]
mod tests;
