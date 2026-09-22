mod native;
mod scoring;
mod wire;
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::{net::SocketAddr, time::Duration};
use terminal_runtime::{AccessArgs, NodeArgs, init_logging, serve_backend};
use union_core::{Service, ServiceId};

#[derive(Parser)]
#[command(version, about = "Federated Minecraft service host")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Host signed federation governance independently of Minecraft world processes.
    Govern {
        #[command(flatten)]
        node: Box<NodeArgs>,
        #[arg(long)]
        journal: std::path::PathBuf,
        #[arg(long, required = true)]
        admin: Vec<union_core::PeerId>,
        /// Initial voter map JSON; identical on every replica. Keep unchanged after bootstrap.
        #[arg(long, requires = "raft_id")]
        raft_peers: Option<std::path::PathBuf>,
        #[arg(long, requires = "raft_peers")]
        raft_id: Option<u64>,
        /// Run only once, on one initial replica.
        #[arg(long, requires = "raft_peers")]
        initialize: bool,
        #[arg(long, requires_all = ["scorer_key", "scoring_token"])]
        scoring_bind: Option<SocketAddr>,
        #[arg(long, requires = "scoring_bind")]
        scorer_key: Option<std::path::PathBuf>,
        #[arg(long, requires = "scoring_bind")]
        scoring_token: Option<std::path::PathBuf>,
        #[arg(long)]
        native_config: Option<std::path::PathBuf>,
    },
    /// Publish an existing Minecraft TCP backend through union-core.
    Serve {
        #[command(flatten)]
        node: Box<NodeArgs>,
        #[command(flatten)]
        access: AccessArgs,
        #[arg(long)]
        service: ServiceId,
        #[arg(long, default_value = "Minecraft server")]
        name: String,
        #[arg(long, default_value = "127.0.0.1:25565")]
        backend: SocketAddr,
    },
    /// Query an existing Java server through the pinned minecraftd library.
    Status {
        #[arg(long, default_value = "127.0.0.1:25565")]
        backend: SocketAddr,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    match Args::parse().command {
        Command::Govern {
            node,
            journal,
            admin,
            raft_peers,
            raft_id,
            initialize,
            scoring_bind,
            scorer_key,
            scoring_token,
            native_config,
        } => {
            let state = union_core::governance::State::new(
                admin.into_iter().map(|p| p.to_string()).collect(),
            )?;
            let host_identity = union_core::Identity::load(&node.key)?;
            let mut node = node.start(false).await?;
            // Incoming service streams are taken before sharing the node with Raft.
            let incoming = if native_config.is_some() {
                Some(node.take_incoming()?)
            } else {
                None
            };
            let node = std::sync::Arc::new(node);
            let cluster = if let (Some(path), Some(id)) = (raft_peers, raft_id) {
                let peers = serde_json::from_slice(&std::fs::read(path)?)?;
                Some(
                    union_core::consensus::Cluster::start(
                        id,
                        node.clone(),
                        &journal,
                        state.clone(),
                        peers,
                    )
                    .await?,
                )
            } else {
                None
            };
            let authority = if let Some(cluster) = &cluster {
                union_core::authority::Authority::Replicated(cluster.clone())
            } else {
                union_core::authority::Authority::Local(std::sync::Arc::new(
                    tokio::sync::Mutex::new(union_core::journal::Journal::open(journal, state)?),
                ))
            };
            let mut governance = {
                let authority = authority.clone();
                let node = node.clone();
                tokio::spawn(async move {
                    match authority {
                        union_core::authority::Authority::Local(journal) => {
                            union_core::journal::serve(&node, journal).await
                        }
                        union_core::authority::Authority::Replicated(cluster) => {
                            cluster.serve().await
                        }
                    }
                })
            };
            if initialize {
                cluster
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Raft configuration required"))?
                    .initialize()
                    .await?;
            }
            let native = if let Some(path) = native_config {
                let config: native::Config = serde_json::from_slice(&std::fs::read(path)?)?;
                let peers = {
                    let j = authority.state(host_identity.peer_id()).await?;
                    config
                        .players
                        .keys()
                        .map(|id| {
                            let member = j
                                .members
                                .get(id)
                                .ok_or_else(|| anyhow::anyhow!("unknown roster member"))?;
                            member
                                .devices()
                                .map(|device| {
                                    device.parse::<union_core::PeerId>().map_err(Into::into)
                                })
                                .collect::<Result<Vec<_>>>()
                        })
                        .collect::<Result<Vec<_>>>()?
                        .into_iter()
                        .flatten()
                        .collect::<std::collections::HashSet<_>>()
                };
                node.publish(Service {
                    id: config.service.parse()?,
                    name: "高校联赛".into(),
                    protocol: "minecraft/java/26.3".into(),
                    access: if let Some(policy) = &config.student_policy {
                        union_core::AccessPolicy::Students {
                            trust: Box::new(policy.trust.clone()),
                            minimum: policy.minimum,
                            current_enrollment: policy.current_enrollment,
                        }
                    } else {
                        union_core::AccessPolicy::Peers(peers)
                    },
                })
                .await?;
                Some((
                    config,
                    incoming.ok_or_else(|| anyhow::anyhow!("missing service receiver"))?,
                ))
            } else {
                None
            };
            let event_server = union_core::events::serve_authority(node.clone(), authority.clone());
            let native = async {
                if let Some((config, incoming)) = native {
                    native::serve(
                        config,
                        node.clone(),
                        authority.clone(),
                        host_identity,
                        incoming,
                    )
                    .await
                } else {
                    std::future::pending::<Result<()>>().await
                }
            };
            let scoring = async {
                if let (Some(bind), Some(key), Some(token)) =
                    (scoring_bind, scorer_key, scoring_token)
                {
                    scoring::serve(
                        bind,
                        authority.clone(),
                        union_core::Identity::load(key)?,
                        std::fs::read_to_string(token)?.trim().to_owned(),
                    )
                    .await
                } else {
                    std::future::pending::<Result<()>>().await
                }
            };
            tokio::select! {
                result=event_server=>result?,
                result=scoring => result?,
                result=native => result?,
                result=&mut governance => result??,
                result=tokio::signal::ctrl_c() => result?,
            }
            governance.abort();
            if let Some(cluster) = cluster {
                cluster.shutdown().await?;
            }
            drop(node);
        }
        Command::Serve {
            node,
            access,
            service,
            name,
            backend,
        } => {
            let node = node.start(false).await?;
            node.publish(Service {
                id: service,
                name,
                protocol: "minecraft/java/tcp".into(),
                access: access.policy(),
            })
            .await?;
            serve_backend(node, backend).await?;
        }
        Command::Status { backend } => {
            let status =
                minecraftd::minecraft::ping::ping_java_server(backend, Duration::from_secs(5))
                    .await?;
            tracing::info!(
                "{} {}/{} players — {}",
                status.version,
                status.current_players,
                status.max_players,
                status.description
            );
        }
    }
    Ok(())
}
