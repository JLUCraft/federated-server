//! Identity-authorized operations over locally configured instances.
use crate::rooms::{InstanceConfig, shutdown_instance};
use anyhow::{Context, Result, ensure};
use minecraftd::{core::state::InstanceState, service::instance::InstanceService};
use node::{
    Node, ServiceId,
    protocol::{
        JsonFrame, OpsInstance, OpsInstanceState, OpsOp, OpsRequest, OpsResponse, read_frame,
        write_frame,
    },
};
use serde::Deserialize;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::{sync::Mutex, task::JoinSet, time::timeout};

pub(crate) const MAX_INSTANCES: usize = 32;
const OP_TIMEOUT: Duration = Duration::from_secs(120);
const PING_TIMEOUT: Duration = Duration::from_secs(2);
const LOG_LINES: usize = 100;
const LOG_BYTES: usize = 8 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub instances: Vec<InstanceConfig>,
}
struct Managed {
    config: InstanceConfig,
    instance: InstanceService,
    operation: Mutex<()>,
}

pub struct Fleet {
    instances: BTreeMap<String, Managed>,
}
impl Fleet {
    pub fn new(config: Config) -> crate::Result<Self> {
        Self::new_inner(config).map_err(crate::operation_error)
    }
    fn new_inner(config: Config) -> Result<Self> {
        ensure!(
            config.instances.len() <= MAX_INSTANCES,
            "at most 32 configured instances"
        );
        let mut instances = BTreeMap::new();
        for config in config.instances {
            ensure!(!instances.contains_key(&config.id), "duplicate instance id");
            let instance = config.create()?;
            instances.insert(
                config.id.clone(),
                Managed {
                    config,
                    instance,
                    operation: Mutex::new(()),
                },
            );
        }
        Ok(Self { instances })
    }
    pub async fn execute(&self, request: OpsRequest) -> crate::Result<OpsResponse> {
        self.execute_inner(request)
            .await
            .map_err(crate::operation_error)
    }
    async fn execute_inner(&self, request: OpsRequest) -> Result<OpsResponse> {
        if let OpsOp::ListInstances {} = request.op {
            let mut instances = Vec::new();
            for managed in self.instances.values() {
                instances.push(status(managed).await?);
            }
            return Ok(OpsResponse {
                ok: true,
                instances,
                ..Default::default()
            });
        }
        let id = match &request.op {
            OpsOp::Status { instance }
            | OpsOp::Start { instance }
            | OpsOp::Stop { instance }
            | OpsOp::Restart { instance }
            | OpsOp::Kill { instance }
            | OpsOp::Logs { instance } => instance,
            OpsOp::ListInstances {} => anyhow::bail!("list operation has no instance"),
        };
        let managed = self.instances.get(id).context("unknown instance")?;
        let _operation = managed
            .operation
            .try_lock()
            .context("instance operation already in progress")?;
        let mut response = OpsResponse {
            ok: true,
            ..Default::default()
        };
        let mut states = managed.instance.state_watch();
        let expected = match request.op {
            OpsOp::Start { .. } => {
                ensure!(
                    matches!(
                        managed.instance.state(),
                        InstanceState::Stopped | InstanceState::Error(_)
                    ),
                    "instance is not stopped"
                );
                managed.instance.start().await?;
                Some(InstanceState::Running)
            }
            OpsOp::Stop { .. } => {
                ensure!(
                    managed.instance.state() == InstanceState::Running,
                    "instance is not running"
                );
                managed.instance.stop().await?;
                Some(InstanceState::Stopped)
            }
            OpsOp::Kill { .. } => {
                ensure!(
                    managed.instance.state() == InstanceState::Running,
                    "instance is not running"
                );
                managed.instance.kill().await?;
                Some(InstanceState::Stopped)
            }
            OpsOp::Restart { .. } => {
                ensure!(
                    managed.instance.state() == InstanceState::Running,
                    "instance is not running"
                );
                managed.instance.restart().await?;
                Some(InstanceState::Running)
            }
            OpsOp::Logs { .. } => {
                let mut logs = managed.instance.recent_output(LOG_LINES).await?.join("\n");
                if logs.len() > LOG_BYTES {
                    let mut boundary = logs.len() - LOG_BYTES;
                    while !logs.is_char_boundary(boundary) {
                        boundary += 1;
                    }
                    logs.drain(..boundary);
                }
                response.logs = Some(logs);
                None
            }
            _ => None,
        };
        if let Some(expected) = expected {
            timeout(OP_TIMEOUT, async {
                loop {
                    let state = states.borrow_and_update().clone();
                    if state == expected {
                        return Ok::<_, anyhow::Error>(());
                    }
                    if let InstanceState::Error(error) = state {
                        anyhow::bail!("instance operation failed: {error}");
                    }
                    states
                        .changed()
                        .await
                        .context("instance supervisor stopped")?;
                }
            })
            .await
            .context("instance operation timed out")??;
        }
        response.instances.push(status(managed).await?);
        Ok(response)
    }
    pub async fn shutdown(&self) -> crate::Result<()> {
        self.shutdown_inner().await.map_err(crate::operation_error)
    }
    async fn shutdown_inner(&self) -> Result<()> {
        let mut failure = None;
        for managed in self.instances.values() {
            if let Err(error) = shutdown_instance(&managed.instance).await {
                failure.get_or_insert(error);
            }
        }
        match failure {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }
}
async fn status(managed: &Managed) -> Result<OpsInstance> {
    let state = match managed.instance.state() {
        InstanceState::Stopped => OpsInstanceState::Stopped,
        InstanceState::Starting => OpsInstanceState::Starting,
        InstanceState::Running => OpsInstanceState::Running,
        InstanceState::Stopping => OpsInstanceState::Stopping,
        InstanceState::Busy => OpsInstanceState::Busy,
        InstanceState::Error(_) => OpsInstanceState::Error,
    };
    let ping = if state == OpsInstanceState::Running {
        minecraftd::minecraft::ping::ping_java_server(managed.config.backend, PING_TIMEOUT)
            .await
            .ok()
    } else {
        None
    };
    Ok(OpsInstance {
        id: managed.config.id.clone(),
        kind: managed.config.server.server_type.clone(),
        state,
        players_online: ping
            .as_ref()
            .map(|p| u32::try_from(p.current_players))
            .transpose()?
            .unwrap_or_default(),
        players_max: ping
            .as_ref()
            .map(|p| u32::try_from(p.max_players))
            .transpose()?
            .unwrap_or_default(),
        version: ping.as_ref().map(|p| p.version.clone()).unwrap_or_default(),
        description: ping.map(|p| p.description),
    })
}

pub async fn serve(
    node: &Node,
    mut incoming: tokio::sync::mpsc::Receiver<node::IncomingSession>,
    service: ServiceId,
    fleet: Arc<Fleet>,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            session = incoming.recv() => {
                let Some(mut session) = session else { break; };
                let fleet = fleet.clone();
                tasks.spawn(async move {
                    timeout(OP_TIMEOUT, async {
                        let frame: JsonFrame = read_frame(&mut session.stream).await?;
                        ensure!(frame.sequence == 0 && frame.last, "invalid ops envelope");
                        let result = match serde_json::from_slice(&frame.json) {
                            Ok(request) => fleet.execute(request).await.map_err(anyhow::Error::from),
                            Err(error) => Err(error.into()),
                        };
                        let response = result.unwrap_or_else(|error| OpsResponse {
                            ok: false, error: Some(error.to_string()), ..Default::default()
                        });
                        write_frame(&mut session.stream, &JsonFrame { json: serde_json::to_vec(&response)?, sequence: 0, last: true }).await?;
                        Ok::<_, anyhow::Error>(())
                    }).await?
                });
            }
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = result { tracing::warn!(%error, "ops task failed"); }
            }
        }
    }
    node.withdraw(service).await;
    tasks.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use minecraftd::instance::server::ServerConfig;

    #[tokio::test]
    async fn failed_start_is_reported_and_unknown_instances_are_rejected() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let config = InstanceConfig {
            id: "test".into(),
            directory: directory.path().into(),
            backend: "127.0.0.1:25565".parse()?,
            server: ServerConfig {
                start_command: "/nonexistent/federated-room-test".into(),
                server_type: "minecraft/java".into(),
                ..Default::default()
            },
        };
        assert!(
            Fleet::new(Config {
                instances: vec![config.clone(), config.clone()]
            })
            .is_err()
        );
        let fleet = Fleet::new(Config {
            instances: vec![config],
        })?;
        let list = fleet
            .execute(OpsRequest {
                op: OpsOp::ListInstances {},
            })
            .await?;
        assert!(list.ok);
        assert_eq!(list.instances.len(), 1);
        assert_eq!(list.instances[0].state, OpsInstanceState::Stopped);
        assert!(
            fleet
                .execute(OpsRequest {
                    op: OpsOp::Status {
                        instance: "unknown".into()
                    }
                })
                .await
                .is_err()
        );
        assert!(
            fleet
                .execute(OpsRequest {
                    op: OpsOp::Start {
                        instance: "test".into()
                    }
                })
                .await
                .is_err()
        );
        fleet.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn identity_session_returns_single_frame_success_and_business_errors() -> Result<()> {
        timeout(Duration::from_secs(20), async {
            use identity::Identity;
            use node::{AccessPolicy, NodeConfig, Service};

            let directory = tempfile::tempdir()?;
            let host_key = Identity::generate();
            let user = Identity::generate();
            let mut identities = crate::test_identity::Identities::new(
                &[(&host_key, "host", "club"), (&user, "user", "club")],
                "host",
            );
            let fleet = Arc::new(Fleet::new(Config {
                instances: vec![InstanceConfig {
                    id: "test".into(),
                    directory: directory.path().into(),
                    backend: "127.0.0.1:25565".parse()?,
                    server: ServerConfig {
                        start_command: "/nonexistent/federated-room-network-test".into(),
                        ..Default::default()
                    },
                }],
            })?);
            let mut host = Node::start(host_key.clone(), NodeConfig::default()).await?;
            let incoming = host.take_incoming()?;
            let service = ServiceId::new();
            identities.service(&host_key, &service.to_string(), "user", "manage");
            let view = identities.log.view(Duration::from_secs(60))?;
            host.publish(Service {
                id: service,
                name: "Operations fixture".into(),
                protocol: node::protocol::OPS_PROTOCOL.into(),
                metadata: vec![],
                access: AccessPolicy::Trust {
                    view,
                    requirement: node::protocol::TrustRequirement {
                        clubs: Default::default(),
                        permission: Some("manage".into()),
                    },
                },
            })
            .await?;
            let client = Node::start(user, NodeConfig::default()).await?;
            client.dial(host.addresses()[0].clone()).await?;
            let mut tasks = JoinSet::new();
            let host = Arc::new(host);
            let serving = host.clone();
            let managed = fleet.clone();
            tasks.spawn(async move { serve(&serving, incoming, service, managed).await });
            for (json, ok) in [
                (r#"{"op":{"op":"list_instances"}}"#, true),
                (r#"{"op":{"op":"status","instance":"missing"}}"#, false),
                (r#"{"op":{"op":"start","instance":"test"}}"#, false),
                (r#"{"op":{"op":"list_instances","unexpected":true}}"#, false),
                (r#"{"op":{"op":"list_instances"}}"#, true),
            ] {
                let mut stream = client.open_service(host.peer_id(), service).await?;
                write_frame(
                    &mut stream,
                    &JsonFrame {
                        json: json.as_bytes().to_vec(),
                        sequence: 0,
                        last: true,
                    },
                )
                .await?;
                let frame: JsonFrame = read_frame(&mut stream).await?;
                assert_eq!(frame.sequence, 0);
                assert!(frame.last);
                let response: OpsResponse = serde_json::from_slice(&frame.json)?;
                assert_eq!(response.ok, ok);
                if ok {
                    assert_eq!(response.instances.len(), 1);
                    assert_eq!(response.instances[0].id, "test");
                } else {
                    assert!(response.error.is_some_and(|message| !message.is_empty()));
                }
            }
            tasks.shutdown().await;
            host.withdraw(service).await;
            fleet.shutdown().await?;
            client.shutdown().await?;
            Arc::try_unwrap(host)
                .map_err(|_| anyhow::anyhow!("operations task still owns host"))?
                .shutdown()
                .await?;
            Ok::<_, anyhow::Error>(())
        })
        .await?
    }
}
