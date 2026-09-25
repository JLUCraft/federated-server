mod gateway;
mod trust;
use std::{
    fs::OpenOptions,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::Result;
use clap::{Parser, Subcommand};
use node::{Identity, PeerId, ServiceId};
use terminal_runtime::{NodeArgs, TargetArgs, init_logging, run_proxy};

#[derive(Parser)]
#[command(version, about = "Federation management terminal foundation")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Args)]
struct BusinessIdentity {
    /// Pinned unified identity genesis, cache and synchronization endpoint JSON.
    #[arg(long)]
    identity_config: PathBuf,
}
impl BusinessIdentity {
    fn load(self) -> Result<client::trust::Config> {
        let path = self.identity_config;
        anyhow::ensure!(
            std::fs::metadata(&path)?.len() <= node::protocol::MAX_FRAME as u64,
            "identity configuration too large"
        );
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }
}

#[derive(Subcommand)]
enum Command {
    /// Unified identity log and co-signing.
    Trust {
        #[command(subcommand)]
        command: trust::Command,
    },
    /// Inspect or verify LLM usage ledger commitments.
    Gateway {
        #[command(subcommand)]
        command: gateway::Command,
    },
    /// Discover member-owned Minecraft rooms through federation seeds.
    Rooms {
        #[command(flatten)]
        node: NodeArgs,
    },
    /// Run an instance operation using unified service permissions.
    Ops {
        #[command(flatten)]
        node: Box<NodeArgs>,
        #[command(flatten)]
        target: TargetArgs,
        #[arg(long)]
        service: ServiceId,
        #[command(subcommand)]
        operation: OpsCommand,
    },
    /// Institution-neutral event planning and approval workflows.
    Office {
        #[command(subcommand)]
        command: OfficeCommand,
    },
    /// Call an LLM gateway using unified service permissions.
    Llm {
        #[command(subcommand)]
        command: LlmCommand,
    },
    /// Signed governance request. Omit --action for a snapshot; action is a JSON file.
    Governance {
        #[command(flatten)]
        authorization: BusinessIdentity,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        address: String,
        #[arg(long)]
        peer: String,
        /// SHA-256 of canonical genesis JSON, confirmed through an independent channel.
        #[arg(long)]
        genesis_hash: String,
        #[arg(long)]
        revision: Option<u64>,
        #[arg(long)]
        action: Option<PathBuf>,
    },
    /// Create a device/issuer key without overwriting an existing identity.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the public PeerId for an existing key.
    Identity {
        #[arg(long)]
        key: PathBuf,
    },
    /// Allocate a stable service identifier.
    NewServiceId,
    /// Find a service via federation discovery seeds; providers are untrusted hints.
    Discover {
        #[command(flatten)]
        node: NodeArgs,
        #[arg(long)]
        service: ServiceId,
    },
    /// Watch invalidations; reconnecting consumers must pull a new snapshot.
    Watch {
        #[command(flatten)]
        node: NodeArgs,
        #[command(flatten)]
        target: TargetArgs,
        #[arg(long, default_value_t = 0)]
        after_revision: u64,
    },
    /// Query a known host's authenticated service directory.
    List {
        #[command(flatten)]
        node: NodeArgs,
        #[command(flatten)]
        target: TargetArgs,
    },
    /// List installed Minecraft instances discovered by the minecraftd library.
    LocalInstances,
    /// Expose a local TCP endpoint for an existing Minecraft client through the federation proxy.
    Proxy {
        #[command(flatten)]
        node: Box<NodeArgs>,
        #[command(flatten)]
        target: TargetArgs,
        #[arg(long)]
        service: ServiceId,
        #[arg(long, default_value = "127.0.0.1:25566")]
        bind: SocketAddr,
    },
}

#[derive(Subcommand)]
enum OpsCommand {
    ListInstances,
    Status { instance: String },
    Start { instance: String },
    Stop { instance: String },
    Restart { instance: String },
    Kill { instance: String },
    Logs { instance: String },
}
impl From<OpsCommand> for node::protocol::OpsOp {
    fn from(command: OpsCommand) -> Self {
        match command {
            OpsCommand::ListInstances => Self::ListInstances {},
            OpsCommand::Status { instance } => Self::Status { instance },
            OpsCommand::Start { instance } => Self::Start { instance },
            OpsCommand::Stop { instance } => Self::Stop { instance },
            OpsCommand::Restart { instance } => Self::Restart { instance },
            OpsCommand::Kill { instance } => Self::Kill { instance },
            OpsCommand::Logs { instance } => Self::Logs { instance },
        }
    }
}

type Office = flows::Flows<events::EventsDomain>;
#[derive(Subcommand)]
enum OfficeCommand {
    /// Upload complete file content and a versioned directory commit to the office journal.
    PutFile {
        #[arg(long)]
        identity_config: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        address: String,
        #[arg(long)]
        peer: PeerId,
        #[arg(long)]
        genesis_hash: String,
        #[arg(long)]
        branch: String,
        #[arg(long)]
        path: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        message: String,
    },
    /// Restore an immutable file version from the verified office snapshot.
    GetFile {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        address: String,
        #[arg(long)]
        peer: PeerId,
        #[arg(long)]
        genesis_hash: String,
        #[arg(long)]
        cid: client::protocol::Cid,
        #[arg(long)]
        out: PathBuf,
    },
    /// Store a local document by its SHA-256; stdout is the on-chain anchor.
    StoreDocument {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        file: PathBuf,
    },
    /// Fetch and hash-verify an authorized document without overwriting a file.
    FetchDocument {
        #[command(flatten)]
        node: Box<NodeArgs>,
        #[command(flatten)]
        target: TargetArgs,
        #[arg(long)]
        service: ServiceId,
        #[arg(long)]
        hash: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Write a public genesis and print its hash for independent pinning.
    Init {
        #[arg(long)]
        binding: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Signed JSON action; omit --action to retrieve a verified snapshot.
    Request {
        #[command(flatten)]
        authorization: BusinessIdentity,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        address: String,
        #[arg(long)]
        peer: String,
        #[arg(long)]
        genesis_hash: String,
        #[arg(long)]
        revision: Option<u64>,
        #[arg(long)]
        action: Option<PathBuf>,
    },
}
pub(crate) fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.sync_all()?;
    Ok(())
}

#[derive(Subcommand)]
enum LlmCommand {
    Ask {
        #[command(flatten)]
        node: Box<NodeArgs>,
        #[command(flatten)]
        target: TargetArgs,
        #[arg(long)]
        service: ServiceId,
        #[arg(long)]
        model: String,
        #[arg(long, default_value = "assistant.ask")]
        purpose: String,
        #[arg(long, default_value_t = 1024)]
        max_tokens: u32,
        #[arg(long)]
        sensitive: bool,
        prompt: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    match Args::parse().command {
        Command::Gateway { command } => gateway::execute(command)?,
        Command::Trust { command } => trust::execute(command).await?,
        Command::Office { command } => match command {
            OfficeCommand::PutFile {
                identity_config,
                key,
                address,
                peer,
                genesis_hash,
                branch,
                path,
                file,
                message,
            } => {
                use std::io::Read;
                let mut bytes = Vec::new();
                std::fs::File::open(file)?
                    .take(events::files::MAX_FILE_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)?;
                let config: client::trust::Config =
                    serde_json::from_slice(&std::fs::read(identity_config)?)?;
                let cache = tokio::sync::Mutex::new(config.open()?);
                let identity = Identity::load(key)?;
                let node = node::Node::start(identity.clone(), node::NodeConfig::default()).await?;
                let result = async {
                    config.synchronize(&node, &cache).await?;
                    node.dial(address.parse()?).await?;
                    client::office::upload(
                        &node,
                        peer,
                        &genesis_hash,
                        &identity,
                        client::office::Upload {
                            branch: &branch,
                            path: &path,
                            message: &message,
                            bytes: &bytes,
                        },
                        &*cache.lock().await,
                    )
                    .await
                    .map_err(anyhow::Error::from)
                }
                .await;
                node.shutdown().await?;
                println!("{}", result?);
            }
            OfficeCommand::GetFile {
                key,
                address,
                peer,
                genesis_hash,
                cid,
                out,
            } => {
                let node =
                    node::Node::start(Identity::load(key)?, node::NodeConfig::default()).await?;
                let result = async {
                    node.dial(address.parse()?).await?;
                    client::office::snapshot(&node, peer, &genesis_hash)
                        .await?
                        .domain
                        .inner
                        .files
                        .read(&cid)
                        .map_err(anyhow::Error::from)
                }
                .await;
                node.shutdown().await?;
                let mut file = OpenOptions::new().write(true).create_new(true).open(out)?;
                file.write_all(&result?)?;
                file.sync_all()?;
            }
            OfficeCommand::StoreDocument { directory, file } => {
                println!("{}", events::documents::store(&directory, &file)?)
            }
            OfficeCommand::FetchDocument {
                node,
                target,
                service,
                hash,
                out,
            } => {
                let node = node.start(false).await?;
                let result = async {
                    target.connect(&node).await?;
                    Ok::<_, anyhow::Error>(
                        events::documents::fetch(&node, target.peer, service, &hash).await?,
                    )
                }
                .await;
                node.shutdown().await?;
                let bytes = result?;
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let mut file = options.open(out)?;
                file.write_all(&bytes)?;
                file.sync_all()?;
            }
            OfficeCommand::Init { binding, out } => {
                let state =
                    state::State::<Office>::new(serde_json::from_slice(&std::fs::read(binding)?)?)?;
                let hash = client::protocol::digest(&serde_json::to_vec(&state)?);
                write_json(&out, &state)?;
                println!("{hash}");
            }
            OfficeCommand::Request {
                authorization,
                key,
                address,
                peer,
                genesis_hash,
                revision,
                action,
            } => {
                let action = action
                    .map(|path| -> Result<_> { Ok(serde_json::from_slice(&std::fs::read(path)?)?) })
                    .transpose()?;
                let reply = client::generic::execute::<Office>(
                    Identity::load(key)?,
                    client::generic::Input {
                        identity: authorization.load()?,
                        address,
                        peer,
                        genesis_hash,
                        revision,
                        action,
                    },
                )
                .await?;
                println!("{}", serde_json::to_string_pretty(&reply)?);
                anyhow::ensure!(reply.error.is_none(), "office request rejected");
            }
        },
        Command::Llm {
            command:
                LlmCommand::Ask {
                    node,
                    target,
                    service,
                    model,
                    purpose,
                    max_tokens,
                    sensitive,
                    prompt,
                },
        } => {
            use client::protocol::{LlmMessage, LlmRequest, Privacy};
            let node = node.start(false).await?;
            let result = async {
                target.connect(&node).await?;
                client::llm::ask(
                    &node,
                    target.peer,
                    service,
                    LlmRequest {
                        model,
                        context: None,
                        purpose,
                        max_tokens,
                        stream: true,
                        privacy: if sensitive {
                            Privacy::Sensitive
                        } else {
                            Privacy::Public
                        },
                        messages: vec![LlmMessage {
                            role: "user".into(),
                            content: prompt,
                        }],
                    },
                    |text| {
                        print!("{text}");
                        let _ = std::io::stdout().flush();
                    },
                )
                .await
                .map_err(anyhow::Error::from)
            }
            .await;
            node.shutdown().await?;
            let result = result?;
            println!();
            if let Some(error) = result.error {
                anyhow::bail!("{error}");
            }
            anyhow::ensure!(!result.truncated, "generation truncated");
        }

        Command::Governance {
            authorization,
            key,
            address,
            peer,
            genesis_hash,
            revision,
            action,
        } => {
            let action = action
                .map(|path| -> Result<_> { Ok(serde_json::from_slice(&std::fs::read(path)?)?) })
                .transpose()?;
            let reply = client::client::execute(
                Identity::load(key)?,
                client::client::Input {
                    identity: authorization.load()?,
                    address,
                    peer,
                    genesis_hash,
                    revision,
                    action,
                },
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&reply)?);
            anyhow::ensure!(reply.error.is_none(), "governance request rejected");
        }
        Command::Keygen { out } => {
            let identity = Identity::generate();
            identity.save_new(out)?;
            println!("{}", identity.peer_id());
        }
        Command::Identity { key } => println!("{}", Identity::load(key)?.peer_id()),
        Command::Rooms { node: args } => {
            let node = args.start(false).await?;
            let result = client::rooms::discover(&node, &args.bootstrap).await;
            node.shutdown().await?;
            println!("{}", serde_json::to_string(&result?)?);
        }
        Command::Ops {
            node: args,
            target,
            service,
            operation,
        } => {
            let node = args.start(false).await?;
            let result = async {
                target.connect(&node).await?;
                let request = node::protocol::OpsRequest {
                    op: operation.into(),
                };
                Ok::<_, anyhow::Error>(
                    tokio::time::timeout(
                        std::time::Duration::from_secs(150),
                        client::ops::execute(&node, target.peer, service, &request),
                    )
                    .await??,
                )
            }
            .await;
            node.shutdown().await?;
            let response = result?;
            println!("{}", serde_json::to_string(&response)?);
            anyhow::ensure!(response.ok, "operation failed");
        }
        Command::Discover { node, service } => {
            let node = node.start(false).await?;
            for peer in node.discover(service).await? {
                println!("{peer}");
            }
            node.shutdown().await?;
        }
        Command::Watch {
            node,
            target,
            after_revision,
        } => {
            let node = node.start(false).await?;
            target.connect(&node).await?;
            let mut events =
                authority::events::subscribe(&node, target.peer, after_revision).await?;
            loop {
                tokio::select! {result=authority::events::next(&mut events)=>println!("{}",serde_json::to_string(&result?)?),_=tokio::signal::ctrl_c()=>break}
            }
            node.shutdown().await?;
        }
        Command::NewServiceId => println!("{}", ServiceId::new()),
        Command::List { node, target } => {
            let node = node.start(false).await?;
            target.connect(&node).await?;
            for service in node.list_services(target.peer).await? {
                println!("{}\t{}\t{}", service.id, service.protocol, service.name);
            }
            node.shutdown().await?;
        }
        Command::LocalInstances => {
            for instance in minecraftd::discovery::discover() {
                println!(
                    "{}\t{}\t{}",
                    instance.id,
                    instance.kind.as_str(),
                    instance.path.display()
                );
            }
        }
        Command::Proxy {
            node,
            target,
            service,
            bind,
        } => {
            run_proxy(node.start(false).await?, target, service, bind).await?;
        }
    }
    Ok(())
}
