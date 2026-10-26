//! Disposable acceptance-fixture driver. Not a shipped or installed terminal.
mod trust;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use terminal_runtime::{NodeArgs, TargetArgs};
#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Application {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        input: PathBuf,
    },
    BusinessGenesis {
        #[arg(long)]
        binding: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    InspectKey {
        #[arg(long)]
        key: PathBuf,
    },
    JavaStatus {
        #[arg(long)]
        address: String,
    },
    Trust {
        #[command(subcommand)]
        command: trust::Command,
    },
    Rooms {
        #[command(flatten)]
        node: NodeArgs,
    },
    Proxy {
        #[command(flatten)]
        node: Box<NodeArgs>,
        #[command(flatten)]
        target: TargetArgs,
        #[arg(long)]
        service: node::ServiceId,
        #[arg(long, default_value = "127.0.0.1:25566")]
        bind: std::net::SocketAddr,
    },
    Run {
        #[arg(long)]
        config: PathBuf,
    },
    Bridge {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        genesis: PathBuf,
    },
}
pub(crate) use federated_server::bootstrap::write_new as write_json;
#[tokio::main]
async fn main() -> Result<()> {
    terminal_runtime::init_logging();
    match Args::parse().command {
        Command::Application { key, input } => {
            let response = client::application::execute(
                node::Identity::load(key)?,
                serde_json::from_slice(&std::fs::read(input)?)?,
            )
            .await?;
            anyhow::ensure!(
                response.error.is_none(),
                "application request rejected: {:?}",
                response.error
            );
            println!("{}", serde_json::to_string(&response)?);
        }
        Command::BusinessGenesis { binding, out } => {
            let state = client::application::Snapshot::new(serde_json::from_slice(
                &std::fs::read(binding)?,
            )?)?;
            let pin = node::protocol::digest(&serde_json::to_vec(&state)?);
            if let Some(out) = out {
                write_json(&out, &state)?;
            }
            println!("{pin}");
        }
        Command::Keygen { out } => {
            let key = node::Identity::generate();
            key.save_new(out)?;
            println!("{}", key.peer_id());
        }
        Command::InspectKey { key } => {
            let identity = node::Identity::load(key)?;
            println!(
                "{}",
                serde_json::to_string(&client::management::PublicIdentity::from_identity(
                    &identity
                ))?
            );
        }
        Command::JavaStatus { address } => {
            let status = minecraftd::minecraft::ping::ping_java_server(
                &address,
                std::time::Duration::from_secs(10),
            )
            .await?;
            println!(
                "{}",
                serde_json::json!({
                    "online": status.online,
                    "version": status.version,
                    "protocol": status.protocol,
                    "current_players": status.current_players,
                    "max_players": status.max_players,
                    "description": status.description,
                    "favicon": status.favicon,
                    "latency_ms": status.latency_ms,
                })
            );
        }
        Command::Trust { command } => trust::execute(command).await?,
        Command::Rooms { node: args } => {
            let node = args.start(false).await?;
            let result = client::rooms::discover(&node, &args.bootstrap).await;
            node.shutdown().await?;
            println!("{}", serde_json::to_string(&result?)?);
        }
        Command::Proxy {
            node,
            target,
            service,
            bind,
        } => terminal_runtime::run_proxy(node.start(false).await?, target, service, bind).await?,
        Command::Run { config } => {
            // Only this explicitly built test fixture permits a synthetic root at runtime.
            let config = config.canonicalize()?;
            let raw: federated_server::runtime::Config =
                serde_json::from_slice(&std::fs::read(&config)?)?;
            let root = raw
                .services
                .identity
                .as_ref()
                .map(|identity| -> Result<client::trust::TrustGenesis> {
                    let source = if identity.genesis.is_absolute() {
                        identity.genesis.clone()
                    } else {
                        config
                            .parent()
                            .context("fixture configuration directory missing")?
                            .join(&identity.genesis)
                    };
                    Ok(serde_json::from_slice(&std::fs::read(source)?)?)
                })
                .transpose()?;
            let mut host = federated_server::runtime::Host::start(
                federated_server::runtime::Config::load(&config, root.as_ref())?,
            )
            .await?;
            println!("{}", serde_json::to_string(&host.status()?)?);
            tokio::select! { result = host.wait() => result?, _ = shutdown() => {} }
            host.close().await?;
        }
        Command::Bridge { config, genesis } => {
            let config = federated_server::identity_bridge::Config::load(&config)?;
            federated_server::identity_bridge::initialize(&config)?;
            let listener = tokio::net::TcpListener::bind(config.bind).await?;
            println!(
                "{}",
                serde_json::json!({"url":format!("http://{}",listener.local_addr()?)})
            );
            let router = federated_server::identity_bridge::router(
                config,
                serde_json::from_slice(&std::fs::read(genesis)?)?,
            )?;
            axum::serve(listener, router)
                .with_graceful_shutdown(shutdown())
                .await?;
        }
    }
    Ok(())
}
async fn shutdown() {
    #[cfg(unix)]
    {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _ = term.recv() => {}, _ = tokio::signal::ctrl_c() => {} }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
