use anyhow::Result;
use clap::{Parser, Subcommand};
use terminal_runtime::init_logging;

#[derive(Parser)]
#[command(version, about = "Federated service host")]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Start configured services on one shared node.
    Run {
        #[arg(long)]
        config: std::path::PathBuf,
    },
    /// Validate configuration without starting a node.
    Check {
        #[arg(long)]
        config: std::path::PathBuf,
    },
}
#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    match Args::parse().command {
        Command::Check { config } => {
            federated_server::runtime::Config::load(&config)?;
            println!("configuration valid");
        }
        Command::Run { config } => {
            let config = federated_server::runtime::Config::load(&config)?;
            let mut host = federated_server::runtime::Host::start(config).await?;
            println!("{}", serde_json::to_string(&host.status()?)?);
            #[cfg(unix)]
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            let termination = async {
                #[cfg(unix)]
                terminate.recv().await;
                #[cfg(not(unix))]
                std::future::pending::<()>().await;
            };
            let result = tokio::select! {
                result = host.wait() => result,
                result = tokio::signal::ctrl_c() => result.map_err(node::Error::from),
                _ = termination => Ok(()),
            };
            let cleanup = host.close().await;
            result?;
            cleanup?;
        }
    }
    Ok(())
}
