use anyhow::Result;
use clap::{Parser, Subcommand};
use terminal_runtime::init_logging;

/// Production identity roots are reviewed at build time and cannot be replaced by configuration.
const FOUNDER_MANIFEST: &str = include_str!(env!(
    "FOUNDER_MANIFEST",
    "set FOUNDER_MANIFEST to the absolute path of the reviewed build manifest"
));

#[derive(Parser)]
#[command(version, about = "Federated service host")]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Download and verify a document using this operator node's authorized identity.
    FetchDocument {
        #[arg(long)]
        config: std::path::PathBuf,
        #[arg(long)]
        address: String,
        #[arg(long)]
        peer: String,
        #[arg(long)]
        service: String,
        #[arg(long)]
        hash: String,
        #[arg(long)]
        out: std::path::PathBuf,
    },
    /// Import local content into the configured document collection by its verified digest.
    ImportDocument {
        #[arg(long)]
        config: std::path::PathBuf,
        #[arg(long)]
        file: std::path::PathBuf,
    },
    /// Export an existing executor's public identity; never exports the private key.
    DevicePublic {
        #[arg(long)]
        key: std::path::PathBuf,
    },
    /// Prove this executor owns the device named in a manager-signed binding record.
    SignDevice {
        #[arg(long)]
        key: std::path::PathBuf,
        #[arg(long)]
        record: std::path::PathBuf,
        #[arg(long)]
        out: std::path::PathBuf,
    },
    /// Export verified identity settings for import into manager or launcher.
    IdentityConfig {
        #[arg(long)]
        config: std::path::PathBuf,
        #[arg(long)]
        address: Option<String>,
    },
    /// Create a new server-side executor device without overwriting a key.
    InitDevice {
        #[arg(long)]
        out: std::path::PathBuf,
    },
    /// Initialize the node key and optional business genesis, without replacing files.
    Init {
        #[arg(long)]
        config: std::path::PathBuf,
    },
    /// Co-sign this host's service registration drafted and signed by a chair.
    SignService {
        #[arg(long)]
        config: std::path::PathBuf,
        #[arg(long)]
        record: std::path::PathBuf,
        #[arg(long)]
        out: std::path::PathBuf,
    },
    /// Export the compiled public identity genesis and its digest.
    Genesis,
    /// Run the skin site's authenticated loopback identity adapter.
    IdentityBridge {
        #[arg(long)]
        config: std::path::PathBuf,
        #[arg(long)]
        init: bool,
    },
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
    let args = Args::parse();
    let genesis = federated_server::bootstrap::parse_genesis(FOUNDER_MANIFEST.as_bytes())?;
    match args.command {
        Command::FetchDocument {
            config,
            address,
            peer,
            service,
            hash,
            out,
        } => {
            let config = federated_server::bootstrap::load(&config, &genesis)?;
            let bytes = client::documents::fetch(
                identity::Identity::load(&config.node.key)?,
                client::documents::Input {
                    address,
                    peer,
                    service,
                    hash,
                },
            )
            .await?;
            federated_server::bootstrap::write_new_bytes(&out, &bytes)?;
        }
        Command::ImportDocument { config, file } => {
            let config = federated_server::bootstrap::load(&config, &genesis)?;
            let documents = config
                .services
                .documents
                .ok_or_else(|| anyhow::anyhow!("document service is not configured"))?;
            println!("{}", events::documents::store(&documents.directory, &file)?);
        }
        Command::DevicePublic { key } => println!(
            "{}",
            serde_json::to_string_pretty(&client::management::PublicIdentity::from_identity(
                &identity::Identity::load(key)?
            ))?
        ),
        Command::SignDevice { key, record, out } => {
            federated_server::bootstrap::sign_device(&key, &genesis, &record, &out)?
        }
        Command::IdentityConfig { config, address } => {
            let config = federated_server::bootstrap::load(&config, &genesis)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&federated_server::bootstrap::identity_config(
                    &config, &genesis, address
                )?)?
            );
        }
        Command::InitDevice { out } => println!(
            "{}",
            serde_json::to_string_pretty(&federated_server::bootstrap::initialize_device(&out)?)?
        ),
        Command::Init { config } => {
            let config = federated_server::bootstrap::load(&config, &genesis)?;
            println!(
                "{}",
                federated_server::bootstrap::initialize(&config, &genesis)?
            );
        }
        Command::SignService {
            config,
            record,
            out,
        } => {
            federated_server::bootstrap::sign_service(
                &federated_server::bootstrap::load(&config, &genesis)?,
                &genesis,
                &record,
                &out,
            )?;
        }
        Command::Genesis => {
            let pin = client::trust::TrustState::genesis_digest(&genesis)?;
            println!(
                "{}",
                serde_json::json!({"genesis":genesis,"genesis_hash":pin})
            );
        }
        Command::IdentityBridge { config, init } => {
            let config = federated_server::identity_bridge::Config::load(&config)?;
            if init {
                println!(
                    "{}",
                    federated_server::identity_bridge::initialize(&config)?
                );
            } else {
                let listener = tokio::net::TcpListener::bind(config.bind).await?;
                let router = federated_server::identity_bridge::router(config, genesis)?;
                axum::serve(listener, router)
                    .with_graceful_shutdown(async {
                        #[cfg(unix)]
                        if let Ok(mut terminate) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                            tokio::select! { _ = terminate.recv() => {}, _ = tokio::signal::ctrl_c() => {} }
                            return;
                        }
                        let _ = tokio::signal::ctrl_c().await;
                    })
                    .await?;
            }
        }
        Command::Check { config } => {
            federated_server::bootstrap::load(&config, &genesis)?;
            println!("configuration valid");
        }
        Command::Run { config } => {
            let config = federated_server::bootstrap::load(&config, &genesis)?;
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
