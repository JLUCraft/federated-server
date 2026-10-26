//! Offline review/co-signing and verified identity synchronization.
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use client::trust::{TrustGenesis, TrustLog, TrustRecord, TrustRequest, TrustState};
use std::path::{Path, PathBuf};
#[derive(Args)]
pub struct Cache {
    #[arg(long)]
    pub genesis: PathBuf,
    #[arg(long)]
    pub genesis_hash: String,
    #[arg(long)]
    pub log: PathBuf,
}
impl Cache {
    pub fn open(&self) -> Result<TrustLog> {
        Ok(TrustLog::open(
            &self.log,
            &read(&self.genesis)?,
            &self.genesis_hash,
        )?)
    }
}
#[derive(Args)]
pub struct Target {
    #[arg(long)]
    pub key: PathBuf,
    #[arg(long)]
    pub address: String,
    #[arg(long)]
    pub peer: String,
}
impl Target {
    async fn node(&self) -> Result<node::Node> {
        let peer: node::PeerId = self.peer.parse()?;
        let address: node::Multiaddr = self.address.parse()?;
        ensure!(
            matches!(address.iter().last(),Some(node::AddressProtocol::P2p(id)) if id==peer),
            "address must end with pinned peer"
        );
        let node = node::Node::start(
            node::Identity::load(&self.key)?,
            node::NodeConfig::default(),
        )
        .await?;
        if let Err(error) = node.dial(address).await {
            node.shutdown().await?;
            return Err(error.into());
        }
        Ok(node)
    }
}
#[derive(Subcommand)]
pub enum Command {
    /// Export a founder record from an Ed25519 device PeerId (no private key required).
    Founder {
        #[arg(long)]
        member: String,
        #[arg(long)]
        club: String,
        #[arg(long)]
        peer: String,
    },
    /// Validate a populated genesis and print the digest for independent confirmation.
    Digest {
        #[arg(long)]
        genesis: PathBuf,
    },
    /// Initialize/replay a local log and display verified facts, without claiming currentness.
    Inspect {
        #[command(flatten)]
        cache: Cache,
    },
    /// Draft an action against the local verified head; synchronize first.
    Draft {
        #[command(flatten)]
        cache: Cache,
        #[arg(long)]
        action: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Add a signature to the exact reviewed proposal; never edits its action or parent.
    Sign {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        record: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Synchronize and persist verified extensions from a pinned source.
    Sync {
        #[command(flatten)]
        cache: Cache,
        #[command(flatten)]
        target: Target,
    },
    /// Submit a co-signed proposal, then synchronize; a head conflict requires a new proposal.
    Submit {
        #[command(flatten)]
        cache: Cache,
        #[command(flatten)]
        target: Target,
        #[arg(long)]
        record: PathBuf,
    },
}
fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    ensure!(
        path.metadata()?.len() <= authority::journal::MAX_SNAPSHOT as u64,
        "input too large"
    );
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}
pub async fn execute(command: Command) -> Result<()> {
    match command {
        Command::Founder { member, club, peer } => {
            let peer: node::PeerId = peer.parse()?;
            let public_key = identity::PublicKey::try_decode_protobuf(peer.as_ref().digest())
                .context("requires an inline Ed25519 PeerId")?;
            ensure!(public_key.to_peer_id() == peer, "public key mismatch");
            println!(
                "{}",
                serde_json::to_string_pretty(&client::protocol::TrustFounder {
                    member,
                    club,
                    public_key: public_key.encode_protobuf()
                })?
            );
        }
        Command::Digest { genesis } => {
            let genesis: TrustGenesis = read(&genesis)?;
            let hash = TrustState::genesis_digest(&genesis)?;
            TrustState::new(&genesis, &hash)?;
            println!("{hash}");
        }
        Command::Inspect { cache } => {
            println!("{}", serde_json::to_string_pretty(cache.open()?.state())?)
        }
        Command::Draft { cache, action, out } => {
            crate::write_json(&out, &cache.open()?.state().draft(read(&action)?))?
        }
        Command::Sign { key, record, out } => {
            let mut record: TrustRecord = read(&record)?;
            client::trust::sign(&mut record, &node::Identity::load(key)?)?;
            crate::write_json(&out, &record)?;
        }
        Command::Sync { cache, target } => remote(cache, target, None).await?,
        Command::Submit {
            cache,
            target,
            record,
        } => remote(cache, target, Some(read(&record)?)).await?,
    }
    Ok(())
}
async fn remote(cache: Cache, target: Target, record: Option<TrustRecord>) -> Result<()> {
    let log = tokio::sync::Mutex::new(cache.open()?);
    let node = target.node().await.context("dial identity target")?;
    let result = async {
        client::trust::synchronize(&node, target.peer.parse()?, &log)
            .await
            .context("synchronize identity before append")?;
        if let Some(record) = record {
            let mut state = log.lock().await.state().clone();
            state.apply(&record)?;
            let response = client::trust::request(
                &node,
                target.peer.parse()?,
                TrustRequest::Append { record },
            )
            .await
            .context("append signed identity record")?;
            if let Some(error) = response.error {
                anyhow::bail!("{error}");
            }
            client::trust::synchronize(&node, target.peer.parse()?, &log)
                .await
                .context("synchronize identity after append")?;
            ensure!(
                log.lock().await.state().checkpoint().sequence >= state.checkpoint().sequence,
                "submitted identity record missing"
            );
        }
        println!(
            "{}",
            serde_json::to_string(log.lock().await.state().checkpoint())?
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    node.shutdown().await?;
    result
}
