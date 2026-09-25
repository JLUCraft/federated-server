use anyhow::Result;
use clap::Subcommand;
use llm_gateway::{Ledger, UsageSummary};
use std::path::PathBuf;
#[derive(Subcommand)]
pub enum Command {
    /// Export a verified ledger prefix and a governance anchor action.
    Audit {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        action: PathBuf,
    },
    /// Compare a saved summary and current ledger to an independently pinned anchor.
    VerifyAudit {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        summary: PathBuf,
        #[arg(long)]
        digest: String,
    },
}
fn write_new(path: PathBuf, value: &impl serde::Serialize) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
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
pub fn execute(command: Command) -> Result<()> {
    match command {
        Command::Audit {
            ledger,
            out,
            action,
        } => {
            let summary = Ledger::audit(ledger, None)?;
            let digest = summary.digest()?;
            let anchor = state::governance::Action::<state::EmptyDomain>::AnchorDigest {
                id: format!("llm-{}-{}", summary.entries, summary.head),
                digest: digest.clone(),
            };
            write_new(out, &summary)?;
            write_new(action, &anchor)?;
            println!("{digest}");
            Ok(())
        }
        Command::VerifyAudit {
            ledger,
            summary,
            digest,
        } => {
            let summary: UsageSummary = serde_json::from_slice(&std::fs::read(summary)?)?;
            summary.verify(ledger, &digest)?;
            println!("verified");
            Ok(())
        }
    }
}
