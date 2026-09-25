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
            crate::write_json(&out, &summary)?;
            crate::write_json(&action, &anchor)?;
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
