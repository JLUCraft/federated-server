//! Content-addressed oracle evidence, outside the bounded application snapshot.
use anyhow::{Context, Result, ensure};
use events::{
    files::FileStore,
    points::{ActivityEvidence, Attestation},
};
use node::protocol::{Cid, IpldBlock, digest};
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    path::{Path, PathBuf},
};

const MAX_BUNDLE_BYTES: u64 = 8 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    root: Cid,
    blocks: Vec<IpldBlock>,
}
pub(crate) struct EvidenceStore {
    directory: PathBuf,
}
impl EvidenceStore {
    pub fn new(directory: PathBuf) -> Result<Self> {
        let parent = directory.parent().context("evidence parent missing")?;
        ensure!(parent.is_dir(), "evidence parent missing");
        std::fs::create_dir_all(&directory)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(Self { directory })
    }
    fn source(&self, source: &str) -> PathBuf {
        self.directory.join(digest(source.as_bytes()))
    }
    fn publish(path: &Path, bytes: &[u8]) -> Result<()> {
        if path.exists() {
            ensure!(
                std::fs::metadata(path)?.len() <= MAX_BUNDLE_BYTES,
                "existing evidence too large"
            );
            ensure!(std::fs::read(path)? == bytes, "existing evidence differs");
            return Ok(());
        }
        let next = path.with_extension("next");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&next)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(next, path)?;
        std::fs::File::open(path.parent().context("evidence directory missing")?)?.sync_all()?;
        Ok(())
    }
    pub fn put(&self, attestation: &Attestation, telemetry: &[u8]) -> Result<IpldBlock> {
        let (root, blocks) = FileStore::default().version(None, telemetry)?;
        let header = ActivityEvidence::block(attestation, root.clone())?;
        let source = self.source(&attestation.source);
        std::fs::create_dir_all(&source)?;
        std::fs::File::open(&self.directory)?.sync_all()?;
        Self::publish(
            &source.join(format!("{root}.json")),
            &serde_json::to_vec(&Bundle { root, blocks })?,
        )?;
        Self::publish(
            &source.join(format!("{}.header", header.cid)),
            &serde_json::to_vec(&header)?,
        )?;
        Ok(header)
    }
    pub fn read(&self, source: &str, cid: &Cid) -> Result<Vec<u8>> {
        let source_id = source;
        let source = self.source(source);
        let path = source.join(format!("{cid}.header"));
        ensure!(
            std::fs::metadata(&path)?.len() <= MAX_BUNDLE_BYTES,
            "evidence header too large"
        );
        let header: IpldBlock = serde_json::from_slice(&std::fs::read(path)?)?;
        ensure!(&header.cid == cid, "evidence CID differs");
        let proof: ActivityEvidence = serde_json::from_slice(&header.bytes()?)?;
        let path = source.join(format!("{}.json", proof.telemetry));
        ensure!(
            std::fs::metadata(&path)?.len() <= MAX_BUNDLE_BYTES,
            "evidence bundle too large"
        );
        let bundle: Bundle = serde_json::from_slice(&std::fs::read(path)?)?;
        ensure!(bundle.root == proof.telemetry, "telemetry root differs");
        let mut files = FileStore::default();
        for block in bundle.blocks {
            files.put(block)?;
        }
        let bytes = files.read(&bundle.root)?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        let attestation: Attestation = serde_json::from_value(
            value
                .get("attestation")
                .cloned()
                .context("evidence summary missing")?,
        )?;
        ensure!(attestation.source == source_id, "evidence source differs");
        ActivityEvidence::verify(&header, &attestation)?;
        Ok(bytes)
    }
}
