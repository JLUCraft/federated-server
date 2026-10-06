//! Deployment trust root. The shared runtime remains usable by embedded hosts and tests.
use crate::runtime::{Config, Domain, Office};
use client::trust::{TrustGenesis, TrustState};
use node::{Error, Identity, Result};
use std::{io::Write, path::Path};

/// Sole production founder manifest. No runtime file or environment override.
pub fn genesis() -> Result<TrustGenesis> {
    let genesis: TrustGenesis = serde_json::from_str(include_str!("founders.json"))
        .map_err(|e| Error::Protocol(e.to_string()))?;
    if genesis.founders.is_empty() {
        return Err(Error::Protocol("founder manifest is not configured; collect public identities in manager and populate src/founders.json before building the server".into()));
    }
    let pin = TrustState::genesis_digest(&genesis)?;
    TrustState::new(&genesis, &pin)?;
    Ok(genesis)
}

/// Standalone deployments cannot replace the compiled root with a configuration file.
pub fn load(path: &Path) -> Result<Config> {
    let config = Config::load(path)?;
    if let Some(identity) = &config.services.identity
        && !identity.genesis.as_os_str().is_empty()
    {
        return Err(Error::Protocol("standalone server uses its built-in founder manifest; remove services.identity.genesis and genesis_hash".into()));
    }
    Ok(config)
}

pub fn write_new(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    write_new_inner(path, value).map_err(crate::operation_error)
}
fn write_new_inner(path: &Path, value: &impl serde::Serialize) -> anyhow::Result<()> {
    write_new_bytes(path, &serde_json::to_vec_pretty(value)?)
}
/// Create an owner-only file and refuse to replace an existing one.
pub fn write_new_bytes(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
/// A secret must be a regular file (not a symlink) that only its owner can access.
pub(crate) fn require_private(path: &Path, what: &str) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(metadata.is_file(), "{what} must be a regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        anyhow::ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "{what} must be private (chmod 600)"
        );
    }
    Ok(())
}

/// Explicit local initialization; never replace a lost key or an existing journal.
pub fn initialize(config: &Config) -> Result<serde_json::Value> {
    initialize_inner(config).map_err(crate::operation_error)
}
fn initialize_inner(config: &Config) -> anyhow::Result<serde_json::Value> {
    let identity = match std::fs::symlink_metadata(&config.node.key) {
        Ok(_) => Identity::load(&config.node.key)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            for path in config
                .services
                .identity
                .iter()
                .map(|v| &v.log)
                .chain(config.services.governance.iter().map(|v| &v.journal))
            {
                anyhow::ensure!(
                    !path.try_exists()?,
                    "refusing to regenerate a node key for existing state"
                );
            }
            let identity = Identity::generate();
            identity.save_new(&config.node.key)?;
            identity
        }
        Err(e) => return Err(e.into()),
    };
    let mut output = serde_json::json!({"peer":identity.peer_id().to_string()});
    if let Some(service) = &config.services.identity {
        output["identity"] =
            serde_json::json!({"genesis":genesis()?,"genesis_hash":service.genesis_hash});
    }
    if let Some(governance) = &config.services.governance {
        let binding = governance
            .binding
            .clone()
            .ok_or_else(|| anyhow::anyhow!("initializing governance requires its binding"))?;
        anyhow::ensure!(
            binding.audience == identity.peer_id().to_string(),
            "business audience must match this node"
        );
        anyhow::ensure!(
            Some(binding.genesis.as_str())
                == config
                    .services
                    .identity
                    .as_ref()
                    .map(|v| v.genesis_hash.as_str()),
            "business binding must match the identity genesis"
        );
        anyhow::ensure!(
            !governance.journal.try_exists()?,
            "business journal already exists"
        );
        let pin = match governance.domain {
            Domain::Identity => write_business::<state::EmptyDomain>(&governance.genesis, binding)?,
            Domain::League => write_business::<league::LeagueDomain>(&governance.genesis, binding)?,
            Domain::Office => write_business::<Office>(&governance.genesis, binding)?,
        };
        output["business_genesis"] = pin.into();
    }
    Ok(output)
}

fn write_business<D: state::Domain>(
    path: &Path,
    binding: node::protocol::TrustBusinessBinding,
) -> anyhow::Result<String> {
    let state = state::State::<D>::new(binding)?;
    let pin = node::protocol::digest(&serde_json::to_vec(&state)?);
    write_new(path, &state)?;
    Ok(pin)
}

#[derive(Clone, Copy)]
enum PossessionProof {
    Service,
    Device,
}
fn sign_possession(
    key: &Identity,
    genesis: &TrustGenesis,
    mut record: client::trust::TrustRecord,
    proof: PossessionProof,
) -> anyhow::Result<client::trust::TrustRecord> {
    let pin = TrustState::genesis_digest(genesis)?;
    client::management::review_record(genesis, &pin, &record)?;
    let own = key.peer_id().to_string();
    let allowed = match (&record.action, proof) {
        (
            node::protocol::TrustAction::RegisterService { audience, .. },
            PossessionProof::Service,
        ) => audience == &own,
        (node::protocol::TrustAction::BindDevice { device, .. }, PossessionProof::Device)
        | (
            node::protocol::TrustAction::ConfirmMember {
                device: Some(device),
                ..
            },
            PossessionProof::Device,
        ) => device == &own,
        _ => false,
    };
    anyhow::ensure!(
        allowed,
        "only this key's own device or service possession can be co-signed"
    );
    identity::trust::verify_signatures(&record)?;
    client::trust::sign(&mut record, key)?;
    Ok(record)
}
fn sign_file(key: &Path, record: &Path, out: &Path, proof: PossessionProof) -> anyhow::Result<()> {
    anyhow::ensure!(
        record.metadata()?.len() <= node::protocol::MAX_TRUST_RECORD as u64,
        "record too large"
    );
    let signed = sign_possession(
        &Identity::load(key)?,
        &genesis()?,
        serde_json::from_slice(&std::fs::read(record)?)?,
        proof,
    )?;
    write_new_inner(out, &signed)
}
/// A host signs only its own service registration; chairs still authorize and submit it.
pub fn sign_service(config: &Config, record: &Path, out: &Path) -> Result<()> {
    sign_file(&config.node.key, record, out, PossessionProof::Service)
        .map_err(crate::operation_error)
}
/// Executors prove possession when being bound; they cannot impersonate a chair or another device.
pub fn sign_device(key: &Path, record: &Path, out: &Path) -> Result<()> {
    sign_file(key, record, out, PossessionProof::Device).map_err(crate::operation_error)
}

/// Public, directly importable client settings. The operator chooses a reachable address;
/// an identity replica exports its pinned writer endpoint instead of accepting writes locally.
pub fn identity_config(config: &Config, address: Option<String>) -> Result<serde_json::Value> {
    identity_config_inner(config, address).map_err(crate::operation_error)
}
fn identity_config_inner(
    config: &Config,
    address: Option<String>,
) -> anyhow::Result<serde_json::Value> {
    let service = config
        .services
        .identity
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("identity service is not configured"))?;
    let (peer, address) = if let Some(source) = &service.source {
        anyhow::ensure!(
            address.is_none(),
            "replica exports its configured identity source; omit --address"
        );
        (source.peer.clone(), source.address.clone())
    } else {
        let peer = Identity::load(&config.node.key)?.peer_id().to_string();
        let address = address.ok_or_else(|| {
            anyhow::anyhow!("provide the reachable writer multiaddr with --address")
        })?;
        let mut parsed: node::Multiaddr = address.parse()?;
        if !matches!(parsed.iter().last(), Some(node::AddressProtocol::P2p(_))) {
            parsed.push(node::AddressProtocol::P2p(peer.parse()?));
        }
        (peer, parsed.to_string())
    };
    Ok(client::management::review_config(&client::trust::Config {
        genesis: genesis()?,
        genesis_hash: service.genesis_hash.clone(),
        log: Default::default(),
        address,
        peer,
    })?)
}

/// Explicit new executor/verifier identity; existing paths are never overwritten.
pub fn initialize_device(path: &Path) -> Result<client::management::PublicIdentity> {
    let identity = Identity::generate();
    identity.save_new(path)?;
    Ok(client::management::PublicIdentity::from_identity(&identity))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manifest_is_either_unconfigured_or_valid() {
        let raw: TrustGenesis = serde_json::from_str(include_str!("founders.json")).unwrap();
        if raw.founders.is_empty() {
            assert!(genesis().is_err());
        } else {
            assert_eq!(genesis().unwrap(), raw);
        }
    }
    #[test]
    fn initialization_preserves_existing_keys_and_rejects_lost_keys() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("node.key");
        let config: Config =
            serde_json::from_value(serde_json::json!({"node":{"key":key}})).unwrap();
        let first = initialize(&config).unwrap();
        assert_eq!(first, initialize(&config).unwrap());
        std::fs::write(&key, b"corrupt").unwrap();
        assert!(initialize(&config).is_err());
        std::fs::remove_file(&key).unwrap();
        let log = dir.path().join("existing.jsonl");
        std::fs::write(&log, b"existing state").unwrap();
        let config: Config = serde_json::from_value(serde_json::json!({"node":{"key":key},"services":{"identity":{
            "genesis":"unused","genesis_hash":"a".repeat(64),"log":log,"writer":true,"max_staleness_seconds":60
        }}})).unwrap();
        assert!(initialize(&config).is_err());
        assert!(!key.exists());
    }
    #[test]
    fn executor_binding_requires_its_own_key_and_never_signs_governance() {
        use node::protocol::{TrustAction, TrustFounder};
        let chair = Identity::generate();
        let executor = Identity::generate();
        let other = Identity::generate();
        let genesis = TrustGenesis {
            federation: "proof-test".into(),
            quorum: 1,
            founders: vec![TrustFounder {
                member: "chair".into(),
                club: "school".into(),
                public_key: chair.public_key().encode_protobuf(),
            }],
        };
        let pin = TrustState::genesis_digest(&genesis).unwrap();
        let mut state = TrustState::new(&genesis, &pin).unwrap();
        let mut record = state.draft(TrustAction::ConfirmMember {
            member: "worker".into(),
            club: "school".into(),
            device: Some(executor.peer_id().to_string()),
            evidence: "manual".into(),
            verifier: None,
        });
        client::trust::sign(&mut record, &chair).unwrap();
        assert!(
            sign_possession(&other, &genesis, record.clone(), PossessionProof::Device).is_err()
        );
        assert!(
            sign_possession(
                &executor,
                &genesis,
                record.clone(),
                PossessionProof::Service
            )
            .is_err()
        );
        let signed = sign_possession(&executor, &genesis, record, PossessionProof::Device).unwrap();
        state.apply(&signed).unwrap();
        assert_eq!(
            state.member_for_device(&executor.peer_id().to_string()),
            Some("worker")
        );
        let mut registration = state.draft(TrustAction::RegisterService {
            service: "office".into(),
            audience: executor.peer_id().to_string(),
            club: "school".into(),
        });
        client::trust::sign(&mut registration, &chair).unwrap();
        assert!(
            sign_possession(
                &other,
                &genesis,
                registration.clone(),
                PossessionProof::Service
            )
            .is_err()
        );
        let registration =
            sign_possession(&executor, &genesis, registration, PossessionProof::Service).unwrap();
        state.apply(&registration).unwrap();
        let mut grant = state.draft(TrustAction::GrantPermission {
            id: "p".into(),
            member: "worker".into(),
            service: "office".into(),
            permission: "admin".into(),
        });
        client::trust::sign(&mut grant, &chair).unwrap();
        assert!(sign_possession(&executor, &genesis, grant, PossessionProof::Device).is_err());
    }
    #[test]
    fn business_export_matches_journal_pin_and_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("business.json");
        let binding = node::protocol::TrustBusinessBinding {
            genesis: "a".repeat(64),
            namespace: "office".into(),
            service: "office".into(),
            club: "school".into(),
            audience: Identity::generate().peer_id().to_string(),
        };
        let pin = write_business::<Office>(&path, binding.clone()).unwrap();
        let state: state::State<Office> =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let journal = authority::journal::Journal::open(dir.path().join("journal"), state).unwrap();
        assert_eq!(pin, journal.genesis_hash());
        assert!(write_business::<Office>(&path, binding).is_err());
    }
}
