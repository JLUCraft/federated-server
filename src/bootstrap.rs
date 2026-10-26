//! Explicit trust-root validation, initialization, and possession signing.
use crate::runtime::{Application, Config};
use client::trust::{TrustGenesis, TrustState};
use node::{Error, Identity, Result};
use std::{io::Write, path::Path};

pub fn parse_genesis(bytes: &[u8]) -> Result<TrustGenesis> {
    let genesis: TrustGenesis =
        serde_json::from_slice(bytes).map_err(|e| Error::Protocol(e.to_string()))?;
    validate_genesis(&genesis)?;
    Ok(genesis)
}

pub fn validate_genesis(genesis: &TrustGenesis) -> Result<String> {
    if genesis.founders.is_empty() {
        return Err(Error::Protocol(
            "identity genesis must contain at least one founder".into(),
        ));
    }
    let pin = TrustState::genesis_digest(genesis)?;
    TrustState::new(genesis, &pin)?;
    Ok(pin)
}

fn validate_identity_root(config: &Config, genesis: &TrustGenesis) -> Result<()> {
    let pin = validate_genesis(genesis)?;
    if let Some(identity) = &config.services.identity
        && identity.genesis_hash != pin
    {
        return Err(Error::Protocol(
            "identity genesis does not match the supplied trust root".into(),
        ));
    }
    Ok(())
}

/// Standalone deployments cannot replace the compiled root with a configuration file.
pub fn load(path: &Path, genesis: &TrustGenesis) -> Result<Config> {
    let config = Config::load(path, Some(genesis))?;
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
pub fn initialize(config: &Config, genesis: &TrustGenesis) -> Result<serde_json::Value> {
    validate_identity_root(config, genesis)?;
    initialize_inner(config, genesis).map_err(crate::operation_error)
}
fn initialize_inner(config: &Config, genesis: &TrustGenesis) -> anyhow::Result<serde_json::Value> {
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
            serde_json::json!({"genesis":genesis,"genesis_hash":service.genesis_hash});
    }
    let mut pins = Vec::new();
    for governance in config.services.governance.iter() {
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
        let pin = write_business::<Application>(&governance.genesis, binding)?;
        pins.push(pin);
    }
    if let Some(pin) = pins.into_iter().next() {
        output["genesis_hash"] = pin.into();
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
fn sign_file(
    key: &Path,
    genesis: &TrustGenesis,
    record: &Path,
    out: &Path,
    proof: PossessionProof,
) -> anyhow::Result<()> {
    validate_genesis(genesis)?;
    anyhow::ensure!(
        record.metadata()?.len() <= node::protocol::MAX_TRUST_RECORD as u64,
        "record too large"
    );
    let signed = sign_possession(
        &Identity::load(key)?,
        genesis,
        serde_json::from_slice(&std::fs::read(record)?)?,
        proof,
    )?;
    write_new_inner(out, &signed)
}
/// A host signs only its own service registration; chairs still authorize and submit it.
pub fn sign_service(
    config: &Config,
    genesis: &TrustGenesis,
    record: &Path,
    out: &Path,
) -> Result<()> {
    validate_identity_root(config, genesis)?;
    sign_file(
        &config.node.key,
        genesis,
        record,
        out,
        PossessionProof::Service,
    )
    .map_err(crate::operation_error)
}
/// Executors prove possession when being bound; they cannot impersonate a chair or another device.
pub fn sign_device(key: &Path, genesis: &TrustGenesis, record: &Path, out: &Path) -> Result<()> {
    sign_file(key, genesis, record, out, PossessionProof::Device).map_err(crate::operation_error)
}

/// Public, directly importable client settings. The operator chooses a reachable address;
/// an identity replica exports its pinned writer endpoint instead of accepting writes locally.
pub fn identity_config(
    config: &Config,
    genesis: &TrustGenesis,
    address: Option<String>,
) -> Result<serde_json::Value> {
    validate_identity_root(config, genesis)?;
    identity_config_inner(config, genesis, address).map_err(crate::operation_error)
}
fn identity_config_inner(
    config: &Config,
    genesis: &TrustGenesis,
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
        genesis: genesis.clone(),
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
    const TEST_ROOT: &[u8] = include_bytes!("../tests/fixtures/founders.json");
    #[test]
    fn explicit_genesis_requires_a_valid_nonempty_trust_root() {
        let bytes = TEST_ROOT;
        let raw: TrustGenesis = serde_json::from_slice(bytes).unwrap();
        assert!(!raw.founders.is_empty());
        assert_eq!(parse_genesis(bytes).unwrap(), raw);
        let mut invalid = raw;
        invalid.quorum = invalid.founders.len() + 1;
        assert!(parse_genesis(&serde_json::to_vec(&invalid).unwrap()).is_err());
        invalid.founders.clear();
        assert!(parse_genesis(&serde_json::to_vec(&invalid).unwrap()).is_err());
        assert!(parse_genesis(b"invalid").is_err());
    }
    #[test]
    fn explicit_root_controls_initialization_and_identity_export() {
        let dir = tempfile::tempdir().unwrap();
        let genesis = parse_genesis(TEST_ROOT).unwrap();
        let pin = validate_genesis(&genesis).unwrap();
        let key = dir.path().join("node.key");
        let config: Config = serde_json::from_value(serde_json::json!({
            "node":{"key":key},"services":{"identity":{
                "genesis_hash":pin,"log":dir.path().join("identity.jsonl"),
                "writer":true,"max_staleness_seconds":60
            }}
        }))
        .unwrap();
        let mut other = genesis.clone();
        other.federation = "different-explicit-test-root".into();
        assert!(initialize(&config, &other).is_err());
        assert!(!key.exists());
        assert!(identity_config(&config, &other, None).is_err());
        let initialized = initialize(&config, &genesis).unwrap();
        assert_eq!(
            initialized["identity"]["genesis"],
            serde_json::to_value(&genesis).unwrap()
        );
        let exported =
            identity_config(&config, &genesis, Some("/ip4/127.0.0.1/tcp/29637".into())).unwrap();
        assert_eq!(exported["genesis"], serde_json::to_value(&genesis).unwrap());
        assert_eq!(exported["genesis_hash"], pin);
    }
    #[test]
    fn initialization_preserves_existing_keys_and_rejects_lost_keys() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("node.key");
        let config: Config =
            serde_json::from_value(serde_json::json!({"node":{"key":key}})).unwrap();
        let genesis = parse_genesis(TEST_ROOT).unwrap();
        let first = initialize(&config, &genesis).unwrap();
        assert_eq!(first, initialize(&config, &genesis).unwrap());
        std::fs::write(&key, b"corrupt").unwrap();
        assert!(initialize(&config, &genesis).is_err());
        std::fs::remove_file(&key).unwrap();
        let log = dir.path().join("existing.jsonl");
        std::fs::write(&log, b"existing state").unwrap();
        let config: Config = serde_json::from_value(serde_json::json!({"node":{"key":key},"services":{"identity":{
            "genesis":"unused","genesis_hash":validate_genesis(&genesis).unwrap(),"log":log,"writer":true,"max_staleness_seconds":60
        }}})).unwrap();
        assert!(initialize(&config, &genesis).is_err());
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
            service: "application".into(),
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
            service: "application".into(),
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
            namespace: "application".into(),
            service: "application".into(),
            club: "school".into(),
            audience: Identity::generate().peer_id().to_string(),
        };
        let pin = write_business::<Application>(&path, binding.clone()).unwrap();
        let state: state::State<Application> =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let journal = authority::journal::Journal::open(dir.path().join("journal"), state).unwrap();
        assert_eq!(pin, journal.genesis_hash());
        assert!(write_business::<Application>(&path, binding).is_err());
    }
}
