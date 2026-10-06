use federated_server::runtime::{Config, Host, Office};
use identity::Identity;
use node::{Node, NodeConfig, ServiceId};
use serde_json::json;
use std::time::Duration;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn write(path: &std::path::Path, value: &impl serde::Serialize) -> Result {
    std::fs::write(path, serde_json::to_vec(value)?)?;
    Ok(())
}
#[tokio::test]
async fn lightweight_node_needs_no_game_or_governance_files() -> Result {
    let dir = tempfile::tempdir()?;
    let key = Identity::generate();
    key.save_new(dir.path().join("node.key"))?;
    let config = dir.path().join("node.json");
    write(
        &config,
        &json!({"node":{"key":"node.key"},"services":{"directory":true,"relay":true}}),
    )?;
    let host = Host::start(Config::load(&config)?).await?;
    let status = host.status()?;
    assert_eq!(status.peer, key.peer_id().to_string());
    assert_eq!(status.services, ["directory", "relay"]);
    host.close().await?;
    assert!(!dir.path().join("journal").exists());
    assert!(!dir.path().join("server.properties").exists());
    Ok(())
}
#[test]
fn configuration_rejects_unknown_fields_missing_governance_and_colliding_services() -> Result {
    for services in [
        json!({"gamez":true}),
        json!({"operations":{"service":ServiceId::new().to_string(),"issuers":[Identity::generate().peer_id().to_string()],"instances":[]}}),
        json!({"ai_worker":{"key":"k","address":"a","peer":"p","service":"s","grant":"g"}}),
    ] {
        let result =
            serde_json::from_value::<Config>(json!({"node":{"key":"unused"},"services":services}));
        assert!(result.is_err() || result?.validate().is_err());
    }
    let id = ServiceId::new().to_string();
    let config: Config = serde_json::from_value(json!({"node":{"key":"unused"},"services":{
        "governance":{"domain":"office","genesis":"unused","journal":"unused"},
        "gateway":{"service":id,"config":"unused","ledger":"unused"},
        "operations":{"service":id,"instances":[]}
    }}))?;
    assert!(config.validate().is_err());
    Ok(())
}
#[tokio::test]
async fn office_gateway_and_operations_share_peer_governance_and_revocation() -> Result {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir = tempfile::tempdir()?;
        let host_key = Identity::generate(); host_key.save_new(dir.path().join("node.key"))?;
        let admin = Identity::generate();let member = Identity::generate();
        let gateway = ServiceId::new(); let operations = ServiceId::new();
        let (identity_config, mut cache, binding) = setup_identity(dir.path(), &admin, &host_key, Some((&member, gateway, operations)))?;
        let genesis = state::State::<Office>::new(binding)?;
        write(&dir.path().join("genesis.json"), &genesis)?;
        let pin = node::protocol::digest(&serde_json::to_vec(&genesis)?);
        write(&dir.path().join("gateway.json"),&json!({
            "providers":[{"url":"http://127.0.0.1:1/v1/chat/completions","key_env":null,"sensitive":true,"self_hosted":true,"models":["local"],"context_tokens":128}],
            "members":{"alice":{"tokens_per_day":1024,"models":["local"]}},"purposes":["assistant.ask"],
            "max_tokens":32,"max_messages":2,"max_input_bytes":128,"concurrency":1
        }))?;
        let path = dir.path().join("node.json");
        write(&path, &json!({"node":{"key":"node.key"},"services":{
            "identity":identity_config,"governance":{"domain":"office","genesis":"genesis.json","journal":"journal"},
            "gateway":{"service":gateway.to_string(),"config":"gateway.json","ledger":"ledger"},
            "operations":{"service":operations.to_string(),"instances":[]}
        }}))?;
        let host = Host::start(Config::load(&path)?).await?;
        let status = host.status()?;
        let node = Node::start(member.clone(),NodeConfig::default()).await?;
        node.dial(status.addresses[0].parse()?).await?;
        let services = node.list_services(host_key.peer_id()).await?;
        assert_eq!(services.len(),2);
        assert!(services.iter().any(|s| s.protocol == node::protocol::LLM_PROTOCOL));
        assert!(services.iter().any(|s| s.protocol == node::protocol::OPS_PROTOCOL));
        let cid = client::office::upload(&node,host_key.peer_id(),&pin,&member,client::office::Upload {
            branch:"main",path:"notes.txt",message:"initial",bytes:b"shared office"
        },&cache).await?;
        let snapshot = client::office::snapshot(&node,host_key.peer_id(),&pin).await?;
        assert_eq!(snapshot.domain.inner.files.read(&cid)?,b"shared office");
        let response = client::ops::execute(&node,host_key.peer_id(),operations,&node::protocol::OpsRequest {op:node::protocol::OpsOp::ListInstances{}}).await?;
        assert!(response.ok && response.instances.is_empty());
        // Membership and office permissions do not imply gateway use.
        assert!(node.open_service(host_key.peer_id(),gateway).await.is_err());
        let admin_node=Node::start(admin.clone(),NodeConfig::default()).await?;
        admin_node.dial(status.addresses[0].parse()?).await?;
        let mut record=cache.state().draft(node::protocol::TrustAction::GrantPermission{id:"gateway-use".into(),member:"alice".into(),service:gateway.to_string(),permission:"use".into()});
        client::trust::sign(&mut record,&admin)?;
        let response=client::trust::request(&admin_node,host_key.peer_id(),node::protocol::TrustRequest::Append{record:record.clone()}).await?;
        assert!(response.error.is_none(),"{:?}",response.error);cache.append(record)?;
        let mut stream=node.open_service(host_key.peer_id(),gateway).await?;
        let mut record=cache.state().draft(node::protocol::TrustAction::RevokeDevice{member:"alice".into(),device:member.peer_id().to_string()});
        client::trust::sign(&mut record,&admin)?;
        let response=client::trust::request(&admin_node,host_key.peer_id(),node::protocol::TrustRequest::Append{record}).await?;
        assert!(response.error.is_none(),"{:?}",response.error);
        assert!(node.open_service(host_key.peer_id(),operations).await.is_err());
        assert!(tokio::time::timeout(Duration::from_secs(3),node::protocol::read_frame::<node::protocol::JsonFrame>(&mut stream)).await?.is_err());
        admin_node.shutdown().await?;
        node.shutdown().await?;
        host.close().await?;
        let replay = authority::journal::Journal::<Office>::open(dir.path().join("journal"),genesis)?;
        assert_eq!(replay.state().domain.inner.files.read(&cid)?,b"shared office");
        Ok::<_,Box<dyn std::error::Error + Send + Sync>>(())
    }).await?
}

#[tokio::test]
async fn failed_start_and_dropped_host_release_governance_ownership() -> Result {
    let dir = tempfile::tempdir()?;
    let identity = Identity::generate();
    identity.save_new(dir.path().join("node.key"))?;
    let (identity_config, _cache, binding) =
        setup_identity(dir.path(), &identity, &identity, None)?;
    let genesis = state::State::<state::EmptyDomain>::new(binding)?;
    write(&dir.path().join("genesis.json"), &genesis)?;
    write(
        &dir.path().join("gateway.json"),
        &json!({"providers":[],"members":{},"purposes":[],"max_tokens":1,"max_messages":1,"max_input_bytes":1,"concurrency":1}),
    )?;
    let path = dir.path().join("node.json");
    let mut value = json!({"node":{"key":"node.key"},"services":{
        "identity":identity_config,"governance":{"domain":"identity","genesis":"genesis.json","journal":"journal"},
        "gateway":{"service":ServiceId::new().to_string(),"config":"gateway.json","ledger":"ledger"}
    }});
    write(&path, &value)?;
    assert!(Host::start(Config::load(&path)?).await.is_err());
    drop(authority::journal::Journal::open(
        dir.path().join("journal"),
        genesis.clone(),
    )?);
    value["services"]
        .as_object_mut()
        .ok_or("services object")?
        .remove("gateway");
    write(&path, &value)?;
    let host = Host::start(Config::load(&path)?).await?;
    drop(host);
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if authority::journal::Journal::open(dir.path().join("journal"), genesis.clone())
                .is_ok()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}

fn setup_identity(
    dir: &std::path::Path,
    admin: &Identity,
    host: &Identity,
    member: Option<(&Identity, ServiceId, ServiceId)>,
) -> Result<(
    serde_json::Value,
    client::trust::TrustLog,
    node::protocol::TrustBusinessBinding,
)> {
    use node::protocol::{TrustAction as A, TrustBusinessBinding, TrustFounder, TrustGenesis};
    let genesis = TrustGenesis {
        federation: "test".into(),
        quorum: 1,
        founders: vec![TrustFounder {
            member: "chair".into(),
            club: "school".into(),
            public_key: admin.public_key().encode_protobuf(),
        }],
    };
    let pin = client::trust::TrustState::genesis_digest(&genesis)?;
    write(&dir.join("identity-genesis.json"), &genesis)?;
    let mut log = client::trust::TrustLog::open(&dir.join("identity.jsonl"), &genesis, &pin)?;
    let mut actions = vec![A::RegisterService {
        service: "office".into(),
        audience: host.peer_id().to_string(),
        club: "school".into(),
    }];
    if let Some((member, gateway, operations)) = member {
        actions.extend([
            A::ConfirmMember {
                member: "alice".into(),
                club: "school".into(),
                device: Some(member.peer_id().to_string()),
                evidence: "manual".into(),
                verifier: None,
            },
            A::RegisterService {
                service: gateway.to_string(),
                audience: host.peer_id().to_string(),
                club: "school".into(),
            },
            A::RegisterService {
                service: operations.to_string(),
                audience: host.peer_id().to_string(),
                club: "school".into(),
            },
            A::GrantPermission {
                id: "office-write".into(),
                member: "alice".into(),
                service: "office".into(),
                permission: "write".into(),
            },
            A::GrantPermission {
                id: "ops-manage".into(),
                member: "alice".into(),
                service: operations.to_string(),
                permission: "manage".into(),
            },
        ]);
    }
    for action in actions {
        let mut record = log.state().draft(action);
        for key in [Some(admin), Some(host), member.map(|m| m.0)]
            .into_iter()
            .flatten()
        {
            if !record
                .signatures
                .iter()
                .any(|s| s.public_key == key.public_key().encode_protobuf())
            {
                client::trust::sign(&mut record, key)?;
            }
        }
        log.append(record)?;
    }
    let mut cache = client::trust::TrustLog::open(&dir.join("cache.jsonl"), &genesis, &pin)?;
    for record in log.history_since(None)?.records {
        cache.append(record)?;
    }
    drop(log);
    Ok((
        json!({"genesis":"identity-genesis.json","genesis_hash":pin,"log":"identity.jsonl","writer":true,"max_staleness_seconds":60}),
        cache,
        TrustBusinessBinding {
            genesis: pin,
            namespace: "office".into(),
            audience: host.peer_id().to_string(),
            service: "office".into(),
            club: "school".into(),
        },
    ))
}

#[tokio::test]
async fn document_terminal_download_checks_hash_and_live_read_permission() -> Result {
    use node::protocol::{TrustAction, TrustRequest};
    let dir = tempfile::tempdir()?;
    let host_key = Identity::generate();
    let admin = Identity::generate();
    let reader = Identity::generate();
    host_key.save_new(dir.path().join("node.key"))?;
    let documents = ServiceId::new();
    let (identity_config, mut cache, _) = setup_identity(
        dir.path(),
        &admin,
        &host_key,
        Some((&reader, ServiceId::new(), documents)),
    )?;
    let source = dir.path().join("source.txt");
    std::fs::write(&source, b"verified terminal document")?;
    let collection = dir.path().join("documents");
    let hash = events::documents::store(&collection, &source)?;
    let path = dir.path().join("node.json");
    write(
        &path,
        &json!({"node":{"key":"node.key"},"services":{"identity":identity_config,"documents":{"service":documents.to_string(),"directory":"documents"}}}),
    )?;
    let host = Host::start(Config::load(&path)?).await?;
    let status = host.status()?;
    let input = || client::documents::Input {
        address: status.addresses[0].clone(),
        peer: status.peer.clone(),
        service: documents.to_string(),
        hash: hash.clone(),
    };
    // Existing manage permission is intentionally insufficient for a document read.
    assert!(
        client::documents::fetch(reader.clone(), input())
            .await
            .is_err()
    );
    let node = Node::start(admin.clone(), NodeConfig::default()).await?;
    node.dial(status.addresses[0].parse()?).await?;
    let mut grant = cache.state().draft(TrustAction::GrantPermission {
        id: "doc-read".into(),
        member: "alice".into(),
        service: documents.to_string(),
        permission: "read".into(),
    });
    client::trust::sign(&mut grant, &admin)?;
    let response = client::trust::request(
        &node,
        host_key.peer_id(),
        TrustRequest::Append {
            record: grant.clone(),
        },
    )
    .await?;
    assert!(response.error.is_none());
    cache.append(grant)?;
    assert_eq!(
        client::documents::fetch(reader.clone(), input()).await?,
        b"verified terminal document"
    );
    std::fs::write(collection.join(&hash), b"tampered")?;
    assert!(
        client::documents::fetch(reader.clone(), input())
            .await
            .is_err()
    );
    std::fs::write(collection.join(&hash), b"verified terminal document")?;
    let mut revoke = cache.state().draft(TrustAction::RevokePermission {
        id: "doc-read".into(),
    });
    client::trust::sign(&mut revoke, &admin)?;
    assert!(
        client::trust::request(
            &node,
            host_key.peer_id(),
            TrustRequest::Append { record: revoke }
        )
        .await?
        .error
        .is_none()
    );
    assert!(client::documents::fetch(reader, input()).await.is_err());
    node.shutdown().await?;
    host.close().await?;
    Ok(())
}
