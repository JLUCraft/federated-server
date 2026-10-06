use llm_gateway::Ledger;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_audit_anchors_to_an_independent_governance_authority()
-> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use identity::Identity;
    use league::{governance::State, journal::Journal};
    use node::{Node, NodeConfig};
    use std::{process::Command, sync::Arc};
    let dir = tempfile::tempdir()?;
    let key = dir.path().join("admin.key");
    let admin = Identity::generate();
    admin.save_new(&key)?;
    let mut ledger = Ledger::open(dir.path().join("ledger"))?;
    let reservation = ledger.reserve(
        llm_gateway::Reservation {
            member: "alice",
            club: "jlu",
            model: "local",
            purpose: "assistant.ask",
            tokens: 100,
        },
        llm_gateway::Quotas {
            member: Some(100),
            club: None,
        },
        1000,
    )?;
    ledger.settle(reservation, 20, 1001)?;
    let host_key = Identity::generate();
    let server = Arc::new(Node::start(host_key.clone(), NodeConfig::default()).await?);
    use client::protocol::{TrustAction as A, TrustBusinessBinding, TrustFounder, TrustGenesis};
    let trust_genesis = TrustGenesis {
        federation: "audit-test".into(),
        quorum: 1,
        founders: vec![TrustFounder {
            member: "chair".into(),
            club: "club".into(),
            public_key: admin.public_key().encode_protobuf(),
        }],
    };
    let trust_pin = client::trust::TrustState::genesis_digest(&trust_genesis)?;
    let mut log =
        client::trust::TrustLog::open(&dir.path().join("identity"), &trust_genesis, &trust_pin)?;
    for action in [
        A::ConfirmMember {
            member: "chair".into(),
            club: "club".into(),
            device: None,
            evidence: "manual".into(),
            verifier: None,
        },
        A::RegisterService {
            service: "audit".into(),
            audience: server.peer_id().to_string(),
            club: "club".into(),
        },
        A::GrantPermission {
            id: "audit-admin".into(),
            member: "chair".into(),
            service: "audit".into(),
            permission: "admin".into(),
        },
    ] {
        let mut record = log.state().draft(action);
        for key in [&admin, &host_key] {
            client::trust::sign(&mut record, key)?;
        }
        log.append(record)?;
    }
    log.mark_current()?;
    let view = log.view(std::time::Duration::from_secs(60))?;
    let log = Arc::new(tokio::sync::Mutex::new(log));
    let identity_service = {
        let server = server.clone();
        let log = log.clone();
        tokio::spawn(async move { authority::trust::serve(&server, log, true).await })
    };
    let config = dir.path().join("identity-config.json");
    std::fs::write(
        &config,
        serde_json::to_vec(&client::trust::Config {
            genesis: trust_genesis,
            genesis_hash: trust_pin.clone(),
            log: dir.path().join("cache"),
            address: server.addresses()[0].to_string(),
            peer: server.peer_id().to_string(),
        })?,
    )?;
    let journal = Arc::new(tokio::sync::Mutex::new(Journal::open(
        dir.path().join("governance"),
        State::new(TrustBusinessBinding {
            genesis: trust_pin,
            namespace: "audit".into(),
            service: "audit".into(),
            audience: server.peer_id().to_string(),
            club: "club".into(),
        })?,
    )?));
    let pin = journal.lock().await.genesis_hash().to_owned();
    let serving = {
        let server = server.clone();
        let journal = journal.clone();
        tokio::spawn(async move { authority::journal::serve(&server, journal, view).await })
    };
    let summary = dir.path().join("summary.json");
    let action = dir.path().join("action.json");
    let export = Command::new(env!("CARGO_BIN_EXE_federated-server"))
        .args(["gateway", "audit", "--ledger"])
        .arg(dir.path().join("ledger"))
        .arg("--out")
        .arg(&summary)
        .arg("--action")
        .arg(&action)
        .output()?;
    assert!(
        export.status.success(),
        "{}",
        String::from_utf8_lossy(&export.stderr)
    );
    let action_value: serde_json::Value = serde_json::from_slice(&std::fs::read(&action)?)?;
    let committed = client::generic::execute::<league::LeagueDomain>(
        admin.clone(),
        client::generic::Input {
            identity: serde_json::from_slice(&std::fs::read(&config)?)?,
            address: server.addresses()[0].to_string(),
            peer: server.peer_id().to_string(),
            genesis_hash: pin,
            revision: Some(0),
            action: Some(serde_json::from_value(action_value.clone())?),
        },
    )
    .await?;
    assert!(committed.error.is_none());
    let committed = serde_json::to_value(committed)?;
    let id = action_value["id"].as_str().ok_or("missing anchor id")?;
    let digest = committed["state"]["digest_anchors"][id]["digest"]
        .as_str()
        .ok_or("missing anchor")?;
    let verify = |digest: &str| {
        Command::new(env!("CARGO_BIN_EXE_federated-server"))
            .args(["gateway", "verify-audit", "--ledger"])
            .arg(dir.path().join("ledger"))
            .arg("--summary")
            .arg(&summary)
            .args(["--digest", digest])
            .output()
    };
    assert!(verify(digest)?.status.success());
    assert!(!verify(&"0".repeat(64))?.status.success());
    // Replacing both local files cannot satisfy the independently stored anchor.
    std::fs::write(dir.path().join("ledger"), b"[]")?;
    std::fs::write(
        &summary,
        serde_json::to_vec(&Ledger::audit(dir.path().join("ledger"), None)?)?,
    )?;
    assert!(!verify(digest)?.status.success());
    identity_service.abort();
    let _ = identity_service.await;
    serving.abort();
    let _ = serving.await;
    Ok(())
}
