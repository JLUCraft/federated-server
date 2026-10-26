use serde_json::json;
use std::process::Command;

#[test]
fn standalone_rejects_external_roots_and_initializes_only_explicitly() {
    let exported = Command::new(env!("CARGO_BIN_EXE_federated-server"))
        .arg("genesis")
        .output()
        .unwrap();
    assert!(exported.status.success());
    let exported: serde_json::Value = serde_json::from_slice(&exported.stdout).unwrap();
    let root = federated_server::bootstrap::parse_genesis(
        &serde_json::to_vec(&exported["genesis"]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        exported["genesis_hash"],
        federated_server::bootstrap::validate_genesis(&root).unwrap()
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.json");
    let config = json!({"node":{"key":"node.key"},"services":{"directory":true}});
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let command = |verb: &str| {
        Command::new(env!("CARGO_BIN_EXE_federated-server"))
            .args([verb, "--config"])
            .arg(&path)
            .output()
            .unwrap()
    };
    assert!(command("check").status.success());
    assert!(!dir.path().join("node.key").exists());
    assert!(command("init").status.success());
    let key = std::fs::read(dir.path().join("node.key")).unwrap();
    assert!(command("init").status.success());
    assert_eq!(key, std::fs::read(dir.path().join("node.key")).unwrap());
    std::fs::write(
        dir.path().join("injected.json"),
        serde_json::to_vec(&exported["genesis"]).unwrap(),
    )
    .unwrap();
    std::fs::write(&path,serde_json::to_vec(&json!({"node":{"key":"node.key"},"services":{"identity":{
        "genesis":"injected.json","genesis_hash":exported["genesis_hash"],"log":"log","writer":true,"max_staleness_seconds":60
    }}})).unwrap()).unwrap();
    let rejected = command("check");
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("built-in founder manifest"));
    let mut substituted = root.clone();
    substituted.federation = "runtime-substitution-test".into();
    std::fs::write(
        dir.path().join("injected.json"),
        serde_json::to_vec(&substituted).unwrap(),
    )
    .unwrap();
    assert!(!command("check").status.success());
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({"node":{"key":"node.key"},"services":{"identity":{
            "log":"log","writer":true,"max_staleness_seconds":60
        }}}))
        .unwrap(),
    )
    .unwrap();
    assert!(command("check").status.success());
}
