use serde_json::json;
use std::process::Command;

#[test]
fn standalone_rejects_external_roots_and_initializes_only_explicitly() {
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
    std::fs::write(&path,serde_json::to_vec(&json!({"node":{"key":"node.key"},"services":{"identity":{
        "genesis":"injected.json","genesis_hash":"a".repeat(64),"log":"log","writer":true,"max_staleness_seconds":60
    }}})).unwrap()).unwrap();
    let rejected = command("check");
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("built-in founder manifest"));
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({"node":{"key":"node.key"},"services":{"identity":{
            "log":"log","writer":true,"max_staleness_seconds":60
        }}}))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        command("check").status.success(),
        federated_server::bootstrap::genesis().is_ok()
    );
}
