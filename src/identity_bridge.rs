//! Authenticated loopback adapter for a skin site's narrowly scoped attestation device.
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::post,
};
use client::trust::{
    Config as TrustConfig, Input, Operation, TrustAction, TrustGenesis, TrustRecord,
};
use serde::Deserialize;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub bind: SocketAddr,
    pub key: PathBuf,
    pub token: PathBuf,
    pub log: PathBuf,
    pub address: String,
    pub peer: String,
    pub club: String,
    pub verifier: String,
}
impl Config {
    pub fn load(path: &Path) -> crate::Result<Self> {
        Self::load_inner(path).map_err(crate::operation_error)
    }
    fn load_inner(path: &Path) -> anyhow::Result<Self> {
        anyhow::ensure!(
            path.metadata()?.len() <= node::protocol::MAX_FRAME as u64,
            "bridge configuration too large"
        );
        let mut config: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        let base = path.parent().unwrap_or(Path::new("."));
        for path in [&mut config.key, &mut config.token, &mut config.log] {
            if path.is_relative() {
                *path = base.join(&*path);
            }
        }
        config.validate()?;
        Ok(config)
    }
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.bind.ip().is_loopback(),
            "identity bridge must bind to loopback"
        );
        node::protocol::validate_identifier(&self.club)?;
        node::protocol::validate_identifier(&self.verifier)?;
        let peer: node::PeerId = self.peer.parse()?;
        let address: node::Multiaddr = self.address.parse()?;
        anyhow::ensure!(
            matches!(address.iter().last(), Some(node::AddressProtocol::P2p(id)) if id == peer),
            "identity source peer mismatch"
        );
        Ok(())
    }
}
pub fn initialize(config: &Config) -> crate::Result<serde_json::Value> {
    initialize_inner(config).map_err(crate::operation_error)
}
fn initialize_inner(config: &Config) -> anyhow::Result<serde_json::Value> {
    config.validate()?;
    let identity = match std::fs::symlink_metadata(&config.key) {
        Ok(_) => node::Identity::load(&config.key)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            anyhow::ensure!(
                !config.log.try_exists()?,
                "refusing to replace identity for existing cache"
            );
            let key = node::Identity::generate();
            key.save_new(&config.key)?;
            key
        }
        Err(e) => return Err(e.into()),
    };
    if !config.token.try_exists()? {
        // An independent random key's public encoding is used only as a bearer secret.
        crate::bootstrap::write_new(
            &config.token,
            &node::Identity::generate().peer_id().to_string(),
        )?;
    }
    read_token(&config.token)?;
    Ok(
        serde_json::json!({"peer":identity.peer_id().to_string(),"public_key":identity.public_key().encode_protobuf()}),
    )
}
fn read_token(path: &Path) -> anyhow::Result<String> {
    crate::bootstrap::require_private(path, "bridge token")?;
    anyhow::ensure!(
        std::fs::symlink_metadata(path)?.len() <= 1024,
        "invalid bridge token file"
    );
    let token: String = serde_json::from_slice(&std::fs::read(path)?)?;
    anyhow::ensure!(
        token.len() >= 32 && token.is_ascii() && !token.chars().any(char::is_whitespace),
        "invalid bridge token"
    );
    Ok(token)
}
struct Bridge {
    config: Config,
    trust: TrustConfig,
    identity: node::Identity,
    token: String,
    serial: Mutex<()>,
}
impl Bridge {
    fn authorize(&self, headers: &HeaderMap) -> Result<(), StatusCode> {
        crate::bearer::require_bearer(headers, self.token.as_bytes())
    }
    fn scoped(&self, action: &TrustAction) -> Result<(), StatusCode> {
        let allowed = match action {
            TrustAction::ConfirmMember {
                club,
                device: Some(_),
                evidence,
                verifier: Some(verifier),
                ..
            } => {
                club == &self.config.club
                    && evidence == "institutional_email"
                    && verifier == &self.config.verifier
            }
            TrustAction::BindGameProfile { club, .. } => club == &self.config.club,
            _ => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(StatusCode::FORBIDDEN)
        }
    }
    async fn execute(&self, operation: Operation) -> Result<serde_json::Value, StatusCode> {
        client::trust::execute_identity(
            self.identity.clone(),
            Input {
                config: self.trust.clone(),
                operation,
            },
        )
        .await
        .map_err(|e| {
            if matches!(e, node::Error::Denied) {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            }
        })
    }
}
/// Explicit genesis parameter supports embedded use and isolated tests; the server entry point
/// always supplies bootstrap::genesis(), with no external trust-root override.
pub fn router(config: Config, genesis: TrustGenesis) -> crate::Result<Router> {
    router_inner(config, genesis).map_err(crate::operation_error)
}
fn router_inner(config: Config, genesis: TrustGenesis) -> anyhow::Result<Router> {
    config.validate()?;
    let genesis_hash = client::trust::TrustState::genesis_digest(&genesis)?;
    client::trust::TrustState::new(&genesis, &genesis_hash)?;
    let bridge = Arc::new(Bridge {
        token: read_token(&config.token)?,
        identity: node::Identity::load(&config.key)?,
        trust: TrustConfig {
            genesis,
            genesis_hash,
            log: config.log.clone(),
            address: config.address.clone(),
            peer: config.peer.clone(),
        },
        config,
        serial: Mutex::new(()),
    });
    Ok(Router::new()
        .route("/state", post(current))
        .route("/draft", post(draft))
        .route("/confirm", post(confirm))
        .layer(DefaultBodyLimit::max(node::protocol::MAX_TRUST_RECORD))
        .with_state(bridge))
}
async fn current(
    State(bridge): State<Arc<Bridge>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    bridge.authorize(&headers)?;
    let _guard = bridge.serial.lock().await;
    bridge.execute(Operation::Sync).await.map(Json)
}
async fn draft(
    State(bridge): State<Arc<Bridge>>,
    headers: HeaderMap,
    Json(action): Json<TrustAction>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    bridge.authorize(&headers)?;
    bridge.scoped(&action)?;
    let _guard = bridge.serial.lock().await;
    bridge.execute(Operation::Draft { action }).await.map(Json)
}
async fn confirm(
    State(bridge): State<Arc<Bridge>>,
    headers: HeaderMap,
    Json(record): Json<TrustRecord>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    bridge.authorize(&headers)?;
    bridge.scoped(&record.action)?;
    if record.signatures.is_empty() {
        return Err(StatusCode::FORBIDDEN);
    }
    let _guard = bridge.serial.lock().await;
    let signed = bridge.execute(Operation::Sign { record }).await?;
    let record = serde_json::from_value(signed).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let state = bridge.execute(Operation::Submit { record }).await?;
    Ok(Json(state["checkpoint"].clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn setup(dir: &Path) -> (Config, TrustGenesis) {
        let founder = node::Identity::generate();
        let config = Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            key: dir.join("issuer.key"),
            token: dir.join("token.json"),
            log: dir.join("cache.jsonl"),
            address: format!("/ip4/127.0.0.1/tcp/1/p2p/{}", founder.peer_id()),
            peer: founder.peer_id().to_string(),
            club: "school".into(),
            verifier: "skin".into(),
        };
        let genesis = TrustGenesis {
            federation: "bridge-test".into(),
            quorum: 1,
            founders: vec![node::protocol::TrustFounder {
                member: "chair".into(),
                club: "school".into(),
                public_key: founder.public_key().encode_protobuf(),
            }],
        };
        (config, genesis)
    }
    #[tokio::test]
    async fn loopback_api_authenticates_and_restricts_signing_scope() {
        let dir = tempfile::tempdir().unwrap();
        let (config, genesis) = setup(dir.path());
        initialize(&config).unwrap();
        let token = read_token(&config.token).unwrap();
        let app = router(config, genesis).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        let client = reqwest::Client::new();
        assert_eq!(
            client
                .post(format!("{base}/state"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            client
                .post(format!("{base}/state"))
                .bearer_auth("wrong")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        for action in [
            serde_json::json!({"type":"confirm_member","member":"m","club":"other","device":"p","evidence":"institutional_email","verifier":"skin"}),
            serde_json::json!({"type":"confirm_member","member":"m","club":"school","device":"p","evidence":"manual","verifier":"skin"}),
            serde_json::json!({"type":"register_service","service":"s","audience":"p","club":"school"}),
        ] {
            assert_eq!(
                client
                    .post(format!("{base}/draft"))
                    .bearer_auth(&token)
                    .json(&action)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                StatusCode::FORBIDDEN
            );
        }
        task.abort();
        let _ = task.await;
    }
    #[test]
    fn public_bind_and_invalid_roots_are_rejected_and_tokens_are_stable() {
        let dir = tempfile::tempdir().unwrap();
        let (mut config, mut genesis) = setup(dir.path());
        let first = initialize(&config).unwrap();
        let token = read_token(&config.token).unwrap();
        assert_eq!(initialize(&config).unwrap(), first);
        assert_eq!(read_token(&config.token).unwrap(), token);
        config.bind = "0.0.0.0:1234".parse().unwrap();
        assert!(router(config.clone(), genesis.clone()).is_err());
        config.bind = "127.0.0.1:0".parse().unwrap();
        genesis.founders.clear();
        assert!(router(config, genesis).is_err());
    }
}
