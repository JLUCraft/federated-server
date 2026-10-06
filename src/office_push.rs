//! Web Push delivery with encrypted, quorum-replicated subscription checkpoints.
use crate::runtime::Office;
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use anyhow::{Context, Result, ensure};
use authority::authority::Authority;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use identity::Identity;
use node::{
    IncomingSession,
    protocol::{
        JsonFrame, OfficePushRequest as Request, OfficePushResponse as Response, read_frame,
        write_frame,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::PathBuf,
    time::Duration,
};
use web_push::{ContentEncoding, SubscriptionInfo, VapidSignatureBuilder, WebPushMessageBuilder};
const MAX_SUBSCRIPTIONS: usize = 1000;
const RETRY_MS: u64 = 60_000;
const MAX_STORE_BYTES: u64 = 64 * 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub service: String,
    pub key: PathBuf,
    pub store: PathBuf,
    pub vapid_key: PathBuf,
    #[serde(default = "default_hosts")]
    pub allowed_hosts: BTreeSet<String>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Subscription {
    member: String,
    endpoint: String,
    p256dh: String,
    auth: String,
    challenge: String,
    verified: bool,
}
#[derive(Default, Serialize, Deserialize)]
struct Store {
    subscriptions: BTreeMap<String, Subscription>,
    sent: BTreeSet<String>,
}
pub async fn serve(
    a: Authority<Office>,
    config: Config,
    mut incoming: tokio::sync::mpsc::Receiver<IncomingSession>,
) -> Result<()> {
    let key = Identity::load(&config.key)?;
    let lock = private_file(&config.store.with_extension("lock"))?;
    lock.try_lock()?;
    require_private(&config.vapid_key)?;
    let pem = std::fs::read(&config.vapid_key)?;
    let vapid = URL_SAFE_NO_PAD
        .encode(VapidSignatureBuilder::from_pem_no_sub(pem.as_slice())?.get_public_key());
    let mut store: Store = if config.store.exists() {
        require_private(&config.store)?;
        ensure!(
            std::fs::metadata(&config.store)?.len() <= MAX_STORE_BYTES,
            "push store too large"
        );
        serde_json::from_slice(&std::fs::read(&config.store)?)?
    } else {
        Store::default()
    };
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(Duration::from_secs(15))
        .build()?;
    let mut updates = a.watch().await;
    let mut next_attempt = BTreeMap::<String, u64>::new();
    let cipher = Aes256Gcm::new_from_slice(&Sha256::digest(&pem))
        .map_err(|_| anyhow::anyhow!("push encryption key invalid"))?;
    let group = node::protocol::digest(vapid.as_bytes());

    // Import an existing private cache once, only if this group has no committed state.
    if !store.subscriptions.is_empty()
        && a.effect_epoch().is_some()
        && !a
            .stored_state()
            .await
            .domain
            .inner
            .office
            .push_checkpoints
            .contains_key(&group)
    {
        replicate(&a, &key, &cipher, &group, 0, &store).await?;
    }
    loop {
        let mut revision;
        let current = a.stored_state().await;
        if let Some(checkpoint) = current.domain.inner.office.push_checkpoints.get(&group) {
            {
                store = decrypt(
                    &cipher,
                    &checkpoint.ciphertext,
                    &checkpoint_aad(&current, &group, checkpoint.revision),
                )?;
                revision = checkpoint.revision;
            }
        } else {
            store = Store::default();
            revision = 0;
        }

        tokio::select! {
            session=incoming.recv()=>{
                let Some(mut session)=session else {break;};
                let result=tokio::time::timeout(Duration::from_secs(20),async {
                    let frame:JsonFrame=read_frame(&mut session.stream).await?;
                    ensure!(frame.sequence==0&&frame.last,"invalid push envelope");
                    let request:Request=serde_json::from_slice(&frame.json)?;
                    let device=session.peer.to_string();
                    let identity=a.identity_view().state()?;
                    let member=identity.member_for_device(&device).context("device revoked")?.to_string();
                    ensure!(identity.permits(&device,&a.state(key.peer_id()).await?.core.identity.audience,&config.service,"use"),"push permission revoked");
                    match request {
                        Request::Info=>{},
                        Request::Subscribe{endpoint,p256dh,auth}=>{
                            validate_endpoint(&endpoint,&config.allowed_hosts)?;
                            ensure!(p256dh.len()==87 && auth.len()==22,"invalid push keys");
                            ensure!(store.subscriptions.len()<MAX_SUBSCRIPTIONS||store.subscriptions.contains_key(&device),"push capacity reached");
                            if !store.subscriptions.get(&device).is_some_and(|s|s.endpoint==endpoint&&s.p256dh==p256dh&&s.auth==auth&&s.verified) {
                                let challenge=uuid::Uuid::new_v4().to_string();
                                let sub=Subscription{member,endpoint,p256dh,auth,challenge:challenge.clone(),verified:false};
                                send(&client,&pem,&sub,&serde_json::json!({"challenge":challenge})).await?;
                                store.subscriptions.insert(device,sub);revision=replicate(&a,&key,&cipher,&group,revision,&store).await?;persist(&config.store,&store)?;
                            }
                        }
                        Request::Verify{challenge}=>{
                            let sub=store.subscriptions.get_mut(&device).context("subscription missing")?;
                            ensure!(sub.challenge==challenge && sub.member==member,"subscription challenge mismatch");sub.verified=true;revision=replicate(&a,&key,&cipher,&group,revision,&store).await?;persist(&config.store,&store)?;
                        }
                        Request::Unsubscribe=>{store.subscriptions.remove(&device);revision=replicate(&a,&key,&cipher,&group,revision,&store).await?;persist(&config.store,&store)?;},
                    }
                    Ok::<_,anyhow::Error>(())
                }).await;
                let response=Response{ok:matches!(result,Ok(Ok(()))),vapid:vapid.clone(),error:(!matches!(result,Ok(Ok(())))).then(||"Push registration failed".into())};
                let _=write_frame(&mut session.stream,&JsonFrame{json:serde_json::to_vec(&response)?,sequence:0,last:true}).await;
                if !response.ok {continue;}
            }
            result=updates.changed()=>{result.context("office closed")?;},
            _=tokio::time::sleep(Duration::from_secs(5))=>{},
        }
        if a.effect_epoch().is_none() {
            continue;
        }
        let Ok(snapshot) = a.state(key.peer_id()).await else {
            continue;
        };
        let now = authority::journal::now_ms()?;
        let Ok(identity) = a.identity_view().state() else {
            continue;
        };
        let mut dirty = false;
        let mut active_deliveries = BTreeSet::new();
        for (id, notice) in &snapshot.domain.inner.office.notices {
            let Some(task) = snapshot.domain.inner.tasks.get(&notice.task) else {
                continue;
            };
            if notice.due_ms > now
                || notice.acknowledged_ms.is_some()
                || task.done
                || task.assignee.as_deref() != Some(&notice.member)
                || snapshot
                    .domain
                    .inner
                    .events
                    .get(&notice.event)
                    .is_none_or(|e| e.phase != events::Phase::Open)
            {
                continue;
            }
            for (device, sub) in &store.subscriptions {
                let delivery = node::protocol::digest(
                    format!("{id}:{}:{device}:{}", notice.due_ms, sub.challenge).as_bytes(),
                );
                active_deliveries.insert(delivery.clone());
                if !sub.verified
                    || sub.member != notice.member
                    || store.sent.contains(&delivery)
                    || next_attempt.get(&delivery).is_some_and(|due| *due > now)
                {
                    continue;
                }
                if identity.member_for_device(device) != Some(&sub.member)
                    || !identity.permits(
                        device,
                        &snapshot.core.identity.audience,
                        &config.service,
                        "use",
                    )
                    || !identity.permits(
                        device,
                        &snapshot.core.identity.audience,
                        &snapshot.core.identity.service,
                        "read",
                    )
                {
                    continue;
                }
                let payload = serde_json::json!({"notice":id,"event":notice.event,"task":notice.task,"title":task.title});
                let request = send(&client, &pem, sub, &payload);
                tokio::pin!(request);
                let mut identity_updates = a.identity_view();
                let epoch = a.effect_epoch();
                let delivered = loop {
                    identity_updates.mark_seen();
                    updates.borrow_and_update();
                    let Ok(current) = a.state(key.peer_id()).await else {
                        break false;
                    };
                    let Ok(identity) = identity_updates.state() else {
                        break false;
                    };
                    if a.effect_epoch() != epoch
                        || epoch.is_none()
                        || identity.member_for_device(device) != Some(&sub.member)
                        || !identity.permits(
                            device,
                            &current.core.identity.audience,
                            &config.service,
                            "use",
                        )
                        || !identity.permits(
                            device,
                            &current.core.identity.audience,
                            &current.core.identity.service,
                            "read",
                        )
                        || current.domain.inner.office.notices.get(id) != Some(notice)
                        || current.domain.inner.tasks.get(&notice.task) != Some(task)
                        || current
                            .domain
                            .inner
                            .events
                            .get(&notice.event)
                            .is_none_or(|e| e.phase != events::Phase::Open)
                    {
                        break false;
                    }
                    tokio::select! {
                        result=&mut request=>break result.is_ok(),
                        _=identity_updates.changed()=>{},
                        _=updates.changed()=>{},
                        _=tokio::time::sleep(Duration::from_secs(1))=>{},
                    }
                };
                if delivered {
                    store.sent.insert(delivery.clone());
                    dirty = true;
                }
                next_attempt.insert(delivery, now.saturating_add(RETRY_MS));
            }
        }
        let sent_count = store.sent.len();
        store.sent.retain(|id| active_deliveries.contains(id));
        next_attempt.retain(|id, _| active_deliveries.contains(id));
        dirty |= sent_count != store.sent.len();
        if dirty || revision == 0 && !store.subscriptions.is_empty() {
            match replicate(&a, &key, &cipher, &group, revision, &store).await {
                Ok(_) => {
                    persist(&config.store, &store)?;
                }
                Err(_) => {
                    tracing::debug!("push checkpoint awaits authority");
                }
            }
        }
    }
    Ok(())
}
fn private_file(path: &std::path::Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    if path.exists() {
        require_private(path)?;
    }
    Ok(options.open(path)?)
}
fn persist(path: &std::path::Path, store: &Store) -> Result<()> {
    let temp = path.with_extension("pending");
    let mut file = private_file(&temp)?;
    file.set_len(0)?;
    file.write_all(&serde_json::to_vec(store)?)?;
    file.sync_all()?;
    std::fs::rename(temp, path)?;
    Ok(())
}
fn validate_endpoint(endpoint: &str, hosts: &BTreeSet<String>) -> Result<()> {
    ensure!(endpoint.len() <= 1000, "endpoint too long");
    let url = reqwest::Url::parse(endpoint)?;
    ensure!(
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.host_str().is_some_and(|h| hosts.contains(h)),
        "unapproved push host"
    );
    Ok(())
}
async fn send(
    client: &reqwest::Client,
    pem: &[u8],
    sub: &Subscription,
    payload: &serde_json::Value,
) -> Result<()> {
    let subscription = SubscriptionInfo::new(&sub.endpoint, &sub.p256dh, &sub.auth);
    let signature = VapidSignatureBuilder::from_pem(pem, &subscription)?.build()?;
    let bytes = serde_json::to_vec(payload)?;
    let mut builder = WebPushMessageBuilder::new(&subscription);
    builder.set_payload(ContentEncoding::Aes128Gcm, &bytes);
    builder.set_vapid_signature(signature);
    builder.set_ttl(3600);
    let message = builder.build()?;
    let payload = message.payload.context("push payload missing")?;
    let mut request = client
        .post(message.endpoint.to_string())
        .header("TTL", message.ttl)
        .header("Content-Encoding", payload.content_encoding.to_str())
        .header("Content-Type", "application/octet-stream");
    for (k, v) in payload.crypto_headers {
        request = request.header(k, v);
    }
    ensure!(
        request
            .body(payload.content)
            .send()
            .await?
            .status()
            .is_success(),
        "push delivery failed"
    );
    Ok(())
}

fn default_hosts() -> BTreeSet<String> {
    BTreeSet::from(["fcm.googleapis.com".into()])
}

fn require_private(path: &std::path::Path) -> Result<()> {
    crate::bootstrap::require_private(path, "push secret")
}

fn checkpoint_aad(state: &state::State<Office>, group: &str, revision: u64) -> Vec<u8> {
    format!(
        "{}:{}:{group}:{revision}",
        state.core.identity.audience, state.core.identity.service
    )
    .into_bytes()
}
fn decrypt(cipher: &Aes256Gcm, text: &str, aad: &[u8]) -> Result<Store> {
    let bytes = URL_SAFE_NO_PAD.decode(text)?;
    ensure!(bytes.len() > 12, "invalid push checkpoint");
    let nonce = Nonce::try_from(&bytes[..12]).map_err(|_| anyhow::anyhow!("invalid push nonce"))?;
    let plain = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &bytes[12..],
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("push checkpoint key mismatch"))?;
    Ok(serde_json::from_slice(&plain)?)
}
async fn replicate(
    a: &Authority<Office>,
    key: &Identity,
    cipher: &Aes256Gcm,
    group: &str,
    expected: u64,
    store: &Store,
) -> Result<u64> {
    let next = expected.checked_add(1).context("push revision exhausted")?;
    let uuid = uuid::Uuid::new_v4();
    let nonce =
        Nonce::try_from(&uuid.as_bytes()[..12]).map_err(|_| anyhow::anyhow!("invalid nonce"))?;
    let state = a.stored_state().await;
    let aad = checkpoint_aad(&state, group, next);
    let mut bytes = nonce.to_vec();
    bytes.extend(
        cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &serde_json::to_vec(store)?,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("push encryption failed"))?,
    );
    let ciphertext = URL_SAFE_NO_PAD.encode(bytes);
    ensure!(
        ciphertext.len() <= events::workflows::MAX_PUSH_CHECKPOINT_BYTES,
        "push checkpoint capacity reached"
    );
    a.apply(
        key,
        state::governance::Action::Domain(flows::FlowAction::Inner(events::EventAction::Office(
            events::workflows::OfficeAction::PushCheckpoint {
                group: group.into(),
                expected,
                ciphertext,
            },
        ))),
    )
    .await?;
    Ok(next)
}
