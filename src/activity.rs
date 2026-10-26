//! Server-side gateway witnesses and an authenticated, event-driven Paper oracle adapter.
use anyhow::{Context, Result, ensure};
use authority::{authority::Authority, journal::now_ms};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use events::points::{ACTIVITY_SLICE_MS, ActivityTotals, Attestation, DAY_MS};
use identity::Identity;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context as TaskContext, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::oneshot,
};
type Application = client::application::Application;
const MAX_SESSIONS: usize = 65_536;
// ActivityOutbox.MAX_REPORT_PLAYERS in the Paper producer uses the same limit.
const MAX_REPORT_PLAYERS: usize = 256;
const MAX_REPORT_BYTES: usize = 512 * 1024;
const MAX_SPOOL_BYTES: usize = 64 * 1024 * 1024;
const MAX_PACKET_SILENCE_MS: u64 = 60_000;
const BATCH_WINDOW_MS: u64 = 6 * ACTIVITY_SLICE_MS;
const MAX_REPORT_LAG_MS: u64 = DAY_MS;
const MIN_LOOK_SAMPLES: u32 = 8;
const MIN_YAW_VARIANCE_MILLI: u64 = 25_000;
const MIN_PITCH_VARIANCE_MILLI: u64 = 10_000;
const MIN_MOVEMENT_STEPS: u32 = 8;
const MIN_DISTINCT_POSITIONS: u32 = 4;
const MIN_WORLD_INTERACTIONS: u32 = 2;
const MIN_PROGRESS_EVENTS: u32 = 2;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActivityMetrics {
    pub movement_steps: u32,
    pub distinct_positions: u32,
    pub look_samples: u32,
    pub yaw_variance_milli: u64,
    pub pitch_variance_milli: u64,
    pub world_interactions: u32,
    pub progress_events: u32,
}
impl ActivityMetrics {
    fn active(&self) -> bool {
        let look = self.look_samples >= MIN_LOOK_SAMPLES
            && (self.yaw_variance_milli >= MIN_YAW_VARIANCE_MILLI
                || self.pitch_variance_milli >= MIN_PITCH_VARIANCE_MILLI);
        let dimensions = [
            self.movement_steps >= MIN_MOVEMENT_STEPS
                && self.distinct_positions >= MIN_DISTINCT_POSITIONS,
            self.world_interactions >= MIN_WORLD_INTERACTIONS,
            self.progress_events >= MIN_PROGRESS_EVENTS,
        ];
        look && dimensions.into_iter().filter(|active| *active).count() >= 2
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProbeReport {
    pub window_start_ms: u64,
    pub window_end_ms: u64,
    pub players: BTreeMap<String, ActivityMetrics>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Witness {
    service: String,
    uuid: String,
    member: String,
    device: String,
    clubs: BTreeSet<String>,
    connected_ms: u64,
    last_packet_ms: u64,
    closed_ms: Option<u64>,
    #[serde(skip)]
    packet_windows: BTreeMap<u64, u64>,
}
#[derive(Default)]
struct WitnessStore {
    next: u64,
    sessions: BTreeMap<u64, Witness>,
}
#[derive(Clone, Default)]
pub struct Witnesses(Arc<Mutex<WitnessStore>>);
pub struct WitnessGuard {
    owner: Witnesses,
    id: u64,
}
impl Witnesses {
    #[cfg(test)]
    pub(crate) fn recorded(&self, service: &str, member: &str, uuid: &str) -> bool {
        self.0.lock().is_ok_and(|store| {
            store
                .sessions
                .values()
                .any(|w| w.service == service && w.member == member && w.uuid == uuid)
        })
    }
    pub fn begin(
        &self,
        service: &str,
        uuid: &str,
        member: &str,
        device: &str,
        clubs: BTreeSet<String>,
    ) -> Result<WitnessGuard> {
        self.begin_at(service, uuid, member, device, clubs, now_ms()?)
    }
    fn begin_at(
        &self,
        service: &str,
        uuid: &str,
        member: &str,
        device: &str,
        clubs: BTreeSet<String>,
        now: u64,
    ) -> Result<WitnessGuard> {
        let mut store = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("witness store unavailable"))?;
        store.sessions.retain(|_, w| {
            w.closed_ms
                .is_none_or(|closed| closed.saturating_add(DAY_MS) >= now)
        });
        ensure!(
            store.sessions.len() < MAX_SESSIONS,
            "witness capacity reached"
        );
        store.next = store
            .next
            .checked_add(1)
            .context("witness sequence exhausted")?;
        let id = store.next;
        store.sessions.insert(
            id,
            Witness {
                service: service.into(),
                uuid: uuid.into(),
                member: member.into(),
                device: device.into(),
                clubs,
                connected_ms: now,
                last_packet_ms: now,
                closed_ms: None,
                packet_windows: [(now / ACTIVITY_SLICE_MS * ACTIVITY_SLICE_MS, now)].into(),
            },
        );
        Ok(WitnessGuard {
            owner: self.clone(),
            id,
        })
    }
    fn covering(
        &self,
        service: &str,
        uuid: &str,
        start: u64,
        end: u64,
        now: u64,
    ) -> Result<Option<Witness>> {
        let store = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("witness store unavailable"))?;
        Ok(store.sessions.values().find_map(|w| {
            if w.service != service
                || w.uuid != uuid
                || w.connected_ms > start
                || w.closed_ms.unwrap_or(now) < end
            {
                return None;
            }
            let last = *w.packet_windows.get(&start)?;
            if last < end.saturating_sub(MAX_PACKET_SILENCE_MS) || last >= end {
                return None;
            }
            let mut proof = w.clone();
            proof.last_packet_ms = last;
            proof.packet_windows.clear();
            Some(proof)
        }))
    }
}
impl WitnessGuard {
    pub fn touch(&self) {
        if let Ok(now) = now_ms() {
            self.touch_at(now);
        }
    }
    fn touch_at(&self, now: u64) {
        if let Ok(mut store) = self.owner.0.lock()
            && let Some(witness) = store.sessions.get_mut(&self.id)
            && now >= witness.last_packet_ms
            && witness.closed_ms.is_none()
        {
            witness.last_packet_ms = now;
            let window = now / ACTIVITY_SLICE_MS * ACTIVITY_SLICE_MS;
            if !witness.packet_windows.contains_key(&window) {
                witness
                    .packet_windows
                    .retain(|start, _| start.saturating_add(DAY_MS) >= now);
            }
            witness.packet_windows.insert(window, now);
        }
    }
}
impl Drop for WitnessGuard {
    fn drop(&mut self) {
        if let Ok(mut store) = self.owner.0.lock()
            && let Some(witness) = store.sessions.get_mut(&self.id)
        {
            witness.closed_ms = Some(now_ms().unwrap_or(witness.last_packet_ms));
        }
    }
}
pub struct Witnessed<T> {
    pub stream: T,
    pub witness: Option<WitnessGuard>,
}
impl<T: AsyncRead + Unpin> AsyncRead for Witnessed<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.stream).poll_read(cx, buf);
        if matches!(&result, Poll::Ready(Ok(())))
            && buf.filled().len() > before
            && let Some(witness) = &this.witness
        {
            witness.touch();
        }
        result
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for Witnessed<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub bind: SocketAddr,
    pub key: PathBuf,
    pub spool: PathBuf,
    pub evidence_directory: PathBuf,
    pub probes: Vec<Probe>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    pub source: String,
    pub service: String,
    pub token: PathBuf,
}
struct Binding {
    service: String,
    token: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
struct VerifiedSlice {
    report: ProbeReport,
    members: BTreeMap<String, String>,
    witnesses: BTreeMap<String, Witness>,
}
#[derive(Default, Serialize, Deserialize)]
struct Pending {
    start: u64,
    end: u64,
    slices: Vec<VerifiedSlice>,
}
struct OracleContext {
    authority: Authority<Application>,
    identity: Identity,
    witnesses: Witnesses,
    bindings: BTreeMap<String, Binding>,
    pending: tokio::sync::Mutex<BTreeMap<String, Pending>>,
    spool: PathBuf,
    _spool_lock: std::fs::File,
    evidence: crate::activity_evidence::EvidenceStore,
}
impl OracleContext {
    fn persist(&self, pending: &BTreeMap<String, Pending>) -> Result<()> {
        use std::io::Write;
        let bytes = serde_json::to_vec(pending)?;
        ensure!(
            bytes.len() <= MAX_SPOOL_BYTES,
            "activity evidence spool full"
        );
        let next = self.spool.with_extension("next");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&next)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(next, &self.spool)?;
        if let Some(parent) = self.spool.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    }
    async fn submit(
        &self,
        source: &str,
        headers: &HeaderMap,
        report: ProbeReport,
    ) -> Result<StatusCode, StatusCode> {
        let binding = self.bindings.get(source).ok_or(StatusCode::NOT_FOUND)?;
        crate::bearer::require_bearer(headers, &binding.token)?;
        let now = now_ms().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if !report.window_start_ms.is_multiple_of(ACTIVITY_SLICE_MS)
            || report.window_start_ms.checked_add(ACTIVITY_SLICE_MS) != Some(report.window_end_ms)
            || report.window_end_ms > now
        {
            return Err(StatusCode::UNPROCESSABLE_ENTITY);
        }
        if now.saturating_sub(report.window_end_ms) > MAX_REPORT_LAG_MS {
            return Err(StatusCode::GONE);
        }
        if report.players.len() > MAX_REPORT_PLAYERS {
            return Err(StatusCode::UNPROCESSABLE_ENTITY);
        }
        let mut pending = self.pending.lock().await;
        let state = self
            .authority
            .state(self.identity.peer_id())
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let config = state
            .domain
            .organization
            .oracle_sources
            .get(source)
            .ok_or(StatusCode::FORBIDDEN)?;
        if !config.config.enabled
            || config.config.oracle_device != self.identity.peer_id().to_string()
            || config.config.service != binding.service
        {
            return Err(StatusCode::FORBIDDEN);
        }
        if let Some(current) = pending.get_mut(source)
            && !current.slices.is_empty()
            && current.end <= config.last_window_end_ms
        {
            self.flush(source, current)
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            self.persist(&pending)
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        }
        if report.window_end_ms <= config.last_window_end_ms {
            // An HTTP retry is acknowledged only for the exact report already pinned in evidence.
            for receipt in state
                .domain
                .organization
                .activity_receipts
                .values()
                .filter(|r| {
                    r.attestation.source == source
                        && r.attestation.window_start_ms <= report.window_start_ms
                        && r.attestation.window_end_ms >= report.window_end_ms
                })
            {
                let evidence = self
                    .evidence
                    .read(source, &receipt.evidence)
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                let proof: serde_json::Value = serde_json::from_slice(&evidence)
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                let slices: Vec<VerifiedSlice> = serde_json::from_value(proof["slices"].clone())
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                if slices.iter().any(|s| s.report == report) {
                    return Ok(StatusCode::NO_CONTENT);
                }
            }
            return Err(StatusCode::CONFLICT);
        }
        if report.window_start_ms < config.last_window_end_ms {
            return Err(StatusCode::CONFLICT);
        }
        let trust = self
            .authority
            .identity_view()
            .state()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let core = state
            .identity_core(&trust)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let mut members = BTreeMap::new();
        let mut witnesses = BTreeMap::new();
        for uuid in report.players.keys() {
            let Ok(profile) = uuid::Uuid::parse_str(uuid) else {
                continue;
            };
            if uuid != &profile.simple().to_string() {
                continue;
            }
            let uuid = profile.simple().to_string();
            let witness = self
                .witnesses
                .covering(
                    &binding.service,
                    &uuid,
                    report.window_start_ms,
                    report.window_end_ms,
                    now,
                )
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            if let Some(witness) = witness
                && let Some(member) = core.members.get(&witness.member)
                && witness.clubs.contains(&member.club)
                && trust.member_for_device(&witness.device) == Some(witness.member.as_str())
                && trust.is_member(&witness.member, &member.club)
                && trust.profile(&witness.member) == Some(uuid.as_str())
            {
                let mut witness = witness;
                witness.clubs = [member.club.clone()].into();
                members.insert(uuid.clone(), witness.member.clone());
                witnesses.insert(uuid, witness);
            }
        }
        let current = pending.entry(source.into()).or_default();
        if let Some(previous) = current
            .slices
            .iter()
            .find(|s| s.report.window_start_ms == report.window_start_ms)
        {
            if previous.report != report {
                return Err(StatusCode::CONFLICT);
            }
            if current.end.saturating_sub(current.start) >= BATCH_WINDOW_MS {
                self.flush(source, current)
                    .await
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            }
            self.persist(&pending)
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            return Ok(StatusCode::NO_CONTENT);
        }
        if !current.slices.is_empty() && report.window_start_ms < current.end {
            return Err(StatusCode::CONFLICT);
        }
        if !current.slices.is_empty() && report.window_start_ms != current.end {
            self.flush(source, current)
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        }
        if current.slices.is_empty() {
            current.start = report.window_start_ms;
        }
        current.end = report.window_end_ms;
        current.slices.push(VerifiedSlice {
            report,
            members,
            witnesses,
        });
        if current.end.saturating_sub(current.start) >= BATCH_WINDOW_MS {
            self.flush(source, current)
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        }
        self.persist(&pending)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        Ok(StatusCode::NO_CONTENT)
    }
    async fn flush(&self, source: &str, pending: &mut Pending) -> Result<()> {
        if pending.slices.is_empty() {
            return Ok(());
        }
        let state = self.authority.state(self.identity.peer_id()).await?;
        for receipt in state
            .domain
            .organization
            .activity_receipts
            .values()
            .filter(|r| {
                r.attestation.source == source
                    && r.attestation.window_start_ms == pending.start
                    && r.attestation.window_end_ms == pending.end
            })
        {
            let bytes = self.evidence.read(source, &receipt.evidence)?;
            let proof: serde_json::Value = serde_json::from_slice(&bytes)?;
            let slices: Vec<VerifiedSlice> = serde_json::from_value(proof["slices"].clone())?;
            if slices == pending.slices {
                *pending = Pending::default();
                return Ok(());
            }
        }
        let trust = self.authority.identity_view().state()?;
        let core = state.identity_core(&trust)?;
        let mut players: BTreeMap<String, ActivityTotals> = BTreeMap::new();
        for slice in &pending.slices {
            let mut seen = BTreeSet::new();
            for (uuid, member) in &slice.members {
                let Some(witness) = slice.witnesses.get(uuid) else {
                    continue;
                };
                if !core.members.contains_key(member)
                    || trust.member_for_device(&witness.device) != Some(member.as_str())
                    || trust.profile(member) != Some(uuid.as_str())
                {
                    continue;
                }
                if !seen.insert(member) {
                    continue;
                }
                let metrics = slice
                    .report
                    .players
                    .get(uuid)
                    .context("canonical profile missing from report")?;
                let total = players.entry(member.clone()).or_default();
                if metrics.active() {
                    total.active_slices = total
                        .active_slices
                        .checked_add(1)
                        .context("activity count overflow")?;
                } else {
                    total.afk_slices = total
                        .afk_slices
                        .checked_add(1)
                        .context("activity count overflow")?;
                }
            }
        }
        let attestation = Attestation {
            source: source.into(),
            window_start_ms: pending.start,
            window_end_ms: pending.end,
            players,
        };
        let evidence = serde_json::to_vec(
            &serde_json::json!({"attestation":attestation,"slices":pending.slices}),
        )?;
        let header = self.evidence.put(&attestation, &evidence)?;
        self.authority
            .apply(
                &self.identity,
                client::application::Action::Domain(flows::FlowAction::Inner(
                    events::EventAction::Organization(
                        events::workflows::OrganizationAction::ActivityAttest {
                            source: source.into(),
                            window_start_ms: pending.start,
                            window_end_ms: pending.end,
                            players: attestation.players,
                            evidence: header,
                        },
                    ),
                )),
            )
            .await?;
        *pending = Pending::default();
        Ok(())
    }
}
async fn report(
    State(context): State<Arc<OracleContext>>,
    Path(source): Path<String>,
    headers: HeaderMap,
    Json(report): Json<ProbeReport>,
) -> Result<StatusCode, StatusCode> {
    context.submit(&source, &headers, report).await
}
async fn flush(
    State(context): State<Arc<OracleContext>>,
    Path(source): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, StatusCode> {
    let binding = context.bindings.get(&source).ok_or(StatusCode::NOT_FOUND)?;
    crate::bearer::require_bearer(&headers, &binding.token)?;
    let mut pending = context.pending.lock().await;
    if let Some(current) = pending.get_mut(&source) {
        context
            .flush(&source, current)
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    }
    context
        .persist(&pending)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn evidence(
    State(context): State<Arc<OracleContext>>,
    Path((source, cid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let binding = context.bindings.get(&source).ok_or(StatusCode::NOT_FOUND)?;
    crate::bearer::require_bearer(&headers, &binding.token)?;
    let cid = cid.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    let bytes = context
        .evidence
        .read(&source, &cid)
        .map_err(|_| StatusCode::NOT_FOUND)?;
    serde_json::from_slice(&bytes)
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
pub struct Oracle {
    stop: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
    completion: tokio::sync::watch::Receiver<()>,
    address: SocketAddr,
}
impl Oracle {
    pub async fn start(
        config: Config,
        authority: Authority<Application>,
        witnesses: Witnesses,
    ) -> Result<Self> {
        ensure!(
            config.bind.ip().is_loopback(),
            "activity adapter must bind loopback"
        );
        ensure!(
            !config.probes.is_empty() && config.probes.len() <= MAX_REPORT_PLAYERS,
            "invalid activity probe count"
        );
        let identity = Identity::load(&config.key)?;
        let mut bindings = BTreeMap::new();
        for probe in config.probes {
            node::protocol::validate_identifier(&probe.source)?;
            let _: node::ServiceId = probe.service.parse()?;
            crate::bootstrap::require_private(&probe.token, "activity probe token")?;
            ensure!(
                std::fs::metadata(&probe.token)?.len() <= 256,
                "activity token too large"
            );
            let token = std::fs::read_to_string(probe.token)?
                .trim()
                .as_bytes()
                .to_vec();
            ensure!(
                (32..=256).contains(&token.len()) && token.iter().all(u8::is_ascii_graphic),
                "invalid activity probe token"
            );
            ensure!(
                bindings
                    .insert(
                        probe.source,
                        Binding {
                            service: probe.service,
                            token
                        }
                    )
                    .is_none(),
                "duplicate activity source"
            );
        }
        let parent = config
            .spool
            .parent()
            .context("activity spool directory missing")?;
        ensure!(parent.is_dir(), "activity spool directory missing");
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(config.spool.with_extension("lock"))?;
        lock.try_lock().context("activity spool already open")?;
        let pending = if config.spool.exists() {
            crate::bootstrap::require_private(&config.spool, "activity evidence spool")?;
            ensure!(
                std::fs::metadata(&config.spool)?.len() <= MAX_SPOOL_BYTES as u64,
                "activity evidence spool too large"
            );
            serde_json::from_slice(&std::fs::read(&config.spool)?)?
        } else {
            BTreeMap::new()
        };
        let context = Arc::new(OracleContext {
            authority,
            identity,
            witnesses,
            bindings,
            pending: tokio::sync::Mutex::new(pending),
            spool: config.spool,
            _spool_lock: lock,
            evidence: crate::activity_evidence::EvidenceStore::new(config.evidence_directory)?,
        });
        let listener = tokio::net::TcpListener::bind(config.bind).await?;
        let address = listener.local_addr()?;
        let router = Router::new()
            .route("/v1/activity/{source}/slice", post(report))
            .route("/v1/activity/{source}/flush", post(flush))
            .route("/v1/activity/{source}/evidence/{cid}", get(evidence))
            .layer(DefaultBodyLimit::max(MAX_REPORT_BYTES))
            .with_state(context.clone());
        let (stop, stopping) = oneshot::channel();
        let (completed, completion) = tokio::sync::watch::channel(());
        let task = tokio::spawn(async move {
            let _completed = completed;
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = stopping.await;
                })
                .await?;
            let mut pending = context.pending.lock().await;
            let mut failure = None;
            for (source, pending) in pending.iter_mut() {
                if let Err(error) = context.flush(source, pending).await {
                    failure = Some(error);
                }
            }
            context.persist(&pending)?;
            if let Some(error) = failure {
                return Err(error);
            }
            Ok(())
        });
        Ok(Self {
            stop: Some(stop),
            task: Some(task),
            completion,
            address,
        })
    }
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    pub async fn closed(&self) {
        let mut completion = self.completion.clone();
        let _ = completion.changed().await;
    }
    pub async fn stop(mut self) -> Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.await??;
        }
        Ok(())
    }
}
impl Drop for Oracle {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

#[cfg(test)]
#[path = "activity_tests.rs"]
mod tests;
