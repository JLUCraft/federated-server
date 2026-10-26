use super::*;
use authority::{journal::Journal, trust::TrustLog};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
type A = client::application::Action;
type F = flows::FlowAction<events::EventsDomain>;
type O = events::workflows::OrganizationAction;
const TOKEN: &str = "activity-test-token-abcdefghijklmnopqrstuvwxyz";
const OTHER_TOKEN: &str = "other-test-token-abcdefghijklmnopqrstuvwxyz";
struct Fixture {
    directory: tempfile::TempDir,
    keys: Vec<Identity>,
    authority: Authority<Application>,
    genesis: state::State<Application>,
    service: String,
    profile: String,
}
impl Fixture {
    async fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let keys: Vec<_> = (0..5).map(|_| Identity::generate()).collect();
        let mut identities = crate::test_identity::Identities::new(
            &[
                (&keys[0], "admin", "a"),
                (&keys[1], "oracle", "a"),
                (&keys[2], "worker", "a"),
                (&keys[3], "player", "a"),
                (&keys[4], "ghost", "b"),
            ],
            "admin",
        );
        let profile = uuid::Uuid::from_u128(42).simple().to_string();
        identities.append(
            node::protocol::TrustAction::BindGameProfile {
                member: "player".into(),
                club: "a".into(),
                profile: profile.clone(),
            },
            &[&identities.root("a"), &keys[3]],
        );
        let genesis = identities.genesis::<Application>();
        let mut log = TrustLog::open(
            &directory.path().join("identity"),
            identities.log.genesis(),
            &identities.binding.genesis,
        )?;
        for record in identities.log.history_since(None)?.records {
            log.append(record)?;
        }
        log.mark_current()?;
        let view = log.view(std::time::Duration::from_secs(60))?;
        let journal = Journal::open(directory.path().join("application"), genesis.clone())?;
        let authority = Authority::Local {
            journal: Arc::new(tokio::sync::Mutex::new(journal)),
            log: Arc::new(tokio::sync::Mutex::new(log)),
            view,
        };
        let service = node::ServiceId::new().to_string();
        let fixture = Self {
            directory,
            keys,
            authority,
            genesis,
            service,
            profile,
        };
        fixture
            .apply(
                0,
                F::Inner(events::EventAction::Organization(O::ActivityPolicy {
                    policy: events::points::ActivityPolicy {
                        daily_member_cap: 100,
                    },
                })),
            )
            .await?;
        fixture
            .apply(
                0,
                F::Inner(events::EventAction::Organization(O::OracleSource {
                    id: "survival".into(),
                    source: events::points::OracleSourcePolicy {
                        title: "Verified survival".into(),
                        club: "a".into(),
                        oracle_device: fixture.keys[1].peer_id().to_string(),
                        service: fixture.service.clone(),
                        weight_bps: 10_000,
                        points_per_slice: 10,
                        max_bonus_per_slice: 0,
                        daily_source_cap: 1000,
                        enabled: true,
                    },
                })),
            )
            .await?;
        for (name, key) in [
            ("oracle.key", &fixture.keys[1]),
            ("worker.key", &fixture.keys[2]),
        ] {
            key.save_new(fixture.directory.path().join(name))?;
        }
        for (name, value) in [("probe.token", TOKEN), ("other.token", OTHER_TOKEN)] {
            let path = fixture.directory.path().join(name);
            std::fs::write(&path, value)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            }
        }
        Ok(fixture)
    }
    async fn apply(&self, key: usize, action: F) -> Result<()> {
        self.authority
            .apply(&self.keys[key], A::Domain(action))
            .await?;
        Ok(())
    }
    fn config(&self) -> Config {
        Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            key: self.directory.path().join("oracle.key"),
            spool: self.directory.path().join("pending.json"),
            evidence_directory: self.directory.path().join("evidence"),
            probes: vec![
                Probe {
                    source: "survival".into(),
                    service: self.service.clone(),
                    token: self.directory.path().join("probe.token"),
                },
                Probe {
                    source: "other".into(),
                    service: self.service.clone(),
                    token: self.directory.path().join("other.token"),
                },
            ],
        }
    }
    async fn file(&self, bytes: &[u8]) -> Result<node::protocol::Cid> {
        let state = self.authority.state(self.keys[0].peer_id()).await?;
        let (cid, blocks) = state.domain.inner.files.version(None, bytes)?;
        for block in blocks {
            self.apply(3, F::Inner(events::EventAction::PutBlock { block }))
                .await?;
        }
        Ok(cid)
    }
    async fn balance(&self) -> Result<u64> {
        Ok(self
            .authority
            .state(self.keys[0].peer_id())
            .await?
            .domain
            .inner
            .organization
            .points
            .get("a")
            .and_then(|m| m.get("player"))
            .copied()
            .unwrap_or(0))
    }
    fn witness(&self, witnesses: &Witnesses, start: u64, end: u64) -> Result<WitnessGuard> {
        let guard = witnesses.begin_at(
            &self.service,
            &self.profile,
            "player",
            &self.keys[3].peer_id().to_string(),
            ["a".into()].into(),
            start,
        )?;
        let mut current = start;
        while current < end {
            guard.touch_at(current + ACTIVITY_SLICE_MS - 1);
            current += ACTIVITY_SLICE_MS;
        }
        Ok(guard)
    }
    fn report(&self, start: u64, active: bool) -> ProbeReport {
        let mut value = metrics();
        if !active {
            value.look_samples = 0;
            value.yaw_variance_milli = 0;
        }
        ProbeReport {
            window_start_ms: start,
            window_end_ms: start + ACTIVITY_SLICE_MS,
            players: [
                (self.profile.clone(), value),
                (uuid::Uuid::from_u128(999).simple().to_string(), metrics()),
            ]
            .into(),
        }
    }
}
fn metrics() -> ActivityMetrics {
    ActivityMetrics {
        movement_steps: 20,
        distinct_positions: 8,
        look_samples: 12,
        yaw_variance_milli: 100_000,
        pitch_variance_milli: 0,
        world_interactions: 3,
        progress_events: 0,
    }
}
fn http() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

#[tokio::test]
async fn report_player_limit_and_expiration_do_not_block_later_valid_reports() -> Result<()> {
    let fixture = Fixture::new().await?;
    let oracle = Oracle::start(
        fixture.config(),
        fixture.authority.clone(),
        Witnesses::default(),
    )
    .await?;
    let client = http();
    let end = now_ms()? / ACTIVITY_SLICE_MS * ACTIVITY_SLICE_MS;
    let mut report = fixture.report(end - 2 * ACTIVITY_SLICE_MS, true);
    report.players = (0..=MAX_REPORT_PLAYERS)
        .map(|index| {
            (
                uuid::Uuid::from_u128(index as u128).simple().to_string(),
                metrics(),
            )
        })
        .collect();
    assert_eq!(
        post(&client, &oracle, "survival", TOKEN, &report).await?,
        422
    );
    let mut expired = report.clone();
    expired.window_start_ms -= MAX_REPORT_LAG_MS + ACTIVITY_SLICE_MS;
    expired.window_end_ms -= MAX_REPORT_LAG_MS + ACTIVITY_SLICE_MS;
    assert_eq!(
        post(&client, &oracle, "survival", TOKEN, &expired).await?,
        410
    );
    report.players.pop_last();
    assert_eq!(report.players.len(), MAX_REPORT_PLAYERS);
    assert_eq!(
        post(&client, &oracle, "survival", TOKEN, &report).await?,
        204
    );
    assert_eq!(
        post(
            &client,
            &oracle,
            "survival",
            TOKEN,
            &fixture.report(end - ACTIVITY_SLICE_MS, true)
        )
        .await?,
        204
    );
    oracle.stop().await?;
    assert_eq!(fixture.balance().await?, 0);
    Ok(())
}

#[tokio::test]
async fn evidence_write_failure_remains_retryable_instead_of_a_permanent_conflict() -> Result<()> {
    let fixture = Fixture::new().await?;
    let oracle = Oracle::start(
        fixture.config(),
        fixture.authority.clone(),
        Witnesses::default(),
    )
    .await?;
    let client = http();
    let end = now_ms()? / ACTIVITY_SLICE_MS * ACTIVITY_SLICE_MS;
    let start = end - BATCH_WINDOW_MS;
    for index in 0..5 {
        assert_eq!(
            post(
                &client,
                &oracle,
                "survival",
                TOKEN,
                &fixture.report(start + index * ACTIVITY_SLICE_MS, true)
            )
            .await?,
            204
        );
    }
    let blocked = fixture
        .config()
        .evidence_directory
        .join(node::protocol::digest(b"survival"));
    std::fs::write(&blocked, b"injected evidence storage failure")?;
    let last = fixture.report(end - ACTIVITY_SLICE_MS, true);
    assert_eq!(post(&client, &oracle, "survival", TOKEN, &last).await?, 503);
    std::fs::remove_file(blocked)?;
    assert_eq!(post(&client, &oracle, "survival", TOKEN, &last).await?, 204);
    oracle.stop().await?;
    Ok(())
}

async fn post(
    client: &reqwest::Client,
    oracle: &Oracle,
    source: &str,
    token: &str,
    report: &ProbeReport,
) -> Result<u16> {
    Ok(client
        .post(format!(
            "http://{}/v1/activity/{source}/slice",
            oracle.address()
        ))
        .header("Connection", "close")
        .bearer_auth(token)
        .json(report)
        .send()
        .await?
        .status()
        .as_u16())
}
#[test]
fn idle_fixed_view_and_two_position_loops_fail_the_activity_predicate() {
    let mut value = metrics();
    assert!(value.active());
    value.yaw_variance_milli = 0;
    assert!(!value.active());
    value = metrics();
    value.distinct_positions = 2;
    assert!(!value.active());
    value = metrics();
    value.world_interactions = 0;
    assert!(!value.active());
    value.progress_events = 2;
    assert!(value.active());
}
#[tokio::test]
async fn bearer_scope_actual_gateway_intervals_and_duplicate_reports_control_minting() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let witnesses = Witnesses::default();
    let end = now_ms()? / ACTIVITY_SLICE_MS * ACTIVITY_SLICE_MS;
    let start = end - BATCH_WINDOW_MS;
    let guard = fixture.witness(&witnesses, start, end)?;
    let oracle = Oracle::start(fixture.config(), fixture.authority.clone(), witnesses).await?;
    let client = http();
    let first = fixture.report(start, true);
    assert_eq!(
        post(&client, &oracle, "survival", "wrong-token", &first).await?,
        401
    );
    assert_eq!(post(&client, &oracle, "other", TOKEN, &first).await?, 401);
    let future = fixture.report(end + ACTIVITY_SLICE_MS, true);
    assert_eq!(
        post(&client, &oracle, "survival", TOKEN, &future).await?,
        422
    );
    for index in 0..6 {
        assert_eq!(
            post(
                &client,
                &oracle,
                "survival",
                TOKEN,
                &fixture.report(start + index * ACTIVITY_SLICE_MS, true)
            )
            .await?,
            204
        );
    }
    assert_eq!(fixture.balance().await?, 60);
    assert_eq!(
        post(&client, &oracle, "survival", TOKEN, &first).await?,
        204
    );
    let mut changed = first;
    changed
        .players
        .get_mut(&fixture.profile)
        .unwrap()
        .world_interactions += 1;
    assert_eq!(
        post(&client, &oracle, "survival", TOKEN, &changed).await?,
        409
    );
    assert_eq!(fixture.balance().await?, 60);
    let state = fixture.authority.state(fixture.keys[0].peer_id()).await?;
    assert!(
        !state
            .domain
            .inner
            .organization
            .points
            .get("b")
            .is_some_and(|m| m.contains_key("ghost"))
    );
    assert_eq!(
        state.domain.inner.organization.activity_members["player"].active_slices,
        6
    );
    assert!(state.domain.inner.files.is_empty());
    let receipt = state
        .domain
        .inner
        .organization
        .activity_receipts
        .values()
        .next()
        .context("missing receipt")?;
    let evidence: serde_json::Value = client
        .get(format!(
            "http://{}/v1/activity/survival/evidence/{}",
            oracle.address(),
            receipt.evidence
        ))
        .bearer_auth(TOKEN)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(
        evidence["slices"]
            .as_array()
            .context("missing slices")?
            .len(),
        6
    );
    let attestation: Attestation = serde_json::from_value(evidence["attestation"].clone())?;
    assert_eq!(attestation, receipt.attestation);
    drop(guard);
    oracle.stop().await?;
    Ok(())
}
#[tokio::test]
async fn acknowledged_pending_evidence_survives_an_adapter_crash_without_recreating_witnesses()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let witnesses = Witnesses::default();
    let end = now_ms()? / ACTIVITY_SLICE_MS * ACTIVITY_SLICE_MS;
    let start = end - 3 * ACTIVITY_SLICE_MS;
    let guard = fixture.witness(&witnesses, start, end)?;
    let mut oracle = Oracle::start(fixture.config(), fixture.authority.clone(), witnesses).await?;
    let client = http();
    for index in 0..3 {
        assert_eq!(
            post(
                &client,
                &oracle,
                "survival",
                TOKEN,
                &fixture.report(start + index * ACTIVITY_SLICE_MS, true)
            )
            .await?,
            204
        );
    }
    assert_eq!(fixture.balance().await?, 0);
    oracle.task.as_ref().unwrap().abort();
    let _ = oracle.task.take().unwrap().await;
    drop(oracle);
    drop(guard);
    let recovered = Oracle::start(
        fixture.config(),
        fixture.authority.clone(),
        Witnesses::default(),
    )
    .await?;
    assert_eq!(
        client
            .post(format!(
                "http://{}/v1/activity/survival/flush",
                recovered.address()
            ))
            .bearer_auth(TOKEN)
            .send()
            .await?
            .status()
            .as_u16(),
        204
    );
    assert_eq!(fixture.balance().await?, 30);
    recovered.stop().await?;
    Ok(())
}
#[tokio::test]
async fn a_plugin_report_without_a_gateway_witness_never_mints_points() -> Result<()> {
    let fixture = Fixture::new().await?;
    let oracle = Oracle::start(
        fixture.config(),
        fixture.authority.clone(),
        Witnesses::default(),
    )
    .await?;
    let end = now_ms()? / ACTIVITY_SLICE_MS * ACTIVITY_SLICE_MS;
    assert_eq!(
        post(
            &http(),
            &oracle,
            "survival",
            TOKEN,
            &fixture.report(end - ACTIVITY_SLICE_MS, true)
        )
        .await?,
        204
    );
    oracle.stop().await?;
    assert_eq!(fixture.balance().await?, 0);
    Ok(())
}
async fn provider() -> Result<(String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}/v1/chat/completions", listener.local_addr()?);
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(stream.read_u8().await.unwrap());
            assert!(header.len() < 16_384);
        }
        let header = String::from_utf8(header).unwrap();
        let length = header
            .lines()
            .find_map(|v| {
                v.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .and_then(|n| n.trim().parse::<usize>().ok())
            })
            .unwrap();
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).await.unwrap();
        let request: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(request["model"], "fixture");
        assert_eq!(request["stream_options"]["include_usage"], true);
        count.fetch_add(1, Ordering::SeqCst);
        let body = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"A verified activity report.\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":16,\"completion_tokens\":8,\"total_tokens\":24}}\n\ndata: [DONE]\n\n";
        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
    });
    Ok((url, calls, task))
}
#[tokio::test]
async fn witnessed_play_mints_then_a_normal_member_funds_local_inference_settles_and_replays()
-> Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let fixture = Fixture::new().await?;
        let (url, calls, provider) = provider().await?;
        fixture
            .apply(
                0,
                F::AiPricing {
                    model: "fixture".into(),
                    pricing: flows::ai::AiPricing {
                        base_points: 1,
                        input_points_per_1k: 2,
                        output_points_per_1k: 3,
                        max_input_tokens: 1000,
                        settlement: flows::ai::Settlement::Burn,
                    },
                },
            )
            .await?;
        fixture
            .apply(
                2,
                F::AiWorker {
                    models: ["fixture".into()].into(),
                    active: true,
                },
            )
            .await?;
        let input = fixture.file(b"Summarize my activity.").await?;
        let request = F::RequestAi {
            id: "paid-member-job".into(),
            input,
            worker: "worker".into(),
            model: "fixture".into(),
            max_tokens: 32,
            max_points: 4,
        };
        assert!(fixture.apply(3, request.clone()).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let witnesses = Witnesses::default();
        let end = now_ms()? / ACTIVITY_SLICE_MS * ACTIVITY_SLICE_MS;
        let start = end - BATCH_WINDOW_MS;
        let guard = fixture.witness(&witnesses, start, end)?;
        let oracle = Oracle::start(fixture.config(), fixture.authority.clone(), witnesses).await?;
        let client = http();
        for index in 0..6 {
            assert_eq!(
                post(
                    &client,
                    &oracle,
                    "survival",
                    TOKEN,
                    &fixture.report(start + index * ACTIVITY_SLICE_MS, true)
                )
                .await?,
                204
            );
        }
        assert_eq!(fixture.balance().await?, 60);
        fixture.apply(3, request).await?;
        assert_eq!(fixture.balance().await?, 56);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let prepared = crate::ai_worker::prepare(crate::ai_worker::Config {
            key: fixture.directory.path().join("worker.key"),
            providers: vec![llm_gateway::Provider {
                id: "local-fixture".into(),
                protocol: llm_gateway::ApiDialect::ChatCompletions,
                url,
                key_env: None,
                key_file: None,
                authentication: None,
                models: ["fixture".into()].into(),
                capabilities: BTreeSet::new(),
                context_tokens: 8192,
            }],
            concurrency: 1,
        })?;
        let worker = tokio::spawn(crate::ai_worker::serve(fixture.authority.clone(), prepared));
        let mut updates = fixture.authority.watch().await;
        let snapshot = loop {
            updates.borrow_and_update();
            let snapshot = fixture.authority.state(fixture.keys[0].peer_id()).await?;
            if snapshot.domain.flows["paid-member-job"].status == flows::Status::Executed {
                break snapshot;
            }
            updates.changed().await?;
        };
        assert_eq!(fixture.balance().await?, 58);
        assert_eq!(snapshot.domain.ai_burned_points, 2);
        let flow = &snapshot.domain.flows["paid-member-job"];
        assert_eq!(flow.payer.member, "player");
        assert_eq!(flow.records[0].escrowed_points, 0);
        assert_eq!(flow.records[0].ai_runs[0].charged_points, 2);
        assert_eq!(flow.records[0].ai_runs[0].refunded_points, 2);
        assert_eq!(
            client::points::output(&snapshot, "paid-member-job", 0)?,
            "A verified activity report."
        );
        let trust = fixture.authority.identity_view().state()?;
        let view = snapshot.identity_presentation(&trust)?;
        let presentation = client::points::present(
            &snapshot,
            &view,
            &fixture.keys[3],
            &fixture.authority.genesis_hash().await,
            now_ms()?,
        )?
        .context("missing point view")?;
        assert_eq!(presentation.overview.available_points, "58");
        assert_eq!(presentation.overview.frozen_points, "0");
        assert_eq!(presentation.overview.earned_today, "60");
        assert!(fixture.keys[3].public_key().verify(
            presentation.statement.payload.as_bytes(),
            &presentation.statement.signature
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        provider.await?;
        worker.abort();
        let _ = worker.await;
        drop(guard);
        oracle.stop().await?;
        let stored = fixture.authority.stored_state().await;
        let path = fixture.directory.path().join("application");
        let Fixture {
            authority,
            genesis,
            directory,
            ..
        } = fixture;
        drop(authority);
        let replay = Journal::<Application>::open(path, genesis)?;
        assert_eq!(replay.state(), &stored);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        drop(replay);
        drop(directory);
        Ok::<(), anyhow::Error>(())
    })
    .await?
}
#[test]
fn packets_from_a_later_slice_cannot_fill_a_silent_earlier_gateway_window() {
    let witnesses = Witnesses::default();
    let guard = witnesses
        .begin_at(
            "service",
            "uuid",
            "member",
            "device",
            ["a".into()].into(),
            0,
        )
        .unwrap();
    guard.touch_at(2 * ACTIVITY_SLICE_MS - 1);
    assert!(
        witnesses
            .covering(
                "service",
                "uuid",
                0,
                ACTIVITY_SLICE_MS,
                2 * ACTIVITY_SLICE_MS
            )
            .unwrap()
            .is_none()
    );
    assert!(
        witnesses
            .covering(
                "service",
                "uuid",
                ACTIVITY_SLICE_MS,
                2 * ACTIVITY_SLICE_MS,
                2 * ACTIVITY_SLICE_MS
            )
            .unwrap()
            .is_some()
    );
}
#[cfg(feature = "server")]
#[tokio::test]
async fn an_assigned_provider_executes_from_a_follower_replica() -> Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        use authority::consensus::{Cluster, Peer};
        let fixture = Fixture::new().await?;
        let (url, calls, provider) = provider().await?;
        let mut genesis = fixture.genesis.clone();
        genesis
            .domain
            .inner
            .organization
            .points
            .insert("a".into(), [("player".into(), 10)].into());
        genesis.domain.ai_pricing.insert(
            "fixture".into(),
            flows::ai::AiPricing {
                base_points: 1,
                input_points_per_1k: 2,
                output_points_per_1k: 3,
                max_input_tokens: 1000,
                settlement: flows::ai::Settlement::Burn,
            },
        );
        let (input, blocks) = genesis
            .domain
            .inner
            .files
            .version(None, b"Follower provider task")?;
        for block in blocks {
            genesis.domain.inner.files.put(block)?;
        }
        let (log, view) = match &fixture.authority {
            Authority::Local { log, view, .. } => (log.clone(), view.clone()),
            _ => unreachable!(),
        };
        let mut nodes = Vec::new();
        for _ in 0..3 {
            nodes.push(Arc::new(
                node::Node::start(Identity::generate(), node::NodeConfig::default()).await?,
            ));
        }
        let peers: BTreeMap<_, _> = nodes
            .iter()
            .enumerate()
            .map(|(index, node)| {
                (
                    (index + 1) as u64,
                    Peer {
                        peer: node.peer_id().to_string(),
                        addresses: node.addresses().iter().map(ToString::to_string).collect(),
                    },
                )
            })
            .collect();
        let mut clusters = Vec::new();
        let mut serving = tokio::task::JoinSet::new();
        for (index, node) in nodes.iter().enumerate() {
            let cluster = Cluster::start(
                (index + 1) as u64,
                node.clone(),
                &fixture.directory.path().join(format!("replica-{index}")),
                genesis.clone(),
                peers.clone(),
                (log.clone(), view.clone()),
            )
            .await?;
            serving.spawn(cluster.clone().serve(client::journal::PROTOCOL));
            clusters.push(cluster);
        }
        tokio::task::yield_now().await;
        clusters[0].initialize().await?;
        let leader_index = loop {
            let mut ready = None;
            for (index, cluster) in clusters.iter().enumerate() {
                if cluster.raft.ensure_linearizable().await.is_ok() {
                    ready = Some(index);
                    break;
                }
            }
            if let Some(index) = ready {
                break index;
            }
            tokio::task::yield_now().await;
        };
        let leader = Authority::Replicated(clusters[leader_index].clone());
        let follower = Authority::Replicated(clusters[(leader_index + 1) % clusters.len()].clone());
        assert!(follower.effect_epoch().is_none());
        let prepared = crate::ai_worker::prepare(crate::ai_worker::Config {
            key: fixture.directory.path().join("worker.key"),
            providers: vec![llm_gateway::Provider {
                id: "follower-fixture".into(),
                protocol: llm_gateway::ApiDialect::ChatCompletions,
                url,
                key_env: None,
                key_file: None,
                authentication: None,
                models: ["fixture".into()].into(),
                capabilities: BTreeSet::new(),
                context_tokens: 8192,
            }],
            concurrency: 1,
        })?;
        let mut updates = leader.watch().await;
        let worker = tokio::spawn(crate::ai_worker::serve(follower.clone(), prepared));
        loop {
            updates.borrow_and_update();
            if leader
                .state(fixture.keys[0].peer_id())
                .await?
                .domain
                .ai_workers
                .contains_key("worker")
            {
                break;
            }
            updates.changed().await?;
        }
        follower
            .apply(
                &fixture.keys[3],
                A::Domain(F::RequestAi {
                    id: "follower-job".into(),
                    input,
                    worker: "worker".into(),
                    model: "fixture".into(),
                    max_tokens: 32,
                    max_points: 4,
                }),
            )
            .await?;
        let result = loop {
            updates.borrow_and_update();
            let state = leader.state(fixture.keys[0].peer_id()).await?;
            if state
                .domain
                .flows
                .get("follower-job")
                .is_some_and(|f| f.status == flows::Status::Executed)
            {
                break state;
            }
            updates.changed().await?;
        };
        assert_eq!(result.domain.inner.organization.points["a"]["player"], 8);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            client::points::output(&result, "follower-job", 0)?,
            "A verified activity report."
        );
        worker.abort();
        let _ = worker.await;
        provider.await?;
        drop(updates);
        drop(leader);
        drop(follower);
        serving.shutdown().await;
        for cluster in &clusters {
            cluster.raft.shutdown().await?;
        }
        drop(clusters);
        for mut node in nodes {
            // Aborted RPC handlers release their cluster references when cancellation is polled.
            let node = loop {
                match Arc::try_unwrap(node) {
                    Ok(node) => break node,
                    Err(retained) => {
                        node = retained;
                        tokio::task::yield_now().await;
                    }
                }
            };
            node.shutdown().await?;
        }
        Ok::<(), anyhow::Error>(())
    })
    .await?
}
