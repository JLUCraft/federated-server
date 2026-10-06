//! Host orchestration of committed office plans; external effects are reconciled on restart.
use crate::runtime::Office;
use anyhow::{Context, Result, ensure};
use authority::authority::Authority;
use events::{
    EventAction as E, Phase,
    workflows::{GameResource, Kind, OfficeAction as O, ReportStatus},
};
use flows::FlowAction as F;
use identity::Identity;
use node::protocol::{OpsInstanceState, OpsOp, OpsRequest};
use serde::Deserialize;
use std::{path::PathBuf, time::Duration};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub key: PathBuf,
    pub identity: PathBuf,
}
async fn apply(
    a: &Authority<Office>,
    key: &Identity,
    action: F<events::EventsDomain>,
) -> Result<()> {
    ensure!(a.effect_epoch().is_some(), "office leader unavailable");
    a.apply(key, state::governance::Action::Domain(action))
        .await?;
    Ok(())
}
async fn action(a: &Authority<Office>, key: &Identity, action: E) -> Result<()> {
    apply(a, key, F::Inner(action)).await
}
pub async fn serve(a: Authority<Office>, config: Config) -> Result<()> {
    let key = Identity::load(&config.key)?;
    let mut trust: client::trust::Config =
        serde_json::from_slice(&std::fs::read(&config.identity)?)?;
    if trust.log.is_relative() {
        trust.log = config
            .identity
            .parent()
            .context("identity config directory missing")?
            .join(&trust.log);
    }
    let mut watch = a.watch().await;
    loop {
        watch.borrow_and_update();
        if a.effect_epoch().is_some()
            && let Err(error) = reconcile(&a, &key, &trust).await
        {
            tracing::warn!(%error,"office workflow reconciliation paused");
        }
        tokio::select! {result=watch.changed()=>{result.context("office closed")?;},_=tokio::time::sleep(Duration::from_secs(5))=>{}}
    }
}
async fn generated_flow(
    a: &Authority<Office>,
    key: &Identity,
    config: &events::workflows::Automation,
    action: O,
) -> Result<()> {
    let snapshot = a.state(key.peer_id()).await?;
    let id = format!(
        "office-{}",
        node::protocol::digest(&serde_json::to_vec(&action)?)
    );
    if let Some(flow) = snapshot.domain.flows.get(&id) {
        if flow.status == flows::Status::Approved {
            apply(a, key, F::Execute { instance: id }).await?;
        }
        return Ok(());
    }
    let bytes = events::workflows::evidence(&snapshot.domain.inner, &action)?;
    let (input, blocks) = snapshot.domain.inner.files.version(None, &bytes)?;
    for block in blocks {
        self::action(a, key, E::PutBlock { block }).await?;
    }
    apply(
        a,
        key,
        F::StartRequirements {
            id,
            stage: automatic_stage(
                config,
                serde_json::to_value(&action)?["type"]
                    .as_str()
                    .context("missing workflow action")?,
            ),
            payload: E::Office(action),
            input,
        },
    )
    .await
}
async fn reconcile(
    a: &Authority<Office>,
    key: &Identity,
    trust: &client::trust::Config,
) -> Result<()> {
    let snapshot = a.state(key.peer_id()).await?;
    let state = &snapshot.domain.inner;
    let Some(config) = &state.office.automation else {
        return Ok(());
    };
    let core = snapshot.identity_core(a.identity_view().state()?.as_ref())?;
    ensure!(
        core.members
            .get(&config.worker)
            .is_some_and(|m| m.owns(&key.peer_id().to_string())),
        "workflow worker identity mismatch"
    );
    let now = authority::journal::now_ms()?;
    for (id, p) in &state.office.plans {
        if p.worker != config.worker {
            continue;
        }
        let event = &state.events[id];
        let result = async {
        if event.phase == Phase::Draft && p.final_epoch == Some(event.epoch) {
            if p.polished.is_none() {
                generated_flow(
                    a,
                    key,
                    config,
                    O::Polish {
                        event: id.clone(),
                        epoch: event.epoch,
                    },
                )
                .await?;
            } else {
                action(a, key, E::Submit { id: id.clone() }).await?;
            }
        } else if event.phase == Phase::Review {
            let flow_id = format!(
                "review-{}-{}",
                node::protocol::digest(id.as_bytes()),
                event.epoch
            );
            match snapshot.domain.flows.get(&flow_id) {
                None => {
                    apply(
                        a,
                        key,
                        F::StartRequirements {
                            id: flow_id,
                            stage:automatic_stage(config,"events.approve"),
                            payload: E::Approve {
                                id: id.clone(),
                                epoch: event.epoch,
                                co_organizers: p
                                    .schools
                                    .keys()
                                    .filter(|c| **c != event.organizer)
                                    .cloned()
                                    .collect(),
                            },
                            input: p.review_input.clone().context("review evidence missing")?,
                        },
                    )
                    .await?
                }
                Some(flow) if flow.status == flows::Status::Approved => {
                    apply(a, key, F::Execute { instance: flow_id }).await?
                }
                _ => {}
            }
        } else if event.phase == Phase::Approved {
            action(a, key, E::Publish { id: id.clone() }).await?;
        } else if matches!(event.phase, Phase::Open | Phase::Cancelled) {
            if p.kind == Kind::Online {
                for game in &p.selected {
                    let resource = state
                        .office
                        .resources
                        .get(game)
                        .context("game resource missing")?;
                    let existing = p.games.get(game);
                    if existing.is_some_and(|g| g.stopped) {
                        continue;
                    }
                    let result = game_step(
                        a,
                        key,
                        trust,
                        id,
                        event,
                        p,
                        game,
                        resource,
                        state.checkins.get(id).cloned().unwrap_or_default(),
                    )
                    .await;
                    if let Err(error) = result {
                        tracing::warn!(%id,%game,%error,"game step failed");
                        let message="Game operation failed; verify resource configuration and service availability".to_string();
                        if existing.and_then(|r| r.error.as_ref()) != Some(&message) {
                            action(
                                a,
                                key,
                                E::Office(O::GameReceipt {
                                    event: id.clone(),
                                    game: game.clone(),
                                    started: existing.is_some_and(|r| r.started),
                                    stopped: false,
                                    results: existing.and_then(|r| r.results.clone()),
                                    evidence: existing.and_then(|r| r.evidence.clone()),
                                    error: Some(message),
                                }),
                            )
                            .await?;
                        }
                    }
                }
            }
            if event.phase == Phase::Open
                && now >= p.ends_ms
                && (p.kind == Kind::Meeting
                    || p.selected.iter().all(|g| {
                        p.games
                            .get(g)
                            .is_some_and(|r| r.results.is_some() && r.stopped)
                    }))
            {
                action(a, key, E::Finish { id: id.clone() }).await?;
            }
        } else if event.phase == Phase::Done {
            if !p.settled {
                action(a, key, E::Office(O::Settle { event: id.clone() })).await?;
            } else if p.summary.is_none() {
                generated_flow(
                    a,
                    key,
                    config,
                    O::Summary {
                        event: id.clone(),
                        epoch: event.epoch,
                    },
                )
                .await?;
            }
        }
        Ok::<_,anyhow::Error>(())
        }.await;
        if let Err(error) = result {
            tracing::warn!(%id,%error,"office plan awaiting recovery");
        }
    }
    for (id, r) in &state.office.reports {
        if r.worker == config.worker && r.status == ReportStatus::Generating {
            let result = generated_flow(
                a,
                key,
                config,
                O::ReportGenerated {
                    id: id.clone(),
                    version: r.version,
                },
            )
            .await;
            if let Err(error) = result {
                tracing::warn!(%id,%error,"office report awaiting recovery");
            }
        }
    }
    Ok(())
}
async fn league(
    key: &Identity,
    trust: &client::trust::Config,
    r: &GameResource,
    action: Option<league::LeagueAction>,
) -> Result<state::State<league::LeagueDomain>> {
    let result = client::generic::execute(
        key.clone(),
        client::generic::Input::<league::LeagueDomain> {
            identity: trust.clone(),
            address: r.address.clone(),
            peer: r.peer.clone(),
            genesis_hash: r.genesis.clone(),
            revision: None,
            action: action.map(state::governance::Action::Domain),
        },
    )
    .await?;
    ensure!(result.error.is_none(), "league operation rejected");
    result.state.context("league snapshot missing")
}
async fn ops(key: &Identity, r: &GameResource, op: OpsOp) -> Result<node::protocol::OpsResponse> {
    let node = node::Node::start(key.clone(), node::NodeConfig::default()).await?;
    let result = async {
        node.dial(r.address.parse()?).await?;
        client::ops::execute(
            &node,
            r.peer.parse()?,
            r.operations_service.parse()?,
            &OpsRequest { op },
        )
        .await
        .map_err(anyhow::Error::from)
    }
    .await;
    node.shutdown().await?;
    let response = result?;
    ensure!(response.ok, "game server operation rejected");
    Ok(response)
}
#[allow(clippy::too_many_arguments)]
async fn game_step(
    a: &Authority<Office>,
    key: &Identity,
    trust: &client::trust::Config,
    id: &str,
    event: &events::Event,
    p: &events::workflows::Plan,
    game: &str,
    r: &GameResource,
    checked: std::collections::BTreeSet<String>,
) -> Result<()> {
    let epoch = a.effect_epoch().context("office leader unavailable")?;
    let now = authority::journal::now_ms()?;
    let league_id = events::workflows::league_id(id, game);
    if event.phase == Phase::Cancelled {
        if !p.games.get(game).is_some_and(|g| g.reserved || g.started) {
            return Ok(());
        }
        stop_league_if_running(a, key, id, event, r, epoch, &league_id).await?;
        return action(
            a,
            key,
            E::Office(O::GameReceipt {
                event: id.into(),
                game: game.into(),
                started: p.games.get(game).is_some_and(|g| g.started),
                stopped: true,
                results: p.games.get(game).and_then(|g| g.results.clone()),
                evidence: p.games.get(game).and_then(|g| g.evidence.clone()),
                error: None,
            }),
        )
        .await;
    }
    let mut snapshot = league(key, trust, r, None).await?;
    if !snapshot.domain.leagues.contains_key(&league_id) {
        ensure_current(a, key, id, event, epoch).await?;
        snapshot = league(
            key,
            trust,
            r,
            Some(league::LeagueAction::CreateLeague {
                league: league_id.clone(),
                rules: league::governance::Rules {
                    seats: r.seats,
                    cross_club: r.cross_school,
                    ..Default::default()
                },
                host: r.host.clone(),
                scorer: r.scorer.clone(),
            }),
        )
        .await?;
    }
    if !snapshot.domain.seasons.contains_key(id) {
        ensure_current(a, key, id, event, epoch).await?;
        snapshot = league(
            key,
            trust,
            r,
            Some(league::LeagueAction::CreateSeason {
                id: id.into(),
                title: event.title.clone(),
            }),
        )
        .await?;
    }
    if snapshot.domain.leagues[&league_id].schedule.is_none() {
        ensure_current(a, key, id, event, epoch).await?;
        snapshot = league(
            key,
            trust,
            r,
            Some(league::LeagueAction::ScheduleLeague {
                season: id.into(),
                league: league_id.clone(),
                schedule: league::season::Schedule {
                    opens_ms: event.window.opens_ms,
                    closes_ms: event.window.closes_ms,
                    starts_ms: event.window.starts_ms,
                },
            }),
        )
        .await?;
    }
    let mut started = p.games.get(game).is_some_and(|g| g.started);
    if now >= p.checkin_opens_ms && !started {
        action(
            a,
            key,
            E::Office(O::GameClaim {
                event: id.into(),
                game: game.into(),
            }),
        )
        .await?;
        ensure_current(a, key, id, event, epoch).await?;
        let status = ops(
            key,
            r,
            OpsOp::StartLeague {
                instance: r.instance.clone(),
                league: league_id.clone(),
            },
        )
        .await?;
        ensure!(
            status
                .instances
                .iter()
                .any(|i| i.state == OpsInstanceState::Running),
            "game server not yet running"
        );
        started = true;
    }
    if now >= event.window.starts_ms
        && snapshot.domain.leagues[&league_id].phase == league::governance::Phase::Registration
    {
        if snapshot.domain.leagues[&league_id].admitted.is_none() {
            ensure_current(a, key, id, event, epoch).await?;
            league(
                key,
                trust,
                r,
                Some(league::LeagueAction::SetAttendance {
                    league: league_id.clone(),
                    members: checked,
                    automatic: r.automatic_teams,
                }),
            )
            .await?;
        }
        let digest = node::protocol::digest(league_id.as_bytes());
        let mut seed = [0; 32];
        seed.copy_from_slice(&digest.as_bytes()[..32]);
        ensure_current(a, key, id, event, epoch).await?;
        snapshot = league(
            key,
            trust,
            r,
            Some(league::LeagueAction::Start {
                league: league_id.clone(),
                seed,
            }),
        )
        .await?;
    }
    if now >= p.ends_ms
        && snapshot.domain.leagues[&league_id].phase == league::governance::Phase::Playing
    {
        ensure_current(a, key, id, event, epoch).await?;
        snapshot = league(
            key,
            trust,
            r,
            Some(league::LeagueAction::Finish {
                league: league_id.clone(),
            }),
        )
        .await?;
    }
    let league_state = &snapshot.domain.leagues[&league_id];
    if league_state.phase == league::governance::Phase::Finished {
        let bytes = serde_json::to_vec(
            &serde_json::json!({"genesis":r.genesis,"revision":snapshot.revision,"league":league_state}),
        )?;
        let state = a.state(key.peer_id()).await?;
        let (evidence, blocks) = state.domain.inner.files.version(None, &bytes)?;
        for block in blocks {
            action(a, key, E::PutBlock { block }).await?;
        }
        stop_league_if_running(a, key, id, event, r, epoch, &league_id).await?;
        action(
            a,
            key,
            E::Office(O::GameReceipt {
                event: id.into(),
                game: game.into(),
                started: true,
                stopped: true,
                results: Some(league_state.player_scores.clone()),
                evidence: Some(evidence),
                error: None,
            }),
        )
        .await?;
    } else if p
        .games
        .get(game)
        .is_none_or(|g| g.started != started || g.error.is_some())
    {
        action(
            a,
            key,
            E::Office(O::GameReceipt {
                event: id.into(),
                game: game.into(),
                started,
                stopped: false,
                results: None,
                evidence: None,
                error: None,
            }),
        )
        .await?;
    }
    Ok(())
}

/// Stop the league on the game server if that instance is currently running one.
async fn stop_league_if_running(
    a: &Authority<Office>,
    key: &Identity,
    id: &str,
    event: &events::Event,
    r: &GameResource,
    epoch: u64,
    league: &str,
) -> Result<()> {
    let status = ops(
        key,
        r,
        OpsOp::Status {
            instance: r.instance.clone(),
        },
    )
    .await?;
    if status
        .instances
        .iter()
        .any(|i| i.state == OpsInstanceState::Running)
    {
        ensure_current(a, key, id, event, epoch).await?;
        ops(
            key,
            r,
            OpsOp::StopLeague {
                instance: r.instance.clone(),
                league: league.into(),
            },
        )
        .await?;
    }
    Ok(())
}
async fn ensure_current(
    a: &Authority<Office>,
    key: &Identity,
    id: &str,
    event: &events::Event,
    epoch: u64,
) -> Result<()> {
    ensure!(a.effect_epoch() == Some(epoch), "leader changed");
    let state = a.state(key.peer_id()).await?;
    ensure!(
        state
            .domain
            .inner
            .events
            .get(id)
            .is_some_and(|e| e.epoch == event.epoch && e.phase == event.phase),
        "event changed"
    );
    Ok(())
}

fn automatic_stage(config: &events::workflows::Automation, purpose: &str) -> flows::Stage {
    flows::Stage {
        name: purpose.into(),
        approver: flows::Approver::Ai {
            mode: if purpose == "events.approve" {
                flows::AiMode::Review
            } else {
                flows::AiMode::Generate
            },
            worker: config.worker.clone(),
            model: config.model.clone(),
            purpose: purpose.into(),
            privacy: node::protocol::Privacy::Sensitive,
            max_tokens: config.max_tokens,
        },
        timeout_ms: Some(config.timeout_ms),
        on_timeout: flows::TimeoutPolicy::Reject,
    }
}
