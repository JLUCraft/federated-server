//! Host orchestration of committed organization plans; external effects are reconciled on restart.
use crate::runtime::Application;
use anyhow::{Context, Result, ensure};
use authority::authority::Authority;
use events::{
    EventAction as E, Phase,
    workflows::{GameResource, Kind, OrganizationAction as O, ReportStatus},
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
}
async fn apply(
    a: &Authority<Application>,
    key: &Identity,
    action: F<events::EventsDomain>,
) -> Result<()> {
    ensure!(a.effect_epoch().is_some(), "application leader unavailable");
    a.apply(key, state::governance::Action::Domain(action))
        .await?;
    Ok(())
}
async fn action(a: &Authority<Application>, key: &Identity, action: E) -> Result<()> {
    apply(a, key, F::Inner(action)).await
}
pub async fn serve(a: Authority<Application>, config: Config) -> Result<()> {
    let key = Identity::load(&config.key)?;
    let mut watch = a.watch().await;
    loop {
        watch.borrow_and_update();
        if a.effect_epoch().is_some()
            && let Err(error) = reconcile(&a, &key).await
        {
            tracing::warn!(%error,"workflow reconciliation paused");
        }
        tokio::select! {result=watch.changed()=>{result.context("application closed")?;},_=tokio::time::sleep(Duration::from_secs(5))=>{}}
    }
}
async fn generated_flow(
    a: &Authority<Application>,
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
            payload: E::Organization(action),
            input,
        },
    )
    .await
}
async fn reconcile(a: &Authority<Application>, key: &Identity) -> Result<()> {
    let snapshot = a.state(key.peer_id()).await?;
    let state = &snapshot.domain.inner;
    let Some(config) = &state.organization.automation else {
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
    for (id, p) in &state.organization.plans {
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
            let flow_id = review_instance(&snapshot.domain, id, event.epoch);
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
                        .organization
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
                                E::Organization(O::GameReceipt {
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
                action(a, key, E::Organization(O::Settle { event: id.clone() })).await?;
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
    for (id, r) in &state.organization.reports {
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
async fn competition(
    a: &Authority<Application>,
    key: &Identity,
    command: Option<league::LeagueAction>,
) -> Result<client::application::Snapshot> {
    if let Some(command) = command {
        a.apply(key, client::application::competition(command))
            .await?;
    }
    Ok(a.state(key.peer_id()).await?)
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
    a: &Authority<Application>,
    key: &Identity,
    id: &str,
    event: &events::Event,
    p: &events::workflows::Plan,
    game: &str,
    r: &GameResource,
    checked: std::collections::BTreeSet<String>,
) -> Result<()> {
    let epoch = a.effect_epoch().context("application leader unavailable")?;
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
            E::Organization(O::GameReceipt {
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
    let mut snapshot = competition(a, key, None).await?;
    if !snapshot.domain.leagues.contains_key(&league_id) {
        ensure_current(a, key, id, event, epoch).await?;
        snapshot = competition(
            a,
            key,
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
        snapshot = competition(
            a,
            key,
            Some(league::LeagueAction::CreateSeason {
                id: id.into(),
                title: event.title.clone(),
            }),
        )
        .await?;
    }
    if snapshot.domain.leagues[&league_id].schedule.is_none() {
        ensure_current(a, key, id, event, epoch).await?;
        snapshot = competition(
            a,
            key,
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
            E::Organization(O::GameClaim {
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
            competition(
                a,
                key,
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
        snapshot = competition(
            a,
            key,
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
        snapshot = competition(
            a,
            key,
            Some(league::LeagueAction::Finish {
                league: league_id.clone(),
            }),
        )
        .await?;
    }
    let league_state = &snapshot.domain.leagues[&league_id];
    if league_state.phase == league::governance::Phase::Finished {
        let bytes = serde_json::to_vec(
            &serde_json::json!({"genesis":a.genesis_hash().await,"revision":snapshot.revision,"league":league_state}),
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
            E::Organization(O::GameReceipt {
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
            E::Organization(O::GameReceipt {
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
    a: &Authority<Application>,
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
    a: &Authority<Application>,
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

/// Reuse a submitted review, including a rejection that needs a new draft revision.
fn review_instance(
    state: &flows::FlowsState<events::EventsDomain>,
    id: &str,
    epoch: u64,
) -> String {
    state.flows.iter().find_map(|(flow_id, flow)| {
        matches!(&flow.payload, E::Approve { id: target, epoch: version, .. } if target == id && *version == epoch)
            .then(|| flow_id.clone())
    }).unwrap_or_else(|| format!("review-{}-{epoch}", node::protocol::digest(id.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use authority::journal::Journal;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[tokio::test]
    async fn competition_effects_advance_the_same_organization_authority() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let worker = Identity::generate();
        let identities =
            crate::test_identity::Identities::new(&[(&worker, "worker", "club")], "worker");
        let genesis = identities.genesis::<Application>();
        let view = identities.log.view(Duration::from_secs(60))?;
        let journal = Journal::open(directory.path().join("application"), genesis)?;
        let pin = journal.genesis_hash().to_owned();
        let authority = Authority::Local {
            journal: Arc::new(Mutex::new(journal)),
            log: Arc::new(Mutex::new(identities.log)),
            view,
        };
        authority
            .apply(
                &worker,
                state::governance::Action::AnchorDigest {
                    id: "before-game".into(),
                    digest: "a".repeat(64),
                },
            )
            .await?;
        let snapshot = competition(
            &authority,
            &worker,
            Some(league::LeagueAction::CreateLeague {
                league: "game".into(),
                rules: Default::default(),
                host: worker.peer_id().to_string(),
                scorer: worker.peer_id().to_string(),
            }),
        )
        .await?;
        assert_eq!(snapshot.revision, 2);
        assert!(snapshot.digest_anchors.contains_key("before-game"));
        assert!(snapshot.domain.leagues.contains_key("game"));
        assert_eq!(authority.genesis_hash().await, pin);
        assert_eq!(
            competition(&authority, &worker, None).await?.revision,
            snapshot.revision
        );
        Ok(())
    }
}
