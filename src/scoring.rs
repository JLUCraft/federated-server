//! Game-independent local adapter API: the plugin receives a scoring-only bearer, never an admin key.
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use client::application::Action;
use identity::Identity;
use league::governance::Phase;
use serde::Deserialize;
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};
#[cfg(test)]
use tokio::sync::Mutex;

#[derive(Clone)]
struct Context {
    journal: client::application::Authority,
    identity: Identity,
    token: Arc<Vec<u8>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Score {
    league: String,
    event: String,
    players: BTreeMap<String, i64>,
    teams: BTreeMap<String, i64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Finish {
    league: String,
}
fn authorize(headers: &HeaderMap, context: &Context) -> Result<(), StatusCode> {
    crate::bearer::require_bearer(headers, &context.token)
}
async fn apply(
    context: Context,
    headers: HeaderMap,
    action: Action,
) -> Result<StatusCode, StatusCode> {
    authorize(&headers, &context)?;
    let journal = context
        .journal
        .state(context.identity.peer_id())
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if let Action::Domain(flows::FlowAction::Inner(events::EventAction::Competition(
        league::LeagueAction::Finish { league },
    ))) = &action
    {
        let league = journal
            .domain
            .leagues
            .get(league)
            .ok_or(StatusCode::NOT_FOUND)?;
        if league.scorer != context.identity.peer_id().to_string() {
            return Err(StatusCode::FORBIDDEN);
        }
        if league.phase == Phase::Finished {
            return Ok(StatusCode::NO_CONTENT);
        }
    }
    context
        .journal
        .apply(&context.identity, action)
        .await
        .map_err(|_| StatusCode::CONFLICT)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn session(
    State(context): State<Context>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    authorize(&headers, &context)?;
    let state = context
        .journal
        .state(context.identity.peer_id())
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let league = state.domain.leagues.get(&id).ok_or(StatusCode::NOT_FOUND)?;
    if league.scorer != context.identity.peer_id().to_string() {
        return Err(StatusCode::FORBIDDEN);
    }
    let identity = context
        .journal
        .identity_view()
        .state()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let players = league
        .teams
        .values()
        .filter(|team| team.registered)
        .flat_map(|team| team.members.iter())
        .filter(|member| {
            league
                .admitted
                .as_ref()
                .is_none_or(|admitted| admitted.contains(*member))
        })
        .map(|member| (member.clone(), identity.profile(member).map(str::to_owned)))
        .collect::<BTreeMap<_, _>>();
    Ok(Json(
        serde_json::json!({"protocol_version":node::protocol::GAME_ADAPTER_VERSION,"league":id,"phase":league.phase,"rules":league.rules,"teams":league.teams,"admitted":league.admitted,"profiles":players,"seats":league.seats}),
    ))
}
pub async fn serve(
    address: SocketAddr,
    journal: client::application::Authority,
    identity: Identity,
    token: String,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        address.ip().is_loopback(),
        "scoring adapter must bind loopback"
    );
    anyhow::ensure!(
        token.len() >= 32 && token.len() <= 256 && token.bytes().all(|b| b.is_ascii_graphic()),
        "scoring token must be 32–256 printable bytes"
    );
    let context = Context {
        journal,
        identity,
        token: Arc::new(token.into_bytes()),
    };
    let router = Router::new()
        .route("/v1/session/{id}", get(session))
        .route(
            "/v1/score",
            post(
                |State(c): State<Context>, h: HeaderMap, Json(s): Json<Score>| async move {
                    apply(
                        c,
                        h,
                        client::application::competition(league::LeagueAction::Score {
                            league: s.league,
                            event: s.event,
                            players: s.players,
                            teams: s.teams,
                        }),
                    )
                    .await
                },
            ),
        )
        .route(
            "/v1/finish",
            post(
                |State(c): State<Context>, h: HeaderMap, Json(s): Json<Finish>| async move {
                    apply(
                        c,
                        h,
                        client::application::competition(league::LeagueAction::Finish {
                            league: s.league,
                        }),
                    )
                    .await
                },
            ),
        )
        .layer(DefaultBodyLimit::max(65536))
        .with_state(context);
    axum::serve(tokio::net::TcpListener::bind(address).await?, router).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use authority::journal::{Journal, now_ms};
    #[tokio::test]
    async fn scoring_only_identity_and_bearer_cannot_manage_the_league() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let admin = Identity::generate();
        let scorer = Identity::generate();
        let ids = crate::test_identity::Identities::new(
            &[(&admin, "admin", "jlu"), (&scorer, "scorer", "jlu")],
            "admin",
        );
        let view = ids.log.view(std::time::Duration::from_secs(60))?;
        let mut journal = Journal::open(directory.path().join("journal"), ids.genesis())?;
        let now = now_ms()?;
        for action in [
            client::application::competition(league::LeagueAction::CreateLeague {
                league: "cup".into(),
                rules: Default::default(),
                host: admin.peer_id().to_string(),
                scorer: scorer.peer_id().to_string(),
            }),
            client::application::competition(league::LeagueAction::Start {
                league: "cup".into(),
                seed: [0; 32],
            }),
        ] {
            ids.run(&mut journal, &admin, now, action)?;
        }
        let journal = Arc::new(Mutex::new(journal));
        let context = Context {
            journal: client::application::Authority::Local {
                journal: journal.clone(),
                log: Arc::new(Mutex::new(ids.log)),
                view,
            },
            identity: scorer,
            token: Arc::new(b"test-scoring-token-with-32-characters".to_vec()),
        };
        let mut headers = HeaderMap::new();
        assert_eq!(
            apply(
                context.clone(),
                headers.clone(),
                client::application::competition(league::LeagueAction::Finish {
                    league: "cup".into()
                })
            )
            .await,
            Err(StatusCode::UNAUTHORIZED)
        );
        headers.insert(
            "authorization",
            "Bearer test-scoring-token-with-32-characters".parse()?,
        );
        assert_eq!(
            apply(
                context.clone(),
                headers.clone(),
                Action::SetMemberRoles {
                    member: "scorer".into(),
                    roles: ["admin".into()].into()
                }
            )
            .await,
            Err(StatusCode::CONFLICT)
        );
        assert_eq!(journal.lock().await.state().revision, 2);
        assert_eq!(
            apply(
                context.clone(),
                headers.clone(),
                client::application::competition(league::LeagueAction::Finish {
                    league: "cup".into()
                })
            )
            .await,
            Ok(StatusCode::NO_CONTENT)
        );
        assert_eq!(
            apply(
                context,
                headers,
                client::application::competition(league::LeagueAction::Finish {
                    league: "cup".into()
                })
            )
            .await,
            Ok(StatusCode::NO_CONTENT)
        );
        assert_eq!(journal.lock().await.state().revision, 3);
        Ok(())
    }
}
