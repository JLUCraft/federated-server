//! Local Paper adapter: the plugin receives a scoring-only bearer, never an admin key.
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::post,
};
use serde::Deserialize;
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};
use subtle::ConstantTimeEq;
#[cfg(test)]
use tokio::sync::Mutex;
use union_core::{
    Identity,
    governance::{Action, Phase},
};

#[derive(Clone)]
struct Context {
    journal: union_core::authority::Authority,
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
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if token.as_bytes().ct_eq(context.token.as_slice()).into() {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
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
    if let Action::Finish { league } = &action {
        let league = journal.leagues.get(league).ok_or(StatusCode::NOT_FOUND)?;
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
pub async fn serve(
    address: SocketAddr,
    journal: union_core::authority::Authority,
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
        .route(
            "/v1/score",
            post(
                |State(c): State<Context>, h: HeaderMap, Json(s): Json<Score>| async move {
                    apply(
                        c,
                        h,
                        Action::Score {
                            league: s.league,
                            event: s.event,
                            players: s.players,
                            teams: s.teams,
                        },
                    )
                    .await
                },
            ),
        )
        .route(
            "/v1/finish",
            post(
                |State(c): State<Context>, h: HeaderMap, Json(s): Json<Finish>| async move {
                    apply(c, h, Action::Finish { league: s.league }).await
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
    use union_core::journal::{Command, Journal, SignedCommand, now_ms};
    #[tokio::test]
    async fn scoring_only_identity_and_bearer_cannot_manage_the_league() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let admin = Identity::generate();
        let scorer = Identity::generate();
        let mut journal = Journal::open(
            directory.path().join("journal"),
            union_core::governance::State::new([admin.peer_id().to_string()].into())?,
        )?;
        let now = now_ms()?;
        for action in [
            Action::CreateLeague {
                league: "cup".into(),
                rules: Default::default(),
                host: admin.peer_id().to_string(),
                scorer: scorer.peer_id().to_string(),
            },
            Action::Start {
                league: "cup".into(),
                seed: [0; 32],
            },
        ] {
            let command = SignedCommand::sign(
                &admin,
                Command {
                    revision: journal.state().revision,
                    expires_ms: now + 30_000,
                    action,
                },
            )?;
            journal.execute(command, now)?;
        }
        let journal = Arc::new(Mutex::new(journal));
        let context = Context {
            journal: journal.clone().into(),
            identity: scorer,
            token: Arc::new(b"test-scoring-token-with-32-characters".to_vec()),
        };
        let mut headers = HeaderMap::new();
        assert_eq!(
            apply(
                context.clone(),
                headers.clone(),
                Action::Finish {
                    league: "cup".into()
                }
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
                Action::Enroll {
                    member: "intruder".into(),
                    club: "jlu".into(),
                    device: admin.peer_id().to_string()
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
                Action::Finish {
                    league: "cup".into()
                }
            )
            .await,
            Ok(StatusCode::NO_CONTENT)
        );
        assert_eq!(
            apply(
                context,
                headers,
                Action::Finish {
                    league: "cup".into()
                }
            )
            .await,
            Ok(StatusCode::NO_CONTENT)
        );
        assert_eq!(journal.lock().await.state().revision, 3);
        Ok(())
    }
}
