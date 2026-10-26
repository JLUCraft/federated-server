//! Automatic, serial execution of committed AI stages. Model I/O never runs in replay.
use crate::runtime::Application;
use anyhow::{Context, Result, bail};
use authority::authority::Authority;
use authority::journal::now_ms;
use base64::Engine;
use identity::Identity;
use serde::Deserialize;
use std::path::PathBuf;
type F = flows::FlowAction<events::EventsDomain>;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub key: PathBuf,
    pub providers: Vec<llm_gateway::Provider>,
    #[serde(default = "llm_gateway::default_concurrency")]
    pub concurrency: usize,
}

pub(crate) struct Prepared {
    identity: Identity,
    providers: llm_gateway::Gateway,
}
pub(crate) fn prepare(config: Config) -> Result<Prepared> {
    Ok(Prepared {
        identity: Identity::load(&config.key)?,
        providers: llm_gateway::Gateway::new(llm_gateway::Config {
            providers: config.providers,
            concurrency: config.concurrency,
        })?,
    })
}
async fn apply(authority: &Authority<Application>, identity: &Identity, action: F) -> Result<()> {
    authority
        .apply(identity, state::governance::Action::Domain(action))
        .await?;
    Ok(())
}
pub(crate) async fn serve(authority: Authority<Application>, prepared: Prepared) -> Result<()> {
    let unified = authority.identity_view();
    let Prepared {
        identity,
        providers,
    } = prepared;
    let device = identity.peer_id().to_string();
    let mut updates = authority.watch().await;
    let mut identity_updates = unified.clone();
    let mut recovered = false;
    loop {
        if !recovered {
            if recover(&authority, &identity).await.is_err() {
                wait_updates(&mut updates, &mut identity_updates).await?;
                continue;
            }
            let snapshot = authority.state(identity.peer_id()).await?;
            let core = effective_core(&snapshot, &unified)?;
            let worker = core
                .members
                .iter()
                .find(|(_, m)| m.owns(&device))
                .map(|(id, _)| id)
                .context("AI worker is not a member")?;
            let models = providers.models();
            let existing = snapshot.domain.ai_workers.get(worker);
            if existing.is_none_or(|w| w.models != models) {
                apply(
                    &authority,
                    &identity,
                    F::AiWorker {
                        models,
                        active: existing.is_none_or(|w| w.active),
                    },
                )
                .await?;
            }
            recovered = true;
        }
        identity_updates.mark_seen();
        updates.borrow_and_update();
        let pending = {
            let state = match authority.state(identity.peer_id()).await {
                Ok(state) => state,
                Err(_) => {
                    wait_updates(&mut updates, &mut identity_updates).await?;
                    continue;
                }
            };
            let core = match effective_core(&state, &unified) {
                Ok(core) => core,
                Err(_) => {
                    wait_updates(&mut updates, &mut identity_updates).await?;
                    continue;
                }
            };
            let worker = core
                .members
                .iter()
                .find(|(_, m)| m.owns(&device))
                .map(|(id, _)| id);
            let now = now_ms()?;
            let expired: Vec<_> = state
                .domain
                .flows
                .iter()
                .filter_map(|(id, flow)| {
                    let template = flows::template_for(&state.domain.flow_templates, flow).ok()?;
                    let flows::Approver::Ai { worker: owner, .. } =
                        &template.stages.get(flow.current)?.approver
                    else {
                        return None;
                    };
                    (flow.status == flows::Status::Active
                        && Some(owner) == worker
                        && flow.deadline_ms.is_some_and(|t| now >= t))
                    .then(|| id.clone())
                })
                .collect();
            if !expired.is_empty() {
                for instance in expired {
                    let _ = apply(&authority, &identity, F::Poke { instance }).await;
                }
                wait_updates(&mut updates, &mut identity_updates).await?;
                continue;
            }
            {
                state
                    .domain
                    .flows
                    .keys()
                    .filter_map(|id| flows::ai_job(&state.domain, id).ok().flatten())
                    .find(|job| {
                        Some(&job.worker) == worker
                            && providers.supports(&job.model)
                            && state.domain.flows[&job.instance]
                                .deadline_ms
                                .is_none_or(|t| now_ms().is_ok_and(|now| now < t))
                    })
            }
        };
        let Some(job) = pending else {
            wait_updates(&mut updates, &mut identity_updates).await?;
            continue;
        };
        let claimed = {
            apply(
                &authority,
                &identity,
                F::ClaimAi {
                    instance: job.instance.clone(),
                    job: job.job.clone(),
                    attempt: job.attempt,
                },
            )
            .await
            .is_ok()
        };
        if !claimed {
            wait_updates(&mut updates, &mut identity_updates).await?;
            continue;
        }
        let result = execute(&authority, &providers, &identity, &job, &unified).await;
        let (output, usage, error) = match result {
            Ok((cid, usage)) => (Some(cid), Some(usage), None),
            Err(_) => (
                None,
                None,
                Some("AI execution failed; inspect provider configuration or retry".into()),
            ),
        };
        // A cancelled, expired, replaced or revoked task must never advance.
        let _ = apply(
            &authority,
            &identity,
            F::FinishAi {
                instance: job.instance.clone(),
                job: job.job,
                attempt: job.attempt,
                output,
                usage,
                error,
            },
        )
        .await;
        let _ = apply(
            &authority,
            &identity,
            F::Execute {
                instance: job.instance,
            },
        )
        .await;
    }
}
async fn recover(authority: &Authority<Application>, identity: &Identity) -> Result<()> {
    let device = identity.peer_id().to_string();
    // A crash may leave an externally billed call without a committed receipt.
    // Record it as failed; explicit retry creates a new attempt instead of silently rebilling.
    {
        let state = authority.state(identity.peer_id()).await?;
        let interrupted: Vec<_> = state
            .domain
            .flows
            .iter()
            .filter_map(|(id, flow)| {
                if flow.status != flows::Status::Active {
                    return None;
                }
                let runs = &flow.records.get(flow.current)?.ai_runs;
                let run = runs.last()?;
                (run.device == device && run.output.is_none() && run.error.is_none())
                    .then(|| (id.clone(), run.job.clone(), runs.len() - 1))
            })
            .collect();
        for (instance, job, attempt) in interrupted {
            // Expired/revoked tasks may reject this receipt; they remain visibly pending.
            let _ = apply(
                authority,
                identity,
                F::FinishAi {
                    instance,
                    job,
                    attempt,
                    output: None,
                    usage: None,
                    error: Some("executor interrupted; retry required".into()),
                },
            )
            .await;
        }
    }
    Ok(())
}
async fn execute(
    authority: &Authority<Application>,
    providers: &llm_gateway::Gateway,
    identity: &Identity,
    job: &flows::AiJob,
    unified: &authority::trust::TrustView,
) -> Result<(client::protocol::Cid, client::protocol::LlmUsage)> {
    let snapshot = authority.state(identity.peer_id()).await?;
    let input = snapshot.domain.inner.files.read(&job.input)?;
    let (attachments, required_capabilities) =
        document_attachments(&snapshot.domain.inner, &input)?;
    let content = String::from_utf8(input).context("AI input must be UTF-8")?;
    let context = serde_json::to_string(
        &serde_json::json!({"task":job.purpose,"mode":job.mode,"job":job.job,"input":job.input,"material":content}),
    )?;
    let mut updates = authority.watch().await;
    let request = providers.complete(client::protocol::LlmRequest {
        attachments,
        required_capabilities,
        model: job.model.clone(),
        purpose: job.purpose.clone(),
        privacy: job.privacy,
        messages: vec![],
        context: Some(context),
        stream: true,
        max_tokens: job.max_tokens,
    });
    tokio::pin!(request);
    let mut identity_updates = unified.clone();
    let completion = loop {
        identity_updates.mark_seen();
        updates.borrow_and_update();
        {
            let state = authority.state(identity.peer_id()).await?;
            if !running(&state, identity, job, unified)? {
                bail!("AI stage cancelled or revoked");
            }
        }
        tokio::select! {
            result=&mut request => break result?,
            _=async {let remaining=identity_updates.remaining();tokio::select!{_=identity_updates.changed()=>{},_=tokio::time::sleep(remaining)=>{}}} => {},
            result=updates.changed() => { result.context("office journal closed")?; }
            _=tokio::time::sleep(std::time::Duration::from_secs(1)) => {},
        }
    };
    if completion.truncated || completion.content.is_empty() {
        bail!("incomplete model output");
    }
    flows::validate_ai_output(job.mode, completion.content.as_bytes())?;
    let state = authority.state(identity.peer_id()).await?;
    if !running(&state, identity, job, unified)? {
        bail!("AI stage changed");
    }
    let (cid, blocks) = state
        .domain
        .inner
        .files
        .version(Some(job.input.clone()), completion.content.as_bytes())?;
    for block in blocks {
        apply(
            authority,
            identity,
            F::Inner(events::EventAction::PutBlock { block }),
        )
        .await?;
    }
    Ok((cid, completion.usage))
}

fn running(
    state: &state::State<Application>,
    identity: &Identity,
    job: &flows::AiJob,
    unified: &authority::trust::TrustView,
) -> Result<bool> {
    let device = identity.peer_id().to_string();
    let Some(flow) = state.domain.flows.get(&job.instance) else {
        return Ok(false);
    };
    {
        let current = unified.state()?;
        if !state.can_write(&device, &current) {
            return Ok(false);
        }
    }
    if flow.allowance.is_some() {
        let expected = <events::EventsDomain as state::Domain>::workflow_input(
            &state.domain.inner,
            &flow.payload,
        );
        let actual = <events::EventsDomain as state::Domain>::artifact(
            &state.domain.inner,
            &job.input.to_string(),
        );
        if <events::EventsDomain as state::Domain>::workflow_worker(
            &state.domain.inner,
            &flow.payload,
        )
        .as_deref()
            != Some(job.worker.as_str())
            || !matches!((expected,actual),(Ok(expected),Ok(actual)) if expected==actual)
        {
            return Ok(false);
        }
    }
    if job.mode == flows::AiMode::Review
        && <events::EventsDomain as state::Domain>::review_artifact(
            &state.domain.inner,
            &flow.payload,
        )
        .ok()
        .as_deref()
            != Some(job.input.to_string().as_str())
    {
        return Ok(false);
    }
    let core = effective_core(state, unified)?;
    Ok(core
        .members
        .get(&job.worker)
        .is_some_and(|m| m.owns(&device))
        && flow.status == flows::Status::Active
        && flow
            .deadline_ms
            .is_none_or(|t| now_ms().is_ok_and(|now| now < t))
        && flow.records.get(flow.current).is_some_and(|r| {
            r.ai_runs.len().checked_sub(1) == Some(job.attempt)
                && r.ai_runs.last().is_some_and(|run| {
                    run.job == job.job
                        && run.device == device
                        && !run.retry_requested
                        && run.error.is_none()
                        && run.output.is_none()
                })
        }))
}

async fn wait_updates(
    updates: &mut tokio::sync::watch::Receiver<authority::events::Event>,
    identity: &mut authority::trust::TrustView,
) -> Result<()> {
    tokio::select! {r=updates.changed()=>r.context("office journal closed")?,r=identity.changed()=>r?,_=tokio::time::sleep(std::time::Duration::from_secs(1))=>{},}
    Ok(())
}

fn effective_core(
    state: &state::State<Application>,
    unified: &authority::trust::TrustView,
) -> Result<state::governance::CoreState> {
    Ok(state.identity_core(unified.state()?.as_ref())?)
}
#[cfg(test)]
#[path = "ai_worker_tests.rs"]
mod tests;

fn document_attachments(
    state: &events::EventsState,
    input: &[u8],
) -> Result<(
    Vec<node::protocol::LlmAttachment>,
    std::collections::BTreeSet<node::protocol::LlmCapability>,
)> {
    fn collect(value: &serde_json::Value, cids: &mut std::collections::BTreeSet<String>) {
        match value {
            serde_json::Value::Object(map) => {
                if map
                    .get("requires_document_review")
                    .and_then(|v| v.as_bool())
                    == Some(true)
                    && let Some(cid) = map.get("cid").and_then(|v| v.as_str())
                {
                    cids.insert(cid.into());
                }
                for child in map.values() {
                    collect(child, cids);
                }
            }
            serde_json::Value::Array(items) => {
                for child in items {
                    collect(child, cids);
                }
            }
            _ => {}
        }
    }
    let mut cids = std::collections::BTreeSet::new();
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(input) {
        collect(&value, &mut cids);
    }
    let mut attachments = Vec::new();
    let mut capabilities = std::collections::BTreeSet::new();
    for cid in cids {
        let bytes = state.files.read(&cid.parse()?)?;
        let mime = node::protocol::llm_document_mime(&bytes)
            .context("unsupported office document format")?;
        let extension = match mime {
            "application/pdf" => {
                capabilities.insert(node::protocol::LlmCapability::Pdf);
                "pdf"
            }
            "image/png" => "png",
            "image/jpeg" => "jpg",
            _ => "webp",
        };

        capabilities.insert(node::protocol::LlmCapability::Vision);
        attachments.push(node::protocol::LlmAttachment {
            name: format!("{cid}.{extension}"),
            mime: mime.into(),
            data: base64::engine::general_purpose::STANDARD.encode(bytes),
        });
    }
    Ok((attachments, capabilities))
}
