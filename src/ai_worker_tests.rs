use super::*;
use authority::journal::Journal;
use client::protocol::Privacy;
use node::{Node, NodeConfig};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Mutex;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[tokio::test]
async fn unified_identity_drives_local_provider_and_paid_worker() -> Result<()> {
    automatic_flow(false, None).await
}
#[cfg(feature = "server")]
#[tokio::test]
async fn replicated_office_runs_automatic_worker_and_replays_identity_witnesses() -> Result<()> {
    automatic_flow(true, None).await
}
#[tokio::test]
async fn automatic_review_applies_decisions_and_pauses_on_invalid_output() -> Result<()> {
    for decision in [
        "approve",
        "changes_requested",
        "reject",
        "invalid",
        "timeout",
    ] {
        automatic_flow(false, Some(decision)).await?;
    }
    Ok(())
}
async fn automatic_flow(replicated: bool, decision: Option<&'static str>) -> Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let dir=tempfile::tempdir()?;
        let admin=Identity::generate(); let worker=Identity::generate(); let human=Identity::generate();
        let now=now_ms()?;
        let mut genesis;
        let template=flows::Template{name:"summarize then review".into(),payload_kinds:[if decision.is_some() {"events.approve".into()} else {"events.create".into()}].into(),stages:vec![flows::Stage{name:"summary".into(),approver:flows::Approver::Ai{mode:if decision.is_some() {flows::AiMode::Review} else {flows::AiMode::Generate},worker:"worker".into(),model:"local".into(),purpose:"events.summary".into(),privacy:Privacy::Sensitive,max_tokens:32},timeout_ms:if decision==Some("timeout") {Some(2000)} else {None},on_timeout:flows::TimeoutPolicy::Reject}]};
        let listener=TcpListener::bind("127.0.0.1:0").await?;
        let url=format!("http://{}/v1/chat/completions",listener.local_addr()?);
        let calls=Arc::new(AtomicUsize::new(0));let count=calls.clone();
        let provider=tokio::spawn(async move {
            let (mut socket,_)=listener.accept().await.unwrap();
            let mut header=Vec::new();
            while !header.ends_with(b"\r\n\r\n") {header.push(socket.read_u8().await.unwrap());assert!(header.len()<16384);}
            let header=String::from_utf8(header).unwrap();
            let length:usize=header.lines().find_map(|line|line.to_lowercase().strip_prefix("content-length:").map(|n|n.trim().parse().unwrap())).unwrap();
            let mut body=vec![0;length];socket.read_exact(&mut body).await.unwrap();
            let request:serde_json::Value=serde_json::from_slice(&body).unwrap();
            assert_eq!(request["messages"][0]["role"],"system");
            assert_eq!(request["messages"][1]["role"],"user");
            let context:serde_json::Value=serde_json::from_str(request["messages"][1]["content"].as_str().unwrap()).unwrap();
            assert_eq!(context["material"],"meeting notes");
            assert_eq!(context["task"],"events.summary");
            assert_eq!(context["mode"],if decision.is_some() {"review"} else {"generate"});
            count.fetch_add(1,Ordering::SeqCst);
            if decision==Some("timeout") {tokio::time::sleep(std::time::Duration::from_secs(3)).await;return;}
            let content=match decision {
                None => "summary result".to_owned(),
                Some("invalid") => "looks good".to_owned(),
                Some(decision) => serde_json::json!({"decision":decision,"summary":"Review complete","issues":["Verify consent"]}).to_string(),
            };
            let delta=serde_json::json!({"choices":[{"index":0,"delta":{"content":content},"finish_reason":null}]}).to_string();
            let body=format!("data: {delta}\n\ndata: {{\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}]}}\n\ndata: {{\"choices\":[],\"usage\":{{\"prompt_tokens\":8,\"completion_tokens\":2,\"total_tokens\":10}}}}\n\ndata: [DONE]\n\n");
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
        });
        let host_key=Identity::generate();
        let identity_genesis=node::protocol::TrustGenesis {federation:"worker-test".into(),quorum:1,founders:vec![node::protocol::TrustFounder {member:"chair".into(),club:"school".into(),public_key:admin.public_key().encode_protobuf()}]};
        let identity_pin=client::trust::TrustState::genesis_digest(&identity_genesis)?;
        {
            use node::protocol::TrustAction as T;
            let mut log=client::trust::TrustLog::open(&dir.path().join("identity.jsonl"),&identity_genesis,&identity_pin)?;
            for action in [
                T::ConfirmMember {member:"worker".into(),club:"school".into(),device:Some(worker.peer_id().to_string()),evidence:"manual".into(),verifier:None},
                T::ConfirmMember {member:"human".into(),club:"school".into(),device:Some(human.peer_id().to_string()),evidence:"manual".into(),verifier:None},
                T::RegisterService {service:"application".into(),audience:host_key.peer_id().to_string(),club:"school".into()},
                T::GrantPermission {id:"worker-office".into(),member:"worker".into(),service:"application".into(),permission:"write".into()},
                T::GrantPermission {id:"human-office".into(),member:"human".into(),service:"application".into(),permission:"admin".into()},
            ] {
                let mut record=log.state().draft(action);
                for key in [&admin,&worker,&human,&host_key] {client::trust::sign(&mut record,key)?;}
                log.append(record)?;
            }
            genesis=state::State::<Application>::new(node::protocol::TrustBusinessBinding {genesis:identity_pin.clone(),namespace:"application".into(),service:"application".into(),audience:host_key.peer_id().to_string(),club:"school".into()})?;
            std::fs::write(dir.path().join("identity-genesis.json"),serde_json::to_vec(&identity_genesis)?)?;
        }

        worker.save_new(dir.path().join("worker.key"))?;
        host_key.save_new(dir.path().join("node.key"))?;
        let mut config=serde_json::json!({
            "node":{"key":"node.key"},"services":{
                "governance":{"genesis":"genesis.json","journal":"office"},
                "ai_worker":{"key":"worker.key","providers":[{"id":"fixture","protocol":"chat_completions","url":url,"models":["local"],"context_tokens":4096}]}
            }
        });
        {
            config["services"]["identity"]=serde_json::json!({"genesis":"identity-genesis.json","genesis_hash":identity_pin,"log":"identity.jsonl","writer":true,"source":null,"max_staleness_seconds":60});
        }
        #[cfg(feature = "server")]
        if replicated {
            let socket=std::net::TcpListener::bind("127.0.0.1:0")?;
            let port=socket.local_addr()?.port(); drop(socket);
            let address=format!("/ip4/127.0.0.1/tcp/{port}");
            let peers=std::collections::BTreeMap::from([(1, authority::consensus::Peer{peer:host_key.peer_id().to_string(),addresses:vec![format!("{address}/p2p/{}",host_key.peer_id())]})]);
            genesis=authority::consensus::Cluster::genesis(genesis,&peers)?;
            config["node"]["listen"]=serde_json::json!([address]);
            config["services"]["governance"]["replication"]=serde_json::json!({"id":1,"initialize":true,"peers":peers});
        }
        #[cfg(not(feature = "server"))]
        assert!(!replicated);
        genesis.domain.ai_pricing.insert("local".into(),flows::ai::AiPricing {base_points:1,input_points_per_1k:1,output_points_per_1k:1,max_input_tokens:1024,settlement:flows::ai::Settlement::Burn});
        genesis.domain.inner.organization.points.insert("school".into(),[("human".into(),1000)].into());
        std::fs::write(dir.path().join("genesis.json"),serde_json::to_vec(&genesis)?)?;
        let hash=node::protocol::digest(&serde_json::to_vec(&genesis)?);
        let config_path=dir.path().join("node.json");
        std::fs::write(&config_path,serde_json::to_vec(&config)?)?;
        let host=crate::runtime::Host::start(crate::runtime::Config::load(&config_path,Some(&identity_genesis))?).await?;
        let client_node=Node::start(human.clone(),NodeConfig::default()).await?;
        client_node.dial(host.status()?.addresses[0].parse()?).await?;
        let cache={
            let log=Mutex::new(client::trust::TrustLog::open(&dir.path().join("client.jsonl"),&identity_genesis,&identity_pin)?);
            authority::trust::synchronize(&client_node,host_key.peer_id(),&log).await?;log.into_inner()
        };
        while client::files::snapshot(&client_node,host_key.peer_id(),&hash).await.is_err() {tokio::time::sleep(std::time::Duration::from_millis(50)).await;}
        let install=state::governance::Action::Domain(F::InstallTemplate{id:"summary".into(),template});
        assert!(genesis.clone().apply(&worker.peer_id().to_string(),0,now,install.clone(),cache.state()).is_err());
        let installed=client::trust::execute::<Application>(&client_node,host_key.peer_id(),&hash,&human,&cache,install,client::journal::PROTOCOL).await?;
        assert!(installed.error.is_none(),"{:?}",installed.error);
        let roles=client::trust::execute::<Application>(&client_node,host_key.peer_id(),&hash,&human,&cache,state::governance::Action::SetMemberRoles{member:"human".into(),roles:["president".into()].into()},client::journal::PROTOCOL).await?;
        assert!(roles.error.is_none());
        let input=client::files::upload(&client_node,host_key.peer_id(),&hash,&human,client::files::Upload{branch:"main",path:"notes.txt",message:"meeting input",bytes:b"meeting notes"},&cache).await?;
        let snapshot=client::files::snapshot(&client_node,host_key.peer_id(),&hash).await?;
        let mut updates=authority::events::subscribe(&client_node,host_key.peer_id(),snapshot.revision,authority::events::PROTOCOL).await?;
        let create=events::EventAction::Create{id:"event".into(),title:"meeting".into(),brief_hash:input.to_string(),window:events::Window{opens_ms:now+60000,closes_ms:now+120000,starts_ms:now+180000}};
        let payload=if decision.is_some() {
            for action in [create,events::EventAction::Submit{id:"event".into()}] {
                let reply=client::trust::execute::<Application>(&client_node,host_key.peer_id(),&hash,&human,&cache,state::governance::Action::Domain(F::Inner(action)),client::journal::PROTOCOL).await?;
                assert!(reply.error.is_none());
            }
            events::EventAction::Approve{id:"event".into(),epoch:1,co_organizers:Default::default()}
        } else {create};
        let action=state::governance::Action::Domain(F::Start{ max_points: 1_000_000,id:"flow".into(),template:"summary".into(),input:Some(input.clone()),payload});
        let reply=client::trust::execute::<Application>(&client_node,host_key.peer_id(),&hash,&human,&cache,action,client::journal::PROTOCOL).await?;
        assert!(reply.error.is_none(),"{:?}",reply.error);
        let mut state=loop {
            let snapshot=client::files::snapshot(&client_node,host_key.peer_id(),&hash).await?;
            let flow=&snapshot.domain.flows["flow"];
            let expected=match decision {Some("reject" | "timeout")=>flows::Status::Rejected,Some("changes_requested")=>flows::Status::ChangesRequested,Some("invalid" | "approve")=>flows::Status::Active,_=>flows::Status::Approved};
            if flow.status==expected && flow.records[0].ai_runs.last().is_some_and(|r|r.output.is_some() || r.error.is_some()) {break snapshot;}
            authority::events::next(&mut updates).await?;
        };
        let run=&state.domain.flows["flow"].records[0].ai_runs[0];
        assert_eq!(state.domain.flows["flow"].records[0].escrowed_points,0);
        assert_eq!(state.domain.inner.organization.points["school"]["human"],if matches!(decision,Some("invalid"|"timeout")) {1000} else {998});

        if matches!(decision,Some("invalid" | "timeout")) {assert!(run.output.is_none());assert!(run.error.is_some());}
        else if decision.is_some() {assert!(run.review.is_some());}
        else {assert_eq!(state.domain.inner.files.read(run.output.as_ref().unwrap())?,b"summary result");}
        if decision==Some("approve") {
            let flow=&state.domain.flows["flow"];
            assert_eq!(flow.current,1);
            assert_eq!(state.domain.inner.events["event"].phase,events::Phase::Review);
            assert!(flow.deadline_ms.is_none());
            assert!(matches!(flows::template_for(&state.domain.flow_templates,flow)?.stages[1].approver,flows::Approver::ClubPresidents{..}));
            let worker_node=Node::start(worker.clone(),NodeConfig::default()).await?;
            worker_node.dial(host.status()?.addresses[0].parse()?).await?;
            let denied=client::trust::execute::<Application>(&worker_node,host_key.peer_id(),&hash,&worker,&cache,state::governance::Action::Domain(F::Approve{instance:"flow".into(),comment_hash:"a".repeat(64)}),client::journal::PROTOCOL).await?;
            assert!(denied.error.is_some());
            worker_node.shutdown().await?;
            for action in [F::Approve{instance:"flow".into(),comment_hash:"a".repeat(64)},F::Execute{instance:"flow".into()}] {
                let reply=client::trust::execute::<Application>(&client_node,host_key.peer_id(),&hash,&human,&cache,state::governance::Action::Domain(action),client::journal::PROTOCOL).await?;
                assert!(reply.error.is_none(),"{:?}",reply.error);
            }
            state=client::files::snapshot(&client_node,host_key.peer_id(),&hash).await?;
            assert_eq!(state.domain.inner.events["event"].phase,events::Phase::Approved);
        }
        assert_eq!(calls.load(Ordering::SeqCst),1);
        provider.await?;
        drop(updates);
        client_node.shutdown().await?;
        host.close().await?;
        if !replicated {
            let replay=Journal::<Application>::open(dir.path().join("office"),genesis.clone())?;
            assert_eq!(replay.state(),&state);
        }
        #[cfg(feature = "server")]
        if replicated {
            let replay=authority::consensus::Store::open(&dir.path().join("office"),genesis)?;
            assert_eq!(replay.state().await,state);
        }
        assert_eq!(calls.load(Ordering::SeqCst),1);
        Ok::<_,anyhow::Error>(())
    }).await?
}
