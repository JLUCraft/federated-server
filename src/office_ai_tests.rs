use super::*;
use authority::journal::Journal;
use client::protocol::Privacy;
use node::{Node, NodeConfig, ServiceId};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Mutex;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[tokio::test]
async fn unified_identity_drives_office_gateway_and_automatic_worker() -> Result<()> {
    automatic_flow(false).await
}
#[cfg(feature = "server")]
#[tokio::test]
async fn replicated_office_runs_automatic_worker_and_replays_identity_witnesses() -> Result<()> {
    automatic_flow(true).await
}
async fn automatic_flow(replicated: bool) -> Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let dir=tempfile::tempdir()?;
        let admin=Identity::generate(); let worker=Identity::generate(); let human=Identity::generate();
        let now=now_ms()?;
        let mut genesis;
        let template=flows::Template{name:"summarize then review".into(),payload_kinds:["events.create".into()].into(),stages:vec![flows::Stage{name:"summary".into(),approver:flows::Approver::Ai{worker:"worker".into(),model:"local".into(),purpose:"events.summary".into(),privacy:Privacy::Sensitive,max_tokens:32},timeout_ms:None,on_timeout:flows::TimeoutPolicy::Reject}]};
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
            assert_eq!(request["messages"][0]["content"],"Summarize: meeting notes");
            count.fetch_add(1,Ordering::SeqCst);
            let body="data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"summary result\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":8,\"completion_tokens\":2,\"total_tokens\":10}}\n\ndata: [DONE]\n\n";
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
        });
        let host_key=Identity::generate();
        let service=ServiceId::new();
        let identity_genesis=node::protocol::TrustGenesis {federation:"worker-test".into(),quorum:1,founders:vec![node::protocol::TrustFounder {member:"chair".into(),club:"school".into(),public_key:admin.public_key().encode_protobuf()}]};
        let identity_pin=client::trust::TrustState::genesis_digest(&identity_genesis)?;
        {
            use node::protocol::TrustAction as T;
            let mut log=client::trust::TrustLog::open(&dir.path().join("identity.jsonl"),&identity_genesis,&identity_pin)?;
            for action in [
                T::ConfirmMember {member:"worker".into(),club:"school".into(),device:Some(worker.peer_id().to_string()),evidence:"manual".into(),verifier:None},
                T::ConfirmMember {member:"human".into(),club:"school".into(),device:Some(human.peer_id().to_string()),evidence:"manual".into(),verifier:None},
                T::RegisterService {service:"office".into(),audience:host_key.peer_id().to_string(),club:"school".into()},
                T::RegisterService {service:service.to_string(),audience:host_key.peer_id().to_string(),club:"school".into()},
                T::GrantPermission {id:"worker-office".into(),member:"worker".into(),service:"office".into(),permission:"write".into()},
                T::GrantPermission {id:"human-office".into(),member:"human".into(),service:"office".into(),permission:"admin".into()},
                T::GrantPermission {id:"worker-gateway".into(),member:"worker".into(),service:service.to_string(),permission:"use".into()},
            ] {
                let mut record=log.state().draft(action);
                for key in [&admin,&worker,&human,&host_key] {client::trust::sign(&mut record,key)?;}
                log.append(record)?;
            }
            genesis=state::State::<Office>::new(node::protocol::TrustBusinessBinding {genesis:identity_pin.clone(),namespace:"office".into(),service:"office".into(),audience:host_key.peer_id().to_string(),club:"school".into()})?;
            std::fs::write(dir.path().join("identity-genesis.json"),serde_json::to_vec(&identity_genesis)?)?;
        }

        worker.save_new(dir.path().join("worker.key"))?;
        host_key.save_new(dir.path().join("node.key"))?;
        let mut config=serde_json::json!({
            "node":{"key":"node.key"},"services":{
                "governance":{"domain":"office","genesis":"genesis.json","journal":"office"},
                "gateway":{"service":service.to_string(),"config":"gateway.json","ledger":"usage"},
                "ai_worker":{"key":"worker.key"}
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
        std::fs::write(dir.path().join("genesis.json"),serde_json::to_vec(&genesis)?)?;
        let hash=node::protocol::digest(&serde_json::to_vec(&genesis)?);
        std::fs::write(dir.path().join("gateway.json"),serde_json::to_vec(&serde_json::json!({
            "providers":[{"url":url,"key_env":null,"sensitive":true,"self_hosted":true,"models":["local"],"context_tokens":128}],
            "members":{"worker":{"tokens_per_day":1024,"models":["local"]}},"purposes":["events.summary"],
            "templates":{"events.summary":"Summarize: {context}"},"max_tokens":32,"max_messages":2,"max_input_bytes":1024,"concurrency":1
        }))?)?;
        let config_path=dir.path().join("node.json");
        std::fs::write(&config_path,serde_json::to_vec(&config)?)?;
        let host=crate::runtime::Host::start(crate::runtime::Config::load(&config_path)?).await?;
        let client_node=Node::start(human.clone(),NodeConfig::default()).await?;
        client_node.dial(host.status()?.addresses[0].parse()?).await?;
        let cache={
            let log=Mutex::new(client::trust::TrustLog::open(&dir.path().join("client.jsonl"),&identity_genesis,&identity_pin)?);
            authority::trust::synchronize(&client_node,host_key.peer_id(),&log).await?;log.into_inner()
        };
        while client::office::snapshot(&client_node,host_key.peer_id(),&hash).await.is_err() {tokio::time::sleep(std::time::Duration::from_millis(50)).await;}
        let install=state::governance::Action::Domain(F::InstallTemplate{id:"summary".into(),template});
        assert!(genesis.clone().apply(&worker.peer_id().to_string(),0,now,install.clone(),cache.state()).is_err());
        let installed=client::trust::execute::<Office>(&client_node,host_key.peer_id(),&hash,&human,&cache,install).await?;
        assert!(installed.error.is_none(),"{:?}",installed.error);
        let input=client::office::upload(&client_node,host_key.peer_id(),&hash,&human,client::office::Upload{branch:"main",path:"notes.txt",message:"meeting input",bytes:b"meeting notes"},&cache).await?;
        let snapshot=client::office::snapshot(&client_node,host_key.peer_id(),&hash).await?;
        let mut updates=authority::events::subscribe(&client_node,host_key.peer_id(),snapshot.revision).await?;
        let action=state::governance::Action::Domain(F::Start{id:"flow".into(),template:"summary".into(),input:Some(input.clone()),payload:events::EventAction::Create{id:"event".into(),title:"meeting".into(),brief_hash:input.to_string(),window:events::Window{opens_ms:now+60000,closes_ms:now+120000,starts_ms:now+180000}}});
        let reply=client::trust::execute::<Office>(&client_node,host_key.peer_id(),&hash,&human,&cache,action).await?;
        assert!(reply.error.is_none(),"{:?}",reply.error);
        let state=loop {
            let snapshot=client::office::snapshot(&client_node,host_key.peer_id(),&hash).await?;
            if snapshot.domain.flows["flow"].status==flows::Status::Approved {break snapshot;}
            authority::events::next(&mut updates).await?;
        };
        let output=state.domain.flows["flow"].records[0].ai_runs[0].output.as_ref().unwrap();
        assert_eq!(state.domain.inner.files.read(output)?,b"summary result");
        assert_eq!(calls.load(Ordering::SeqCst),1);
        provider.await?;
        drop(updates);
        client_node.shutdown().await?;
        host.close().await?;
        if !replicated {
            let replay=Journal::<Office>::open(dir.path().join("office"),genesis.clone())?;
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
