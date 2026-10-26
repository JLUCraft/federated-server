use super::*;
use authority::journal::Journal;
use hmac::{Hmac, KeyInit, Mac};
use league::governance::Rules;
use node::{AccessPolicy, NodeConfig, Service, ServiceId};
use sha2::Sha256;
use tokio::net::TcpListener;

async fn paper_connection(
    mut stream: TcpStream,
    secret: Vec<u8>,
    profiles: Vec<Profile>,
) -> Result<()> {
    let handshake = Packet::decode(&protocol::read_frame(&mut stream).await?, None)?;
    let mut f = Fields::new(&handshake.body);
    assert_eq!(f.int()?, protocol::VERSION);
    f.text(255)?;
    f.bytes(2)?;
    let intention = f.int()?;
    if intention == 1 {
        protocol::read_frame(&mut stream).await?;
        let mut body = vec![];
        protocol::string(
            &serde_json::json!({"version":{"protocol":protocol::VERSION}}).to_string(),
            &mut body,
        )?;
        protocol::write_packet(&mut stream, Packet { id: 0, body }, None).await?;
        return Ok(());
    }
    let login = Packet::decode(&protocol::read_frame(&mut stream).await?, None)?;
    assert_eq!(login.id, 0);
    let mut identity = Fields::new(&login.body);
    let name = identity.text(16)?;
    let uuid = uuid::Uuid::from_slice(identity.bytes(16)?)?;
    let profile = profiles
        .iter()
        .find(|p| p.uuid == uuid && p.name == name)
        .ok_or_else(|| anyhow::anyhow!("unexpected backend profile"))?;
    let mut query = vec![];
    protocol::varint(u32::MAX, &mut query);
    protocol::string("velocity:player_info", &mut query)?;
    query.push(4);
    protocol::write_packet(&mut stream, Packet { id: 4, body: query }, None).await?;
    let response = Packet::decode(&protocol::read_frame(&mut stream).await?, None)?;
    assert_eq!(response.id, 2);
    let mut f = Fields::new(&response.body);
    assert_eq!(f.int()?, -1);
    assert_eq!(f.bytes(1)?, [1]);
    let signature = f.bytes(32)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&secret)?;
    mac.update(f.remaining());
    mac.verify_slice(signature)?;
    assert_eq!(f.int()?, 1);
    assert_eq!(f.text(64)?, "127.0.0.1");
    assert_eq!(f.bytes(16)?, profile.uuid.as_bytes());
    assert_eq!(f.text(16)?, profile.name);
    let mut compression = vec![];
    protocol::varint(128, &mut compression);
    protocol::write_packet(
        &mut stream,
        Packet {
            id: 3,
            body: compression,
        },
        None,
    )
    .await?;
    let mut body = profile.uuid.as_bytes().to_vec();
    protocol::string(&profile.name, &mut body)?;
    protocol::varint(0, &mut body);
    protocol::write_packet(&mut stream, Packet { id: 2, body }, Some(128)).await?;
    assert_eq!(
        Packet::decode(&protocol::read_frame(&mut stream).await?, Some(128))?.id,
        3
    );
    protocol::write_packet(
        &mut stream,
        Packet {
            id: 3,
            body: vec![],
        },
        Some(128),
    )
    .await?;
    assert_eq!(
        Packet::decode(&protocol::read_frame(&mut stream).await?, Some(128))?.id,
        3
    );
    // A play packet larger than the compression threshold exercises actual zlib.
    protocol::write_packet(
        &mut stream,
        Packet {
            id: 1,
            body: vec![9; 512],
        },
        Some(128),
    )
    .await?;
    let _closed = protocol::read_frame(&mut stream).await;
    Ok(())
}
async fn proxy_session(address: std::net::SocketAddr, session: IncomingSession) -> Result<()> {
    let mut remote = TcpStream::connect(address).await?;
    let mut stream = session.stream.compat();
    tokio::io::copy_bidirectional(&mut remote, &mut stream).await?;
    Ok(())
}
async fn room_host(
    gateway: node::PeerId,
    secret: Vec<u8>,
    profiles: Vec<Profile>,
) -> Result<(Node, Backend, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let mut node = Node::start(Identity::generate(), NodeConfig::default()).await?;
    let id = ServiceId::new();
    node.publish(Service {
        metadata: Vec::new(),
        id,
        name: "room".into(),
        protocol: "minecraft/java/tcp".into(),
        access: AccessPolicy::Peers([gateway].into()),
    })
    .await?;
    let mut incoming = node.take_incoming()?;
    let backend = Backend {
        endpoint: Endpoint::Union {
            peer: node.peer_id().to_string(),
            addresses: node.addresses().iter().map(ToString::to_string).collect(),
            service: id.to_string(),
        },
        forwarding_secret: PathBuf::new(),
    };
    let task = tokio::spawn(async move {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                connection = listener.accept() => {
                    let (stream, _) = connection.unwrap();
                    tasks.spawn(paper_connection(stream, secret.clone(), profiles.clone()));
                }
                session = incoming.recv() => {
                    let Some(session) = session else { break };
                    tasks.spawn(proxy_session(address, session));
                }
                Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                    result.unwrap().unwrap();
                }
            }
        }
    });
    Ok((node, backend, task))
}
async fn login(stream: &mut Connection, profile: &Profile) -> Result<()> {
    protocol::write_packet(stream, handshake("127.0.0.1", 25566, 2)?, None).await?;
    let mut body = vec![];
    protocol::string(&profile.name, &mut body)?;
    body.extend(profile.uuid.as_bytes());
    protocol::write_packet(stream, Packet { id: 0, body }, None).await?;
    let compression = Packet::decode(&protocol::read_frame(stream).await?, None)?;
    assert_eq!(compression.id, 3);
    assert_eq!(
        Packet::decode(&protocol::read_frame(stream).await?, Some(128))?.id,
        2
    );
    protocol::write_packet(
        stream,
        Packet {
            id: 3,
            body: vec![],
        },
        Some(128),
    )
    .await?;
    assert_eq!(
        Packet::decode(&protocol::read_frame(stream).await?, Some(128))?.id,
        3
    );
    protocol::write_packet(
        stream,
        Packet {
            id: 3,
            body: vec![],
        },
        Some(128),
    )
    .await?;
    let play = Packet::decode(&protocol::read_frame(stream).await?, Some(128))?;
    assert_eq!(play.body, vec![9; 512]);
    Ok(())
}
async fn transfer(stream: &mut Connection) -> Result<()> {
    let packet = Packet::decode(&protocol::read_frame(stream).await?, Some(128))?;
    assert_eq!(packet.id, protocol::PLAY_TRANSFER);
    let mut f = Fields::new(&packet.body);
    assert_eq!(f.text(255)?, "127.0.0.1");
    assert_eq!(f.int()?, 25566);
    Ok(())
}
#[tokio::test]
async fn native_cross_node_transfer_substitution_and_returner_fencing() -> Result<()> {
    timeout(Duration::from_secs(30), async {
        let dir = tempfile::tempdir()?;
        let key = b"native-forwarding-secret-at-least-32-bytes";
        let path = dir.path().join("forwarding");
        std::fs::write(&path, key)?;
        let admin = Identity::generate();
        let users = [Identity::generate(), Identity::generate()];
        let members = ["alice", "bob"];
        let profiles = [
            Profile {
                uuid: uuid::Uuid::from_u128(1),
                name: "Alice".into(),
                textures: None,
            },
            Profile {
                uuid: uuid::Uuid::from_u128(2),
                name: "Bob".into(),
                textures: None,
            },
        ];
        let mut identities = crate::test_identity::Identities::new(
            &[
                (&admin, "admin", "jlu"),
                (&users[0], "alice", "jlu"),
                (&users[1], "bob", "jlu"),
            ],
            "admin",
        );
        let root = identities.root("jlu");
        for (i, member) in members.iter().enumerate() {
            identities.append(
                node::protocol::TrustAction::BindGameProfile {
                    club: "jlu".into(),
                    member: (*member).into(),
                    profile: profiles[i].uuid.simple().to_string(),
                },
                &[&root, &users[i]],
            );
        }
        let mut journal = Journal::open(dir.path().join("journal"), identities.genesis())?;
        let now = now_ms()?;
        for (signer, action) in [
            (
                &admin,
                client::application::competition(league::LeagueAction::CreateLeague {
                    league: "cup".into(),
                    rules: Rules {
                        seats: 1,
                        reconnect_min_ms: 500,
                        reconnect_max_ms: 1000,
                        ..Default::default()
                    },
                    host: admin.peer_id().to_string(),
                    scorer: admin.peer_id().to_string(),
                }),
            ),
            (
                &users[0],
                client::application::competition(league::LeagueAction::CreateTeam {
                    league: "cup".into(),
                    team: "a".into(),
                }),
            ),
            (
                &users[0],
                client::application::competition(league::LeagueAction::Invite {
                    league: "cup".into(),
                    team: "a".into(),
                    member: "bob".into(),
                }),
            ),
            (
                &users[1],
                client::application::competition(league::LeagueAction::Accept {
                    league: "cup".into(),
                    team: "a".into(),
                }),
            ),
            (
                &users[0],
                client::application::competition(league::LeagueAction::Register {
                    league: "cup".into(),
                    team: "a".into(),
                }),
            ),
        ] {
            identities.run(&mut journal, signer, now, action)?;
        }
        let journal = Arc::new(Mutex::new(journal));
        let mut gateway = Node::start(admin.clone(), NodeConfig::default()).await?;
        let service = ServiceId::new();
        identities.service(&admin, &service.to_string(), "alice", "play");
        let view = identities.log.view(Duration::from_secs(60))?;
        let authority = Authority::Local {
            journal: journal.clone(),
            log: Arc::new(Mutex::new(identities.log)),
            view: view.clone(),
        };
        gateway
            .publish(Service {
                metadata: Vec::new(),
                id: service,
                name: "league".into(),
                protocol: "minecraft/java/26.3".into(),
                access: AccessPolicy::Trust {
                    view,
                    requirement: node::protocol::TrustRequirement {
                        clubs: ["jlu".into()].into(),
                        permission: None,
                    },
                },
            })
            .await?;
        let (waiting, mut waiting_config, wt) =
            room_host(gateway.peer_id(), key.to_vec(), profiles.to_vec()).await?;
        let (arena, mut arena_config, at) =
            room_host(gateway.peer_id(), key.to_vec(), profiles.to_vec()).await?;
        waiting_config.forwarding_secret = path.clone();
        arena_config.forwarding_secret = path;
        let config = Config {
            league: "cup".into(),
            service: service.to_string(),
            waiting: waiting_config,
            arena: arena_config,
            skin_site: None,
        };
        let incoming = gateway.take_incoming()?;
        let gateway = Arc::new(gateway);
        let witnesses = crate::activity::Witnesses::default();
        let native = tokio::spawn(serve(
            config,
            gateway.clone(),
            authority.clone(),
            admin.clone(),
            incoming,
            Some(witnesses.clone()),
        ));
        let clients = [
            Node::start(users[0].clone(), NodeConfig::default()).await?,
            Node::start(users[1].clone(), NodeConfig::default()).await?,
        ];
        for client in &clients {
            client.dial(gateway.addresses()[0].clone()).await?;
        }
        let mut bad: Connection = Box::new(
            clients[0]
                .open_service(gateway.peer_id(), service)
                .await?
                .compat(),
        );
        assert!(login(&mut bad, &profiles[1]).await.is_err());
        drop(bad);
        let mut streams: Vec<Connection> = vec![];
        for (client, profile) in clients.iter().zip(&profiles) {
            let mut stream: Connection = Box::new(
                client
                    .open_service(gateway.peer_id(), service)
                    .await?
                    .compat(),
            );
            login(&mut stream, profile).await?;
            streams.push(stream);
        }
        assert_eq!(
            journal.lock().await.state().domain.leagues["cup"]
                .online
                .len(),
            2
        );
        for (index, profile) in profiles.iter().enumerate() {
            assert!(witnesses.recorded(
                &service.to_string(),
                members[index],
                &profile.uuid.simple().to_string()
            ));
        }
        authority
            .apply(
                &admin,
                client::application::competition(league::LeagueAction::Start {
                    league: "cup".into(),
                    seed: [0; 32],
                }),
            )
            .await?;
        let selected = usize::from(
            journal.lock().await.state().domain.leagues["cup"].seats["a"][0].player == "bob",
        );
        let standby = 1 - selected;
        transfer(&mut streams[selected]).await?;
        let mut arena_stream: Connection = Box::new(
            clients[selected]
                .open_service(gateway.peer_id(), service)
                .await?
                .compat(),
        );
        login(&mut arena_stream, &profiles[selected]).await?;
        // Player disappears; controller measures timeout and sends a transfer to the
        // remaining online teammate without any game-plugin event.
        drop(arena_stream);
        transfer(&mut streams[standby]).await?;
        let mut replacement: Connection = Box::new(
            clients[standby]
                .open_service(gateway.peer_id(), service)
                .await?
                .compat(),
        );
        login(&mut replacement, &profiles[standby]).await?;
        let mut returned: Connection = Box::new(
            clients[selected]
                .open_service(gateway.peer_id(), service)
                .await?
                .compat(),
        );
        login(&mut returned, &profiles[selected]).await?;
        {
            let j = journal.lock().await;
            assert!(matches!(
                j.state().domain.leagues["cup"].route(members[standby]),
                Route::Match { .. }
            ));
            assert_eq!(
                j.state().domain.leagues["cup"].route(members[selected]),
                Route::Waiting
            );
        }
        authority
            .apply(
                &admin,
                client::application::competition(league::LeagueAction::Finish {
                    league: "cup".into(),
                }),
            )
            .await?;
        transfer(&mut replacement).await?;
        let mut finished: Connection = Box::new(
            clients[standby]
                .open_service(gateway.peer_id(), service)
                .await?
                .compat(),
        );
        login(&mut finished, &profiles[standby]).await?;
        // The competition route closes at finish; the gateway still admits the waiting backend.
        assert_eq!(
            journal.lock().await.state().domain.leagues["cup"].route(members[standby]),
            Route::Unavailable
        );
        drop(finished);
        drop(returned);
        drop(replacement);
        drop(streams);
        native.abort();
        wt.abort();
        at.abort();
        for client in clients {
            client.shutdown().await?;
        }
        drop(gateway);
        waiting.shutdown().await?;
        arena.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    })
    .await?
}

#[test]
fn native_configuration_rejects_a_separate_player_roster() {
    let backend = serde_json::json!({"endpoint":{"transport":"local","address":"127.0.0.1:25565"},"forwarding_secret":"/tmp/unused"});
    let mut config = serde_json::json!({"league":"cup","service":ServiceId::new().to_string(),"waiting":backend,"arena":backend});
    assert!(serde_json::from_value::<Config>(config.clone()).is_ok());
    config["players"] = serde_json::json!({});
    assert!(serde_json::from_value::<Config>(config).is_err());
}

#[test]
fn documented_gateway_configuration_parses_and_rejects_unsafe_skin_sites() {
    let document = |skin_site: serde_json::Value| {
        serde_json::from_value::<Config>(serde_json::json!({
            "league": "cup",
            "service": ServiceId::new().to_string(),
            "waiting": {"endpoint": {"transport": "local", "address": "127.0.0.1:25566"}, "forwarding_secret": "waiting.secret"},
            "arena": {"endpoint": {"transport": "local", "address": "127.0.0.1:25567"}, "forwarding_secret": "arena.secret"},
            "skin_site": skin_site,
        }))
    };
    assert!(document(serde_json::json!("https://skin.jlucraft.com")).is_ok());
    assert!(document(serde_json::Value::Null).is_ok());
    assert!(document(serde_json::json!("http://skin.jlucraft.com")).is_err());
    assert!(document(serde_json::json!("https://skin.jlucraft.com/path")).is_err());
}
