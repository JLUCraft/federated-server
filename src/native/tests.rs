use super::*;
use tokio::net::TcpListener;
use union_core::journal::{Command, Journal, SignedCommand};
use union_core::{
    AccessPolicy, NodeConfig, Service, ServiceId,
    governance::{Rules, State},
};

async fn paper_connection(
    mut stream: TcpStream,
    secret: Vec<u8>,
    profiles: Vec<Profile>,
) -> Result<()> {
    let handshake = Packet::decode(&wire::read_frame(&mut stream).await?, None)?;
    let mut f = Fields::new(&handshake.body);
    assert_eq!(f.int()?, wire::VERSION);
    f.text(255)?;
    f.bytes(2)?;
    let intention = f.int()?;
    if intention == 1 {
        wire::read_frame(&mut stream).await?;
        let mut body = vec![];
        wire::string(
            &serde_json::json!({"version":{"protocol":wire::VERSION}}).to_string(),
            &mut body,
        )?;
        wire::write_packet(&mut stream, Packet { id: 0, body }, None).await?;
        return Ok(());
    }
    let login = Packet::decode(&wire::read_frame(&mut stream).await?, None)?;
    assert_eq!(login.id, 0);
    let mut identity = Fields::new(&login.body);
    let name = identity.text(16)?;
    let uuid = uuid::Uuid::from_slice(identity.bytes(16)?)?;
    let profile = profiles
        .iter()
        .find(|p| p.uuid == uuid && p.name == name)
        .ok_or_else(|| anyhow::anyhow!("unexpected backend profile"))?;
    let mut query = vec![];
    wire::varint(7, &mut query);
    wire::string("velocity:player_info", &mut query)?;
    query.push(4);
    wire::write_packet(&mut stream, Packet { id: 4, body: query }, None).await?;
    let response = Packet::decode(&wire::read_frame(&mut stream).await?, None)?;
    assert_eq!(response.id, 2);
    let mut f = Fields::new(&response.body);
    assert_eq!(f.int()?, 7);
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
    wire::varint(128, &mut compression);
    wire::write_packet(
        &mut stream,
        Packet {
            id: 3,
            body: compression,
        },
        None,
    )
    .await?;
    let mut body = profile.uuid.as_bytes().to_vec();
    wire::string(&profile.name, &mut body)?;
    wire::varint(0, &mut body);
    wire::write_packet(&mut stream, Packet { id: 2, body }, Some(128)).await?;
    assert_eq!(
        Packet::decode(&wire::read_frame(&mut stream).await?, Some(128))?.id,
        3
    );
    wire::write_packet(
        &mut stream,
        Packet {
            id: 3,
            body: vec![],
        },
        Some(128),
    )
    .await?;
    assert_eq!(
        Packet::decode(&wire::read_frame(&mut stream).await?, Some(128))?.id,
        3
    );
    // A play packet larger than the compression threshold exercises actual zlib.
    wire::write_packet(
        &mut stream,
        Packet {
            id: 1,
            body: vec![9; 512],
        },
        Some(128),
    )
    .await?;
    let _closed = wire::read_frame(&mut stream).await;
    Ok(())
}
async fn room_host(
    gateway: union_core::PeerId,
    secret: Vec<u8>,
    profiles: Vec<Profile>,
) -> Result<(Node, Backend, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let mut node = Node::start(Identity::generate(), NodeConfig::default()).await?;
    let id = ServiceId::new();
    node.publish(Service {
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
             connection=listener.accept()=>{let (stream,_)=connection.unwrap();let (secret,profiles)=(secret.clone(),profiles.clone());tasks.spawn(async move{paper_connection(stream,secret,profiles).await});},
             session=incoming.recv()=>{let Some(session)=session else {break};tasks.spawn(async move{let mut remote=TcpStream::connect(address).await?;let mut stream=session.stream.compat();tokio::io::copy_bidirectional(&mut remote,&mut stream).await?;Ok(())});},
             Some(result)=tasks.join_next(),if !tasks.is_empty()=>{result.unwrap().unwrap();}
            }
        }
    });
    Ok((node, backend, task))
}
async fn login(stream: &mut Connection, profile: &Profile) -> Result<()> {
    wire::write_packet(stream, handshake("127.0.0.1", 25566, 2)?, None).await?;
    let mut body = vec![];
    wire::string(&profile.name, &mut body)?;
    body.extend(profile.uuid.as_bytes());
    wire::write_packet(stream, Packet { id: 0, body }, None).await?;
    let compression = Packet::decode(&wire::read_frame(stream).await?, None)?;
    assert_eq!(compression.id, 3);
    assert_eq!(
        Packet::decode(&wire::read_frame(stream).await?, Some(128))?.id,
        2
    );
    wire::write_packet(
        stream,
        Packet {
            id: 3,
            body: vec![],
        },
        Some(128),
    )
    .await?;
    assert_eq!(
        Packet::decode(&wire::read_frame(stream).await?, Some(128))?.id,
        3
    );
    wire::write_packet(
        stream,
        Packet {
            id: 3,
            body: vec![],
        },
        Some(128),
    )
    .await?;
    let play = Packet::decode(&wire::read_frame(stream).await?, Some(128))?;
    assert_eq!(play.body, vec![9; 512]);
    Ok(())
}
async fn transfer(stream: &mut Connection) -> Result<()> {
    let packet = Packet::decode(&wire::read_frame(stream).await?, Some(128))?;
    assert_eq!(packet.id, wire::PLAY_TRANSFER);
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
                properties: vec![],
            },
            Profile {
                uuid: uuid::Uuid::from_u128(2),
                name: "Bob".into(),
                properties: vec![],
            },
        ];
        let mut journal = Journal::open(
            dir.path().join("journal"),
            State::new([admin.peer_id().to_string()].into())?,
        )?;
        let now = now_ms()?;
        for (signer, action) in [
            (
                &admin,
                Action::Enroll {
                    member: "alice".into(),
                    club: "jlu".into(),
                    device: users[0].peer_id().to_string(),
                },
            ),
            (
                &admin,
                Action::Enroll {
                    member: "bob".into(),
                    club: "jlu".into(),
                    device: users[1].peer_id().to_string(),
                },
            ),
            (
                &admin,
                Action::CreateLeague {
                    league: "cup".into(),
                    rules: Rules {
                        seats: 1,
                        reconnect_min_ms: 500,
                        reconnect_max_ms: 1000,
                        ..Default::default()
                    },
                    host: admin.peer_id().to_string(),
                    scorer: admin.peer_id().to_string(),
                },
            ),
            (
                &users[0],
                Action::CreateTeam {
                    league: "cup".into(),
                    team: "a".into(),
                },
            ),
            (
                &users[0],
                Action::Invite {
                    league: "cup".into(),
                    team: "a".into(),
                    member: "bob".into(),
                },
            ),
            (
                &users[1],
                Action::Accept {
                    league: "cup".into(),
                    team: "a".into(),
                },
            ),
            (
                &users[0],
                Action::Register {
                    league: "cup".into(),
                    team: "a".into(),
                },
            ),
        ] {
            let signed = SignedCommand::sign(
                signer,
                Command {
                    revision: journal.state().revision,
                    expires_ms: now + 30000,
                    action,
                },
            )?;
            journal.execute(signed, now)?;
        }
        let journal = Arc::new(Mutex::new(journal));
        let mut gateway = Node::start(admin.clone(), NodeConfig::default()).await?;
        let service = ServiceId::new();
        gateway
            .publish(Service {
                id: service,
                name: "league".into(),
                protocol: "minecraft/java/26.3".into(),
                access: AccessPolicy::Peers(users.iter().map(Identity::peer_id).collect()),
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
            players: members
                .iter()
                .zip(profiles.iter())
                .map(|(m, p)| (m.to_string(), p.clone()))
                .collect(),
            student_policy: None,
        };
        let incoming = gateway.take_incoming()?;
        let gateway = Arc::new(gateway);
        let native = tokio::spawn(serve(
            config,
            gateway.clone(),
            journal.clone().into(),
            admin.clone(),
            incoming,
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
                .open_service(gateway.peer_id(), service, None)
                .await?
                .compat(),
        );
        assert!(login(&mut bad, &profiles[1]).await.is_err());
        drop(bad);
        let mut streams: Vec<Connection> = vec![];
        for (client, profile) in clients.iter().zip(&profiles) {
            let mut stream: Connection = Box::new(
                client
                    .open_service(gateway.peer_id(), service, None)
                    .await?
                    .compat(),
            );
            login(&mut stream, profile).await?;
            streams.push(stream);
        }
        let selected = {
            let mut j = journal.lock().await;
            assert_eq!(j.state().leagues["cup"].online.len(), 2);
            let now = now_ms()?;
            let command = SignedCommand::sign(
                &admin,
                Command {
                    revision: j.state().revision,
                    expires_ms: now + 30000,
                    action: Action::Start {
                        league: "cup".into(),
                        seed: [0; 32],
                    },
                },
            )?;
            j.execute(command, now)?;
            usize::from(j.state().leagues["cup"].seats["a"][0].player == "bob")
        };
        let standby = 1 - selected;
        transfer(&mut streams[selected]).await?;
        let mut arena_stream: Connection = Box::new(
            clients[selected]
                .open_service(gateway.peer_id(), service, None)
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
                .open_service(gateway.peer_id(), service, None)
                .await?
                .compat(),
        );
        login(&mut replacement, &profiles[standby]).await?;
        let mut returned: Connection = Box::new(
            clients[selected]
                .open_service(gateway.peer_id(), service, None)
                .await?
                .compat(),
        );
        login(&mut returned, &profiles[selected]).await?;
        {
            let j = journal.lock().await;
            assert!(matches!(
                j.state().leagues["cup"].route(members[standby]),
                Route::Match { .. }
            ));
            assert_eq!(
                j.state().leagues["cup"].route(members[selected]),
                Route::Waiting
            );
        }
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
