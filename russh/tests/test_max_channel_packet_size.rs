#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::borrow::Cow;
use std::sync::Arc;

use russh::keys::PrivateKeyWithHashAlg;
use russh::keys::ssh_key::rand_core::OsRng;
use russh::*;
use ssh_key::PrivateKey;
use tokio::io::AsyncWriteExt;

const MAX_CHANNEL_PACKET_SIZE: u32 = 256 * 1024;

#[tokio::test]
async fn test_aes256_gcm_allows_full_256k_channel_packet() {
    let _ = env_logger::try_init();

    let client_key = PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap();

    let mut server_config = server::Config::default();
    server_config.inactivity_timeout = None;
    server_config.auth_rejection_time = std::time::Duration::from_secs(3);
    server_config.maximum_packet_size = MAX_CHANNEL_PACKET_SIZE;
    server_config.window_size = MAX_CHANNEL_PACKET_SIZE * 4;
    server_config
        .keys
        .push(PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap());
    server_config.preferred = {
        let mut preferred = Preferred::default();
        preferred.cipher = Cow::Borrowed(&[cipher::AES_256_GCM]);
        preferred
    };

    let server_config = Arc::new(server_config);
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let (socket, _) = socket.accept().await.unwrap();
        server::run_stream(server_config, socket, EchoServer {})
            .await
            .unwrap();
    });

    let mut client_config = client::Config::default();
    client_config.maximum_packet_size = MAX_CHANNEL_PACKET_SIZE;
    client_config.window_size = MAX_CHANNEL_PACKET_SIZE * 4;
    client_config.preferred = {
        let mut preferred = Preferred::default();
        preferred.cipher = Cow::Borrowed(&[cipher::AES_256_GCM]);
        preferred
    };

    let mut session = client::connect(Arc::new(client_config), addr, TestClient {})
        .await
        .unwrap();

    let authenticated = session
        .authenticate_publickey(
            std::env::var("USER").unwrap_or("user".to_owned()),
            PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
        )
        .await
        .unwrap()
        .success();
    assert!(authenticated);

    let payload = vec![0x5a; MAX_CHANNEL_PACKET_SIZE as usize];
    let mut channel = session.channel_open_session().await.unwrap();
    let mut writer = channel.make_writer();
    writer.write_all(&payload).await.unwrap();
    writer.flush().await.unwrap();

    let mut echoed = Vec::with_capacity(payload.len());
    while echoed.len() < payload.len() {
        match channel
            .wait()
            .await
            .expect("channel closed before echoing a full 256 KiB packet")
        {
            ChannelMsg::Data { data } => echoed.extend_from_slice(&data),
            msg => panic!("Unexpected message while waiting for echoed payload: {msg:?}"),
        }
    }

    assert_eq!(echoed, payload);

    channel.eof().await.unwrap();
    session
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();
}

#[derive(Clone)]
struct EchoServer {}

impl server::Handler for EchoServer {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &ssh_key::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<server::Msg>,
        _session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.data(channel, CryptoVec::from_slice(data))?;
        Ok(())
    }
}

struct TestClient {}

impl client::Handler for TestClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
