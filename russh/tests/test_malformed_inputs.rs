#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Regression tests for malformed SSH inputs.

use std::borrow::Cow;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use byteorder::{BigEndian, ByteOrder};
#[cfg(feature = "flate2")]
use flate2::FlushCompress;
use futures::stream;
use russh::keys::agent::client::AgentClient;
use russh::{Channel, ChannelId, Pty, cipher, client, compression, kex, mac, server};
use ssh_key::{Algorithm, PrivateKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const MSG_SERVICE_REQUEST: u8 = 5;
const MSG_SERVICE_ACCEPT: u8 = 6;
const MSG_KEXINIT: u8 = 20;
const MSG_NEWKEYS: u8 = 21;
const MSG_USERAUTH_REQUEST: u8 = 50;
const MSG_USERAUTH_SUCCESS: u8 = 52;
const MSG_CHANNEL_OPEN: u8 = 90;
const MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
const MSG_CHANNEL_REQUEST: u8 = 98;
const EXCESSIVE_PROMPT_COUNT: u32 = 1025;
#[cfg(feature = "flate2")]
const OVERSIZED_DECOMPRESSED_LEN: usize = 2 * 1024 * 1024;
const OVERSIZED_AGENT_MESSAGE_LEN: usize = 4 * 1024 * 1024;

#[tokio::test]
async fn malformed_pty_req_truncated_modes_rejected_by_server() {
    let (signal, panicked) = capture_panics(async {
        tokio::time::timeout(
            Duration::from_secs(3),
            raw_pty_req_signal(|server_channel| {
                pty_req_payload(server_channel, &[Pty::VINTR as u8, 0, 0, 0])
            }),
        )
        .await
    })
    .await;

    assert!(!panicked, "truncated pty modes caused an internal panic");
    assert!(
        matches!(
            &signal,
            Ok(ServerSignal::Closed | ServerSignal::ProtocolError(_))
        ),
        "truncated pty modes panicked or hung at the parser: {signal:?}"
    );
    assert_not_task_panic(signal);
}

#[tokio::test]
async fn malformed_pty_req_too_many_modes_does_not_crash_server() {
    let (signal, panicked) = capture_panics(async {
        tokio::time::timeout(
            Duration::from_secs(3),
            raw_pty_req_signal(|server_channel| {
                let mut modes = Vec::with_capacity(5 * 131 + 1);
                for value in 0..131u32 {
                    modes.push(Pty::VINTR as u8);
                    modes.extend_from_slice(&value.to_be_bytes());
                }
                modes.push(Pty::TTY_OP_END as u8);
                pty_req_payload(server_channel, &modes)
            }),
        )
        .await
    })
    .await;

    assert!(!panicked, "oversized pty modes caused an internal panic");
    assert!(
        matches!(
            &signal,
            Ok(ServerSignal::Closed | ServerSignal::ProtocolError(_) | ServerSignal::Survived)
        ),
        "oversized pty modes panicked or hung at the parser: {signal:?}"
    );
    assert_not_task_panic(signal);
}

#[tokio::test]
async fn malformed_pty_req_rejects_bytes_after_mode_end() {
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        raw_pty_req_signal(|server_channel| {
            pty_req_payload(server_channel, &[Pty::TTY_OP_END as u8, 0])
        }),
    )
    .await;

    assert!(
        matches!(
            result,
            Ok(ServerSignal::Closed | ServerSignal::ProtocolError(_))
        ),
        "server accepted trailing bytes inside pty terminal modes: {result:?}"
    );
}

#[tokio::test]
async fn keyboard_interactive_rejects_excessive_prompt_count() {
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        keyboard_interactive_prompt_count_signal(),
    )
    .await;

    assert!(
        matches!(result, Ok(ServerSignal::ProtocolError(_))),
        "client did not reject a large keyboard-interactive prompt count: {result:?}"
    );
}

#[tokio::test]
#[cfg(feature = "flate2")]
async fn zlib_decompression_rejects_excessive_expansion() {
    let compressed = compressed_zero_payload(OVERSIZED_DECOMPRESSED_LEN);
    assert!(
        compressed.len() < OVERSIZED_DECOMPRESSED_LEN / 128,
        "fixture is not a high-ratio compressed payload"
    );

    let mut decompressor = compression::Decompress::Zlib(flate2::Decompress::new(false));
    let mut output = Vec::new();

    assert!(
        matches!(
            decompressor.decompress(&compressed, &mut output),
            Err(russh::Error::PacketSize(_))
        ),
        "decompression should reject expansion beyond the transport packet bound"
    );
}

#[tokio::test]
async fn agent_client_rejects_oversized_response_before_body_read() {
    let saw_body_read = Arc::new(AtomicBool::new(false));
    let stream = OversizedAgentResponse {
        stage: 0,
        saw_body_read: saw_body_read.clone(),
    };
    let mut client = AgentClient::connect(stream);

    let result = tokio::time::timeout(Duration::from_secs(3), client.request_identities()).await;

    assert!(
        matches!(result, Ok(Err(_))),
        "agent client did not fail after an oversized response length: {result:?}"
    );
    assert!(
        !saw_body_read.load(Ordering::SeqCst),
        "agent client attempted to read an oversized response body"
    );
}

#[tokio::test]
async fn agent_server_rejects_oversized_request_before_body_read() {
    let saw_body_read = Arc::new(AtomicBool::new(false));
    let stream = OversizedAgentRequest {
        stage: 0,
        saw_body_read: saw_body_read.clone(),
    };
    let listener = stream::iter(vec![Ok(stream)]);

    let serve = tokio::spawn(async move {
        let _ = russh::keys::agent::server::serve(listener, ()).await;
    });

    tokio::time::timeout(Duration::from_secs(3), serve)
        .await
        .unwrap()
        .unwrap();

    assert!(
        !saw_body_read.load(Ordering::SeqCst),
        "agent server attempted to read an oversized request body"
    );
}

#[tokio::test]
async fn service_request_with_trailing_bytes_rejected_by_server() {
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        raw_service_request_signal(|payload| {
            payload.push(MSG_SERVICE_REQUEST);
            encode_string(payload, b"ssh-userauth");
            payload.push(0);
        }),
    )
    .await;

    assert!(
        matches!(
            result,
            Ok(ServerSignal::Closed | ServerSignal::ProtocolError(_))
        ),
        "server accepted a service request with trailing bytes: {result:?}"
    );
}

#[tokio::test]
async fn auth_none_with_trailing_bytes_rejected_by_server() {
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        raw_auth_request_signal(|payload| {
            payload.push(MSG_USERAUTH_REQUEST);
            encode_string(payload, b"test");
            encode_string(payload, b"ssh-connection");
            encode_string(payload, b"none");
            payload.push(0);
        }),
    )
    .await;

    assert!(
        matches!(
            result,
            Ok(ServerSignal::Closed | ServerSignal::ProtocolError(_))
        ),
        "server accepted a none auth request with trailing bytes: {result:?}"
    );
}

#[tokio::test]
async fn auth_password_with_trailing_bytes_rejected_by_server() {
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        raw_auth_request_signal(|payload| {
            payload.push(MSG_USERAUTH_REQUEST);
            encode_string(payload, b"test");
            encode_string(payload, b"ssh-connection");
            encode_string(payload, b"password");
            payload.push(0);
            encode_string(payload, b"secret");
            payload.push(0);
        }),
    )
    .await;

    assert!(
        matches!(
            result,
            Ok(ServerSignal::Closed | ServerSignal::ProtocolError(_))
        ),
        "server accepted a password auth request with trailing bytes: {result:?}"
    );
}

#[tokio::test]
async fn auth_password_change_request_uses_normal_rejection_path() {
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        raw_auth_request_signal(|payload| {
            payload.push(MSG_USERAUTH_REQUEST);
            encode_string(payload, b"test");
            encode_string(payload, b"ssh-connection");
            encode_string(payload, b"password");
            payload.push(1);
            encode_string(payload, b"old-secret");
            encode_string(payload, b"new-secret");
        }),
    )
    .await;

    assert!(
        matches!(result, Ok(ServerSignal::Survived)),
        "password change request should be rejected without a protocol error: {result:?}"
    );
}

#[cfg(windows)]
#[tokio::test]
async fn pageant_rejects_oversized_response_before_body_read() {
    let saw_body_read = Arc::new(AtomicBool::new(false));
    let stream = OversizedAgentResponse {
        stage: 0,
        saw_body_read: saw_body_read.clone(),
    };
    let mut client = AgentClient::connect(stream);

    let result = tokio::time::timeout(Duration::from_secs(3), client.request_identities()).await;

    assert!(matches!(result, Ok(Err(_))));
    assert!(
        !saw_body_read.load(Ordering::SeqCst),
        "Pageant-compatible agent framing attempted to read an oversized response body"
    );
}

#[derive(Debug)]
enum ServerSignal {
    Closed,
    ProtocolError(String),
    Panicked,
    Survived,
}

fn assert_not_task_panic(signal: Result<ServerSignal, tokio::time::error::Elapsed>) {
    match signal {
        Ok(ServerSignal::ProtocolError(error)) => {
            assert_ne!(error, "JoinError", "server task panicked")
        }
        Ok(ServerSignal::Panicked) => panic!("server task panicked"),
        Ok(ServerSignal::Closed | ServerSignal::Survived) => {}
        Err(error) => panic!("server task hung: {error}"),
    }
}

async fn capture_panics<T>(future: impl std::future::Future<Output = T>) -> (T, bool) {
    static PANIC_HOOK_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    let _guard = PANIC_HOOK_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap();
    let panicked = Arc::new(AtomicBool::new(false));
    let panicked_hook = panicked.clone();
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |_| {
        panicked_hook.store(true, Ordering::SeqCst);
    }));

    let result = future.await;

    std::panic::set_hook(previous_hook);
    (result, panicked.load(Ordering::SeqCst))
}

async fn raw_pty_req_signal(build_payload: impl FnOnce(u32) -> Vec<u8>) -> ServerSignal {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mut server_task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let running = server::run_stream(no_crypto_server_config(), socket, MalformedInputServer)
            .await
            .unwrap();
        running.await
    });

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    raw_client_no_crypto_handshake(&mut stream).await.unwrap();
    raw_auth_none(&mut stream).await.unwrap();
    let server_channel = raw_open_session(&mut stream).await.unwrap();
    stream
        .write_all(&ssh_packet(&build_payload(server_channel)))
        .await
        .unwrap();
    stream.flush().await.unwrap();

    match tokio::time::timeout(Duration::from_millis(200), &mut server_task).await {
        Ok(Ok(Ok(()))) => ServerSignal::Closed,
        Ok(Ok(Err(error))) => ServerSignal::ProtocolError(error.to_string()),
        Ok(Err(join)) if join.is_panic() => ServerSignal::Panicked,
        Err(_) => {
            server_task.abort();
            ServerSignal::Survived
        }
        _ => ServerSignal::Closed,
    }
}

async fn keyboard_interactive_prompt_count_signal() -> ServerSignal {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut config = server::Config::default();
        config.inactivity_timeout = None;
        config.auth_rejection_time = Duration::from_millis(1);
        config.auth_rejection_time_initial = Some(Duration::from_millis(1));
        config
            .keys
            .push(PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap());
        let running = server::run_stream(
            Arc::new(config),
            socket,
            MalformedPromptServer {
                prompt_count: EXCESSIVE_PROMPT_COUNT,
            },
        )
        .await
        .unwrap();
        let _ = running.await;
    });

    let result = match client::connect(
        Arc::new(client::Config::default()),
        addr,
        MalformedInputClient,
    )
    .await
    {
        Ok(mut session) => {
            session
                .authenticate_keyboard_interactive_start("test", None::<String>)
                .await
        }
        Err(error) => Err(error),
    };

    let _ = server_task.await;

    match result {
        Ok(_) => ServerSignal::Closed,
        Err(error) => ServerSignal::ProtocolError(error.to_string()),
    }
}

async fn raw_service_request_signal(
    build_payload: impl FnOnce(&mut Vec<u8>) + 'static,
) -> ServerSignal {
    raw_auth_phase_signal(|stream| {
        Box::pin(async move {
            let mut payload = Vec::new();
            build_payload(&mut payload);
            stream.write_all(&ssh_packet(&payload)).await?;
            stream.flush().await
        })
    })
    .await
}

async fn raw_auth_request_signal(
    build_payload: impl FnOnce(&mut Vec<u8>) + 'static,
) -> ServerSignal {
    raw_auth_phase_signal(|stream| {
        Box::pin(async move {
            let mut service = Vec::new();
            service.push(MSG_SERVICE_REQUEST);
            encode_string(&mut service, b"ssh-userauth");
            stream.write_all(&ssh_packet(&service)).await?;

            let accept = read_packet(stream).await?;
            assert_eq!(accept.first(), Some(&MSG_SERVICE_ACCEPT));

            let mut payload = Vec::new();
            build_payload(&mut payload);
            stream.write_all(&ssh_packet(&payload)).await?;
            stream.flush().await
        })
    })
    .await
}

async fn raw_auth_phase_signal<F>(send_malformed: F) -> ServerSignal
where
    F: for<'a> FnOnce(
        &'a mut tokio::net::TcpStream,
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<()>> + 'a>>,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mut server_task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let running = server::run_stream(no_crypto_server_config(), socket, MalformedInputServer)
            .await
            .unwrap();
        running.await
    });

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    raw_client_no_crypto_handshake(&mut stream).await.unwrap();
    send_malformed(&mut stream).await.unwrap();

    match tokio::time::timeout(Duration::from_millis(200), &mut server_task).await {
        Ok(Ok(Ok(()))) => ServerSignal::Closed,
        Ok(Ok(Err(error))) => ServerSignal::ProtocolError(error.to_string()),
        Ok(Err(join)) if join.is_panic() => ServerSignal::Panicked,
        Err(_) => {
            server_task.abort();
            ServerSignal::Survived
        }
        _ => ServerSignal::Closed,
    }
}

fn no_crypto_server_config() -> Arc<server::Config> {
    let mut config = server::Config::default();
    config.inactivity_timeout = None;
    config.auth_rejection_time = Duration::from_millis(1);
    config.auth_rejection_time_initial = Some(Duration::from_millis(1));
    config.preferred = no_crypto_preferred();
    config
        .keys
        .push(PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap());
    Arc::new(config)
}

fn no_crypto_preferred() -> russh::Preferred {
    russh::Preferred {
        kex: Cow::Owned(vec![kex::NONE]),
        key: Cow::Owned(vec![Algorithm::Ed25519]),
        cipher: Cow::Owned(vec![cipher::NONE]),
        mac: Cow::Owned(vec![mac::NONE]),
        compression: Cow::Owned(vec![compression::NONE]),
    }
}

async fn raw_client_no_crypto_handshake(stream: &mut tokio::net::TcpStream) -> io::Result<()> {
    stream.write_all(b"SSH-2.0-russh-test\r\n").await?;
    read_ssh_id(stream).await?;
    let _server_kex = read_packet(stream).await?;
    stream
        .write_all(&ssh_packet(&kexinit_payload("none")))
        .await?;
    let newkeys = read_packet(stream).await?;
    assert_eq!(newkeys.first(), Some(&MSG_NEWKEYS));
    stream.write_all(&ssh_packet(&[MSG_NEWKEYS])).await?;
    stream.flush().await
}

async fn raw_auth_none(stream: &mut tokio::net::TcpStream) -> io::Result<()> {
    let mut service = Vec::new();
    service.push(MSG_SERVICE_REQUEST);
    encode_string(&mut service, b"ssh-userauth");
    stream.write_all(&ssh_packet(&service)).await?;

    let accept = read_packet(stream).await?;
    assert_eq!(accept.first(), Some(&MSG_SERVICE_ACCEPT));

    let mut auth = Vec::new();
    auth.push(MSG_USERAUTH_REQUEST);
    encode_string(&mut auth, b"test");
    encode_string(&mut auth, b"ssh-connection");
    encode_string(&mut auth, b"none");
    stream.write_all(&ssh_packet(&auth)).await?;

    let success = read_packet(stream).await?;
    assert_eq!(success.first(), Some(&MSG_USERAUTH_SUCCESS));
    Ok(())
}

async fn raw_open_session(stream: &mut tokio::net::TcpStream) -> io::Result<u32> {
    let mut open = Vec::new();
    open.push(MSG_CHANNEL_OPEN);
    encode_string(&mut open, b"session");
    push_u32(&mut open, 0);
    push_u32(&mut open, 1024 * 1024);
    push_u32(&mut open, 32 * 1024);
    stream.write_all(&ssh_packet(&open)).await?;

    let confirmation = read_packet(stream).await?;
    assert_eq!(confirmation.first(), Some(&MSG_CHANNEL_OPEN_CONFIRMATION));
    Ok(BigEndian::read_u32(&confirmation[5..9]))
}

fn pty_req_payload(server_channel: u32, terminal_modes: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(MSG_CHANNEL_REQUEST);
    push_u32(&mut payload, server_channel);
    encode_string(&mut payload, b"pty-req");
    payload.push(1);
    encode_string(&mut payload, b"xterm");
    push_u32(&mut payload, 80);
    push_u32(&mut payload, 24);
    push_u32(&mut payload, 0);
    push_u32(&mut payload, 0);
    encode_string(&mut payload, terminal_modes);
    payload
}

fn kexinit_payload(kex_name: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(MSG_KEXINIT);
    payload.extend_from_slice(&[0; 16]);
    encode_name_list(&mut payload, &[kex_name]);
    encode_name_list(&mut payload, &["ssh-ed25519"]);
    encode_name_list(&mut payload, &["none"]);
    encode_name_list(&mut payload, &["none"]);
    encode_name_list(&mut payload, &["none"]);
    encode_name_list(&mut payload, &["none"]);
    encode_name_list(&mut payload, &["none"]);
    encode_name_list(&mut payload, &["none"]);
    encode_name_list(&mut payload, &[]);
    encode_name_list(&mut payload, &[]);
    payload.push(0);
    push_u32(&mut payload, 0);
    payload
}

fn ssh_packet(payload: &[u8]) -> Vec<u8> {
    let mut padding_len = 8 - ((5 + payload.len()) % 8);
    if padding_len < 4 {
        padding_len += 8;
    }
    let packet_len = 1 + payload.len() + padding_len;
    let mut packet = Vec::with_capacity(4 + packet_len);
    push_u32(&mut packet, packet_len as u32);
    packet.push(padding_len as u8);
    packet.extend_from_slice(payload);
    packet.resize(packet.len() + padding_len, 0);
    packet
}

async fn read_packet(stream: &mut tokio::net::TcpStream) -> io::Result<Vec<u8>> {
    let mut len_buf = [0; 4];
    stream.read_exact(&mut len_buf).await?;
    let packet_len = BigEndian::read_u32(&len_buf) as usize;
    let mut packet = vec![0; packet_len];
    stream.read_exact(&mut packet).await?;
    let padding_len = packet[0] as usize;
    Ok(packet[1..packet.len() - padding_len].to_vec())
}

async fn read_ssh_id(stream: &mut tokio::net::TcpStream) -> io::Result<Vec<u8>> {
    let mut id = Vec::new();
    loop {
        let mut byte = [0];
        stream.read_exact(&mut byte).await?;
        id.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(id);
        }
    }
}

fn encode_name_list(buf: &mut Vec<u8>, names: &[&str]) {
    encode_string(buf, names.join(",").as_bytes());
}

fn encode_string(buf: &mut Vec<u8>, value: &[u8]) {
    push_u32(buf, value.len() as u32);
    buf.extend_from_slice(value);
}

fn push_u32(buf: &mut Vec<u8>, value: u32) {
    let mut bytes = [0; 4];
    BigEndian::write_u32(&mut bytes, value);
    buf.extend_from_slice(&bytes);
}

#[cfg(feature = "flate2")]
fn compressed_zero_payload(len: usize) -> Vec<u8> {
    let input = vec![0; len];
    let mut compressor = flate2::Compress::new(flate2::Compression::best(), false);
    let mut output = vec![0; 1024];
    let n_in = compressor.total_in() as usize;
    let n_out = compressor.total_out() as usize;
    loop {
        let n_in_now = compressor.total_in() as usize - n_in;
        let n_out_now = compressor.total_out() as usize - n_out;
        match compressor
            .compress(
                &input[n_in_now..],
                &mut output[n_out_now..],
                FlushCompress::Finish,
            )
            .unwrap()
        {
            flate2::Status::BufError => output.resize(output.len() * 2, 0),
            flate2::Status::Ok => output.resize(output.len() * 2, 0),
            flate2::Status::StreamEnd => {
                output.truncate(compressor.total_out() as usize);
                return output;
            }
        }
    }
}

#[derive(Clone)]
struct MalformedInputServer;

impl server::Handler for MalformedInputServer {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<server::Msg>,
        _session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        _channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Clone)]
struct MalformedPromptServer {
    prompt_count: u32,
}

impl server::Handler for MalformedPromptServer {
    type Error = russh::Error;

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _user: &str,
        _submethods: &str,
        _response: Option<server::Response<'a>>,
    ) -> Result<server::Auth, Self::Error> {
        let prompts = (0..self.prompt_count)
            .map(|_| (Cow::Borrowed("test"), false))
            .collect::<Vec<_>>();

        Ok(server::Auth::Partial {
            name: Cow::Borrowed("test"),
            instructions: Cow::Borrowed("too many prompts"),
            prompts: Cow::Owned(prompts),
        })
    }
}

struct MalformedInputClient;

impl client::Handler for MalformedInputClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

struct OversizedAgentResponse {
    stage: u8,
    saw_body_read: Arc<AtomicBool>,
}

impl AsyncRead for OversizedAgentResponse {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.stage == 0 {
            buf.put_slice(&(OVERSIZED_AGENT_MESSAGE_LEN as u32).to_be_bytes());
            self.stage = 1;
            return Poll::Ready(Ok(()));
        }

        if buf.remaining() >= OVERSIZED_AGENT_MESSAGE_LEN {
            self.saw_body_read.store(true, Ordering::SeqCst);
        }

        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized response body read",
        )))
    }
}

impl AsyncWrite for OversizedAgentResponse {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct OversizedAgentRequest {
    stage: u8,
    saw_body_read: Arc<AtomicBool>,
}

impl AsyncRead for OversizedAgentRequest {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.stage == 0 {
            buf.put_slice(&(OVERSIZED_AGENT_MESSAGE_LEN as u32).to_be_bytes());
            self.stage = 1;
            return Poll::Ready(Ok(()));
        }

        if buf.remaining() >= OVERSIZED_AGENT_MESSAGE_LEN {
            self.saw_body_read.store(true, Ordering::SeqCst);
        }

        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized request body read",
        )))
    }
}

impl AsyncWrite for OversizedAgentRequest {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
