//! End-to-end tests: the client half of this crate against the server half,
//! over a real asynchronous transport.
//!
//! The unit tests in `frame` and `handshake` cover the encodings in isolation.
//! What they cannot cover is the part that only exists when both halves run at
//! once — masking in one direction and not the other, control frames arriving
//! between data frames, and a close that has to be echoed before it is
//! reported.

use embedded_io_adapters::tokio_1::FromTokio;
use microtun_ws::{ClientRequest, CloseCode, Connection, Error, ServerConfig, Status};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use tokio::io::{DuplexStream, ReadHalf, WriteHalf, duplex, split};

const PATH: &str = "/v1/peers";
const CLIENT_REQUEST: ClientRequest<'static> = ClientRequest {
    host: "10.0.0.9",
    path: PATH,
};

const SERVER_CONFIG: ServerConfig<'static> = ServerConfig { path: PATH };

type Half<T> = FromTokio<T>;

fn test_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

type Ends = (
    Half<ReadHalf<DuplexStream>>,
    Half<WriteHalf<DuplexStream>>,
    Half<ReadHalf<DuplexStream>>,
    Half<WriteHalf<DuplexStream>>,
);

/// A connected pair of transports: (client reader, client writer, server
/// reader, server writer).
fn transport() -> Ends {
    let (client, server) = duplex(8192);
    let (client_reader, client_writer) = split(client);
    let (server_reader, server_writer) = split(server);
    (
        FromTokio::new(client_reader),
        FromTokio::new(client_writer),
        FromTokio::new(server_reader),
        FromTokio::new(server_writer),
    )
}

/// Accept one connection, echoing the upgrade the client asked for.
async fn accept(
    mut reader: Half<ReadHalf<DuplexStream>>,
    mut writer: Half<WriteHalf<DuplexStream>>,
) -> Connection<Half<ReadHalf<DuplexStream>>, Half<WriteHalf<DuplexStream>>> {
    let mut scratch = [0u8; 1024];
    let upgrade = microtun_ws::request_upgrade(&mut reader, &SERVER_CONFIG, &mut scratch)
        .await
        .expect("the client sends a conforming handshake");
    upgrade.accept(&mut writer).await.expect("101 is written");
    Connection::server(reader, writer)
}

/// Open one connection from the client side.
async fn connect(
    reader: Half<ReadHalf<DuplexStream>>,
    writer: Half<WriteHalf<DuplexStream>>,
    seed: u8,
) -> Connection<Half<ReadHalf<DuplexStream>>, Half<WriteHalf<DuplexStream>>> {
    let mut scratch = [0u8; 512];
    let mut rng = test_rng(seed);
    Connection::client(reader, writer, &CLIENT_REQUEST, &mut rng, &mut scratch)
        .await
        .expect("the server accepts the handshake")
}

/// Both halves of a connected, upgraded pair.
async fn pair() -> (
    Connection<Half<ReadHalf<DuplexStream>>, Half<WriteHalf<DuplexStream>>>,
    Connection<Half<ReadHalf<DuplexStream>>, Half<WriteHalf<DuplexStream>>>,
) {
    let (client_reader, client_writer, server_reader, server_writer) = transport();
    let server = tokio::spawn(accept(server_reader, server_writer));
    let client = connect(client_reader, client_writer, 0xDE).await;
    let server = server.await.expect("the server task completes");
    (client, server)
}

#[tokio::test]
async fn client_accepts_a_caller_owned_crypto_rng() {
    let (client_reader, client_writer, server_reader, server_writer) = transport();
    let server = tokio::spawn(accept(server_reader, server_writer));

    let mut scratch = [0u8; 512];
    let mut rng = test_rng(0xCA);
    let mut client = Connection::client(
        client_reader,
        client_writer,
        &CLIENT_REQUEST,
        &mut rng,
        &mut scratch,
    )
    .await
    .expect("the custom RNG client handshakes");
    let mut server = server.await.expect("the server task completes");

    client
        .send_text(b"generic mask source")
        .await
        .expect("sent");
    let mut buf = [0u8; 64];
    let len = server.recv_text(&mut buf).await.expect("received");
    assert_eq!(&buf[..len], b"generic mask source");
}

#[tokio::test]
async fn messages_cross_in_both_directions() {
    let (mut client, mut server) = pair().await;
    let mut buf = [0u8; 256];

    // Client to server: masked on the wire, plain when it arrives.
    client
        .send_text(br#"{"id":1,"method":"peer.by_key"}"#)
        .await
        .expect("the request is sent");
    let len = server.recv_text(&mut buf).await.expect("it arrives");
    assert_eq!(&buf[..len], br#"{"id":1,"method":"peer.by_key"}"#);

    // Server to client: unmasked.
    server
        .send_text(br#"{"id":1,"result":{"not_found":{}}}"#)
        .await
        .expect("the response is sent");
    let len = client.recv_text(&mut buf).await.expect("it arrives");
    assert_eq!(&buf[..len], br#"{"id":1,"result":{"not_found":{}}}"#);
}

/// Every length escape has to survive a real transport, not only the encoder.
#[tokio::test]
async fn long_messages_use_the_extended_length() {
    let (mut client, mut server) = pair().await;
    let mut buf = [0u8; 4096];

    for len in [0usize, 1, 125, 126, 1000, 4096] {
        let payload = vec![b'x'; len];
        client.send_text(&payload).await.expect("sent");
        let received = server.recv_text(&mut buf).await.expect("received");
        assert_eq!(&buf[..received], &payload[..], "{len}-byte message");
    }
}

/// A ping is answered without the caller doing anything but keep receiving.
#[tokio::test]
async fn pings_are_answered_inside_recv() {
    let (mut client, mut server) = pair().await;
    let mut buf = [0u8; 256];

    server
        .sender_mut()
        .send_ping(b"keepalive")
        .await
        .expect("the ping is sent");
    server
        .send_text(b"after")
        .await
        .expect("the message is sent");

    // The client never sees the ping: it answers it and goes on reading.
    let len = client
        .recv_text(&mut buf)
        .await
        .expect("the message arrives");
    assert_eq!(&buf[..len], b"after");

    // And the server sees the pong while waiting for the next message.
    client.send_text(b"reply").await.expect("sent");
    let len = server.recv_text(&mut buf).await.expect("the reply arrives");
    assert_eq!(&buf[..len], b"reply");
}

/// A message larger than the receive buffer is refused, and the refusal is a
/// close the sender can see rather than a silently truncated message.
#[tokio::test]
async fn an_oversized_message_closes_the_connection() {
    let (mut client, mut server) = pair().await;

    let payload = vec![b'x'; 300];
    client.send_text(&payload).await.expect("sent");

    let mut small = [0u8; 256];
    assert_eq!(
        server.recv_text(&mut small).await.unwrap_err(),
        Error::TooLarge
    );

    let mut buf = [0u8; 256];
    assert_eq!(
        client.recv_text(&mut buf).await.unwrap_err(),
        Error::Closed(Some(CloseCode::MESSAGE_TOO_BIG))
    );
}

/// Receiving is resumable: the resolvers drop the receive future every time a
/// command beats the socket, so a receive that is cancelled between two reads
/// must lose nothing. The test drives that directly by cancelling repeatedly
/// against a peer that dribbles a message out in pieces.
#[tokio::test]
async fn a_cancelled_receive_resumes_mid_message() {
    let (client_reader, client_writer, server_reader, server_writer) = transport();
    let server = tokio::spawn(accept(server_reader, server_writer));
    let mut client = connect(client_reader, client_writer, 7).await;
    let mut server = server.await.expect("the server task completes");

    let payload = vec![b'z'; 900];
    let sent = payload.clone();
    let writer = tokio::spawn(async move {
        // A pause long enough that the reader below has certainly given up on
        // its current poll before the rest of the message arrives.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        server.send_text(&sent).await.expect("sent");
        server
    });

    let mut buf = [0u8; 1024];
    // Poll the receive to exhaustion of patience, repeatedly, exactly as a
    // `select` against a busy command channel would.
    let len = loop {
        match tokio::time::timeout(
            std::time::Duration::from_millis(5),
            client.recv_text(&mut buf),
        )
        .await
        {
            Ok(result) => break result.expect("the message arrives"),
            Err(_) => continue,
        }
    };
    assert_eq!(&buf[..len], &payload[..]);
    writer.await.expect("the writer task completes");
}

#[tokio::test]
async fn a_close_is_reported_with_its_code() {
    let (mut client, mut server) = pair().await;

    server
        .close(CloseCode::POLICY_VIOLATION, "not admitted")
        .await
        .expect("the close is sent");

    let mut buf = [0u8; 256];
    assert_eq!(
        client.recv_text(&mut buf).await.unwrap_err(),
        Error::Closed(Some(CloseCode::POLICY_VIOLATION))
    );
    // Having closed, the client refuses to send anything more rather than
    // writing frames onto a stream the peer has stopped reading.
    assert_eq!(
        client.send_text(b"late").await.unwrap_err(),
        Error::AlreadyClosed
    );
}

/// The refusal path a server uses before it upgrades. A browser sees this as a
/// failed connection with an HTTP status, not as a WebSocket that opens and
/// immediately closes.
#[tokio::test]
async fn a_rejected_handshake_never_upgrades() {
    let (client_reader, client_writer, mut server_reader, mut server_writer) = transport();

    let server = tokio::spawn(async move {
        let mut scratch = [0u8; 1024];
        microtun_ws::request_upgrade(&mut server_reader, &SERVER_CONFIG, &mut scratch)
            .await
            .expect("the request itself is well formed");
        microtun_ws::reject(&mut server_writer, Status::Forbidden)
            .await
            .expect("the refusal is written");
    });

    let mut scratch = [0u8; 512];
    let mut rng = test_rng(1);
    let outcome = Connection::client(
        client_reader,
        client_writer,
        &CLIENT_REQUEST,
        &mut rng,
        &mut scratch,
    )
    .await;
    assert!(matches!(outcome, Err(Error::Handshake)));
    server.await.expect("the server task completes");
}
