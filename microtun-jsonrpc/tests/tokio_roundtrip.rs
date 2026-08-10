//! Integration coverage for raw Tokio 1.x transports:
//! `cargo test -p microtun-jsonrpc --features tokio`

#![cfg(feature = "tokio")]

use microtun_jsonrpc::{Connection, Handler, Notifier, Params, Reply, Responder};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

struct Calc;

impl Handler for Calc {
    fn handle_request(&mut self, method: &str, params: Params<'_>, resp: Responder<'_>) -> Reply {
        match method {
            "add" => match params.parse::<(i64, i64)>() {
                Ok((a, b)) => resp.ok(&(a + b)),
                Err(_) => resp.invalid_params(),
            },
            _ => resp.method_not_found(),
        }
    }
}

async fn read_frame<R>(reader: &mut R) -> Vec<u8>
where
    R: AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        reader.read_exact(&mut byte).await.unwrap();
        out.push(byte[0]);
        if byte[0] == b'\n' {
            return out;
        }
    }
}

#[tokio::test]
async fn tokio_connection_accepts_raw_tokio_halves() {
    let (client, server) = tokio::io::duplex(2048);
    let (client_reader, client_writer) = tokio::io::split(client);
    let (mut server_reader, mut server_writer) = tokio::io::split(server);

    let server_task = tokio::spawn(async move {
        let request = read_frame(&mut server_reader).await;
        assert_eq!(
            request,
            b"{\"jsonrpc\":\"2.0\",\"method\":\"compute\",\"params\":[5],\"id\":1}\n"
        );

        server_writer
            .write_all(
                b"{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"add\",\"params\":[3,4]}\n\
                  {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":99}\n",
            )
            .await
            .unwrap();
        server_writer.flush().await.unwrap();

        let response = read_frame(&mut server_reader).await;
        assert_eq!(response, b"{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":7}\n");
    });

    let mut connection: Connection<_, _, _, 512, 512> =
        Connection::from_tokio(client_reader, client_writer, Calc);
    let value: i64 = connection.call("compute", Some(&(5i64,))).await.unwrap();
    assert_eq!(value, 99);

    let (_reader, _writer, _handler) = connection.into_tokio_parts();
    server_task.await.unwrap();
}

#[tokio::test]
async fn tokio_notifier_accepts_raw_tokio_writer() {
    let (client, server) = tokio::io::duplex(512);
    let (_client_reader, client_writer) = tokio::io::split(client);
    let (mut server_reader, _server_writer) = tokio::io::split(server);

    let mut notifier: Notifier<_, 256> = Notifier::from_tokio(client_writer);
    notifier.notify("ping", Some(&[1u8, 2u8])).await.unwrap();

    assert_eq!(
        read_frame(&mut server_reader).await,
        b"{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"params\":[1,2]}\n"
    );

    let _writer = notifier.into_tokio_inner();
}
