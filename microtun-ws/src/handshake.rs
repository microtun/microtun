//! The RFC 6455 opening handshake.
//!
//! A WebSocket connection begins as one HTTP/1.1 `GET` carrying an `Upgrade`
//! header and a client nonce, answered by `101 Switching Protocols` and the
//! SHA-1 digest of that nonce. The digest proves only that the responder
//! understood the request — it is not authentication, and RFC 6455 does not
//! present it as any — so nothing in this module decides who may connect. That
//! is the embedding's job, and the two phases here exist so it can be done at
//! the right moment: [`request_upgrade`] reads and validates the request,
//! after which the caller either completes the upgrade with [`Upgrade::accept`]
//! or turns the caller away with [`reject`].
//!
//! # Why the head is read one byte at a time
//!
//! The end of an HTTP head is a byte sequence, not a length, so a reader that
//! pulls in chunks can and eventually will read part of the first WebSocket
//! frame while looking for `\r\n\r\n`. Keeping those bytes would mean carrying
//! a leftover buffer into the frame decoder for the rest of the connection —
//! state that exists solely because of the first few hundred bytes of the
//! session, and that has to be right in every path that touches the stream.
//!
//! Reading to the delimiter one byte at a time cannot overshoot, so the
//! connection starts with no leftovers at all. The cost is a few hundred small
//! reads once per connection, on transports that either buffer already
//! (smoltcp, a Tokio socket behind the split) or are carrying a control
//! channel where a handshake's worth of syscalls is not the expensive part.

use core::fmt::Write as _;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use embedded_io_async::{Read, Write};
use sha1::{Digest, Sha1};

use crate::{
    error::Error,
    io::{Cursor, flush, read_exact, write_all},
    mask::Masker,
};

/// The fixed GUID RFC 6455 §1.3 concatenates with the client nonce.
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The only WebSocket version this crate speaks.
const VERSION: &str = "13";

/// Characters in the base64 of a 20-byte SHA-1 digest.
const ACCEPT_LEN: usize = 28;

/// Characters in the base64 of a 16-byte client nonce.
const NONCE_TEXT_LEN: usize = 24;

/// Headers parsed from one handshake message.
///
/// A browser sends rather more than the handshake needs — `Origin`,
/// `User-Agent`, `Accept-Encoding`, cookies — and all of them count against
/// this bound even though none is read.
const MAX_HEADERS: usize = 32;

/// What a client asks for.
#[derive(Debug, Clone, Copy)]
pub struct ClientRequest<'a> {
    /// The `Host` header, which is the server's inner address here.
    pub host: &'a str,
    /// The request path, for example `/v1/peers`.
    pub path: &'a str,
}

/// What a server accepts.
#[derive(Debug, Clone, Copy)]
pub struct ServerConfig<'a> {
    /// The only path this server upgrades. A request for anything else is
    /// refused rather than upgraded, so a mistyped endpoint fails at the
    /// handshake instead of opening a session that answers nothing.
    pub path: &'a str,
}

/// An HTTP status a server may answer a handshake with instead of upgrading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The request is not a well-formed WebSocket upgrade for this endpoint.
    BadRequest,
    /// The caller is authenticated but not permitted to use this endpoint.
    Forbidden,
    /// Nothing is served at the requested path.
    NotFound,
    /// The endpoint is temporarily unable to accept another connection.
    ServiceUnavailable,
}

impl Status {
    const fn line(self) -> &'static str {
        match self {
            Status::BadRequest => "400 Bad Request",
            Status::Forbidden => "403 Forbidden",
            Status::NotFound => "404 Not Found",
            Status::ServiceUnavailable => "503 Service Unavailable",
        }
    }
}

/// A validated client upgrade request, ready to be accepted or refused.
///
/// Holding this value means the request was a conforming WebSocket handshake
/// for the configured path. It does **not** mean the caller is
/// allowed to proceed: that question belongs to the embedding, which is
/// exactly why accepting is a separate step.
#[derive(Debug)]
pub struct Upgrade {
    accept: [u8; ACCEPT_LEN],
}

impl Upgrade {
    /// Complete the upgrade with `101 Switching Protocols`.
    pub async fn accept<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        let mut buf = [0u8; 256];
        let mut head = Cursor::new(&mut buf);
        let accept = core::str::from_utf8(&self.accept).map_err(|_| Error::Handshake)?;
        write!(
            &mut head,
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n"
        )
        .map_err(|_| Error::TooLarge)?;
        write!(&mut head, "\r\n").map_err(|_| Error::TooLarge)?;
        write_all(writer, head.written()).await?;
        flush(writer).await
    }
}

/// Read and validate one client handshake.
///
/// `scratch` holds the HTTP head for the duration of the call; the returned
/// value borrows nothing from it.
pub async fn request_upgrade<R: Read>(
    reader: &mut R,
    config: &ServerConfig<'_>,
    scratch: &mut [u8],
) -> Result<Upgrade, Error> {
    let len = read_head(reader, scratch).await?;

    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(&scratch[..len]) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err(Error::Handshake),
    }

    if !request.method.is_some_and(|method| method == "GET") {
        return Err(Error::Handshake);
    }
    // HTTP/1.1 or later. `httparse` reports the minor version only.
    if request.version != Some(1) {
        return Err(Error::Handshake);
    }
    // Compare the path alone: a query string is not part of the endpoint, and
    // this crate has nothing to do with one.
    let path = request.path.ok_or(Error::Handshake)?;
    let path = path.split('?').next().unwrap_or(path);
    if path != config.path {
        return Err(Error::Handshake);
    }

    let headers = request.headers;
    if !header_matches(headers, "upgrade", "websocket")
        || !header_has_token(headers, "connection", "upgrade")
        || !header_matches(headers, "sec-websocket-version", VERSION)
    {
        return Err(Error::Handshake);
    }

    let key = header(headers, "sec-websocket-key").ok_or(Error::Handshake)?;
    // A conforming key is the base64 of 16 bytes. The digest would be computed
    // over any string at all, so checking the shape here is what makes a
    // client that sends something else fail at the handshake rather than
    // succeed into a session neither end can explain.
    if key.len() != NONCE_TEXT_LEN {
        return Err(Error::Handshake);
    }

    Ok(Upgrade {
        accept: accept_token(key),
    })
}

/// Refuse a handshake with an HTTP status.
///
/// This is the only way to turn a caller away *before* the connection becomes
/// a WebSocket. It matters that it exists: once the upgrade completes, the
/// same refusal has to be a close frame, which a browser surfaces as a bare
/// `onclose` rather than as a status a fetch-style client can read.
pub async fn reject<W: Write>(writer: &mut W, status: Status) -> Result<(), Error> {
    let mut buf = [0u8; 128];
    let mut head = Cursor::new(&mut buf);
    write!(
        &mut head,
        "HTTP/1.1 {}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        status.line()
    )
    .map_err(|_| Error::TooLarge)?;
    write_all(writer, head.written()).await?;
    flush(writer).await
}

/// Perform the client half of the handshake.
pub(crate) async fn client_handshake<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    request: &ClientRequest<'_>,
    mask: &mut Masker,
    scratch: &mut [u8],
) -> Result<(), Error> {
    let nonce = mask.nonce();
    let mut nonce_text = [0u8; NONCE_TEXT_LEN];
    STANDARD
        .encode_slice(nonce, &mut nonce_text)
        .map_err(|_| Error::Handshake)?;
    let nonce_text = core::str::from_utf8(&nonce_text).map_err(|_| Error::Handshake)?;

    {
        let mut head = Cursor::new(scratch);
        write!(
            &mut head,
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: {}\r\n",
            request.path, request.host, nonce_text, VERSION
        )
        .map_err(|_| Error::TooLarge)?;
        write!(&mut head, "\r\n").map_err(|_| Error::TooLarge)?;
        write_all(writer, head.written()).await?;
        flush(writer).await?;
    }

    let expected = accept_token(nonce_text);
    let len = read_head(reader, scratch).await?;

    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    match response.parse(&scratch[..len]) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err(Error::Handshake),
    }
    if response.code != Some(101) {
        return Err(Error::Handshake);
    }

    let headers = response.headers;
    if !header_matches(headers, "upgrade", "websocket")
        || !header_has_token(headers, "connection", "upgrade")
    {
        return Err(Error::Handshake);
    }
    // The digest is checked because the RFC requires it, and because a
    // response that echoes the wrong one is not a WebSocket server that
    // understood this request — it is something else answering on this port.
    let accept = header(headers, "sec-websocket-accept").ok_or(Error::Handshake)?;
    if accept.as_bytes() != expected {
        return Err(Error::Handshake);
    }
    Ok(())
}

/// `base64(sha1(key ++ GUID))`, the value RFC 6455 §4.2.2 defines.
fn accept_token(key: &str) -> [u8; ACCEPT_LEN] {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(GUID.as_bytes());
    let digest = hasher.finalize();

    let mut token = [0u8; ACCEPT_LEN];
    let written = STANDARD
        .encode_slice(digest.as_slice(), &mut token)
        .unwrap_or(0);
    debug_assert_eq!(written, ACCEPT_LEN);
    token
}

/// Read an HTTP head up to and including its terminating blank line.
async fn read_head<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, Error> {
    let mut len = 0;
    loop {
        if len == buf.len() {
            return Err(Error::TooLarge);
        }
        read_exact(reader, &mut buf[len..len + 1]).await?;
        len += 1;
        if len >= 4 && buf[len - 4..len] == *b"\r\n\r\n" {
            return Ok(len);
        }
    }
}

/// The value of one header, by case-insensitive name.
fn header<'a>(headers: &[httparse::Header<'a>], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .and_then(|header| core::str::from_utf8(header.value).ok())
        .map(str::trim)
}

/// Whether a header is present with exactly this value, ignoring case.
fn header_matches(headers: &[httparse::Header<'_>], name: &str, value: &str) -> bool {
    header(headers, name).is_some_and(|found| found.eq_ignore_ascii_case(value))
}

/// Whether a comma-separated header contains this token.
///
/// `Connection` in particular is a token list — a browser behind a proxy sends
/// `keep-alive, Upgrade` — so an equality test against `upgrade` would reject
/// a perfectly ordinary request.
fn header_has_token(headers: &[httparse::Header<'_>], name: &str, token: &str) -> bool {
    header(headers, name).is_some_and(|value| {
        value
            .split(',')
            .any(|found| found.trim().eq_ignore_ascii_case(token))
    })
}

#[cfg(test)]
mod tests {
    use std::{string::String, vec::Vec};

    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;
    use crate::mask::Masker;

    /// The example exchange from RFC 6455 §1.3. If this crate ever computes a
    /// different token, every browser will refuse the connection, so the one
    /// published vector is worth pinning.
    #[test]
    fn the_accept_token_matches_the_rfc_example() {
        let token = accept_token("dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(
            core::str::from_utf8(&token).unwrap(),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    /// An in-memory transport that hands out a canned read stream and records
    /// everything written to it.
    struct Pipe {
        input: Vec<u8>,
        read: usize,
        output: Vec<u8>,
    }

    impl Pipe {
        fn new(input: &str) -> Self {
            Self {
                input: input.as_bytes().to_vec(),
                read: 0,
                output: Vec::new(),
            }
        }

        fn written(&self) -> String {
            String::from_utf8(self.output.clone()).expect("handshakes are ASCII")
        }
    }

    impl embedded_io_async::ErrorType for Pipe {
        type Error = embedded_io_async::ErrorKind;
    }

    impl Read for Pipe {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            let remaining = self.input.len() - self.read;
            if remaining == 0 || buf.is_empty() {
                return Ok(0);
            }
            let take = remaining.min(buf.len());
            buf[..take].copy_from_slice(&self.input[self.read..self.read + take]);
            self.read += take;
            Ok(take)
        }
    }

    impl Write for Pipe {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }

        // Writes land in `output` immediately, so there is nothing buffered
        // for a flush to push. It is still a required method: a transport that
        // *does* buffer has to be told when a message ends, which is exactly
        // what the handshake and every frame write rely on.
        async fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn block_on<F: core::future::Future>(future: F) -> F::Output {
        // The handshake code never yields on these transports: every read is
        // already buffered and every write completes immediately. Polling once
        // is therefore enough, and it keeps an async runtime out of the unit
        // tests.
        let mut future = core::pin::pin!(future);
        let waker = core::task::Waker::noop();
        let mut context = core::task::Context::from_waker(waker);
        match future.as_mut().poll(&mut context) {
            core::task::Poll::Ready(output) => output,
            core::task::Poll::Pending => panic!("handshake futures never pend on a Pipe"),
        }
    }

    const CONFIG: ServerConfig<'static> = ServerConfig { path: "/v1/peers" };

    fn test_mask(seed: u8) -> Masker {
        let mut entropy = ChaCha20Rng::from_seed([seed; 32]);
        Masker::from_rng(&mut entropy)
    }

    fn browser_request() -> String {
        String::from(
            "GET /v1/peers HTTP/1.1\r\n\
             Host: 10.0.0.9\r\n\
             Upgrade: websocket\r\n\
             Connection: keep-alive, Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Origin: http://10.0.0.9\r\n\
             \r\n",
        )
    }

    #[test]
    fn a_browser_handshake_is_accepted_and_echoed() {
        let mut pipe = Pipe::new(&browser_request());
        let mut scratch = [0u8; 1024];
        let upgrade = block_on(request_upgrade(&mut pipe, &CONFIG, &mut scratch))
            .expect("a conforming browser request upgrades");
        block_on(upgrade.accept(&mut pipe)).expect("the response is written");

        let response = pipe.written();
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(response.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"));
        assert!(response.ends_with("\r\n\r\n"));
    }

    #[test]
    fn non_conforming_requests_are_refused() {
        let original = browser_request();
        let cases = [
            // Wrong endpoint.
            original.replace("/v1/peers", "/v2/peers"),
            // Not an upgrade at all.
            original.replace("Upgrade: websocket\r\n", ""),
            // A version this crate does not implement.
            original.replace("Sec-WebSocket-Version: 13", "Sec-WebSocket-Version: 8"),
            // A nonce that is not 16 base64-encoded bytes.
            original.replace("dGhlIHNhbXBsZSBub25jZQ==", "short"),
            // A method that is not GET.
            original.replace("GET ", "POST "),
        ];
        for request in cases {
            let mut pipe = Pipe::new(&request);
            let mut scratch = [0u8; 1024];
            assert_eq!(
                block_on(request_upgrade(&mut pipe, &CONFIG, &mut scratch)).unwrap_err(),
                Error::Handshake,
                "request must be refused:\n{request}"
            );
        }
    }

    /// A query string is not part of the endpoint.
    #[test]
    fn a_query_string_does_not_change_the_path() {
        let request = browser_request().replace("/v1/peers", "/v1/peers?trace=1");
        let mut pipe = Pipe::new(&request);
        let mut scratch = [0u8; 1024];
        assert!(block_on(request_upgrade(&mut pipe, &CONFIG, &mut scratch)).is_ok());
    }

    /// A head with no terminator must not be read forever.
    #[test]
    fn an_oversized_head_is_rejected() {
        let mut request = String::from("GET /v1/peers HTTP/1.1\r\nX: ");
        request.push_str(&"a".repeat(4096));
        let mut pipe = Pipe::new(&request);
        let mut scratch = [0u8; 512];
        assert_eq!(
            block_on(request_upgrade(&mut pipe, &CONFIG, &mut scratch)).unwrap_err(),
            Error::TooLarge
        );
    }

    #[test]
    fn the_client_half_round_trips_against_the_server_half() {
        // Phase one: what the client puts on the wire.
        let mut client = Pipe::new("");
        let mut mask = test_mask(0x12);
        let mut scratch = [0u8; 512];
        let request = ClientRequest {
            host: "10.0.0.9",
            path: "/v1/peers",
        };
        // The response half of the exchange is missing, so the client fails at
        // end of stream — after having written a complete request.
        let mut reader = Pipe::new("");
        assert_eq!(
            block_on(client_handshake(
                &mut reader,
                &mut client,
                &request,
                &mut mask,
                &mut scratch
            ))
            .unwrap_err(),
            Error::Eof
        );
        let sent = client.written();
        assert!(sent.starts_with("GET /v1/peers HTTP/1.1\r\n"));
        assert!(sent.contains("Host: 10.0.0.9\r\n"));
        assert!(sent.contains("Sec-WebSocket-Version: 13\r\n"));

        // Phase two: the server accepts exactly that request, and the client
        // accepts exactly that response. Doing it in one test is what proves
        // the two halves agree on the digest.
        let mut server = Pipe::new(&sent);
        let mut server_scratch = [0u8; 1024];
        let upgrade = block_on(request_upgrade(&mut server, &CONFIG, &mut server_scratch))
            .expect("the server accepts its own client");
        block_on(upgrade.accept(&mut server)).expect("101 is written");

        let mut response = Pipe::new(&server.written());
        let mut sink = Pipe::new("");
        let mut mask = test_mask(0x12);
        block_on(client_handshake(
            &mut response,
            &mut sink,
            &request,
            &mut mask,
            &mut scratch,
        ))
        .expect("the client accepts the server's response");
    }

    /// A wrong digest means something other than this server answered.
    #[test]
    fn a_bad_accept_token_fails_the_client_handshake() {
        let response = "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\
             \r\n";
        let mut reader = Pipe::new(response);
        let mut writer = Pipe::new("");
        let mut mask = test_mask(7);
        let mut scratch = [0u8; 512];
        assert_eq!(
            block_on(client_handshake(
                &mut reader,
                &mut writer,
                &ClientRequest {
                    host: "10.0.0.9",
                    path: "/v1/peers",
                },
                &mut mask,
                &mut scratch
            ))
            .unwrap_err(),
            Error::Handshake
        );
    }

    #[test]
    fn a_rejection_is_a_plain_http_response() {
        let mut pipe = Pipe::new("");
        block_on(reject(&mut pipe, Status::Forbidden)).expect("the status is written");
        assert_eq!(
            pipe.written(),
            "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        );
    }
}
