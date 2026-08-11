//! Integration tests for the default (blocking) build.
//!
//! The transport is simulated with a scripted input slice (`&[u8]` already
//! implements `embedded_io::Read`) and a `Vec<u8>`-backed sink so we can
//! assert exactly what went over the wire, byte for byte.

#![cfg(feature = "sync")]

use core::convert::Infallible;

use microtun_jsonrpc::{Connection, Error, Handler, NoHandler, Params, Reply, Responder, codes};
use serde::Deserialize;

/// Captures everything the connection writes.
#[derive(Default)]
struct Sink(Vec<u8>);

impl embedded_io::ErrorType for Sink {
    type Error = Infallible;
}

impl embedded_io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Test service: `add(a, b) -> a + b`, `greet {name} -> "hello <name>"`,
/// counts `ping` notifications.
#[derive(Default)]
struct Calc {
    pings: usize,
}

#[derive(Deserialize)]
struct GreetParams<'a> {
    #[serde(borrow)]
    name: &'a str,
}

impl Handler for Calc {
    fn handle_request(&mut self, method: &str, params: Params<'_>, resp: Responder<'_>) -> Reply {
        match method {
            "add" => match params.parse::<(i64, i64)>() {
                Ok((a, b)) => resp.ok(&(a + b)),
                Err(_) => resp.invalid_params(),
            },
            // Demonstrates zero-copy borrowed params.
            "greet" => match params.parse::<GreetParams<'_>>() {
                Ok(p) => {
                    let mut s = heapless::String::<32>::new();
                    let _ = s.push_str("hello ");
                    let _ = s.push_str(p.name);
                    resp.ok(s.as_str())
                }
                Err(_) => resp.invalid_params(),
            },
            "fail" => resp.error(1000, "custom failure"),
            _ => resp.method_not_found(),
        }
    }

    fn handle_notification(&mut self, method: &str, _params: Params<'_>) {
        if method == "ping" {
            self.pings += 1;
        }
    }
}

type TestConnection<'a, H> = Connection<&'a [u8], Sink, H, 512, 512>;

fn connection<H: Handler>(input: &[u8], h: H) -> TestConnection<'_, H> {
    Connection::new(input, Sink::default(), h)
}

fn written<H>(p: TestConnection<'_, H>) -> String {
    String::from_utf8(p.into_parts().1.0).unwrap()
}

// ---------------------------------------------------------------------------
// Client role
// ---------------------------------------------------------------------------

#[test]
fn call_with_params() {
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":10}\n";
    let mut p = connection(input, NoHandler);

    let out: i64 = p.call("add", Some(&(4i64, 6i64))).unwrap();
    assert_eq!(out, 10);
    assert_eq!(
        written(p),
        "{\"jsonrpc\":\"2.0\",\"method\":\"add\",\"params\":[4,6],\"id\":1}\n"
    );
}

#[test]
fn call_no_params_and_null_result() {
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":null}\n";
    let mut p = connection(input, NoHandler);

    // `()` deserializes from JSON null.
    p.call_no_params::<()>("reset").unwrap();
    assert_eq!(
        written(p),
        "{\"jsonrpc\":\"2.0\",\"method\":\"reset\",\"id\":1}\n"
    );
}

#[test]
fn notify_has_no_id_and_reads_nothing() {
    let mut p = connection(b"", Calc::default());
    p.notify("ping", Some(&[1u8])).unwrap();
    assert_eq!(
        written(p),
        "{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"params\":[1]}\n"
    );
}

#[test]
fn remote_error_is_surfaced() {
    let input =
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"method not found\"}}\n";
    let mut p = connection(&input[..], NoHandler);

    match p.call::<(), i64>("nope", None) {
        Err(Error::Remote(e)) => {
            assert_eq!(e.code, codes::METHOD_NOT_FOUND);
            assert_eq!(e.message.as_str(), "method not found");
        }
        other => panic!("expected remote error, got {other:?}"),
    }
}

#[test]
fn stale_responses_are_skipped() {
    // A response for an unknown id arrives before ours.
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":99,\"result\":0}\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":7}\n";
    let mut p = connection(&input[..], NoHandler);
    let v: i64 = p.call_no_params("x").unwrap();
    assert_eq!(v, 7);
}

#[test]
fn ids_increment() {
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":1}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":2}\n";
    let mut p = connection(&input[..], NoHandler);
    assert_eq!(p.call_no_params::<i64>("a").unwrap(), 1);
    assert_eq!(p.call_no_params::<i64>("b").unwrap(), 2);
}

#[test]
fn eof_reported() {
    let mut p = connection(b"", NoHandler);
    assert_eq!(p.call_no_params::<i64>("x").unwrap_err(), Error::Eof);
}

// ---------------------------------------------------------------------------
// Server role
// ---------------------------------------------------------------------------

#[test]
fn serve_request_notification_and_unknown_method() {
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"add\",\"params\":[2,3]}\n\
                  {\"jsonrpc\":\"2.0\",\"method\":\"ping\"}\n\
                  {\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"nope\"}\n";
    let mut p = connection(&input[..], Calc::default());

    p.poll().unwrap(); // add
    p.poll().unwrap(); // ping (notification -> no output)
    p.poll().unwrap(); // nope -> method not found

    assert_eq!(p.handler().pings, 1);
    assert_eq!(
        written(p),
        "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":5}\n\
         {\"jsonrpc\":\"2.0\",\"id\":8,\"error\":{\"code\":-32601,\"message\":\"method not found\"}}\n"
    );
}

#[test]
fn serve_borrowed_params_and_i64_id() {
    // The id is echoed exactly while params borrow from the receive buffer.
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":-9223372036854775808,\"method\":\"greet\",\"params\":{\"name\":\"ferris\"}}\n";
    let mut p = connection(&input[..], Calc::default());
    p.poll().unwrap();
    assert_eq!(
        written(p),
        "{\"jsonrpc\":\"2.0\",\"id\":-9223372036854775808,\"result\":\"hello ferris\"}\n"
    );
}

#[test]
fn serve_custom_error_and_invalid_params() {
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"fail\"}\n\
                  {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"add\",\"params\":\"oops\"}\n";
    let mut p = connection(&input[..], Calc::default());
    p.poll().unwrap();
    p.poll().unwrap();
    assert_eq!(
        written(p),
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":1000,\"message\":\"custom failure\"}}\n\
         {\"jsonrpc\":\"2.0\",\"id\":2,\"error\":{\"code\":-32602,\"message\":\"invalid params\"}}\n"
    );
}

/// Input that is not JSON at all is `-32700`, and the stream is abandoned:
/// once a frame is malformed, this receiver and the sender no longer agree on
/// where messages begin.
#[test]
fn malformed_input_answered_with_parse_error() {
    let input = b"this is not json\n";
    let mut p = connection(&input[..], Calc::default());
    assert!(matches!(p.poll(), Err(Error::Parse)));
    assert_eq!(
        written(p),
        "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32700,\"message\":\"parse error\"}}\n"
    );
}

/// A batch is valid JSON but unsupported here, so it is malformed traffic
/// rather than a bad envelope.
#[test]
fn batch_input_answered_with_parse_error() {
    let input = b"[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"add\",\"params\":[1,2]}]\n";
    let mut p = connection(&input[..], Calc::default());
    assert!(matches!(p.poll(), Err(Error::Parse)));
    assert!(written(p).contains("-32700"));
}

/// Valid JSON with a broken envelope is `-32600`, not `-32700`. The JSON
/// parsed fine; what failed was the JSON-RPC layer, and a caller told the
/// wrong one of the two cannot act on the report.
#[test]
fn wrong_version_is_an_invalid_request() {
    let input = b"{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"add\",\"params\":[1,2]}\n";
    let mut p = connection(&input[..], Calc::default());
    assert!(matches!(p.poll(), Err(Error::InvalidRequest)));
    assert!(written(p).contains("-32600"));
}

#[test]
fn missing_version_is_an_invalid_request() {
    let input = b"{\"id\":1,\"method\":\"add\",\"params\":[1,2]}\n";
    let mut p = connection(&input[..], Calc::default());
    assert!(matches!(p.poll(), Err(Error::InvalidRequest)));
    assert!(written(p).contains("-32600"));
}

/// A notification omits `id`. Spelling it out as null is a different message,
/// and must not be silently served as a notification.
#[test]
fn explicit_null_id_is_an_invalid_request() {
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"ping\"}\n";
    let mut p = connection(&input[..], Calc::default());
    assert!(matches!(p.poll(), Err(Error::InvalidRequest)));
    assert!(written(p).contains("-32600"));
}

/// The counterpart to the test above, and the reason its field type matters:
/// a notification *omits* `id`, and must still be dispatched normally. Any
/// null-id probe built on `Option` accepts an absent member too, which would
/// silently turn every notification into an invalid request.
#[test]
fn a_notification_omitting_id_is_still_a_notification() {
    let input = b"{\"jsonrpc\":\"2.0\",\"method\":\"ping\"}\n";
    let mut p = connection(&input[..], Calc::default());
    p.poll().unwrap();
    assert_eq!(p.handler().pings, 1);
    assert_eq!(written(p), "", "a notification draws no response");
}

/// An id that is not a signed 64-bit integer.
#[test]
fn structured_id_is_an_invalid_request() {
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":{\"a\":1},\"method\":\"ping\"}\n";
    let mut p = connection(&input[..], Calc::default());
    assert!(matches!(p.poll(), Err(Error::InvalidRequest)));
    assert!(written(p).contains("-32600"));
}

#[test]
fn string_id_is_an_invalid_request() {
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":\"req-1\",\"method\":\"add\",\"params\":[1,2]}\n";
    let mut p = connection(&input[..], Calc::default());
    assert!(matches!(p.poll(), Err(Error::InvalidRequest)));
    assert!(written(p).contains("-32600"));
}

#[test]
fn fractional_id_is_an_invalid_request() {
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1.5,\"method\":\"add\",\"params\":[1,2]}\n";
    let mut p = connection(&input[..], Calc::default());
    assert!(matches!(p.poll(), Err(Error::InvalidRequest)));
    assert!(written(p).contains("-32600"));
}

#[test]
fn out_of_range_integer_ids_are_invalid_requests() {
    for id in ["9223372036854775808", "-9223372036854775809"] {
        let input =
            format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"add\",\"params\":[1,2]}}\n");
        let mut p = connection(input.as_bytes(), Calc::default());
        assert!(
            matches!(p.poll(), Err(Error::InvalidRequest)),
            "id {id} must be rejected as an invalid request"
        );
        assert!(written(p).contains("-32600"));
    }
}

#[test]
fn i64_max_id_is_echoed_exactly() {
    let input =
        b"{\"jsonrpc\":\"2.0\",\"id\":9223372036854775807,\"method\":\"add\",\"params\":[1,2]}\n";
    let mut p = connection(&input[..], Calc::default());
    p.poll().unwrap();
    assert_eq!(
        written(p),
        "{\"jsonrpc\":\"2.0\",\"id\":9223372036854775807,\"result\":3}\n"
    );
}

#[test]
fn crlf_and_blank_lines_tolerated() {
    let input = b"\r\n{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"add\",\"params\":[1,1]}\r\n";
    let mut p = connection(&input[..], Calc::default());
    p.poll().unwrap();
    assert_eq!(written(p), "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":2}\n");
}

// ---------------------------------------------------------------------------
// Bidirectional
// ---------------------------------------------------------------------------

#[test]
fn incoming_traffic_served_while_waiting_for_response() {
    // While we wait for the response to our call, the remote connection first
    // sends us a request and a notification of its own; both must be served
    // before our call resolves.
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":42,\"method\":\"add\",\"params\":[20,22]}\n\
                  {\"jsonrpc\":\"2.0\",\"method\":\"ping\"}\n\
                  {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":123}\n";
    let mut p = connection(&input[..], Calc::default());

    let v: i64 = p.call("compute", Some(&(1i64,))).unwrap();
    assert_eq!(v, 123);
    assert_eq!(p.handler().pings, 1);

    // Wire order: our request first, then our answer to theirs.
    assert_eq!(
        written(p),
        "{\"jsonrpc\":\"2.0\",\"method\":\"compute\",\"params\":[1],\"id\":1}\n\
         {\"jsonrpc\":\"2.0\",\"id\":42,\"result\":42}\n"
    );
}

// ---------------------------------------------------------------------------
// Buffer limits
// ---------------------------------------------------------------------------

#[cfg(not(feature = "alloc"))]
#[test]
fn oversized_frame_is_overflow() {
    let mut input = vec![b'{'; 600]; // > RX_BUFFER_SIZE = 512, no newline in first 512
    input.push(b'\n');
    let mut p: Connection<&[u8], Sink, NoHandler, 512, 512> =
        Connection::new(&input[..], Sink::default(), NoHandler);
    assert_eq!(p.poll().unwrap_err(), Error::Overflow);
}

/// With `alloc` the receive buffer grows past `RX_BUFFER_SIZE` instead of overflowing.
#[cfg(feature = "alloc")]
#[test]
fn oversized_frame_grows_with_alloc() {
    let mut input = vec![b'{'; 600];
    input.push(b'\n');
    let mut p: Connection<&[u8], Sink, NoHandler, 512, 512> =
        Connection::new(&input[..], Sink::default(), NoHandler);
    // Garbage JSON -> answered with a parse error, then the stream is dropped.
    assert!(matches!(p.poll(), Err(Error::Parse)));
    assert!(written(p).contains("-32700"));
}

/// A frame that fits the buffer must be accepted regardless of how the
/// transport chopped the stream into reads.
///
/// The reader previously topped its buffer up in fixed 64-byte reads without
/// regard for how full it already was. Once a frame had been consumed, the
/// bytes of the *next* one were already buffered, and a further 64-byte read
/// could overrun the backing store on bytes that lay beyond a newline the
/// reader had not looked at yet. Whether a conforming frame was accepted then
/// depended on where the transport happened to split its reads: the same
/// frame arriving alone would fit, while pipelined behind another it would
/// not.
///
/// The sizes here are chosen to land exactly in that window — every frame is
/// comfortably under `RX_BUFFER_SIZE`, and the third one only exists so the reads stay
/// full-size rather than being cut short by end-of-stream.
#[cfg(not(feature = "alloc"))]
#[test]
fn conforming_frames_pipelined_near_the_buffer_limit_are_accepted() {
    fn frame(id: i64, a: u32, b: u32, total: usize) -> String {
        let stem = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"add\",\"params\":[{a},{b}],\"pad\":\"\"}}"
        );
        let pad = "p".repeat(total - stem.len());
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"add\",\"params\":[{a},{b}],\"pad\":\"{pad}\"}}"
        )
    }

    let frames = [
        frame(1, 1, 2, 400),
        frame(2, 3, 4, 500),
        frame(3, 5, 6, 120),
    ];
    for f in &frames {
        assert!(f.len() < 512, "every frame must fit the receive buffer");
    }
    let input = frames.join("\n") + "\n";

    let mut p: Connection<&[u8], Sink, Calc, 512, 512> =
        Connection::new(input.as_bytes(), Sink::default(), Calc::default());
    p.poll().unwrap();
    // Before the fix, this second frame overflowed even though it fits.
    p.poll().unwrap();
    p.poll().unwrap();
    assert_eq!(
        written(p),
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":3}\n\
         {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":7}\n\
         {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":11}\n"
    );
}

#[test]
fn oversized_reply_becomes_internal_error() {
    // Handler result does not fit into TX_BUFFER_SIZE=96: connection must degrade to the
    // internal error response instead.
    struct Big;
    impl Handler for Big {
        fn handle_request(&mut self, _: &str, _: Params<'_>, r: Responder<'_>) -> Reply {
            r.ok(&[0u8; 200][..])
        }
    }
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"big\"}\n";
    let mut p: Connection<&[u8], Sink, Big, 512, 96> =
        Connection::new(&input[..], Sink::default(), Big);
    p.poll().unwrap();
    let out = String::from_utf8(p.into_parts().1.0).unwrap();
    assert_eq!(
        out,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32603,\"message\":\"internal error\"}}\n"
    );
}
