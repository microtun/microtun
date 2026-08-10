//! Integration tests for the `async` build:
//! `cargo test --no-default-features --features async`
//!
//! The mock transport is always ready, so a minimal noop-waker `block_on`
//! is all the executor we need.

#![cfg(all(feature = "async", not(feature = "sync")))]

use core::{
    convert::Infallible,
    future::Future,
    pin::pin,
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
};

use microtun_jsonrpc::{Connection, Handler, Params, Reply, Responder};

fn block_on<F: Future>(fut: F) -> F::Output {
    fn raw() -> RawWaker {
        fn no_op(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            raw()
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
        RawWaker::new(core::ptr::null(), &VTABLE)
    }
    // Safety-free version: construct via the raw parts (stable API).
    let waker = unsafe { Waker::from_raw(raw()) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = pin!(fut);
    loop {
        if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
            return out;
        }
    }
}

/// Always-ready reader over a byte script.
struct Rx<'a>(&'a [u8]);

impl embedded_io_async::ErrorType for Rx<'_> {
    type Error = Infallible;
}

impl embedded_io_async::Read for Rx<'_> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let n = self.0.len().min(buf.len());
        buf[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        Ok(n)
    }
}

#[derive(Default)]
struct Sink(Vec<u8>);

impl embedded_io_async::ErrorType for Sink {
    type Error = Infallible;
}

impl embedded_io_async::Write for Sink {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }
    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

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

#[test]
fn async_bidirectional_call() {
    // Remote sends us a request before answering ours.
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"add\",\"params\":[3,4]}\n\
                  {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":99}\n";
    let mut connection: Connection<_, _, _, 512, 512> =
        Connection::new(Rx(input), Sink::default(), Calc);

    let v: i64 = block_on(connection.call("compute", Some(&(5i64,)))).unwrap();
    assert_eq!(v, 99);

    let out = String::from_utf8(connection.into_parts().1.0).unwrap();
    assert_eq!(
        out,
        "{\"jsonrpc\":\"2.0\",\"method\":\"compute\",\"params\":[5],\"id\":1}\n\
         {\"jsonrpc\":\"2.0\",\"id\":9,\"result\":7}\n"
    );
}

#[test]
fn async_serve() {
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"add\",\"params\":[1,2]}\n";
    let mut connection: Connection<_, _, _, 512, 512> =
        Connection::new(Rx(input), Sink::default(), Calc);
    block_on(connection.poll()).unwrap();
    let out = String::from_utf8(connection.into_parts().1.0).unwrap();
    assert_eq!(out, "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":3}\n");
}
