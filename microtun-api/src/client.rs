//! Typed Peers API client.
//!
//! The protocol-facing API is shared by embedded and Tokio integrations.
//! [`Connection`] is the allocation-free `embedded-io-async` connection type;
//! enabling `tokio-client` additionally exposes [`TokioConnection`], which uses
//! the JSON-RPC crate's Tokio adapter while keeping the same lookup/watch API.
//!
//! Keeping the transport features additive is important because Cargo unifies
//! features when `microtun-std` and `microtun-embassy` are built in one graph.

use core::net::IpAddr;

use embedded_io_async::{Read, Write};
#[cfg(not(feature = "alloc"))]
use heapless::Vec;
use microtun_core::{ResolveOutcome, ResolveQuery};
pub use microtun_jsonrpc::Connection;
#[cfg(feature = "tokio-client")]
pub use microtun_jsonrpc::TokioIo;
use microtun_jsonrpc::{Error as RpcError, Handler};

/// Peers API connection constructed from native Tokio reader/writer halves.
#[cfg(feature = "tokio-client")]
pub type TokioConnection<R, W, H, const RX_BUFFER_SIZE: usize, const TX_BUFFER_SIZE: usize> =
    Connection<TokioIo<R>, TokioIo<W>, H, RX_BUFFER_SIZE, TX_BUFFER_SIZE>;

use crate::{
    Error, KeyParams, LookupResult, METHOD_CHANGED, METHOD_UNWATCH, METHOD_WATCH, QueryText,
    classify_result, decode_key, encode_key, encode_query,
};

/// Failure produced while issuing a typed Peers API operation.
#[derive(Debug)]
pub enum ClientError {
    /// A query could not be rendered into the bounded wire representation.
    Codec(Error),
    /// The JSON-RPC transport or remote endpoint rejected the operation.
    Rpc(RpcError),
    /// A by-key or watch response named a key other than the requested one.
    UnexpectedPublicKey {
        /// Key the operation requested.
        expected: [u8; 32],
        /// Key returned in the positive record.
        actual: [u8; 32],
    },
}

impl From<Error> for ClientError {
    fn from(error: Error) -> Self {
        Self::Codec(error)
    }
}

impl From<RpcError> for ClientError {
    fn from(error: RpcError) -> Self {
        Self::Rpc(error)
    }
}

/// Collects public keys named by `v1.peer.changed` notifications.
///
/// `MAX_CHANGES` is the maximum number of queued changes on allocation-free
/// builds. With `alloc`, the queue grows as needed and `MAX_CHANGES` is
/// ignored. Keeping the const parameter in both configurations makes the type
/// stable under Cargo feature unification when std and Embassy clients are built
/// in the same graph.
#[derive(Debug, Default)]
pub struct ChangeHandler<const MAX_CHANGES: usize = 0> {
    #[cfg(feature = "alloc")]
    changed: alloc::collections::VecDeque<[u8; 32]>,
    #[cfg(not(feature = "alloc"))]
    changed: Vec<[u8; 32], MAX_CHANGES>,
    #[cfg(not(feature = "alloc"))]
    overflowed: bool,
}

impl<const MAX_CHANGES: usize> ChangeHandler<MAX_CHANGES> {
    /// Pop the next coalesced invalidated key.
    pub fn take_changed(&mut self) -> Option<[u8; 32]> {
        #[cfg(feature = "alloc")]
        {
            self.changed.pop_front()
        }
        #[cfg(not(feature = "alloc"))]
        {
            if self.changed.is_empty() {
                None
            } else {
                Some(self.changed.swap_remove(0))
            }
        }
    }

    /// Drop any queued invalidation for a key the client no longer holds.
    pub fn forget(&mut self, public_key: [u8; 32]) {
        #[cfg(feature = "alloc")]
        self.changed.retain(|queued| *queued != public_key);

        #[cfg(not(feature = "alloc"))]
        if let Some(index) = self.changed.iter().position(|queued| *queued == public_key) {
            self.changed.swap_remove(index);
        }
    }

    /// Return and clear the fixed-capacity overflow flag.
    ///
    /// Alloc-backed queues never overflow and therefore always return `false`.
    pub fn take_overflowed(&mut self) -> bool {
        #[cfg(feature = "alloc")]
        {
            false
        }
        #[cfg(not(feature = "alloc"))]
        {
            core::mem::take(&mut self.overflowed)
        }
    }

    fn push_changed(&mut self, public_key: [u8; 32]) {
        if self.changed.contains(&public_key) {
            return;
        }

        #[cfg(feature = "alloc")]
        self.changed.push_back(public_key);

        #[cfg(not(feature = "alloc"))]
        if self.changed.push(public_key).is_err() {
            self.overflowed = true;
        }
    }
}

fn decode_changed_notification(
    method: &str,
    params: microtun_jsonrpc::Params<'_>,
) -> Option<[u8; 32]> {
    if method != METHOD_CHANGED {
        return None;
    }
    let args = params.parse::<KeyParams<'_>>().ok()?;
    decode_key(args.public_key).ok()
}

impl<const MAX_CHANGES: usize> microtun_jsonrpc::Handler for ChangeHandler<MAX_CHANGES> {
    fn handle_request(
        &mut self,
        _method: &str,
        _params: microtun_jsonrpc::Params<'_>,
        responder: microtun_jsonrpc::Responder<'_>,
    ) -> microtun_jsonrpc::Reply {
        responder.method_not_found()
    }

    fn handle_notification(&mut self, method: &str, params: microtun_jsonrpc::Params<'_>) {
        if let Some(public_key) = decode_changed_notification(method, params) {
            self.push_changed(public_key);
        }
    }
}

/// Perform one side-effect-free lookup and validate by-key identity.
pub async fn lookup<R, W, H, const RX_BUFFER_SIZE: usize, const TX_BUFFER_SIZE: usize>(
    connection: &mut Connection<R, W, H, RX_BUFFER_SIZE, TX_BUFFER_SIZE>,
    query: ResolveQuery,
) -> Result<ResolveOutcome, ClientError>
where
    R: Read,
    W: Write,
    H: Handler,
{
    let expected = match query {
        ResolveQuery::ByPublicKey(public_key) => Some(public_key),
        ResolveQuery::ByDstAddress(_) => None,
    };
    let mut text = QueryText::new();
    let call = encode_query(&query, &mut text)?;
    let outcome = call_result(connection, call.method, &call.params).await?;
    validate_public_key(outcome, expected)
}

/// Resolve one peer by its public key.
pub async fn resolve_key<R, W, H, const RX_BUFFER_SIZE: usize, const TX_BUFFER_SIZE: usize>(
    connection: &mut Connection<R, W, H, RX_BUFFER_SIZE, TX_BUFFER_SIZE>,
    public_key: [u8; 32],
) -> Result<ResolveOutcome, ClientError>
where
    R: Read,
    W: Write,
    H: Handler,
{
    lookup(connection, ResolveQuery::ByPublicKey(public_key)).await
}

/// Resolve the peer owning one destination address.
pub async fn resolve_address<R, W, H, const RX_BUFFER_SIZE: usize, const TX_BUFFER_SIZE: usize>(
    connection: &mut Connection<R, W, H, RX_BUFFER_SIZE, TX_BUFFER_SIZE>,
    address: IpAddr,
) -> Result<ResolveOutcome, ClientError>
where
    R: Read,
    W: Write,
    H: Handler,
{
    lookup(connection, ResolveQuery::ByDstAddress(address)).await
}

/// Atomically subscribe to one public key and return its current state.
pub async fn watch<R, W, H, const RX_BUFFER_SIZE: usize, const TX_BUFFER_SIZE: usize>(
    connection: &mut Connection<R, W, H, RX_BUFFER_SIZE, TX_BUFFER_SIZE>,
    public_key: [u8; 32],
) -> Result<ResolveOutcome, ClientError>
where
    R: Read,
    W: Write,
    H: Handler,
{
    let text = encode_key(&public_key);
    let params = KeyParams {
        public_key: text.as_str(),
    };
    let outcome = call_result(connection, METHOD_WATCH, &params).await?;
    validate_public_key(outcome, Some(public_key))
}

/// Best-effort removal of one key from the connection watch set.
pub async fn unwatch<R, W, H, const RX_BUFFER_SIZE: usize, const TX_BUFFER_SIZE: usize>(
    connection: &mut Connection<R, W, H, RX_BUFFER_SIZE, TX_BUFFER_SIZE>,
    public_key: [u8; 32],
) -> Result<(), ClientError>
where
    R: Read,
    W: Write,
    H: Handler,
{
    let text = encode_key(&public_key);
    let params = KeyParams {
        public_key: text.as_str(),
    };
    connection.notify(METHOD_UNWATCH, Some(&params)).await?;
    Ok(())
}

async fn call_result<R, W, H, P, const RX_BUFFER_SIZE: usize, const TX_BUFFER_SIZE: usize>(
    connection: &mut Connection<R, W, H, RX_BUFFER_SIZE, TX_BUFFER_SIZE>,
    method: &str,
    params: &P,
) -> Result<ResolveOutcome, ClientError>
where
    R: Read,
    W: Write,
    H: Handler,
    P: serde::Serialize + ?Sized,
{
    let result = connection
        .call::<_, LookupResult>(method, Some(params))
        .await?;
    Ok(classify_result(&result))
}

fn validate_public_key(
    outcome: ResolveOutcome,
    expected: Option<[u8; 32]>,
) -> Result<ResolveOutcome, ClientError> {
    match (expected, &outcome) {
        (Some(expected), ResolveOutcome::Found(peer)) if peer.public_key != expected => {
            Err(ClientError::UnexpectedPublicKey {
                expected,
                actual: peer.public_key,
            })
        }
        _ => Ok(outcome),
    }
}
