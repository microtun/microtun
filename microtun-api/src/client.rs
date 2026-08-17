//! Typed Peers API client.
//!
//! The protocol-facing API is shared by embedded and Tokio integrations. A
//! [`Session`] over any `embedded-io-async` transport carries the lookups and
//! the invalidations; enabling `tokio` additionally exposes [`TokioIo`], which
//! adapts native Tokio halves while keeping the same API.
//!
//! Keeping the transport features additive is important because Cargo unifies
//! features when `microtun-std` and `microtun-embassy` are built in one graph.
//!
//! # Opening a connection
//!
//! [`connect`] performs the WebSocket handshake against
//! [`crate::PEERS_API_PATH`], so a
//! resolver never restates the endpoint and cannot drift from the server's
//! idea of it. Everything about *routing* the underlying stream — which
//! interface it binds to, which address it reaches — stays with the caller,
//! because that routing is the whole of this protocol's security.

use core::net::IpAddr;

use embedded_io_async::{Read, Write};
#[cfg(not(feature = "alloc"))]
use heapless::Vec;
use microtun_core::{ResolveOutcome, ResolveQuery};
#[cfg(feature = "tokio")]
pub use microtun_ws::TokioIo;
use microtun_ws::{ClientRequest, Connection};
use rand_core::{CryptoRng, RngCore};

use crate::{
    Error, KeyParams, LookupResult, METHOD_CHANGED, METHOD_REMOVED, METHOD_UNWATCH, METHOD_WATCH,
    PEERS_API_PATH, QueryText, classify_result, decode_key, encode_key, encode_query,
    session::{Handler, Params, Reply, Responder, Session, SessionError},
};

/// A Peers API session over native Tokio reader/writer halves.
#[cfg(feature = "tokio")]
pub type TokioSession<R, W, H, const RX_BUFFER_SIZE: usize, const TX_BUFFER_SIZE: usize> =
    Session<TokioIo<R>, TokioIo<W>, H, RX_BUFFER_SIZE, TX_BUFFER_SIZE>;

/// Failure produced while issuing a typed Peers API operation.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// A query could not be rendered into the bounded wire representation.
    #[error("Peers API codec error: {0}")]
    Codec(#[from] Error),
    /// The session or the remote endpoint rejected the operation.
    #[error("Peers API session error: {0}")]
    Session(#[from] SessionError),
    /// A by-key or watch response named a key other than the requested one.
    #[error("Peers API response returned an unexpected public key")]
    UnexpectedPublicKey {
        /// Key the operation requested.
        expected: [u8; 32],
        /// Key returned in the positive record.
        actual: [u8; 32],
    },
}

impl ClientError {
    /// Whether this failure left the connection usable.
    ///
    /// A remote error *object* is a complete, well-formed answer that happens
    /// to say no: the message boundary is intact and the session is
    /// synchronized, so the connection survives it. Everything else either
    /// lost the connection or lost confidence in what the peer is saying, and
    /// a WebSocket stream offers no place to resynchronize.
    pub fn keeps_connection(&self) -> bool {
        matches!(
            self,
            ClientError::Codec(_) | ClientError::Session(SessionError::Remote(_))
        )
    }
}

/// Open a Peers API session over an already-connected byte stream.
///
/// Opening the stream is the caller's job, and deliberately so: the route it
/// takes is the whole of this protocol's security, so this function is handed
/// a connection rather than an address it might resolve some other way.
///
/// `rng` supplies the cryptographic entropy RFC 6455 requires for the opening
/// handshake nonce and client-to-server frame masking keys. The WebSocket layer
/// draws from it during connection setup and does not retain the borrow.
pub async fn connect<R, W, H, RNG, const RX_BUFFER_SIZE: usize, const TX_BUFFER_SIZE: usize>(
    reader: R,
    writer: W,
    rng: &mut RNG,
    handler: H,
) -> Result<Session<R, W, H, RX_BUFFER_SIZE, TX_BUFFER_SIZE>, ClientError>
where
    R: Read,
    W: Write,
    H: Handler,
    RNG: RngCore + CryptoRng + ?Sized,
{
    let mut scratch = [0u8; crate::CLIENT_HANDSHAKE_LEN];
    let ws = Connection::client(
        reader,
        writer,
        &ClientRequest {
            host: crate::PEERS_API_HOST,
            path: PEERS_API_PATH,
        },
        rng,
        &mut scratch,
    )
    .await
    .map_err(SessionError::Transport)?;
    Ok(Session::new(ws, handler))
}

/// Collects public keys named by `peer.changed` and `peer.removed`
/// notifications.
///
/// `MAX_CHANGES` is the maximum number of queued changes on allocation-free
/// builds. With `alloc`, the queue grows as needed and `MAX_CHANGES` is
/// ignored. Keeping the const parameter in both configurations makes the type
/// stable under Cargo feature unification when std and Embassy clients are built
/// in the same graph.
#[derive(Debug, Default)]
pub struct ChangeHandler<const MAX_CHANGES: usize = 0> {
    #[cfg(feature = "alloc")]
    invalidated: alloc::collections::VecDeque<[u8; 32]>,
    #[cfg(not(feature = "alloc"))]
    invalidated: Vec<[u8; 32], MAX_CHANGES>,
    #[cfg(not(feature = "alloc"))]
    overflowed: bool,
}

impl<const MAX_CHANGES: usize> ChangeHandler<MAX_CHANGES> {
    /// Pop the next coalesced invalidated key.
    pub fn take_invalidated(&mut self) -> Option<[u8; 32]> {
        #[cfg(feature = "alloc")]
        {
            self.invalidated.pop_front()
        }
        #[cfg(not(feature = "alloc"))]
        {
            if self.invalidated.is_empty() {
                None
            } else {
                Some(self.invalidated.swap_remove(0))
            }
        }
    }

    /// Drop any queued invalidation for a key the client no longer holds.
    pub fn forget(&mut self, public_key: [u8; 32]) {
        #[cfg(feature = "alloc")]
        self.invalidated.retain(|queued| *queued != public_key);

        #[cfg(not(feature = "alloc"))]
        if let Some(index) = self
            .invalidated
            .iter()
            .position(|queued| *queued == public_key)
        {
            self.invalidated.swap_remove(index);
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

    fn push_invalidated(&mut self, public_key: [u8; 32]) {
        if self.invalidated.contains(&public_key) {
            return;
        }

        #[cfg(feature = "alloc")]
        self.invalidated.push_back(public_key);

        #[cfg(not(feature = "alloc"))]
        if self.invalidated.push(public_key).is_err() {
            self.overflowed = true;
        }
    }
}

fn decode_invalidation_notification(method: &str, params: Params<'_>) -> Option<[u8; 32]> {
    if method != METHOD_CHANGED && method != METHOD_REMOVED {
        return None;
    }
    let args = params.parse::<KeyParams<'_>>().ok()?;
    decode_key(args.public_key).ok()
}

impl<const MAX_CHANGES: usize> Handler for ChangeHandler<MAX_CHANGES> {
    fn handle_request(
        &mut self,
        _method: &str,
        _params: Params<'_>,
        responder: Responder<'_>,
    ) -> Reply {
        responder.unknown_method()
    }

    fn handle_notification(&mut self, method: &str, params: Params<'_>) {
        if let Some(public_key) = decode_invalidation_notification(method, params) {
            self.push_invalidated(public_key);
        }
    }
}

/// Perform one side-effect-free lookup and validate by-key identity.
pub async fn lookup<R, W, H, const RX_BUFFER_SIZE: usize, const TX_BUFFER_SIZE: usize>(
    session: &mut Session<R, W, H, RX_BUFFER_SIZE, TX_BUFFER_SIZE>,
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
    let outcome = call_result(session, call.method, &call.params).await?;
    validate_public_key(outcome, expected)
}

/// Resolve one peer by its public key.
pub async fn resolve_key<R, W, H, const RX_BUFFER_SIZE: usize, const TX_BUFFER_SIZE: usize>(
    session: &mut Session<R, W, H, RX_BUFFER_SIZE, TX_BUFFER_SIZE>,
    public_key: [u8; 32],
) -> Result<ResolveOutcome, ClientError>
where
    R: Read,
    W: Write,
    H: Handler,
{
    lookup(session, ResolveQuery::ByPublicKey(public_key)).await
}

/// Resolve the peer owning one destination address.
pub async fn resolve_address<R, W, H, const RX_BUFFER_SIZE: usize, const TX_BUFFER_SIZE: usize>(
    session: &mut Session<R, W, H, RX_BUFFER_SIZE, TX_BUFFER_SIZE>,
    address: IpAddr,
) -> Result<ResolveOutcome, ClientError>
where
    R: Read,
    W: Write,
    H: Handler,
{
    lookup(session, ResolveQuery::ByDstAddress(address)).await
}

/// Atomically subscribe to one public key and return its current state.
pub async fn watch<R, W, H, const RX_BUFFER_SIZE: usize, const TX_BUFFER_SIZE: usize>(
    session: &mut Session<R, W, H, RX_BUFFER_SIZE, TX_BUFFER_SIZE>,
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
    let outcome = call_result(session, METHOD_WATCH, &params).await?;
    validate_public_key(outcome, Some(public_key))
}

/// Best-effort removal of one public key from the current connection's watch
/// set.
pub async fn unwatch<R, W, H, const RX_BUFFER_SIZE: usize, const TX_BUFFER_SIZE: usize>(
    session: &mut Session<R, W, H, RX_BUFFER_SIZE, TX_BUFFER_SIZE>,
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
    session.notify(METHOD_UNWATCH, Some(&params)).await?;
    Ok(())
}

async fn call_result<R, W, H, P, const RX_BUFFER_SIZE: usize, const TX_BUFFER_SIZE: usize>(
    session: &mut Session<R, W, H, RX_BUFFER_SIZE, TX_BUFFER_SIZE>,
    method: &str,
    params: &P,
) -> Result<ResolveOutcome, ClientError>
where
    R: Read,
    W: Write,
    H: Handler,
    P: serde::Serialize + ?Sized,
{
    let result = session
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
