//! Lookups and watches.
//!
//! ```text
//! v1.peer.by_key      {"public_key": "<44-char base64>"}  -> LookupResult
//! v1.peer.by_address  {"address": "10.0.0.5"}             -> LookupResult
//! v1.peer.watch       {"public_key": "<44-char base64>"}  -> LookupResult
//! v1.peer.unwatch     {"public_key": "<44-char base64>"}  -> notification
//! v1.peer.changed     {"public_key": "<44-char base64>"}  -> server notification
//! ```
//!
//! A `LookupResult` is externally tagged: `{"found":{...}}` or
//! `{"not_found":{}}`. Nothing else is an authoritative lookup result.
//!
//! Lookups are side-effect free. A client that wants to keep a record current
//! explicitly calls `v1.peer.watch` for its public key. `v1.peer.watch` inserts that
//! key into the connection watch set and reads the current record inside one
//! [`SharedRegistry::read`] critical section, returning the same tagged
//! `LookupResult` as `v1.peer.by_key`. That makes the subscription explicit without
//! reopening the race between the state a client installs and the watch that
//! protects it.
//!
//! Config reloads and authenticated endpoint observations push `v1.peer.changed`
//! for watched keys whose effective records changed.
//! That notification names a key and carries nothing else: the client answers
//! it with an ordinary `v1.peer.by_key`. A reconnecting client replays
//! `v1.peer.watch` for its desired set, which both reconciles current state and
//! re-establishes every subscription.
//!
//! Because the notification carries no state it cannot be reordered into a
//! stale install, so this server owes no write ordering between responses and
//! notifications. The only cross-task ordering guarantee is the atomic
//! watch-and-snapshot performed by `v1.peer.watch`; serialization and the actual
//! write may happen later.
//!
//! Every method is gated on admission, and there is no ungated probe: a
//! connection that establishes at all has already proved a WireGuard session,
//! which is a stronger liveness signal than anything this layer could answer.
//!
//! # How a request is attributed to a peer
//!
//! Every Peers API operation must come from a configured peer. The Peers API server terminates
//! the tunnel itself, so a connection arrives already bound to the static
//! public key whose WireGuard session carried its packets: the accept loop
//! attaches that key to the connection's handler, and admission is a `by_key`
//! lookup against the same peer list the API serves. A key with no record is
//! refused.
//!
//! This is not an inference from the source address. The core delivers only
//! cryptokey-routed packets, so the address would also be trustworthy, but a
//! peer may legitimately own a prefix that contains another peer's address —
//! `10.0.0.0/24` and `10.0.0.1/32` can belong to different peers — and a
//! longest-prefix match on the source would then credit the wrong one. The key
//! has no such ambiguity.
//!
//! Identity is per *connection*, not per request, which is a small tightening
//! over the request-scoped extension this replaces: a handler is constructed
//! with the accepted key and has no way to be told about another.
//!
//! Resource accounting uses that same authenticated key. Configured peers may
//! hold at most [`MAX_CONNECTIONS_PER_PEER`] simultaneous API connections and
//! share a token bucket across those connections. Exceeding the request budget
//! returns a transient JSON-RPC error rather than the authoritative `not_found`
//! sentinel, so overload cannot poison a client's negative cache.
//!
//! # `not_found` describes the registry, not the caller
//!
//! `{"not_found":{}}` means exactly one thing: *the registry holds no record
//! for the target you named*. The client treats it as authoritative, negative
//! caches it, and — on a refresh for a record it already holds — deletes that
//! record. So the sentinel must be reserved for statements about the target,
//! and three other outcomes that are not such statements answer differently:
//!
//! * **The caller has no record of its own.** Refused at accept, so the usual
//!   case never reaches a handler at all. A request that slips through the
//!   window between a reload removing the caller and the notifier closing the
//!   connection answers [`microtun_api::ERROR_NOT_ADMITTED`]. Answering a miss
//!   here would tell a client whose admission had just lapsed that every peer
//!   it holds had been deleted, and one bad config push would delete every
//!   client's routing state fleet-wide instead of merely disconnecting it.
//! * **The argument is not a key or an address.** Answered `-32602`. A caller
//!   that cannot spell a key has learned nothing about who exists, so there is
//!   nothing to conceal and a silent negative cache entry would hide the bug.
//! * **Overload.** Answered [`microtun_api::ERROR_RATE_LIMITED`].
//!
//! All three are transient in the client's classification, so an installed
//! record survives them. What remains indistinguishable is what the enumeration
//! argument actually covers: an unknown key and an unclaimed address are the
//! same miss, and a caller cannot tell which of the two it hit.
//!
//! Reload failures likewise keep serving the previous validated snapshot rather
//! than briefly turning every record into a miss.
//!
//! Because the sentinel is explicit, this server must never answer a lookup or watch
//! with a bare `null`, an omitted `result`, or a record placed directly in
//! `result`: a client reads all three as a transient failure and keeps
//! whatever it already had.

use std::{
    collections::{HashMap, HashSet},
    io,
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use microtun_api::{
    ByAddressParams, KeyParams, LookupResult, METHOD_BY_ADDRESS, METHOD_BY_KEY, METHOD_CHANGED,
    METHOD_UNWATCH, METHOD_WATCH, PeerInfo, QUERY_FRAME_LEN, RECORD_FRAME_LEN,
};
use microtun_core::key::{decode_key, encode_key};
use microtun_jsonrpc::{
    Connection as RpcConnection, Handler, Notifier, Params, Reply, Responder, TokioIo, codes,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::registry::{KEY_PREFIX_LEN, PeerRecord, Registry, SharedRegistry};

/// Maximum simultaneous Peers API TCP connections accepted from one
/// configured, authenticated tunnel key. Multiple connections are useful for
/// reconnect overlap, but an unbounded number multiplies watch and refresh
/// work during registry churn.
const MAX_CONNECTIONS_PER_PEER: usize = 4;
/// Sustained Peers API request budget per configured, authenticated tunnel key.
const REQUESTS_PER_SEC: u32 = 20;
/// Short request bursts allowed before the sustained budget takes effect.
const REQUEST_BURST: u32 = 40;
const REQUEST_COST_MT: u32 = 1000;

/// Cloneable embedded-I/O writer that serializes a JSON-RPC reader task and
/// an asynchronous notification task onto one stream half.
struct SharedWriter<W: 'static> {
    inner: Arc<tokio::sync::Mutex<W>>,
    guard: Option<tokio::sync::OwnedMutexGuard<W>>,
}

impl<W: 'static> core::fmt::Debug for SharedWriter<W> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SharedWriter")
            .field("locked", &self.guard.is_some())
            .finish_non_exhaustive()
    }
}

impl<W: 'static> Clone for SharedWriter<W> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            guard: None,
        }
    }
}

impl<W: 'static> SharedWriter<W> {
    fn new(writer: W) -> Self {
        Self {
            inner: Arc::new(tokio::sync::Mutex::new(writer)),
            guard: None,
        }
    }
}

impl<W> embedded_io_async::ErrorType for SharedWriter<W>
where
    W: AsyncWrite + Unpin + 'static,
{
    type Error = io::Error;
}

impl<W> embedded_io_async::Write for SharedWriter<W>
where
    W: AsyncWrite + Unpin + 'static,
{
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        if self.guard.is_none() {
            self.guard = Some(Arc::clone(&self.inner).lock_owned().await);
        }
        let result = self
            .guard
            .as_mut()
            .expect("writer lock was just acquired")
            .write(buf)
            .await;
        if matches!(result, Ok(0) | Err(_)) {
            self.guard = None;
        }
        result
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        if self.guard.is_none() {
            self.guard = Some(Arc::clone(&self.inner).lock_owned().await);
        }
        let result = self
            .guard
            .as_mut()
            .expect("writer lock was just acquired")
            .flush()
            .await;
        self.guard = None;
        result
    }
}

#[derive(Debug)]
struct PeerUsage {
    connections: usize,
    request_tokens_mt: u32,
    last_refill: Instant,
}

impl PeerUsage {
    fn new(now: Instant) -> Self {
        Self {
            connections: 0,
            request_tokens_mt: REQUEST_BURST.saturating_mul(REQUEST_COST_MT),
            last_refill: now,
        }
    }

    fn allow_request(&mut self, now: Instant) -> bool {
        let elapsed_ms = now.saturating_duration_since(self.last_refill).as_millis();
        let gained = elapsed_ms
            .saturating_mul(u128::from(REQUESTS_PER_SEC))
            .min(u128::from(u32::MAX)) as u32;
        self.request_tokens_mt = self
            .request_tokens_mt
            .saturating_add(gained)
            .min(REQUEST_BURST.saturating_mul(REQUEST_COST_MT));
        self.last_refill = now;

        if self.request_tokens_mt < REQUEST_COST_MT {
            return false;
        }
        self.request_tokens_mt -= REQUEST_COST_MT;
        true
    }
}

/// RAII accounting for one accepted connection.
struct ConnectionPermit {
    state: Arc<AppState>,
    key: [u8; 32],
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.state.close_connection(self.key);
    }
}

/// Everything the connection handlers share.
///
/// The peer list is a replaceable validated snapshot. RPC handlers and the
/// tunnel's local resolver read the same snapshot, so a successful config
/// reload changes both sets of answers together.
#[derive(Debug)]
pub struct AppState {
    registry: SharedRegistry,
    /// Which configured peers have been heard from during this process. The
    /// set is historical, so it can include a peer later removed by reload.
    seen: Mutex<HashSet<[u8; 32]>>,
    /// Requests from keys with no record. Counted, never recorded per key — an
    /// unconfigured caller must not be able to grow a table here.
    refused: AtomicU64,
    /// Per-configured-peer connection and request accounting. Entries are
    /// created only for keys present in the registry, so an unconfigured
    /// authenticated caller cannot grow this table.
    usage: Mutex<HashMap<[u8; 32], PeerUsage>>,
    rate_limited: AtomicU64,
    connection_limited: AtomicU64,
}

impl AppState {
    pub fn new(registry: Registry) -> Arc<Self> {
        Arc::new(Self {
            registry: SharedRegistry::new(registry),
            seen: Mutex::new(HashSet::new()),
            refused: AtomicU64::new(0),
            usage: Mutex::new(HashMap::new()),
            rate_limited: AtomicU64::new(0),
            connection_limited: AtomicU64::new(0),
        })
    }

    /// Shared registry handle used by the config-backed tunnel resolver.
    pub fn registry(&self) -> SharedRegistry {
        self.registry.clone()
    }

    /// Distinct peers heard from.
    pub fn known_count(&self) -> usize {
        self.seen().len()
    }

    /// Peers API operations refused for coming from an unconfigured key.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    pub fn rate_limited(&self) -> u64 {
        self.rate_limited.load(Ordering::Relaxed)
    }

    pub fn connection_limited(&self) -> u64 {
        self.connection_limited.load(Ordering::Relaxed)
    }

    /// Reserve one connection slot for a configured authenticated key.
    ///
    /// Unconfigured keys remain untracked so they cannot grow `usage`; their
    /// ordinary request admission still returns the protocol's indistinguishable
    /// `not_found` result.
    fn open_connection(self: &Arc<Self>, key: [u8; 32]) -> Option<ConnectionPermit> {
        let registry = self.registry.config_snapshot();
        if registry.lookup_key(&key).is_none() {
            return Some(ConnectionPermit {
                state: Arc::clone(self),
                key,
            });
        }

        let mut usage = self
            .usage
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        usage.retain(|public_key, peer| {
            peer.connections != 0 || registry.lookup_key(public_key).is_some()
        });
        let peer = usage
            .entry(key)
            .or_insert_with(|| PeerUsage::new(Instant::now()));
        if peer.connections >= MAX_CONNECTIONS_PER_PEER {
            let count = self.connection_limited.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::warn!(
                "dropping Peers API connection from {}: per-peer connection limit {} reached ({count} dropped so far)",
                &encode_key(&key).as_str()[..KEY_PREFIX_LEN],
                MAX_CONNECTIONS_PER_PEER,
            );
            return None;
        }
        peer.connections += 1;
        Some(ConnectionPermit {
            state: Arc::clone(self),
            key,
        })
    }

    fn close_connection(&self, key: [u8; 32]) {
        let configured = self.registry.config_snapshot().lookup_key(&key).is_some();
        let mut usage = self
            .usage
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(peer) = usage.get_mut(&key) else {
            return;
        };
        peer.connections = peer.connections.saturating_sub(1);
        // Once a key disappears from the registry and has no live connection,
        // forget its limiter state rather than retaining historical keys.
        if peer.connections == 0 && !configured {
            usage.remove(&key);
        }
    }

    fn allow_request(&self, key: [u8; 32]) -> bool {
        let registry = self.registry.config_snapshot();
        if registry.lookup_key(&key).is_none() {
            return true;
        }
        let mut usage = self
            .usage
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        usage.retain(|public_key, peer| {
            peer.connections != 0 || registry.lookup_key(public_key).is_some()
        });
        let peer = usage
            .entry(key)
            .or_insert_with(|| PeerUsage::new(Instant::now()));
        if peer.allow_request(Instant::now()) {
            return true;
        }
        let count = self.rate_limited.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::debug!(
            "rate limiting Peers API request from {} ({count} limited so far)",
            &encode_key(&key).as_str()[..KEY_PREFIX_LEN]
        );
        false
    }

    /// Note an API operation from a peer. Returns `true` the first time each key is
    /// seen, which the caller uses to log arrivals once rather than per
    /// request.
    fn note(&self, record: &PeerRecord) -> bool {
        self.seen().insert(record.public_key)
    }

    /// Account for an API operation from a key with no record.
    ///
    /// The first one is worth an operator's attention — a peer the tunnel
    /// accepted is missing from the map. The rest are counted and logged at
    /// `debug`, so a persistent caller cannot turn this into a log amplifier.
    fn refuse(&self, source: [u8; 32]) {
        let count = self.refused.fetch_add(1, Ordering::Relaxed) + 1;
        if count == 1 {
            tracing::warn!(
                "refusing a Peers API operation from authenticated peer {}: it has no [Server] or \
                 [Peer.name] record. It can open a tunnel session but cannot resolve",
                encode_key(&source)
            );
        } else {
            tracing::debug!(
                "refusing a Peers API operation from {} ({count} refused so far)",
                encode_key(&source)
            );
        }
    }

    /// A poisoned lock only means a previous holder panicked while holding a
    /// set of keys; the server has no reason to stop answering API operations over it.
    fn seen(&self) -> std::sync::MutexGuard<'_, HashSet<[u8; 32]>> {
        self.seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// What the accept loop knows about one connection.
///
/// Set once, at accept, and never varies for the life of the connection.
#[derive(Debug, Clone, Copy)]
pub struct Connection {
    /// The authenticated tunnel identity the connection was attributed to.
    /// This, and only this, is what a request is admitted on.
    pub key: [u8; 32],
}

impl Connection {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
}

/// The RPC dispatcher for one accepted connection.
#[derive(Debug)]
pub struct PeersApiHandler {
    state: Arc<AppState>,
    connection: Connection,
    /// The caller's key prefix for log lines. Connection identity is fixed at
    /// accept, so this is rendered once rather than per request.
    caller: String,
    watched: Arc<Mutex<HashSet<[u8; 32]>>>,
}

/// What one lookup asks for. The two methods differ only in this.
#[derive(Debug, Clone, Copy)]
enum Lookup<'a> {
    Key(&'a str),
    Address(&'a str),
}

/// What the registry had to say about one request.
///
/// The three non-record outcomes are kept apart deliberately. Only
/// [`Answer::Miss`] is a statement about the *target*, and only a statement
/// about the target may become the authoritative `{"not_found":{}}` a client
/// deletes a held record on.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum Answer {
    /// The registry holds this record.
    Record(PeerInfo),
    /// The registry authoritatively holds nothing for the requested target.
    Miss,
    /// The caller's own key has no registry record.
    NotAdmitted,
    /// The parameter was well-shaped JSON but not a decodable key or address.
    BadArgument,
}

impl PeersApiHandler {
    pub fn new(
        state: Arc<AppState>,
        connection: Connection,
        watched: Arc<Mutex<HashSet<[u8; 32]>>>,
    ) -> Self {
        let caller = encode_key(&connection.key).as_str()[..KEY_PREFIX_LEN].to_string();
        Self {
            state,
            connection,
            caller,
            watched,
        }
    }

    /// Admit the caller and resolve one side-effect-free lookup.
    fn lookup(&self, query: Lookup<'_>) -> Answer {
        self.state.registry.read(|published| {
            if admit(&self.state, published.config(), self.connection.key).is_none() {
                return Answer::NotAdmitted;
            }
            let record = match query {
                Lookup::Key(text) => {
                    let Ok(key) = decode_key(text) else {
                        return Answer::BadArgument;
                    };
                    published.lookup_key(&key)
                }
                Lookup::Address(text) => {
                    let Ok(address) = text.parse::<IpAddr>() else {
                        return Answer::BadArgument;
                    };
                    published.lookup_address(microtun_api::unmap_address(address))
                }
            };
            match record {
                Some(record) => Answer::Record(published.info(record)),
                None => Answer::Miss,
            }
        })
    }

    /// Explicitly subscribe to one key and return its current record.
    ///
    /// The watch-set insertion and published-state read share one critical
    /// section so neither a config reload nor an endpoint observation can land
    /// after the returned snapshot but before the watch becomes visible. Every
    /// outcome other than a hit subscribes nothing.
    fn watch(&self, text: &str) -> Answer {
        self.state.registry.read(|published| {
            if admit(&self.state, published.config(), self.connection.key).is_none() {
                return Answer::NotAdmitted;
            }
            let Ok(public_key) = decode_key(text) else {
                return Answer::BadArgument;
            };
            let Some(record) = published.lookup_key(&public_key) else {
                return Answer::Miss;
            };
            self.watched().insert(public_key);
            Answer::Record(published.info(record))
        })
    }

    /// Turn one resolved answer into a response.
    fn respond(&self, method: &str, answer: Answer, responder: Responder<'_>) -> Reply {
        match answer {
            Answer::Record(record) => {
                tracing::debug!(
                    "{method} from {} answered with peer {}",
                    self.caller,
                    &record.public_key.as_str()[..KEY_PREFIX_LEN]
                );
                responder.ok(&LookupResult::Found(record))
            }
            Answer::Miss => {
                tracing::debug!("{method} from {} not found", self.caller);
                miss(responder)
            }
            // Never a miss: see the module header. The caller's own admission
            // says nothing about whether the peer it asked about exists.
            Answer::NotAdmitted => {
                tracing::debug!("{method} from unadmitted caller {}", self.caller);
                responder.error(
                    microtun_api::ERROR_NOT_ADMITTED,
                    "caller is not a configured peer",
                )
            }
            Answer::BadArgument => {
                tracing::debug!("{method} from {} had an undecodable argument", self.caller);
                responder.error(
                    codes::INVALID_PARAMS,
                    "params member is not a valid public key or address",
                )
            }
        }
    }

    fn watched(&self) -> std::sync::MutexGuard<'_, HashSet<[u8; 32]>> {
        self.watched
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Handler for PeersApiHandler {
    fn handle_request(
        &mut self,
        method: &str,
        params: Params<'_>,
        responder: Responder<'_>,
    ) -> Reply {
        if !self.state.allow_request(self.connection.key) {
            // A rate limit is transient. Never turn it into `not_found`, which
            // clients are required to negative-cache as authoritative.
            return responder.error(
                microtun_api::ERROR_RATE_LIMITED,
                "request rate limit exceeded",
            );
        }
        match method {
            METHOD_BY_KEY => {
                let Ok(args) = params.parse::<KeyParams<'_>>() else {
                    return responder.invalid_params();
                };
                let record = self.lookup(Lookup::Key(args.public_key));
                self.respond(METHOD_BY_KEY, record, responder)
            }
            METHOD_BY_ADDRESS => {
                let Ok(args) = params.parse::<ByAddressParams<'_>>() else {
                    return responder.invalid_params();
                };
                let record = self.lookup(Lookup::Address(args.address));
                self.respond(METHOD_BY_ADDRESS, record, responder)
            }
            METHOD_WATCH => {
                let Ok(args) = params.parse::<KeyParams<'_>>() else {
                    return responder.invalid_params();
                };
                let record = self.watch(args.public_key);
                self.respond(METHOD_WATCH, record, responder)
            }
            _ => responder.method_not_found(),
        }
    }

    fn handle_notification(&mut self, method: &str, params: Params<'_>) {
        if method != METHOD_UNWATCH {
            return;
        }
        let Ok(args) = params.parse::<KeyParams<'_>>() else {
            tracing::debug!("ignoring {method} with invalid params");
            return;
        };
        let registry = self.state.registry.config_snapshot();
        if admit(&self.state, &registry, self.connection.key).is_none() {
            return;
        }
        let Ok(public_key) = decode_key(args.public_key) else {
            tracing::debug!("ignoring {method} from {} with invalid key", self.caller);
            return;
        };

        self.watched().remove(&public_key);
        tracing::debug!(
            "{METHOD_UNWATCH} from {} for {}",
            self.caller,
            encode_key(&public_key)
        );
    }
}

/// Resolve the caller by the authenticated tunnel peer key.
fn admit<'a>(state: &AppState, registry: &'a Registry, source: [u8; 32]) -> Option<&'a PeerRecord> {
    match registry.lookup_key(&source) {
        Some(caller) => {
            if state.note(caller) {
                tracing::info!("first Peers API operation from {}", caller.key_prefix());
            }
            Some(caller)
        }
        None => {
            state.refuse(source);
            None
        }
    }
}

/// The authoritative miss.
///
/// An unknown key and an address nobody claims are the same
/// `{"not_found":{}}` and are meant to be indistinguishable. An unadmitted
/// caller, an undecodable argument, and an overloaded server are *not* misses
/// and never reach here; see the module header.
fn miss(responder: Responder<'_>) -> Reply {
    responder.ok(&LookupResult::NotFound {})
}

/// Serve JSON-RPC on one connection until it ends.
///
/// A reply that does not fit the transmit buffer degrades to an `internal
/// error` response inside `microtun-jsonrpc` rather than desynchronizing the
/// stream, and [`microtun_api::RECORD_FRAME_LEN`] is sized so that a
/// worst-case record never reaches that path.
pub async fn serve_connection<S>(stream: S, state: Arc<AppState>, connection: Connection)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    // Refuse an unadmitted caller by closing the stream rather than by serving
    // it misses. A client classifies a refused connection as transient and
    // keeps the records it holds; it would classify a `not_found` replay as
    // authoritative and delete all of them. The two are indistinguishable to a
    // caller that was never admitted, and decisively different to one whose
    // admission lapsed because of a bad config push.
    if state
        .registry
        .config_snapshot()
        .lookup_key(&connection.key)
        .is_none()
    {
        state.refuse(connection.key);
        return;
    }
    let Some(_connection_permit) = state.open_connection(connection.key) else {
        return;
    };
    let registry = state.registry();
    let mut changes = registry.subscribe();
    let watched = Arc::new(Mutex::new(HashSet::new()));

    let (reader, writer) = tokio::io::split(stream);
    let writer = SharedWriter::new(writer);
    let reader_writer = writer.clone();
    let reader_state = Arc::clone(&state);
    let reader_watched = Arc::clone(&watched);
    let mut reader_task = tokio::spawn(async move {
        let mut connection: RpcConnection<_, _, _, QUERY_FRAME_LEN, RECORD_FRAME_LEN> =
            RpcConnection::new(
                TokioIo::new(reader),
                reader_writer,
                PeersApiHandler::new(reader_state, connection, reader_watched),
            );
        loop {
            connection.poll().await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), microtun_jsonrpc::Error>(())
    });
    let mut notifier: Notifier<_, RECORD_FRAME_LEN> = Notifier::new(writer);

    loop {
        tokio::select! {
            result = &mut reader_task => {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => tracing::debug!("RPC connection ended: {error}"),
                    Err(error) => tracing::debug!("RPC reader task ended: {error}"),
                }
                return;
            }
            change = changes.recv() => {
                match change {
                    Ok(change) => {
                        if registry.config_snapshot().lookup_key(&connection.key).is_none() {
                            reader_task.abort();
                            return;
                        }
                        let interested = watched
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .contains(&change.public_key);
                        if interested
                            && send_peer_changed(&mut notifier, change.public_key)
                                .await
                                .is_err()
                        {
                            reader_task.abort();
                            return;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // A slow connection may have missed several changes.
                        // Since a notification carries no state, recovering
                        // needs no registry read and no comparison: name every
                        // watched key once and let the client re-look-up.
                        let keys: Vec<_> = watched
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .iter()
                            .copied()
                            .collect();
                        if registry.config_snapshot().lookup_key(&connection.key).is_none() {
                            reader_task.abort();
                            return;
                        }
                        for public_key in keys {
                            if send_peer_changed(&mut notifier, public_key).await.is_err() {
                                reader_task.abort();
                                return;
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        reader_task.abort();
                        return;
                    }
                }
            }
        }
    }
}

/// Tell this connection that one watched key may no longer be current.
///
/// The notification names the key and nothing else, so this reads no registry
/// state and compares nothing. The client answers it with an ordinary
/// `v1.peer.by_key`; the notification itself therefore never installs or removes
/// a record. It cannot be reordered into a stale install, and sending a
/// spurious one costs a round trip rather than correctness.
async fn send_peer_changed<W>(
    notifier: &mut Notifier<W, RECORD_FRAME_LEN>,
    public_key: [u8; 32],
) -> Result<(), microtun_jsonrpc::Error>
where
    W: embedded_io_async::Write,
{
    let text = encode_key(&public_key);
    let params = KeyParams {
        public_key: text.as_str(),
    };
    notifier.notify(METHOD_CHANGED, Some(&params)).await
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use microtun_api::PeerInfo;
    use microtun_jsonrpc::{Error as RpcError, NoHandler};
    use serde::Serialize;
    use tokio::sync::mpsc;

    use super::*;
    use crate::config::{
        self,
        tests::{SERVER_PRIVATE, server_public},
    };

    const GATEWAY_KEY: [u8; 32] = [0xAA; 32];
    const LAPTOP_KEY: [u8; 32] = [0xBB; 32];
    const ABSENT_KEY: [u8; 32] = [0xCC; 32];

    /// The same three keys as a configuration file, a parameter, and a result
    /// spell them: WireGuard's base64, which is now the only spelling there is.
    const GATEWAY: &str = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=";
    const LAPTOP: &str = "u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s=";
    const ABSENT: &str = "zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw=";

    /// Collects the public keys named by `v1.peer.changed`. A notification carries
    /// nothing else, so there is nothing else to capture.
    #[derive(Debug)]
    struct CaptureChanged(mpsc::UnboundedSender<[u8; 32]>);

    impl Handler for CaptureChanged {
        fn handle_request(
            &mut self,
            _method: &str,
            _params: Params<'_>,
            responder: Responder<'_>,
        ) -> Reply {
            responder.method_not_found()
        }

        fn handle_notification(&mut self, method: &str, params: Params<'_>) {
            if method != METHOD_CHANGED {
                return;
            }
            let args = params
                .parse::<KeyParams<'_>>()
                .expect("server sends valid change notifications");
            let key = decode_key(args.public_key).expect("server names a valid key");
            let _ = self.0.send(key);
        }
    }

    /// The test network: the server and gateway each own a /32, while the
    /// laptop owns the /24 around them, so longest-prefix behavior is exercised
    /// — and so a source-address attribution would get the laptop wrong.
    fn config_text() -> String {
        format!(
            "\
[Server]
PrivateKey = {SERVER_PRIVATE}
ListenPort = 51820
Endpoint = 203.0.113.10:51820
Addresses = 10.0.0.9/32

[Peer.gateway]
PublicKey = {GATEWAY}
Endpoint = 198.51.100.20:51820
Addresses = 10.0.0.1/32, 10.5.0.0/24

[Peer.laptop]
PublicKey = {LAPTOP}
Addresses = 10.0.0.0/24
Relay = gateway
"
        )
    }

    fn app_state() -> Arc<AppState> {
        let loaded =
            config::parse(&config_text(), Path::new("test.conf")).expect("test config loads");
        AppState::new(loaded.registry)
    }

    fn connection(from: [u8; 32]) -> Connection {
        Connection::new(from)
    }

    /// Issue one call over a real connection, as if it arrived over a session
    /// authenticated to `from`.
    async fn call_on<P, T>(
        state: &Arc<AppState>,
        connection: Connection,
        method: &str,
        params: Option<&P>,
    ) -> Result<T, RpcError>
    where
        P: Serialize + ?Sized,
        T: serde::de::DeserializeOwned,
    {
        let (client, server) = tokio::io::duplex(8192);
        tokio::spawn(serve_connection(server, Arc::clone(state), connection));

        let (reader, writer) = tokio::io::split(client);
        let mut connection: RpcConnection<_, _, _, RECORD_FRAME_LEN, QUERY_FRAME_LEN> =
            RpcConnection::from_tokio(reader, writer, NoHandler);
        connection.call(method, params).await
    }

    /// The same, over a connection from `from` at the usual test source.
    async fn call<P, T>(
        state: &Arc<AppState>,
        from: [u8; 32],
        method: &str,
        params: Option<&P>,
    ) -> Result<T, RpcError>
    where
        P: Serialize + ?Sized,
        T: serde::de::DeserializeOwned,
    {
        call_on(state, connection(from), method, params).await
    }

    /// Reduce a lookup result to the record it carries, asserting on the way
    /// through that the server emitted one of the two conforming shapes.
    ///
    /// Every test that only cares about hit-or-miss goes through here, so the
    /// wire shape is checked on every lookup the suite makes rather than in
    /// one dedicated test.
    fn found(result: LookupResult) -> Option<PeerInfo> {
        match result {
            LookupResult::Found(peer) => Some(peer),
            LookupResult::NotFound {} => None,
        }
    }

    /// A `by_key` lookup, built exactly as a client builds one.
    async fn by_key(state: &Arc<AppState>, from: [u8; 32], key: &str) -> Option<PeerInfo> {
        let result: LookupResult = call(
            state,
            from,
            METHOD_BY_KEY,
            Some(&microtun_api::QueryParams::ByKey { public_key: key }),
        )
        .await
        .expect("the call completes");
        found(result)
    }

    /// The error code a call was rejected with.
    ///
    /// Undecodable arguments and unadmitted callers are now errors rather than
    /// misses, so the suite has to be able to look at the code.
    fn error_code<T: std::fmt::Debug>(result: Result<T, RpcError>) -> i32 {
        match result {
            Err(RpcError::Remote(error)) => error.code,
            other => panic!("expected a remote error, got {other:?}"),
        }
    }

    /// A `by_key` call that is expected to be rejected.
    async fn by_key_error(state: &Arc<AppState>, from: [u8; 32], key: &str) -> i32 {
        error_code(
            call::<_, LookupResult>(
                state,
                from,
                METHOD_BY_KEY,
                Some(&microtun_api::QueryParams::ByKey { public_key: key }),
            )
            .await,
        )
    }

    /// A `by_address` lookup from the laptop.
    async fn by_address(state: &Arc<AppState>, address: &str) -> Option<PeerInfo> {
        let result: LookupResult = call(
            state,
            LAPTOP_KEY,
            METHOD_BY_ADDRESS,
            Some(&microtun_api::QueryParams::ByAddress { address }),
        )
        .await
        .expect("the call completes");
        found(result)
    }

    #[tokio::test]
    async fn by_key_hits_and_misses() {
        let state = app_state();

        let record = by_key(&state, LAPTOP_KEY, GATEWAY)
            .await
            .expect("the gateway is configured");
        assert_eq!(record.public_key.as_str(), GATEWAY);
        assert_eq!(record.endpoint.as_deref(), Some("198.51.100.20:51820"));

        // The Peers API server's own record is keyed by the key derived from
        // [Server] PrivateKey.
        let server_text = encode_key(&server_public());
        let record = by_key(&state, LAPTOP_KEY, server_text.as_str())
            .await
            .expect("the server has its own record");
        assert_eq!(record.public_key.as_str(), server_text.as_str());

        // A well-formed key nobody holds is the authoritative miss.
        assert!(by_key(&state, LAPTOP_KEY, ABSENT).await.is_none());

        // A string that is not a key at all is not a statement about the peer
        // table, so it is a caller error rather than a negative-cached miss.
        for key in [
            "not-a-key",
            // The URL-safe, unpadded spelling was a property of a path
            // segment. There are no paths, and it is not a key.
            &GATEWAY[..43],
            // Base64 is case-sensitive, and re-casing this key also leaves
            // non-canonical trailing bits, so it does not decode.
            &GATEWAY.to_uppercase(),
        ] {
            assert_eq!(
                by_key_error(&state, LAPTOP_KEY, key).await,
                microtun_jsonrpc::codes::INVALID_PARAMS,
                "expected invalid-params for {key}"
            );
        }
    }

    #[tokio::test]
    async fn learned_endpoint_overrides_config_in_rpc_answers() {
        let state = app_state();
        let learned: std::net::SocketAddr = "203.0.113.20:42424".parse().unwrap();
        state.registry().observe_endpoint(GATEWAY_KEY, learned);

        let by_key_record = by_key(&state, LAPTOP_KEY, GATEWAY).await.expect("gateway");
        assert_eq!(
            by_key_record.endpoint.as_deref(),
            Some("203.0.113.20:42424")
        );

        let by_address_record = by_address(&state, "10.0.0.1").await.expect("gateway");
        assert_eq!(
            by_address_record.endpoint.as_deref(),
            Some("203.0.113.20:42424")
        );
    }

    #[tokio::test]
    async fn by_address_uses_the_longest_prefix() {
        let state = app_state();

        // 10.0.0.1/32 (gateway) beats 10.0.0.0/24 (laptop).
        let record = by_address(&state, "10.0.0.1").await.expect("gateway");
        assert_eq!(record.public_key.as_str(), GATEWAY);

        let record = by_address(&state, "10.0.0.5").await.expect("laptop");
        assert_eq!(record.public_key.as_str(), LAPTOP);

        // 10.0.0.9/32 from [Server] also beats the laptop's /24.
        let record = by_address(&state, "10.0.0.9").await.expect("server");
        assert_eq!(
            record.public_key.as_str(),
            encode_key(&server_public()).as_str()
        );

        // IPv4-mapped IPv6 finds the same v4 prefix.
        let record = by_address(&state, "::ffff:10.0.0.1")
            .await
            .expect("gateway");
        assert_eq!(record.public_key.as_str(), GATEWAY);

        // An address nobody claims is a miss; a string that is not an address
        // is a caller error.
        for address in ["192.0.2.1", "fd00::1"] {
            assert!(
                by_address(&state, address).await.is_none(),
                "expected a miss for {address}"
            );
        }
        let rejected = error_code(
            call::<_, LookupResult>(
                &state,
                LAPTOP_KEY,
                METHOD_BY_ADDRESS,
                Some(&microtun_api::QueryParams::ByAddress {
                    address: "not-an-address",
                }),
            )
            .await,
        );
        assert_eq!(rejected, microtun_jsonrpc::codes::INVALID_PARAMS);
    }

    /// The answer this server produces must decode with the codec every client
    /// uses. This is the contract test; the rest is plumbing.
    #[tokio::test]
    async fn answers_decode_with_the_client_codec() {
        let state = app_state();

        let record = by_key(&state, LAPTOP_KEY, GATEWAY).await.expect("gateway");
        let peer = microtun_api::decode_peer(&record).expect("client codec decodes");
        assert_eq!(peer.public_key, GATEWAY_KEY);
        assert_eq!(peer.endpoint, Some("198.51.100.20:51820".parse().unwrap()));
        assert_eq!(peer.relay, None);
        assert_eq!(peer.addresses.len(), 2);

        let record = by_key(&state, LAPTOP_KEY, LAPTOP).await.expect("laptop");
        let peer = microtun_api::decode_peer(&record).expect("client codec decodes");
        assert_eq!(peer.public_key, LAPTOP_KEY);
        assert_eq!(peer.endpoint, None);
        assert_eq!(peer.relay, Some(GATEWAY_KEY));

        // A by-address answer must cover the queried address, or the core
        // discards it as a mismatched positive.
        let queried: IpAddr = "10.0.0.5".parse().unwrap();
        let record = by_address(&state, "10.0.0.5").await.expect("laptop");
        let peer = microtun_api::decode_peer(&record).expect("client codec decodes");
        assert!(peer.addresses.iter().any(|cidr| cidr.contains(&queried)));
    }

    #[tokio::test]
    async fn lookups_are_pure_and_explicit_watch_receives_changed() {
        let state = app_state();
        let (client, server) = tokio::io::duplex(8192);
        tokio::spawn(serve_connection(
            server,
            Arc::clone(&state),
            connection(LAPTOP_KEY),
        ));

        let (reader, writer) = tokio::io::split(client);
        let (changed_tx, mut changed_rx) = mpsc::unbounded_channel();
        let mut connection: RpcConnection<_, _, _, RECORD_FRAME_LEN, QUERY_FRAME_LEN> =
            RpcConnection::from_tokio(reader, writer, CaptureChanged(changed_tx));

        // Ordinary lookups are side-effect free.
        let initial_peer: LookupResult = connection
            .call(
                METHOD_BY_KEY,
                Some(&microtun_api::QueryParams::ByKey {
                    public_key: GATEWAY,
                }),
            )
            .await
            .expect("lookup completes");
        assert_eq!(
            found(initial_peer)
                .as_ref()
                .and_then(|peer| peer.endpoint.as_deref()),
            Some("198.51.100.20:51820")
        );

        let replacement = config_text().replace("198.51.100.20:51820", "198.51.100.99:51820");
        let loaded =
            config::parse(&replacement, Path::new("test.conf")).expect("replacement loads");
        state.registry().replace(loaded.registry);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), connection.poll())
                .await
                .is_err(),
            "a pure lookup must not create a watch"
        );

        // `v1.peer.watch` explicitly creates the subscription and returns the
        // current by-key record in the same atomic operation.
        let watched: LookupResult = connection
            .call(
                METHOD_WATCH,
                Some(&KeyParams {
                    public_key: GATEWAY,
                }),
            )
            .await
            .expect("watch completes");
        assert_eq!(
            found(watched).and_then(|peer| peer.endpoint.map(|text| text.as_str().to_string())),
            Some("198.51.100.99:51820".to_string())
        );
        assert!(changed_rx.try_recv().is_err());

        // A watch miss subscribes nothing: there is no record to keep fresh.
        let absent: LookupResult = connection
            .call(METHOD_WATCH, Some(&KeyParams { public_key: ABSENT }))
            .await
            .expect("watch miss completes");
        assert!(found(absent).is_none());

        let replacement = replacement.replace("198.51.100.99:51820", "198.51.100.77:51820");
        let loaded =
            config::parse(&replacement, Path::new("test.conf")).expect("second replacement loads");
        state.registry().replace(loaded.registry);

        // The notification names the key and nothing else. Learning what
        // changed takes an ordinary side-effect-free lookup.
        connection.poll().await.expect("notification arrives");
        assert_eq!(
            changed_rx.recv().await.expect("captured changed key"),
            GATEWAY_KEY
        );

        let refreshed: LookupResult = connection
            .call(
                METHOD_BY_KEY,
                Some(&microtun_api::QueryParams::ByKey {
                    public_key: GATEWAY,
                }),
            )
            .await
            .expect("re-lookup completes");
        assert_eq!(
            found(refreshed).and_then(|peer| peer.endpoint.map(|text| text.as_str().to_string())),
            Some("198.51.100.77:51820".to_string())
        );

        connection
            .notify(
                METHOD_UNWATCH,
                Some(&KeyParams {
                    public_key: GATEWAY,
                }),
            )
            .await
            .expect("unwatch is sent");
        // A following request is an ordering barrier: the server must consume
        // the unwatch before it can answer it. The request itself is pure.
        let _: LookupResult = connection
            .call(
                METHOD_BY_KEY,
                Some(&microtun_api::QueryParams::ByKey { public_key: ABSENT }),
            )
            .await
            .expect("lookup ordering barrier completes");

        let replacement = replacement.replace("198.51.100.77:51820", "198.51.100.66:51820");
        let loaded =
            config::parse(&replacement, Path::new("test.conf")).expect("third replacement loads");
        state.registry().replace(loaded.registry);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), connection.poll())
                .await
                .is_err(),
            "unwatched keys must not receive later notifications"
        );
    }

    /// A removed peer is reported by the same notification as a modified one.
    /// Only the re-lookup's `not_found` distinguishes them, and that is the only
    /// authoritative removal signal in the protocol.
    #[tokio::test]
    async fn removal_is_a_change_notification_and_then_a_not_found_lookup() {
        let state = app_state();
        let (client, server) = tokio::io::duplex(8192);
        tokio::spawn(serve_connection(
            server,
            Arc::clone(&state),
            connection(LAPTOP_KEY),
        ));

        let (reader, writer) = tokio::io::split(client);
        let (changed_tx, mut changed_rx) = mpsc::unbounded_channel();
        let mut connection: RpcConnection<_, _, _, RECORD_FRAME_LEN, QUERY_FRAME_LEN> =
            RpcConnection::from_tokio(reader, writer, CaptureChanged(changed_tx));

        let hit: LookupResult = connection
            .call(
                METHOD_WATCH,
                Some(&KeyParams {
                    public_key: GATEWAY,
                }),
            )
            .await
            .expect("watch completes");
        assert!(found(hit).is_some());

        // Drop the gateway from the registry entirely.
        let without_gateway = format!(
            "\
[Server]
PrivateKey = {SERVER_PRIVATE}
ListenPort = 51820
Endpoint = 203.0.113.10:51820
Addresses = 10.0.0.9/32

[Peer.laptop]
PublicKey = {LAPTOP}
Addresses = 10.0.0.0/24
"
        );
        let loaded = config::parse(&without_gateway, Path::new("test.conf"))
            .expect("gateway-less config loads");
        state.registry().replace(loaded.registry);

        connection.poll().await.expect("notification arrives");
        assert_eq!(
            changed_rx.recv().await.expect("captured changed key"),
            GATEWAY_KEY
        );

        let gone: LookupResult = connection
            .call(
                METHOD_BY_KEY,
                Some(&microtun_api::QueryParams::ByKey {
                    public_key: GATEWAY,
                }),
            )
            .await
            .expect("re-lookup completes");
        assert!(found(gone).is_none(), "the not_found result is the removal");
    }

    #[tokio::test]
    async fn published_registry_replacement_changes_answers() {
        let state = app_state();

        let replacement = config_text()
            .replace("198.51.100.20:51820", "198.51.100.99:51820")
            .replace("10.5.0.0/24", "10.6.0.0/24");
        let loaded =
            config::parse(&replacement, Path::new("test.conf")).expect("replacement config loads");
        state.registry().replace(loaded.registry);

        let record = by_key(&state, LAPTOP_KEY, GATEWAY).await.expect("gateway");
        assert_eq!(record.endpoint.as_deref(), Some("198.51.100.99:51820"));

        assert!(by_address(&state, "10.5.0.1").await.is_none());
        assert!(by_address(&state, "10.6.0.1").await.is_some());
    }

    /// An unadmitted caller must never receive `not_found`.
    ///
    /// This is the whole point of refusing at accept. A client classifies a
    /// closed connection as transient and keeps its records; it classifies
    /// `not_found` as authoritative and deletes them. If admission lapses
    /// because of a bad config push, the difference between those two
    /// behaviours is the difference between a fleet that reconnects and a
    /// fleet that has erased its routing state.
    #[tokio::test]
    async fn unconfigured_callers_are_refused_without_an_authoritative_miss() {
        let state = app_state();

        // Same lookup, once from a configured peer and once from a key with no
        // record. The configured peer is answered; the unconfigured one never
        // gets a response frame at all.
        assert!(by_key(&state, GATEWAY_KEY, GATEWAY).await.is_some());

        for (method, params) in [
            (METHOD_BY_KEY, serde_json::json!({ "public_key": GATEWAY })),
            (
                METHOD_BY_ADDRESS,
                serde_json::json!({ "address": "10.0.0.1" }),
            ),
            (METHOD_WATCH, serde_json::json!({ "public_key": GATEWAY })),
        ] {
            let result: Result<LookupResult, _> =
                call(&state, ABSENT_KEY, method, Some(&params)).await;
            match result {
                // The stream closed without answering. Anything else would be
                // a regression only if it were a successful `not_found`.
                Err(RpcError::Eof) | Err(RpcError::Io(_)) => {}
                Ok(LookupResult::NotFound {}) => {
                    panic!("{method} answered an unadmitted caller with an authoritative miss")
                }
                other => panic!("expected a refused connection for {method}, got {other:?}"),
            }
        }

        // One refusal per refused connection.
        assert_eq!(state.refused(), 3);
        assert_eq!(state.known_count(), 1);
    }

    /// A caller removed by a reload mid-connection is disconnected, and any
    /// request that races the close is a transient error rather than a miss.
    #[tokio::test]
    async fn a_caller_removed_mid_connection_never_sees_a_miss() {
        let state = app_state();
        let registry = state.registry();
        let handler = PeersApiHandler::new(
            Arc::clone(&state),
            connection(LAPTOP_KEY),
            Arc::new(Mutex::new(HashSet::new())),
        );

        // Drop the laptop — the caller itself — from the registry.
        let without_laptop = format!(
            "\
[Server]
PrivateKey = {SERVER_PRIVATE}
ListenPort = 51820
Endpoint = 203.0.113.10:51820
Addresses = 10.0.0.9/32

[Peer.gateway]
PublicKey = {GATEWAY}
Endpoint = 198.51.100.20:51820
Addresses = 10.0.0.1/32, 10.5.0.0/24
"
        );
        let loaded = config::parse(&without_laptop, Path::new("test.conf")).expect("config loads");
        registry.replace(loaded.registry);

        // The gateway still exists, so a miss here would be a lie about the
        // gateway rather than a statement about the caller.
        assert!(matches!(
            handler.lookup(Lookup::Key(GATEWAY)),
            Answer::NotAdmitted
        ));
        assert!(matches!(handler.watch(GATEWAY), Answer::NotAdmitted));
    }

    #[tokio::test]
    async fn peers_are_tracked_once_per_key() {
        let state = app_state();

        let _ = by_key(&state, LAPTOP_KEY, GATEWAY).await;
        let _ = by_key(
            &state,
            LAPTOP_KEY,
            "zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw=",
        )
        .await;
        let _ = by_key(&state, GATEWAY_KEY, LAPTOP).await;

        assert_eq!(state.known_count(), 2);
        assert_eq!(state.refused(), 0);
    }

    #[tokio::test]
    async fn unknown_and_unsupported_versions_are_rejected() {
        let state = app_state();
        for method in ["peer.by_key", "v2.peer.by_key", "v1.peer.by_name"] {
            let result: Result<LookupResult, _> =
                call(&state, LAPTOP_KEY, method, None::<&()>).await;
            match result {
                Err(RpcError::Remote(error)) => {
                    assert_eq!(error.code, microtun_jsonrpc::codes::METHOD_NOT_FOUND)
                }
                other => panic!("expected method-not-found for {method}, got {other:?}"),
            }
        }
    }

    /// A broken caller learns it is broken; the peer table stays opaque.
    #[tokio::test]
    async fn malformed_params_are_an_error_not_a_miss() {
        let state = app_state();
        let result: Result<LookupResult, _> =
            call(&state, LAPTOP_KEY, METHOD_BY_KEY, None::<&()>).await;
        match result {
            Err(RpcError::Remote(error)) => {
                assert_eq!(error.code, microtun_jsonrpc::codes::INVALID_PARAMS)
            }
            other => panic!("expected invalid-params, got {other:?}"),
        }
    }

    /// One connection carries many lookups, and its identity does not drift.
    #[tokio::test]
    async fn a_connection_serves_repeated_lookups() {
        let state = app_state();
        let (client, server) = tokio::io::duplex(8192);
        tokio::spawn(serve_connection(
            server,
            Arc::clone(&state),
            connection(LAPTOP_KEY),
        ));

        let (reader, writer) = tokio::io::split(client);
        let mut connection: RpcConnection<_, _, _, RECORD_FRAME_LEN, QUERY_FRAME_LEN> =
            RpcConnection::from_tokio(reader, writer, NoHandler);

        for _ in 0..4 {
            let record: LookupResult = connection
                .call(
                    METHOD_BY_KEY,
                    Some(&microtun_api::QueryParams::ByKey {
                        public_key: GATEWAY,
                    }),
                )
                .await
                .expect("the call completes");
            assert_eq!(found(record).expect("gateway").public_key.as_str(), GATEWAY);
        }
        assert_eq!(state.known_count(), 1);
    }

    #[test]
    fn request_bucket_allows_burst_then_refills() {
        let start = Instant::now();
        let mut usage = PeerUsage::new(start);

        for _ in 0..REQUEST_BURST {
            assert!(usage.allow_request(start));
        }
        assert!(!usage.allow_request(start));

        let one_token_later =
            start + std::time::Duration::from_millis(1000 / u64::from(REQUESTS_PER_SEC));
        assert!(usage.allow_request(one_token_later));
        assert!(!usage.allow_request(one_token_later));
    }

    #[test]
    fn connections_are_bounded_per_configured_key() {
        let state = app_state();
        let mut permits = Vec::new();

        for _ in 0..MAX_CONNECTIONS_PER_PEER {
            permits.push(
                state
                    .open_connection(LAPTOP_KEY)
                    .expect("connection within limit is accepted"),
            );
        }
        assert!(state.open_connection(LAPTOP_KEY).is_none());
        assert_eq!(state.connection_limited(), 1);

        permits.pop();
        assert!(state.open_connection(LAPTOP_KEY).is_some());
    }

    #[tokio::test]
    async fn excessive_requests_return_transient_errors() {
        let state = app_state();
        let (client, server) = tokio::io::duplex(8192);
        tokio::spawn(serve_connection(
            server,
            Arc::clone(&state),
            connection(LAPTOP_KEY),
        ));

        let (reader, writer) = tokio::io::split(client);
        let mut connection: RpcConnection<_, _, _, RECORD_FRAME_LEN, QUERY_FRAME_LEN> =
            RpcConnection::from_tokio(reader, writer, NoHandler);

        for _ in 0..REQUEST_BURST {
            let result: LookupResult = connection
                .call(
                    METHOD_BY_KEY,
                    Some(&microtun_api::QueryParams::ByKey {
                        public_key: GATEWAY,
                    }),
                )
                .await
                .expect("burst request is accepted");
            assert!(found(result).is_some());
        }

        let limited: Result<LookupResult, _> = connection
            .call(
                METHOD_BY_KEY,
                Some(&microtun_api::QueryParams::ByKey {
                    public_key: GATEWAY,
                }),
            )
            .await;
        match limited {
            Err(RpcError::Remote(error)) => {
                assert_eq!(error.code, microtun_api::ERROR_RATE_LIMITED);
                assert_eq!(error.message, "request rate limit exceeded");
            }
            other => panic!("expected transient rate-limit error, got {other:?}"),
        }
        assert_eq!(state.rate_limited(), 1);
    }
}
