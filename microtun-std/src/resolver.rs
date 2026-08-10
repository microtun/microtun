//! Tokio/`std` Peers API resolver.
//!
//! Lookups, explicit `v1.peer.watch` requests, `v1.peer.unwatch` notifications, and
//! `v1.peer.changed` notifications all share one long-lived newline-delimited
//! JSON-RPC connection. Ordinary lookups are side-effect free. Before returning
//! a positive resolution to the core, the resolver explicitly watches that
//! key; `v1.peer.watch` returns the current record while installing the
//! subscription atomically. The resolver services the socket while idle, so
//! notifications do not depend on a lookup being outstanding.
//!
//! # One re-lookup queue
//!
//! `v1.peer.changed` names a key and carries nothing else, so it cannot be applied:
//! it means *whatever we hold for this key may no longer be current*. The
//! answer is an ordinary `v1.peer.by_key`, whose result installs the new record
//! or authoritatively removes the peer. Reconnect replay is slightly different:
//! it reissues `v1.peer.watch` for every held key so the replacement connection
//! restores its explicit subscriptions. Both kinds of work share one ordered
//! reconciliation queue.
//!
//! The queue also settles an invalidation that races `v1.peer.watch`. Only one
//! call is ever in flight here, and a notification read during that call is
//! queued before its answer is applied, so the newly watched key is refreshed
//! once more before the queue drains.
//!
//! # Failure handling
//!
//! A resolver answer must distinguish "authoritatively unknown" from "I could
//! not ask", because the core evicts a dynamic peer on the former and retains
//! it on the latter. The mapping is:
//!
//! * exactly `{"not_found":{}}` — [`ResolveOutcome::NotFound`];
//! * `{"found":{...}}` whose record decodes — [`ResolveOutcome::Found`];
//! * anything else, including a JSON-RPC `error` object, an absent or `null`
//!   `result`, an unknown or missing variant, a malformed record, a dead
//!   connection, and a timeout — [`ResolveOutcome::Failed`].
//!
//! The tag is what makes that first line safe. Only an explicit sentinel
//! removes a peer, so no amount of truncation, omission, or decoder default
//! can be mistaken for the server saying "this peer is gone".
//!
//! Every failure is transient and drops the session. The core keeps the record
//! it already had and asks again when traffic next needs it, and the
//! replacement connection reconciles the whole set, so there is no
//! retry-on-a-fresh-connection special case to get right. A `v1.peer.changed` lost
//! with a dropped connection is recovered by that same replay.

use std::{
    collections::{HashSet, VecDeque},
    future::Future,
    io,
    net::SocketAddr,
    time::Duration,
};

use microtun_api::{
    Jitter, QUERY_FRAME_LEN, RECORD_FRAME_LEN, REFRESH_BURST_WINDOW_MS,
    client::{self as peer_api, ChangeHandler, ClientError},
};
use microtun_core::{
    PeerUpdate, ResolveOutcome, ResolveQuery, ResolveRequest, ResolveResponse, ResolverCommand,
    ResolverEvent,
};
use microtun_jsonrpc::Error as RpcError;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf},
    sync::mpsc,
};

/// Ceiling on a single lookup or connection attempt.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Base reconnect delay, spread by [`Jitter::spread_ms`] over
/// `[500ms, 1500ms)`.
///
/// A Peers API server restart drops every client at the same instant, so an
/// unjittered delay would reconnect the whole fleet in one spike. See
/// `docs/peers-api.md` §11.3.
const RECONNECT_DELAY_MS: u32 = 1_000;

/// JSON-RPC connection over the read/write halves of the Tokio transport.
type RpcConnection<S> = peer_api::TokioConnection<
    ReadHalf<S>,
    WriteHalf<S>,
    ChangeHandler,
    RECORD_FRAME_LEN,
    QUERY_FRAME_LEN,
>;

/// How the resolver reaches the Peers API server.
///
/// See [`PeersApiResolver`]: the route a lookup takes is the whole of its security,
/// so opening the connection is the caller's job and this crate ships no
/// implementation of it.
pub trait PeersApiTransport: Clone + Send + Sync + 'static {
    /// The connected byte stream.
    type Stream: AsyncRead + AsyncWrite + Send + Unpin + 'static;

    /// Open a connection to the Peers API server's inner address.
    ///
    /// The resulting connection is retained for lookups, watches, and pushed
    /// updates until either side closes it. TCP implementations must enable
    /// keep-alive probes plus a bounded liveness timeout so an otherwise quiet
    /// session cannot survive indefinitely after the peer or path disappears
    /// without a FIN/RST.
    fn connect(&self, api: SocketAddr) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reconcile {
    /// Re-establish an explicit subscription on a replacement connection.
    Rewatch([u8; 32]),
    /// Refresh a subscription that is already active on this connection.
    Refresh([u8; 32]),
}

impl Reconcile {
    const fn public_key(self) -> [u8; 32] {
        match self {
            Self::Rewatch(public_key) | Self::Refresh(public_key) => public_key,
        }
    }
}

/// Stateful Peers API client.
///
/// # Transport security
///
/// Peers API server traffic carries **no transport authentication of its own**. Its
/// integrity rests entirely on the shared connection being carried inside the
/// tunnel to the pinned Peers API server peer, whose WireGuard session authenticates
/// it.
///
/// That is not a property this type can check, so it is not one it will
/// assume. There is deliberately no constructor that supplies a default
/// transport: the caller must provide one and is thereby forced to decide how
/// its connections are routed. A resolver pointed at a routable address over an
/// unbound transport is talking to whoever answers, and a forged lookup result
/// installs attacker-chosen dynamic peers, endpoints, relays, and tunnel
/// prefixes. The core's own validation bounds the damage — a resolver
/// answer can never name a pinned key, claim a default route, or impersonate
/// this interface — but everything inside those bounds is granted.
///
/// Two conditions make a deployment sound, and both belong to the caller:
///
/// 1. `api` is the Peers API server's **tunnel** address, so the route to it is the
///    pinned peer's cryptokey route. Deriving it from the pinned peer's own
///    configured prefix rather than from separate configuration keeps the two
///    from drifting apart.
/// 2. [`PeersApiTransport::connect`] binds to the tunnel interface, so the
///    connection cannot leave by another route if the tunnel is down or a more
///    specific system route exists.
///
/// There are no redirects to refuse and no proxy environment variables to
/// disable: the transport is a caller-provided byte stream to exactly `api`.
pub struct PeersApiResolver<T: PeersApiTransport> {
    api: SocketAddr,
    transport: T,
    /// Keys whose records the core currently holds. A successful `v1.peer.watch`
    /// puts each one here; a `v1.peer.unwatch` command takes it away.
    desired: HashSet<[u8; 32]>,
    /// Ordered reconnect and invalidation reconciliation work.
    replay: VecDeque<Reconcile>,
    /// Pacing source for reconnect delays and reconciliation bursts.
    jitter: Jitter,
    /// When the current change-driven burst may issue its first refresh.
    ///
    /// `None` outside a burst, and always `None` for reconnect replay, which
    /// the jittered reconnect delay has already spread.
    burst_at: Option<tokio::time::Instant>,
    connection: Option<RpcConnection<T::Stream>>,
}

impl<T: PeersApiTransport> core::fmt::Debug for PeersApiResolver<T> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PeersApiResolver")
            .field("api", &self.api)
            .field("connected", &self.connection.is_some())
            .field("watches", &self.desired.len())
            .finish_non_exhaustive()
    }
}

impl<T: PeersApiTransport> PeersApiResolver<T> {
    /// Construct a resolver from a caller-provided transport.
    ///
    /// See the type-level documentation: routing policy is what makes
    /// resolution trustworthy, so the caller owns it.
    pub fn new(api: SocketAddr, transport: T) -> Self {
        // A std node has a real clock, so nanosecond arrival time plus the
        // server address decorrelates instances adequately. Prefer
        // [`Self::with_seed`] where a stable per-node seed is available.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.subsec_nanos() as u64 ^ since.as_secs());
        Self::with_seed(api, transport, nanos ^ (api.port() as u64))
    }

    /// Construct a resolver with an explicit pacing seed.
    ///
    /// The seed decides only *when* this client reconnects and refreshes, not
    /// what it asks for. It must differ between nodes: a fleet sharing one
    /// seed reconnects in lockstep and defeats the jitter the protocol
    /// requires. Deriving it from the node's static public key
    /// ([`Jitter::from_key`]) satisfies that by construction.
    pub fn with_seed(api: SocketAddr, transport: T, seed: u64) -> Self {
        Self {
            api,
            transport,
            desired: HashSet::new(),
            replay: VecDeque::new(),
            jitter: Jitter::new(seed),
            burst_at: None,
            connection: None,
        }
    }

    /// The Peers API server's inner address.
    pub fn api(&self) -> SocketAddr {
        self.api
    }

    /// Resolve one request over the shared session.
    pub async fn resolve(&mut self, request: ResolveRequest) -> ResolveResponse {
        let outcome = match tokio::time::timeout(REQUEST_TIMEOUT, self.fetch(request.query())).await
        {
            Ok(outcome) => outcome,
            Err(_) => {
                // A canceled call may have consumed part of a frame. Never
                // reuse that stream.
                log::warn!("Peers API server lookup exceeded the request timeout");
                self.connection = None;
                ResolveOutcome::Failed
            }
        };
        request.complete(outcome)
    }

    async fn establish(&mut self) -> Result<(), ()> {
        let stream = self.transport.connect(self.api).await.map_err(|error| {
            log::warn!("Peers API server connect to {} failed: {error}", self.api);
        })?;
        let (reader, writer) = tokio::io::split(stream);
        self.connection = Some(peer_api::TokioConnection::from_tokio(
            reader,
            writer,
            ChangeHandler::default(),
        ));
        // Subscriptions live on the connection, so a replacement connection
        // has none. Re-issuing `v1.peer.watch` restores each one and returns the
        // current record in the same round trip.
        self.replay = self
            .desired
            .iter()
            .copied()
            .map(Reconcile::Rewatch)
            .collect();
        // Reconnect replay is already paced by the jittered reconnect delay
        // that preceded it, so it starts immediately.
        self.burst_at = None;
        log::debug!(
            "Peers API server session connected; {} records to reconcile",
            self.replay.len()
        );
        Ok(())
    }

    async fn fetch(&mut self, query: ResolveQuery) -> ResolveOutcome {
        match query {
            ResolveQuery::ByPublicKey(public_key) => self.watch(public_key).await,
            ResolveQuery::ByDstAddress(_) => match self.lookup(query).await {
                ResolveOutcome::Found(peer) => self.watch(peer.public_key).await,
                outcome => outcome,
            },
        }
    }

    /// Perform one side-effect-free lookup.
    async fn lookup(&mut self, query: ResolveQuery) -> ResolveOutcome {
        if self.connection.is_none() && self.establish().await.is_err() {
            return ResolveOutcome::Failed;
        }
        let result = peer_api::lookup(
            self.connection
                .as_mut()
                .expect("a connection was just established"),
            query,
        )
        .await;
        self.finish_client_call("lookup", result)
    }

    /// Explicitly subscribe to one key and return the atomically sampled state.
    async fn watch(&mut self, public_key: [u8; 32]) -> ResolveOutcome {
        if self.connection.is_none() && self.establish().await.is_err() {
            return ResolveOutcome::Failed;
        }

        let result = peer_api::watch(
            self.connection
                .as_mut()
                .expect("a connection was just established"),
            public_key,
        )
        .await;
        let outcome = self.finish_client_call(microtun_api::METHOD_WATCH, result);
        match &outcome {
            ResolveOutcome::Found(_) => {
                self.desired.insert(public_key);
            }
            ResolveOutcome::NotFound => {
                self.desired.remove(&public_key);
            }
            ResolveOutcome::Failed => {}
        }
        outcome
    }

    /// Refresh a key that is already watched on this connection.
    async fn refresh(&mut self, public_key: [u8; 32]) -> ResolveOutcome {
        if self.connection.is_none() && self.establish().await.is_err() {
            return ResolveOutcome::Failed;
        }
        let result = peer_api::resolve_key(
            self.connection
                .as_mut()
                .expect("a connection was just established"),
            public_key,
        )
        .await;
        self.finish_client_call(microtun_api::METHOD_BY_KEY, result)
    }

    fn finish_client_call(
        &mut self,
        operation: &str,
        result: Result<ResolveOutcome, ClientError>,
    ) -> ResolveOutcome {
        match result {
            Ok(outcome) => outcome,
            // A JSON-RPC error response is application-level: the complete
            // frame was received, so the session remains synchronized.
            Err(ClientError::Rpc(RpcError::Remote(error))) => {
                log::warn!("Peers API server {operation} call failed: {error}");
                ResolveOutcome::Failed
            }
            Err(ClientError::Codec(error)) => {
                log::error!("failed to render Peers API server {operation}: {error:?}");
                ResolveOutcome::Failed
            }
            Err(ClientError::UnexpectedPublicKey { .. }) => {
                log::warn!("Peers API server {operation} returned a different public key");
                ResolveOutcome::Failed
            }
            Err(ClientError::Rpc(error)) => {
                log::warn!("Peers API server {operation} call failed: {error}");
                self.connection = None;
                ResolveOutcome::Failed
            }
        }
    }

    async fn apply_unwatch(&mut self, public_key: [u8; 32]) {
        if let Some(connection) = self.connection.as_mut() {
            connection.handler_mut().forget(public_key);
        }
        self.replay
            .retain(|queued| queued.public_key() != public_key);
        if !self.desired.remove(&public_key) || self.connection.is_none() {
            return;
        }
        let result =
            peer_api::unwatch(self.connection.as_mut().expect("checked above"), public_key).await;
        if let Err(error) = result {
            log::warn!("Peers API server unwatch failed: {error:?}");
            self.connection = None;
        }
    }

    /// Move every notified key onto the re-lookup queue.
    ///
    /// A key the core no longer holds is dropped here rather than looked up:
    /// an eviction and a notification crossing is the normal outcome for a
    /// client that has not sent `v1.peer.unwatch` yet, and the record set is the
    /// final local authority on whether the answer would be wanted.
    fn drain_changed(&mut self) {
        let mut changed = VecDeque::new();
        if let Some(connection) = self.connection.as_mut() {
            while let Some(public_key) = connection.handler_mut().take_changed() {
                changed.push_back(public_key);
            }
        }
        let was_empty = self.replay.is_empty();
        let mut queued_any = false;
        for public_key in changed {
            if self.desired.contains(&public_key)
                && !self
                    .replay
                    .iter()
                    .any(|queued| queued.public_key() == public_key)
            {
                self.replay.push_back(Reconcile::Refresh(public_key));
                queued_any = true;
            }
        }
        // One reload invalidates the same key for every client at once. Offset
        // the start of this burst so the fleet's refreshes arrive spread over
        // the window rather than as a single spike. Only the first refresh of
        // a burst waits; the rest follow it immediately.
        if queued_any && was_empty {
            let offset = self.jitter.window_ms(REFRESH_BURST_WINDOW_MS);
            self.burst_at =
                Some(tokio::time::Instant::now() + Duration::from_millis(u64::from(offset)));
        }
    }
}

/// Run one multiplexed resolver session until the command side closes.
///
/// The same connection carries lookups, explicit `v1.peer.watch` requests,
/// `v1.peer.unwatch` notifications, and `v1.peer.changed` notifications. While no core
/// command is ready the task polls the RPC connection, so notifications arrive
/// without a request being outstanding. Losing a session triggers reconnect
/// and an explicit re-watch of every record the core holds.
pub async fn resolver_task<T: PeersApiTransport>(
    mut resolver: PeersApiResolver<T>,
    mut commands: mpsc::Receiver<ResolverCommand>,
    events: mpsc::Sender<ResolverEvent>,
) {
    loop {
        resolver.drain_changed();

        if resolver.connection.is_none() && !resolver.desired.is_empty() {
            let connected = matches!(
                tokio::time::timeout(REQUEST_TIMEOUT, resolver.establish()).await,
                Ok(Ok(()))
            );
            if connected {
                continue;
            }
            resolver.connection = None;
            resolver.replay.clear();
            if !wait_before_retry(&mut resolver, &mut commands, &events).await {
                return;
            }
            continue;
        }

        // A change-driven burst waits out its jittered offset before issuing
        // its first refresh. Commands are still served meanwhile, so the delay
        // paces the Peers API server without stalling the core.
        if resolver.connection.is_some()
            && !resolver.replay.is_empty()
            && let Some(ready_at) = resolver.burst_at
        {
            if tokio::time::Instant::now() < ready_at {
                if !wait_for_burst(&mut resolver, ready_at, &mut commands, &events).await {
                    return;
                }
                continue;
            }
            resolver.burst_at = None;
        }

        // Reconcile one outstanding record before servicing anything else.
        // Reconnect items explicitly restore the watch; refresh items use a pure
        // by-key lookup because the subscription is already active.
        if resolver.connection.is_some()
            && let Some(item) = resolver.replay.pop_front()
        {
            let public_key = item.public_key();
            let operation = async {
                match item {
                    Reconcile::Rewatch(public_key) => resolver.watch(public_key).await,
                    Reconcile::Refresh(public_key) => resolver.refresh(public_key).await,
                }
            };
            let outcome = match tokio::time::timeout(REQUEST_TIMEOUT, operation).await {
                Ok(ResolveOutcome::Failed) | Err(_) => {
                    // Reconnect and start the set again rather than leaving one
                    // record unsubscribed and silently stale.
                    log::warn!("failed to reconcile a watched record; reconnecting");
                    resolver.connection = None;
                    resolver.replay.clear();
                    continue;
                }
                Ok(outcome) => outcome,
            };
            let update = PeerUpdate::new(public_key, outcome);
            if events
                .send(ResolverEvent::PeerUpdated(update))
                .await
                .is_err()
            {
                return;
            }
            continue;
        }

        if resolver.connection.is_none() {
            let Some(command) = commands.recv().await else {
                return;
            };
            if !handle_command(&mut resolver, command, &events).await {
                return;
            }
            continue;
        }

        enum Ready {
            Command(Option<ResolverCommand>),
            Incoming(Result<(), RpcError>),
        }

        let ready = {
            let connection = resolver.connection.as_mut().expect("checked above");
            tokio::select! {
                command = commands.recv() => Ready::Command(command),
                incoming = connection.poll() => Ready::Incoming(incoming),
            }
        };

        match ready {
            Ready::Command(Some(command)) => {
                if !handle_command(&mut resolver, command, &events).await {
                    return;
                }
            }
            Ready::Command(None) => return,
            Ready::Incoming(Ok(())) => {}
            Ready::Incoming(Err(error)) => {
                log::warn!("Peers API server session ended: {error}");
                resolver.connection = None;
            }
        }
    }
}

async fn handle_command<T: PeersApiTransport>(
    resolver: &mut PeersApiResolver<T>,
    command: ResolverCommand,
    events: &mpsc::Sender<ResolverEvent>,
) -> bool {
    match command {
        ResolverCommand::Resolve(request) => {
            let response = resolver.resolve(request).await;
            // Any key invalidated while the lookup/watch sequence was in
            // flight is queued. Once the watch succeeds the key is in the held
            // set, so the queued invalidation forces one refresh at the
            // top of the loop.
            events.send(ResolverEvent::Resolved(response)).await.is_ok()
        }
        ResolverCommand::Unwatch(public_key) => {
            resolver.apply_unwatch(public_key).await;
            true
        }
    }
}

/// Hold a change-driven reconciliation burst until its jittered start time.
///
/// Core commands are handled normally while waiting, so the offset paces
/// outgoing refreshes without delaying a lookup the core actually needs. A
/// command that resolves or evicts a key may empty the queue outright, which
/// is why the caller re-tests the queue rather than assuming it survived.
///
/// Returns `false` when the command channel closed.
async fn wait_for_burst<T: PeersApiTransport>(
    resolver: &mut PeersApiResolver<T>,
    ready_at: tokio::time::Instant,
    commands: &mut mpsc::Receiver<ResolverCommand>,
    events: &mpsc::Sender<ResolverEvent>,
) -> bool {
    let delay = tokio::time::sleep_until(ready_at);
    tokio::pin!(delay);
    loop {
        tokio::select! {
            _ = &mut delay => {
                resolver.burst_at = None;
                return true;
            }
            command = commands.recv() => {
                let Some(command) = command else {
                    return false;
                };
                if !handle_command(resolver, command, events).await {
                    return false;
                }
                // A failed command may have dropped the session, in which case
                // reconnect handling takes over and this burst is moot.
                if resolver.connection.is_none() {
                    resolver.burst_at = None;
                    return true;
                }
            }
        }
    }
}

async fn wait_before_retry<T: PeersApiTransport>(
    resolver: &mut PeersApiResolver<T>,
    commands: &mut mpsc::Receiver<ResolverCommand>,
    events: &mpsc::Sender<ResolverEvent>,
) -> bool {
    let spread = resolver.jitter.spread_ms(RECONNECT_DELAY_MS);
    let delay = tokio::time::sleep(Duration::from_millis(u64::from(spread)));
    tokio::pin!(delay);
    loop {
        if resolver.desired.is_empty() {
            return true;
        }
        tokio::select! {
            _ = &mut delay => return true,
            command = commands.recv() => {
                let Some(command) = command else {
                    return false;
                };
                match command {
                    ResolverCommand::Unwatch(public_key) => {
                        resolver.apply_unwatch(public_key).await
                    }
                    ResolverCommand::Resolve(request) => {
                        if events
                            .send(ResolverEvent::Resolved(request.complete(ResolveOutcome::Failed)))
                            .await
                            .is_err()
                        {
                            return false;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use microtun_api::{KeyParams, LookupResult, METHOD_CHANGED, METHOD_UNWATCH, METHOD_WATCH};
    use microtun_core::{ResolveQuery, decode_key, encode_key};
    use microtun_jsonrpc::{Connection, Handler, Params, Reply, Responder, TokioIo};
    use tokio::{io::DuplexStream, sync::Mutex};

    use super::*;

    const RECORD: &str = concat!(
        r#"{"public_key":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=","#,
        r#""endpoint":"203.0.113.5:51820","addresses":["10.1.2.3/32"]}"#,
    );

    #[derive(Clone, Copy, Debug)]
    enum Script {
        Record(&'static str),
        RecordThenClose(&'static str),
        Missing,
        /// A bare record in `result`, as the previous protocol revision sent.
        Untagged(&'static str),
        /// `"result":null`, which used to mean "authoritatively unknown".
        NullResult,
        Error,
        Hangup,
    }

    struct ScriptedHandler(Script);

    impl Handler for ScriptedHandler {
        fn handle_request(
            &mut self,
            method: &str,
            _params: Params<'_>,
            responder: Responder<'_>,
        ) -> Reply {
            assert!(
                method == microtun_api::METHOD_BY_KEY
                    || method == microtun_api::METHOD_BY_ADDRESS
                    || method == microtun_api::METHOD_WATCH,
                "unexpected method {method}"
            );
            match self.0 {
                Script::Record(json) | Script::RecordThenClose(json) => {
                    let (record, _) = serde_json_core::from_str::<microtun_api::PeerInfo>(json)
                        .expect("test record parses");
                    responder.ok(&LookupResult::Found(record))
                }
                Script::Missing => responder.ok(&LookupResult::NotFound {}),
                // A result that is well-formed JSON-RPC but not a conforming
                // `LookupResult`. It must never read as an authoritative miss.
                Script::Untagged(json) => {
                    let (record, _) = serde_json_core::from_str::<microtun_api::PeerInfo>(json)
                        .expect("test record parses");
                    responder.ok(&record)
                }
                Script::NullResult => responder.ok(&Option::<()>::None),
                Script::Error => responder.error(-32000, "unavailable"),
                Script::Hangup => unreachable!("a hung-up connection serves no request"),
            }
        }
    }

    #[derive(Clone)]
    struct ScriptedTransport {
        scripts: Arc<Mutex<Vec<Script>>>,
        connections: Arc<AtomicUsize>,
    }

    impl ScriptedTransport {
        fn new(scripts: &[Script]) -> (Self, Arc<AtomicUsize>) {
            let connections = Arc::new(AtomicUsize::new(0));
            let mut queued = scripts.to_vec();
            queued.reverse();
            (
                Self {
                    scripts: Arc::new(Mutex::new(queued)),
                    connections: Arc::clone(&connections),
                },
                connections,
            )
        }
    }

    impl PeersApiTransport for ScriptedTransport {
        type Stream = DuplexStream;

        async fn connect(&self, _api: SocketAddr) -> io::Result<DuplexStream> {
            let script = self
                .scripts
                .lock()
                .await
                .pop()
                .ok_or_else(|| io::Error::other("no scripted connection left"))?;
            self.connections.fetch_add(1, Ordering::SeqCst);

            let (client, server) = tokio::io::duplex(4096);
            if matches!(script, Script::Hangup) {
                drop(server);
                return Ok(client);
            }

            tokio::spawn(async move {
                let (reader, writer) = tokio::io::split(server);
                let mut connection: Connection<_, _, _, QUERY_FRAME_LEN, RECORD_FRAME_LEN> =
                    Connection::from_tokio(reader, writer, ScriptedHandler(script));
                match script {
                    Script::RecordThenClose(_) => {
                        let _ = connection.poll().await;
                    }
                    _ => while connection.poll().await.is_ok() {},
                }
            });
            Ok(client)
        }
    }

    fn resolver(scripts: &[Script]) -> (PeersApiResolver<ScriptedTransport>, Arc<AtomicUsize>) {
        let (transport, connections) = ScriptedTransport::new(scripts);
        (
            PeersApiResolver::with_seed("10.0.0.9:80".parse().unwrap(), transport, 1),
            connections,
        )
    }

    #[tokio::test]
    async fn a_record_resolves() {
        let (mut resolver, _) = resolver(&[Script::Record(RECORD)]);
        let outcome = resolver.fetch(ResolveQuery::ByPublicKey([0xAA; 32])).await;

        let ResolveOutcome::Found(peer) = outcome else {
            panic!("expected a record, got {outcome:?}");
        };
        assert_eq!(peer.public_key, [0xAA; 32]);
        assert_eq!(peer.endpoint, Some("203.0.113.5:51820".parse().unwrap()));
        assert_eq!(peer.addresses.len(), 1);
    }

    #[tokio::test]
    async fn the_not_found_sentinel_is_authoritative() {
        let (mut resolver, _) = resolver(&[Script::Missing]);
        let outcome = resolver
            .fetch(ResolveQuery::ByDstAddress("10.9.9.9".parse().unwrap()))
            .await;
        assert!(matches!(outcome, ResolveOutcome::NotFound), "{outcome:?}");
    }

    /// The sentinel is the *only* authoritative miss. A bare `null` result
    /// meant "gone" under the previous revision of this protocol; it must not
    /// mean that now, or a downgraded server would silently evict every
    /// dynamic peer this node holds.
    #[tokio::test]
    async fn a_null_result_is_no_longer_authoritative() {
        let (mut resolver, _) = resolver(&[Script::NullResult]);
        let outcome = resolver.fetch(ResolveQuery::ByPublicKey([0xAA; 32])).await;
        assert!(matches!(outcome, ResolveOutcome::Failed), "{outcome:?}");
    }

    /// An untagged record carries a peer, but not in the shape the protocol
    /// defines. Installing it would skip the tag check the spec requires.
    #[tokio::test]
    async fn an_untagged_record_is_transient() {
        let (mut resolver, _) = resolver(&[Script::Untagged(RECORD)]);
        let outcome = resolver.fetch(ResolveQuery::ByPublicKey([0xAA; 32])).await;
        assert!(matches!(outcome, ResolveOutcome::Failed), "{outcome:?}");
    }

    /// A key removed from `desired` would not be replayed after a reconnect,
    /// so only an authoritative miss may remove it. Both non-conforming
    /// results have to leave the held set alone.
    #[tokio::test]
    async fn a_non_conforming_result_does_not_forget_the_key() {
        for script in [Script::NullResult, Script::Untagged(RECORD)] {
            let (mut resolver, _) = resolver(&[script]);
            resolver.desired.insert([0xAA; 32]);

            let outcome = resolver.fetch(ResolveQuery::ByPublicKey([0xAA; 32])).await;
            assert!(matches!(outcome, ResolveOutcome::Failed), "{outcome:?}");
            assert!(
                resolver.desired.contains(&[0xAA; 32]),
                "{script:?} must leave the record in the replay set"
            );
        }
    }

    #[tokio::test]
    async fn a_remote_error_is_transient_without_dropping_the_session() {
        let (mut resolver, connections) = resolver(&[Script::Error]);
        let outcome = resolver.fetch(ResolveQuery::ByPublicKey([0xAA; 32])).await;
        assert!(matches!(outcome, ResolveOutcome::Failed), "{outcome:?}");
        assert_eq!(connections.load(Ordering::SeqCst), 1);
        assert!(resolver.connection.is_some());
    }

    #[tokio::test]
    async fn one_connection_serves_many_lookups() {
        let (mut resolver, connections) = resolver(&[Script::Record(RECORD)]);
        for _ in 0..3 {
            let outcome = resolver.fetch(ResolveQuery::ByPublicKey([0xAA; 32])).await;
            assert!(matches!(outcome, ResolveOutcome::Found(_)), "{outcome:?}");
        }
        assert_eq!(connections.load(Ordering::SeqCst), 1);
    }

    /// A session that dies mid-conversation is dropped and the lookup reports
    /// a transient failure. Nothing is retried inline: the core keeps what it
    /// has, and the next lookup opens a fresh connection.
    #[tokio::test]
    async fn a_stale_connection_fails_transiently_and_is_dropped() {
        let (mut resolver, connections) =
            resolver(&[Script::RecordThenClose(RECORD), Script::Record(RECORD)]);

        assert!(matches!(
            resolver.fetch(ResolveQuery::ByPublicKey([0xAA; 32])).await,
            ResolveOutcome::Found(_)
        ));
        assert!(matches!(
            resolver.fetch(ResolveQuery::ByPublicKey([0xAA; 32])).await,
            ResolveOutcome::Failed
        ));
        assert!(resolver.connection.is_none());
        assert_eq!(connections.load(Ordering::SeqCst), 1);

        assert!(matches!(
            resolver.fetch(ResolveQuery::ByPublicKey([0xAA; 32])).await,
            ResolveOutcome::Found(_)
        ));
        assert_eq!(connections.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_dead_server_reports_a_transient_failure() {
        let (mut resolver, connections) = resolver(&[Script::Hangup]);
        let outcome = resolver.fetch(ResolveQuery::ByPublicKey([0xAA; 32])).await;
        assert!(matches!(outcome, ResolveOutcome::Failed), "{outcome:?}");
        assert_eq!(connections.load(Ordering::SeqCst), 1);
        assert!(resolver.connection.is_none());
    }

    #[derive(Debug)]
    struct CombinedHandler {
        /// Keys the client explicitly started watching.
        watches: mpsc::UnboundedSender<[u8; 32]>,
        /// Keys the client asked to stop watching.
        unwatches: mpsc::UnboundedSender<[u8; 32]>,
        /// Keys the client refreshed with side-effect-free by-key lookups.
        lookups: mpsc::UnboundedSender<[u8; 32]>,
    }

    impl Handler for CombinedHandler {
        fn handle_request(
            &mut self,
            method: &str,
            params: Params<'_>,
            responder: Responder<'_>,
        ) -> Reply {
            let Ok(args) = params.parse::<KeyParams<'_>>() else {
                return responder.invalid_params();
            };
            let Ok(public_key) = decode_key(args.public_key) else {
                return responder.invalid_params();
            };
            match method {
                METHOD_WATCH => {
                    let _ = self.watches.send(public_key);
                }
                microtun_api::METHOD_BY_KEY => {
                    let _ = self.lookups.send(public_key);
                }
                _ => return responder.method_not_found(),
            }
            let (record, _) = serde_json_core::from_str::<microtun_api::PeerInfo>(RECORD)
                .expect("test record parses");
            responder.ok(&LookupResult::Found(record))
        }

        fn handle_notification(&mut self, method: &str, params: Params<'_>) {
            if method != METHOD_UNWATCH {
                return;
            }
            let Ok(args) = params.parse::<KeyParams<'_>>() else {
                return;
            };
            let Ok(public_key) = decode_key(args.public_key) else {
                return;
            };
            let _ = self.unwatches.send(public_key);
        }
    }

    #[derive(Clone)]
    struct CombinedTransport {
        servers: mpsc::UnboundedSender<DuplexStream>,
        connections: Arc<AtomicUsize>,
    }

    impl PeersApiTransport for CombinedTransport {
        type Stream = DuplexStream;

        async fn connect(&self, _api: SocketAddr) -> io::Result<DuplexStream> {
            let (client, server) = tokio::io::duplex(4096);
            self.connections.fetch_add(1, Ordering::SeqCst);
            self.servers
                .send(server)
                .map_err(|_| io::Error::other("test server closed"))?;
            Ok(client)
        }
    }

    async fn next_peer_update(events: &mut mpsc::Receiver<ResolverEvent>) -> PeerUpdate {
        loop {
            let event = tokio::time::timeout(Duration::from_secs(2), events.recv())
                .await
                .expect("resolver event arrives")
                .expect("resolver event channel stays open");
            if let ResolverEvent::PeerUpdated(update) = event {
                return update;
            }
        }
    }

    async fn server_connection(
        stream: DuplexStream,
    ) -> (
        Connection<
            TokioIo<ReadHalf<DuplexStream>>,
            TokioIo<WriteHalf<DuplexStream>>,
            CombinedHandler,
            QUERY_FRAME_LEN,
            RECORD_FRAME_LEN,
        >,
        mpsc::UnboundedReceiver<[u8; 32]>,
        mpsc::UnboundedReceiver<[u8; 32]>,
        mpsc::UnboundedReceiver<[u8; 32]>,
    ) {
        let (reader, writer) = tokio::io::split(stream);
        let (watch_tx, watch_rx) = mpsc::unbounded_channel();
        let (unwatch_tx, unwatch_rx) = mpsc::unbounded_channel();
        let (lookup_tx, lookup_rx) = mpsc::unbounded_channel();
        (
            Connection::from_tokio(
                reader,
                writer,
                CombinedHandler {
                    watches: watch_tx,
                    unwatches: unwatch_tx,
                    lookups: lookup_tx,
                },
            ),
            watch_rx,
            unwatch_rx,
            lookup_rx,
        )
    }

    /// One connection carries the explicit watch and pushed updates at once.
    #[tokio::test]
    async fn an_explicit_watch_shares_its_connection_with_updates() {
        const A: [u8; 32] = [0xAA; 32];
        let (servers_tx, mut servers_rx) = mpsc::unbounded_channel();
        let connections = Arc::new(AtomicUsize::new(0));
        let mut resolver = PeersApiResolver::with_seed(
            "10.0.0.9:80".parse().unwrap(),
            CombinedTransport {
                servers: servers_tx,
                connections: Arc::clone(&connections),
            },
            1,
        );

        let client = tokio::spawn(async move {
            let outcome = resolver.fetch(ResolveQuery::ByPublicKey(A)).await;
            (resolver, outcome)
        });

        let stream = servers_rx.recv().await.expect("one session opens");
        let (mut server, mut watch_rx, mut unwatch_rx, mut lookup_rx) =
            server_connection(stream).await;

        // The notifications arrive while the same client Connection is waiting for
        // the `v1.peer.watch` response. `Connection::call` dispatches them before
        // completing the request, proving the connection is genuinely
        // multiplexed and exercising the in-flight watch race.
        let key_text = encode_key(&A);
        let params = KeyParams {
            public_key: key_text.as_str(),
        };
        server
            .notify(METHOD_CHANGED, Some(&params))
            .await
            .expect("first notification sent");
        server
            .notify(METHOD_CHANGED, Some(&params))
            .await
            .expect("repeat notification sent");
        server.poll().await.expect("watch arrives on same session");
        assert_eq!(watch_rx.recv().await, Some(A));

        let (mut resolver, outcome) = client.await.expect("client finishes");
        assert!(matches!(outcome, ResolveOutcome::Found(_)));

        // The explicit watch is mirrored locally, and no unwatch was sent.
        assert!(resolver.desired.contains(&A));
        assert!(unwatch_rx.try_recv().is_err());
        assert!(lookup_rx.try_recv().is_err());

        // A notification that raced the watch still forces one pure by-key
        // refresh, and repeats coalesce into one queue entry.
        resolver.drain_changed();
        assert_eq!(resolver.replay.pop_front(), Some(Reconcile::Refresh(A)));
        assert!(
            resolver.replay.is_empty(),
            "notifications for one key coalesce into a single re-lookup"
        );
        assert_eq!(connections.load(Ordering::SeqCst), 1);
    }

    /// A notification for a key the core no longer holds is discarded rather
    /// than turned into a lookup.
    #[tokio::test]
    async fn a_notification_for_an_unheld_key_is_discarded() {
        const A: [u8; 32] = [0xAA; 32];
        const B: [u8; 32] = [0xBB; 32];
        let (servers_tx, mut servers_rx) = mpsc::unbounded_channel();
        let connections = Arc::new(AtomicUsize::new(0));
        let mut resolver = PeersApiResolver::with_seed(
            "10.0.0.9:80".parse().unwrap(),
            CombinedTransport {
                servers: servers_tx,
                connections: Arc::clone(&connections),
            },
            1,
        );

        let client = tokio::spawn(async move {
            let outcome = resolver.fetch(ResolveQuery::ByPublicKey(A)).await;
            (resolver, outcome)
        });

        let stream = servers_rx.recv().await.expect("one session opens");
        let (mut server, mut watch_rx, _unwatch_rx, _lookup_rx) = server_connection(stream).await;

        let key_text = encode_key(&B);
        server
            .notify(
                METHOD_CHANGED,
                Some(&KeyParams {
                    public_key: key_text.as_str(),
                }),
            )
            .await
            .expect("notification sent");
        server.poll().await.expect("watch arrives");
        assert_eq!(watch_rx.recv().await, Some(A));

        let (mut resolver, _) = client.await.expect("client finishes");
        resolver.drain_changed();
        assert!(
            resolver.replay.is_empty(),
            "a key the core never held is not looked up"
        );
    }

    /// After a disconnect every held record is explicitly watched again.
    #[tokio::test]
    async fn reconnect_rewatches_every_held_record() {
        const A: [u8; 32] = [0xAA; 32];
        let (servers_tx, mut servers_rx) = mpsc::unbounded_channel();
        let connections = Arc::new(AtomicUsize::new(0));
        let resolver = PeersApiResolver::with_seed(
            "10.0.0.9:80".parse().unwrap(),
            CombinedTransport {
                servers: servers_tx,
                connections: Arc::clone(&connections),
            },
            1,
        );
        let (commands_tx, commands_rx) = mpsc::channel(8);
        let (events_tx, mut events_rx) = mpsc::channel(8);
        let task = tokio::spawn(resolver_task(resolver, commands_rx, events_tx));

        // Resolve one record and wait until the client has processed the
        // answer. That makes A part of the held set before the idle session is
        // disconnected, avoiding an unanswered second call racing the
        // reconnect path.
        commands_tx
            .send(ResolverCommand::Resolve(ResolveRequest::for_test(
                ResolveQuery::ByPublicKey(A),
            )))
            .await
            .unwrap();

        let first = servers_rx.recv().await.expect("first session opens");
        let (mut server, mut watch_rx, _unwatch_rx, _lookup_rx) = server_connection(first).await;
        server.poll().await.expect("first watch arrives");
        assert_eq!(watch_rx.recv().await, Some(A));

        let resolved = tokio::time::timeout(Duration::from_secs(2), events_rx.recv())
            .await
            .expect("initial resolution completes")
            .expect("resolver event channel stays open");
        assert!(matches!(resolved, ResolverEvent::Resolved(_)));

        // Closing an otherwise idle session must trigger a replacement
        // connection and a replayed `v1.peer.watch` for every held record.
        drop(server);

        let second = tokio::time::timeout(Duration::from_secs(5), servers_rx.recv())
            .await
            .expect("session is re-established")
            .expect("transport stays open");
        let (mut server, mut watch_rx, _unwatch_rx, _lookup_rx) = server_connection(second).await;
        server.poll().await.expect("the replay watch arrives");
        assert_eq!(watch_rx.recv().await, Some(A));

        let a = next_peer_update(&mut events_rx).await;
        assert_eq!(a.public_key, A);
        let ResolveOutcome::Found(a) = a.outcome else {
            panic!("expected reconciled A record")
        };
        assert_eq!(a.endpoint, Some("203.0.113.5:51820".parse().unwrap()));
        assert_eq!(connections.load(Ordering::SeqCst), 2);

        drop(commands_tx);
        task.await.expect("resolver exits");
    }
}
