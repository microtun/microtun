//! The peer-resolution task.
//!
//! A single long-lived TCP/JSON-RPC session carries lookups and
//! `v1.peer.changed` / `v1.peer.removed` broadcasts. The server sends every peer invalidation to every
//! admitted client; this resolver keeps a local set of the peer keys the core
//! currently holds and ignores broadcasts for everything else. While the core
//! has no command ready the task continuously polls the same RPC connection.
//!
//! `v1.peer.changed` / `v1.peer.removed` name a key and carry nothing else, so they cannot be
//! applied directly. If the key is locally held, the resolver answers it with
//! an ordinary `v1.peer.by_key`; otherwise it discards the notification. On
//! reconnect it re-looks up every held key, which reconciles any broadcasts
//! lost with the previous connection.
//!
//! Only one call is ever in flight here. A notification read during a lookup
//! is queued before its answer is applied, so a matching successful lookup adds
//! the key to the held set before the queued invalidation is processed.

use core::future::Future;

use defmt_or_log::{debug, error, trace, warn};
use embassy_futures::select::{Either, select};
use embassy_net::{IpEndpoint, Stack, tcp::TcpSocket};
use embassy_sync::{
    blocking_mutex::raw::CriticalSectionRawMutex,
    channel::{Receiver, Sender},
};
use embassy_time::{Instant, Timer};
use heapless::Vec;
use microtun_api::{
    Jitter, QUERY_FRAME_LEN, RECORD_FRAME_LEN, REFRESH_BURST_WINDOW_MS,
    client::{self as peer_api, ChangeHandler as ApiChangeHandler, ClientError, Connection},
};
use microtun_core::{PeerUpdate, ResolveOutcome, ResolveQuery, ResolverCommand, ResolverEvent};
use microtun_jsonrpc::Error as RpcError;

const TCP_CONNECT_TIMEOUT: embassy_time::Duration = embassy_time::Duration::from_secs(5);
const REQUEST_TIMEOUT: embassy_time::Duration = embassy_time::Duration::from_secs(15);
const TCP_KEEP_ALIVE: embassy_time::Duration = embassy_time::Duration::from_secs(15);
const TCP_IDLE_TIMEOUT: embassy_time::Duration = embassy_time::Duration::from_secs(45);
/// Base reconnect delay, spread over `[500ms, 1500ms)` by the resolver's
/// jitter. A Peers API server restart drops every client at once, so an unjittered
/// delay would reconnect the whole fleet in one spike.
const RECONNECT_DELAY_MS: u32 = 1_000;
/// The embassy runner currently supports eight peers total, so this covers
/// every possible dynamic peer and one queued invalidation per peer.
const MAX_HELD_PEERS: usize = 8;
const CHANNEL_DEPTH: usize = 16;

/// Commands from the tunnel loop to the resolver task.
pub type CommandSender<'a> = Sender<'a, CriticalSectionRawMutex, ResolverCommand, CHANNEL_DEPTH>;
pub type CommandReceiver<'a> =
    Receiver<'a, CriticalSectionRawMutex, ResolverCommand, CHANNEL_DEPTH>;
/// Lookup completions and pushed peer updates back to the tunnel loop.
pub type EventSender<'a> = Sender<'a, CriticalSectionRawMutex, ResolverEvent, CHANNEL_DEPTH>;
pub type EventReceiver<'a> = Receiver<'a, CriticalSectionRawMutex, ResolverEvent, CHANNEL_DEPTH>;

/// Bundle of channel endpoints handed to [`resolver_task`].
pub struct ResolverChannels<'a> {
    pub commands: CommandReceiver<'a>,
    pub events: EventSender<'a>,
}

/// Caller-owned storage for the resolver's persistent TCP connection.
pub struct ResolverBuffers<'a> {
    /// TCP receive buffer retained for the life of the resolver task.
    pub socket_rx: &'a mut [u8],
    /// TCP transmit buffer retained for the life of the resolver task.
    pub socket_tx: &'a mut [u8],
}

/// Static Peers API server address configuration.
#[derive(Clone, Copy)]
pub struct ResolverConfig {
    /// Peers API server's inner IP endpoint.
    pub server: IpEndpoint,
    /// Pacing seed for reconnect and refresh jitter.
    ///
    /// This decides only *when* the resolver reconnects and refreshes, never
    /// what it asks for, so it needs no entropy quality — but it MUST differ
    /// between nodes. Devices flashed from one image and powered on together
    /// observe the same uptime, so a clock-derived seed would leave them in
    /// lockstep and defeat the jitter the protocol requires
    /// (`docs/microtun-peers-api.md` §10.3).
    ///
    /// Derive it from the node's own static public key, which is unique by
    /// construction and known before the first connection attempt:
    ///
    /// ```ignore
    /// let cfg = ResolverConfig {
    ///     server,
    ///     jitter_seed: microtun_api::Jitter::seed_from_key(&local_public_key),
    /// };
    /// ```
    pub jitter_seed: u64,
}

type ChangeHandler = ApiChangeHandler<MAX_HELD_PEERS>;

type HeldSet = Vec<[u8; 32], MAX_HELD_PEERS>;

/// Run the multiplexed Peers API resolver forever.
pub async fn resolver_task<'stack, 'channels, 'buffers>(
    stack: Stack<'stack>,
    cfg: ResolverConfig,
    ch: ResolverChannels<'channels>,
    buffers: ResolverBuffers<'buffers>,
) -> ! {
    let mut desired = HeldSet::new();
    let mut jitter = Jitter::new(cfg.jitter_seed);

    loop {
        let mut socket = TcpSocket::new(stack, &mut *buffers.socket_rx, &mut *buffers.socket_tx);
        // Keep a quiet broadcast session alive without application polling, but
        // still detect a Peers API server or path that disappears without a FIN/RST.
        // The timeout intentionally exceeds the TCP keep-alive interval.
        socket.set_keep_alive(Some(TCP_KEEP_ALIVE));
        socket.set_timeout(Some(TCP_IDLE_TIMEOUT));
        trace!(
            "resolver connecting to Peers API server: port={}",
            cfg.server.port
        );

        let connected = matches!(
            embassy_time::with_timeout(TCP_CONNECT_TIMEOUT, socket.connect(cfg.server)).await,
            Ok(Ok(()))
        );
        if !connected {
            warn!("resolver TCP connect failed");
            retry_delay(&ch, &mut desired, &mut jitter).await;
            continue;
        }

        debug!("resolver session connected");
        let session_ok = {
            let (reader, writer) = socket.split();
            let mut connection: Connection<_, _, _, RECORD_FRAME_LEN, QUERY_FRAME_LEN> =
                Connection::new(reader, writer, ChangeHandler::default());

            // A replacement socket may have missed broadcasts while the old
            // session was down. Re-look up every locally held key to reconcile it.
            debug!("resolver reconciling {} records", desired.len());
            if reconcile(&mut connection, &ch, &mut desired).await {
                run_session(&mut connection, &ch, &mut desired, &mut jitter).await
            } else {
                false
            }
        };

        socket.close();
        if session_ok {
            // The session loop is intentionally infinite; this is defensive.
            warn!("resolver session exited unexpectedly");
        } else {
            warn!("resolver session disconnected");
        }
        retry_delay(&ch, &mut desired, &mut jitter).await;
    }
}

async fn run_session<R, W>(
    connection: &mut Connection<R, W, ChangeHandler, RECORD_FRAME_LEN, QUERY_FRAME_LEN>,
    ch: &ResolverChannels<'_>,
    desired: &mut HeldSet,
    jitter: &mut Jitter,
) -> bool
where
    R: embedded_io_async::Read,
    W: embedded_io_async::Write,
{
    enum Ready {
        Command(ResolverCommand),
        Incoming(Result<(), RpcError>),
    }

    // embassy-futures' two-way select is ordered, so alternate the poll order
    // to prevent either a busy command channel or a busy socket from starving
    // the other half of the multiplexed session.
    let mut command_first = false;
    loop {
        if !reconcile_invalidated(connection, ch, desired, jitter).await {
            return false;
        }

        let ready = if command_first {
            match select(ch.commands.receive(), connection.poll()).await {
                Either::First(command) => Ready::Command(command),
                Either::Second(incoming) => Ready::Incoming(incoming),
            }
        } else {
            match select(connection.poll(), ch.commands.receive()).await {
                Either::First(incoming) => Ready::Incoming(incoming),
                Either::Second(command) => Ready::Command(command),
            }
        };
        command_first = !command_first;

        match ready {
            Ready::Command(ResolverCommand::Forget(public_key)) => {
                connection.handler_mut().forget(public_key);
                forget_desired(desired, public_key);
            }
            Ready::Command(ResolverCommand::Resolve(request)) => {
                let (outcome, reconnect) = resolve(connection, desired, request.query()).await;
                ch.events
                    .send(ResolverEvent::Resolved(request.complete(outcome)))
                    .await;
                if reconnect {
                    return false;
                }
                // Any broadcast read while the lookup is in flight is queued.
                // Once a successful lookup adds its key to the held set, a
                // matching invalidation is refreshed at the top of the loop.
            }
            Ready::Incoming(Ok(())) => {}
            Ready::Incoming(Err(_)) => return false,
        }
    }
}

/// Resolve one core query and remember any positive peer locally.
async fn resolve<R, W>(
    connection: &mut Connection<R, W, ChangeHandler, RECORD_FRAME_LEN, QUERY_FRAME_LEN>,
    desired: &mut HeldSet,
    query: ResolveQuery,
) -> (ResolveOutcome, bool)
where
    R: embedded_io_async::Read,
    W: embedded_io_async::Write,
{
    let queried_key = match query {
        ResolveQuery::ByPublicKey(public_key) => Some(public_key),
        ResolveQuery::ByDstAddress(_) => None,
    };
    let (outcome, reconnect) = lookup(connection, query).await;
    if reconnect {
        return (outcome, true);
    }
    match &outcome {
        ResolveOutcome::Found(record) => remember_desired(desired, record.public_key),
        ResolveOutcome::NotFound => {
            if let Some(public_key) = queried_key {
                forget_desired(desired, public_key);
            }
        }
        ResolveOutcome::Failed => {}
    }
    (outcome, false)
}

/// Perform one side-effect-free lookup.
async fn lookup<R, W>(
    connection: &mut Connection<R, W, ChangeHandler, RECORD_FRAME_LEN, QUERY_FRAME_LEN>,
    query: ResolveQuery,
) -> (ResolveOutcome, bool)
where
    R: embedded_io_async::Read,
    W: embedded_io_async::Write,
{
    timed_call("lookup", peer_api::lookup(connection, query)).await
}

/// Refresh a locally held key after a broadcast or reconnect.
async fn refresh<R, W>(
    connection: &mut Connection<R, W, ChangeHandler, RECORD_FRAME_LEN, QUERY_FRAME_LEN>,
    public_key: [u8; 32],
) -> (ResolveOutcome, bool)
where
    R: embedded_io_async::Read,
    W: embedded_io_async::Write,
{
    timed_call(
        microtun_api::METHOD_BY_KEY,
        peer_api::resolve_key(connection, public_key),
    )
    .await
}

async fn timed_call<F>(operation: &str, future: F) -> (ResolveOutcome, bool)
where
    F: Future<Output = Result<ResolveOutcome, ClientError>>,
{
    match embassy_time::with_timeout(REQUEST_TIMEOUT, future).await {
        Ok(Ok(outcome)) => {
            debug!(
                "Peers API server answered: found={}",
                matches!(outcome, ResolveOutcome::Found(_))
            );
            (outcome, false)
        }
        Ok(Err(ClientError::Codec(_))) => {
            error!("failed to render Peers API server request");
            (ResolveOutcome::Failed, false)
        }
        Ok(Err(ClientError::UnexpectedPublicKey { .. })) => {
            warn!("Peers API server response returned a different public key");
            (ResolveOutcome::Failed, true)
        }
        Ok(Err(ClientError::Rpc(_))) => {
            warn!("Peers API server call failed: {}", operation);
            (ResolveOutcome::Failed, true)
        }
        Err(_) => {
            // Cancellation can leave a partial frame in the connection's receive
            // buffer, so a timed-out request always discards the session.
            warn!(
                "Peers API server request exceeded total timeout: {}",
                operation
            );
            (ResolveOutcome::Failed, true)
        }
    }
}

/// Re-look-up every key a peer invalidation notification has named.
///
/// A notification carries no state, so this is where its only effect happens:
/// one ordinary `v1.peer.by_key`, whose result installs the new record or
/// authoritatively removes the peer. A key the core no longer holds is
/// discarded instead; the local held set is the final authority on whether a
/// broadcast is relevant.
///
/// Returns `false` when the session must be discarded.
async fn reconcile_invalidated<R, W>(
    connection: &mut Connection<R, W, ChangeHandler, RECORD_FRAME_LEN, QUERY_FRAME_LEN>,
    ch: &ResolverChannels<'_>,
    desired: &mut HeldSet,
    jitter: &mut Jitter,
) -> bool
where
    R: embedded_io_async::Read,
    W: embedded_io_async::Write,
{
    if connection.handler_mut().take_overflowed() {
        warn!("resolver invalidation queue overflowed; reconnecting for reconciliation");
        return false;
    }
    let mut offset_taken = false;
    while let Some(public_key) = connection.handler_mut().take_invalidated() {
        if !desired.contains(&public_key) {
            continue;
        }
        // One reload invalidates the same key for every client at the same
        // instant. Offset the first refresh of a burst so the fleet's traffic
        // is spread over the window instead of arriving as one spike. The rest
        // of the burst follows immediately; reconnect replay is not delayed
        // here because the jittered reconnect delay already spread it.
        if !offset_taken {
            offset_taken = true;
            Timer::after(embassy_time::Duration::from_millis(u64::from(
                jitter.window_ms(REFRESH_BURST_WINDOW_MS),
            )))
            .await;
        }
        if !refresh_one(connection, ch, public_key).await {
            return false;
        }
    }
    true
}

/// Re-look up every held record on a freshly opened session.
///
/// This is the whole of reconnect recovery: each by-key lookup reconciles one
/// locally held peer after any notifications lost with the previous session.
/// Returns `false` when the session dies partway through.
async fn reconcile<R, W>(
    connection: &mut Connection<R, W, ChangeHandler, RECORD_FRAME_LEN, QUERY_FRAME_LEN>,
    ch: &ResolverChannels<'_>,
    desired: &mut HeldSet,
) -> bool
where
    R: embedded_io_async::Read,
    W: embedded_io_async::Write,
{
    let held: HeldSet = desired.iter().copied().collect();
    for public_key in held {
        if !refresh_one(connection, ch, public_key).await {
            return false;
        }
    }
    true
}

/// Refresh one locally held key after a peer invalidation or reconnect.
async fn refresh_one<R, W>(
    connection: &mut Connection<R, W, ChangeHandler, RECORD_FRAME_LEN, QUERY_FRAME_LEN>,
    ch: &ResolverChannels<'_>,
    public_key: [u8; 32],
) -> bool
where
    R: embedded_io_async::Read,
    W: embedded_io_async::Write,
{
    let (outcome, reconnect) = refresh(connection, public_key).await;
    if reconnect || matches!(outcome, ResolveOutcome::Failed) {
        warn!("failed to refresh a held record; reconnecting");
        return false;
    }
    ch.events
        .send(ResolverEvent::PeerUpdated(PeerUpdate::new(
            public_key, outcome,
        )))
        .await;
    true
}

/// Record that the core now holds this key.
fn remember_desired(desired: &mut HeldSet, public_key: [u8; 32]) {
    if desired.contains(&public_key) {
        return;
    }
    if desired.push(public_key).is_err() {
        // This must remain aligned with the runner's peer capacity.
        error!("resolver held-peer capacity exhausted");
    }
}

/// Drop a key from the desired set, reporting whether it was there.
fn forget_desired(desired: &mut HeldSet, public_key: [u8; 32]) -> bool {
    let Some(index) = desired.iter().position(|key| *key == public_key) else {
        return false;
    };
    desired.swap_remove(index);
    true
}

async fn retry_delay(ch: &ResolverChannels<'_>, desired: &mut HeldSet, jitter: &mut Jitter) {
    let spread =
        embassy_time::Duration::from_millis(u64::from(jitter.spread_ms(RECONNECT_DELAY_MS)));
    let retry_at = Instant::now() + spread;
    loop {
        // Put the absolute timer first so a continuously ready command channel
        // cannot postpone reconnection after the delay has elapsed.
        match select(Timer::at(retry_at), ch.commands.receive()).await {
            Either::First(()) => return,
            Either::Second(ResolverCommand::Forget(public_key)) => {
                forget_desired(desired, public_key);
            }
            Either::Second(ResolverCommand::Resolve(request)) => {
                ch.events
                    .send(ResolverEvent::Resolved(
                        request.complete(ResolveOutcome::Failed),
                    ))
                    .await;
            }
        }
    }
}
