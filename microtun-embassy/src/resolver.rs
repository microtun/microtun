//! The peer-resolution task.
//!
//! A single long-lived TCP/JSON-RPC session carries lookups, explicit
//! `v1.peer.watch` requests, `v1.peer.unwatch` notifications, and `v1.peer.changed`
//! notifications. Ordinary lookups are side-effect free. Before returning a
//! positive resolution to the core, the resolver explicitly watches that key;
//! `v1.peer.watch` returns the current record while installing the subscription
//! atomically. While the core has no command ready the task continuously polls
//! the same RPC connection.
//!
//! `v1.peer.changed` names a key and carries nothing else, so it cannot be applied:
//! it means *whatever we hold for this key may no longer be current*, and the
//! answer is an ordinary `v1.peer.by_key`. Reconnect instead reissues
//! `v1.peer.watch` for every held record so the new connection restores its
//! explicit subscriptions.
//!
//! Only one call is ever in flight here, and a notification read during a
//! `v1.peer.watch` call is queued before its answer is applied, so a key
//! invalidated while its subscription is being established is refreshed once
//! more before the queue drains.

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
const MAX_WATCHES: usize = 8;
const CHANNEL_DEPTH: usize = 16;

/// Commands from the tunnel loop to the resolver task.
pub type CommandSender<'a> = Sender<'a, CriticalSectionRawMutex, ResolverCommand, CHANNEL_DEPTH>;
pub type CommandReceiver<'a> =
    Receiver<'a, CriticalSectionRawMutex, ResolverCommand, CHANNEL_DEPTH>;
/// Lookup completions and pushed watched-peer updates back to the tunnel loop.
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
    /// (`docs/peers-api.md` §11.3).
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

type ChangeHandler = ApiChangeHandler<MAX_WATCHES>;

type WatchSet = Vec<[u8; 32], MAX_WATCHES>;

/// Run the multiplexed Peers API resolver forever.
pub async fn resolver_task<'stack, 'channels, 'buffers>(
    stack: Stack<'stack>,
    cfg: ResolverConfig,
    ch: ResolverChannels<'channels>,
    buffers: ResolverBuffers<'buffers>,
) -> ! {
    let mut desired = WatchSet::new();
    let mut jitter = Jitter::new(cfg.jitter_seed);

    loop {
        let mut socket = TcpSocket::new(stack, &mut *buffers.socket_rx, &mut *buffers.socket_tx);
        // Keep a quiet watch session alive without application polling, but
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

            // Subscriptions live on the socket, so a replacement socket has
            // none. Reissuing `v1.peer.watch` for each held record restores its
            // subscription and reconciles its contents in one round trip.
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
    desired: &mut WatchSet,
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
        if !reconcile_changed(connection, ch, desired, jitter).await {
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
            Ready::Command(ResolverCommand::Unwatch(public_key)) => {
                connection.handler_mut().forget(public_key);
                if forget_desired(desired, public_key)
                    && send_unwatch(connection, public_key).await.is_err()
                {
                    return false;
                }
            }
            Ready::Command(ResolverCommand::Resolve(request)) => {
                let (outcome, reconnect) = resolve(connection, desired, request.query()).await;
                ch.events
                    .send(ResolverEvent::Resolved(request.complete(outcome)))
                    .await;
                if reconnect {
                    return false;
                }
                // Any key invalidated while the lookup/watch sequence was in
                // flight is queued. Once the explicit watch succeeds the key is
                // in the held set, so the queued invalidation is refreshed at
                // the top of the loop.
            }
            Ready::Incoming(Ok(())) => {}
            Ready::Incoming(Err(_)) => return false,
        }
    }
}

/// Resolve one core query and explicitly establish a watch before returning a
/// positive result.
///
/// A by-key resolution can go straight to `v1.peer.watch`. A by-address lookup is
/// side-effect free, so its returned key is watched explicitly and the watch
/// response becomes the authoritative record returned to the core.
async fn resolve<R, W>(
    connection: &mut Connection<R, W, ChangeHandler, RECORD_FRAME_LEN, QUERY_FRAME_LEN>,
    desired: &mut WatchSet,
    query: ResolveQuery,
) -> (ResolveOutcome, bool)
where
    R: embedded_io_async::Read,
    W: embedded_io_async::Write,
{
    match query {
        ResolveQuery::ByPublicKey(public_key) => watch(connection, desired, public_key).await,
        ResolveQuery::ByDstAddress(_) => {
            let (outcome, reconnect) = lookup(connection, query).await;
            if reconnect {
                return (outcome, true);
            }
            match outcome {
                ResolveOutcome::Found(record) => {
                    watch(connection, desired, record.public_key).await
                }
                outcome => (outcome, false),
            }
        }
    }
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

/// Explicitly subscribe to one key and return the atomically sampled state.
async fn watch<R, W>(
    connection: &mut Connection<R, W, ChangeHandler, RECORD_FRAME_LEN, QUERY_FRAME_LEN>,
    desired: &mut WatchSet,
    public_key: [u8; 32],
) -> (ResolveOutcome, bool)
where
    R: embedded_io_async::Read,
    W: embedded_io_async::Write,
{
    let (outcome, reconnect) = timed_call(
        microtun_api::METHOD_WATCH,
        peer_api::watch(connection, public_key),
    )
    .await;
    if reconnect {
        return (outcome, true);
    }
    match &outcome {
        ResolveOutcome::Found(_) => remember_desired(desired, public_key),
        ResolveOutcome::NotFound => {
            forget_desired(desired, public_key);
        }
        ResolveOutcome::Failed => {}
    }
    (outcome, false)
}

/// Refresh a key that is already watched on this connection.
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

/// Re-look-up every key a `v1.peer.changed` notification has named.
///
/// A notification carries no state, so this is where its only effect happens:
/// one ordinary `v1.peer.by_key`, whose result installs the new record or
/// authoritatively removes the peer. A key the core no longer holds is
/// discarded instead — an eviction and a notification crossing is the normal
/// outcome for a client that has not sent `v1.peer.unwatch` yet, and the held set
/// is the final local authority.
///
/// Returns `false` when the session must be discarded.
async fn reconcile_changed<R, W>(
    connection: &mut Connection<R, W, ChangeHandler, RECORD_FRAME_LEN, QUERY_FRAME_LEN>,
    ch: &ResolverChannels<'_>,
    desired: &mut WatchSet,
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
    while let Some(public_key) = connection.handler_mut().take_changed() {
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

/// Re-watch every held record on a freshly opened session.
///
/// This is the whole of reconnect recovery: `v1.peer.watch` re-establishes the
/// subscription and returns the current state in one atomic round trip.
/// Returns `false` when the session died partway through, so the caller
/// reconnects and starts again rather than leaving a record unwatched.
async fn reconcile<R, W>(
    connection: &mut Connection<R, W, ChangeHandler, RECORD_FRAME_LEN, QUERY_FRAME_LEN>,
    ch: &ResolverChannels<'_>,
    desired: &mut WatchSet,
) -> bool
where
    R: embedded_io_async::Read,
    W: embedded_io_async::Write,
{
    let held: WatchSet = desired.iter().copied().collect();
    for public_key in held {
        if !rewatch_one(connection, ch, desired, public_key).await {
            return false;
        }
    }
    true
}

/// Refresh one key after `v1.peer.changed` using the already-active subscription.
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
        warn!("failed to refresh a watched record; reconnecting");
        return false;
    }
    ch.events
        .send(ResolverEvent::PeerUpdated(PeerUpdate::new(
            public_key, outcome,
        )))
        .await;
    true
}

/// Re-establish one explicit watch on a replacement connection.
async fn rewatch_one<R, W>(
    connection: &mut Connection<R, W, ChangeHandler, RECORD_FRAME_LEN, QUERY_FRAME_LEN>,
    ch: &ResolverChannels<'_>,
    desired: &mut WatchSet,
    public_key: [u8; 32],
) -> bool
where
    R: embedded_io_async::Read,
    W: embedded_io_async::Write,
{
    let (outcome, reconnect) = watch(connection, desired, public_key).await;
    if reconnect || matches!(outcome, ResolveOutcome::Failed) {
        warn!("failed to restore a watched record; reconnecting");
        return false;
    }
    ch.events
        .send(ResolverEvent::PeerUpdated(PeerUpdate::new(
            public_key, outcome,
        )))
        .await;
    true
}

/// Record that `v1.peer.watch` successfully subscribed this key.
fn remember_desired(desired: &mut WatchSet, public_key: [u8; 32]) {
    if desired.contains(&public_key) {
        return;
    }
    if desired.push(public_key).is_err() {
        // This must remain aligned with the runner's peer capacity.
        error!("resolver watch capacity exhausted");
    }
}

/// Drop a key from the desired set, reporting whether it was there.
fn forget_desired(desired: &mut WatchSet, public_key: [u8; 32]) -> bool {
    let Some(index) = desired.iter().position(|key| *key == public_key) else {
        return false;
    };
    desired.swap_remove(index);
    true
}

async fn send_unwatch<R, W>(
    connection: &mut Connection<R, W, ChangeHandler, RECORD_FRAME_LEN, QUERY_FRAME_LEN>,
    public_key: [u8; 32],
) -> Result<(), ClientError>
where
    R: embedded_io_async::Read,
    W: embedded_io_async::Write,
{
    peer_api::unwatch(connection, public_key).await
}

async fn retry_delay(ch: &ResolverChannels<'_>, desired: &mut WatchSet, jitter: &mut Jitter) {
    let spread =
        embassy_time::Duration::from_millis(u64::from(jitter.spread_ms(RECONNECT_DELAY_MS)));
    let retry_at = Instant::now() + spread;
    loop {
        // Put the absolute timer first so a continuously ready command channel
        // cannot postpone reconnection after the delay has elapsed.
        match select(Timer::at(retry_at), ch.commands.receive()).await {
            Either::First(()) => return,
            Either::Second(ResolverCommand::Unwatch(public_key)) => {
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
