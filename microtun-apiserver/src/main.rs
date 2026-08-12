//! microtun Peers API server.
//!
//! Answers the two resolver lookups from a `wg.conf`-shaped configuration file
//! listing every peer in the network — an `[Server]` section for this
//! server, then one named `[Peer.name]` section per peer:
//!
//! ```bash
//! microtun-apiserver /etc/microtun/apiserver.conf
//! ```
//!
//! # Where this belongs in a deployment
//!
//! The Peers API server terminates the tunnel itself. It binds a UDP socket
//! (`ListenPort`), runs the protocol engine, and serves JSON-RPC over a virtual
//! TCP stack that exists only inside the tunnel — there is no operating-system
//! socket an off-tunnel caller could reach. A lookup is therefore always
//! attributable to a peer whose WireGuard session was authenticated first, and
//! new peer identities are admitted only when the current configuration has a
//! record for them.
//!
//! # Peer records reload while the process is running
//!
//! The tunnel starts with no pinned peers. Unknown tunnel identities and
//! destinations are resolved from the same published peer state used by the
//! Peers API: validated configuration plus authenticated direct-endpoint
//! observations learned by the running tunnel. Learned endpoints override
//! configured `Endpoint` values for the same key. The file is checked for
//! changes once a second; a successful reload updates future answers without
//! tearing down existing peers or sessions. Server identity, UDP listen
//! address, tunnel addresses, and relay-forwarding policy still require a
//! restart.

mod config;
mod registry;
mod resolver;
mod rpc;
mod smoltcp_net;

use std::{path::PathBuf, process::ExitCode, sync::Arc};

use clap::Parser;
use microtun_core::{Config as TunnelConfig, key::encode_key};
use microtun_std::{RESOLVER_QUEUE_DEPTH, TunnelObserver, TunnelRunner, core::Event};
use tokio::sync::{Notify, mpsc};

use crate::{
    registry::SharedRegistry,
    rpc::{AppState, serve_connection},
    smoltcp_net::{SmolTcpListener, SmolTcpNic},
};

/// Listener backlog for the virtual TCP stack.
const ACCEPT_BACKLOG: usize = 64;
/// The Peers API's fixed port inside the tunnel.
///
/// Unchanged across the move off HTTP: the port is a rendezvous with deployed
/// clients, and repurposing it costs nothing because nothing but this protocol
/// has ever been served on it.
const RPC_PORT: u16 = 80;

#[derive(Debug, Clone)]
struct LearnedEndpointObserver {
    registry: SharedRegistry,
}

impl TunnelObserver for LearnedEndpointObserver {
    fn event(&self, event: Event) {
        if let Event::PeerEndpointUpdate {
            public_key,
            endpoint,
        } = event
        {
            self.registry.observe_endpoint(public_key, endpoint);
            tracing::debug!(
                peer = %encode_key(&public_key),
                %endpoint,
                "authenticated peer endpoint observed"
            );
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    about = "Serves the microtun Peers API from a wg.conf-style list of network peers",
    version
)]
struct Args {
    /// Path to the configuration file listing the network's peers.
    #[arg(value_name = "CONFIG", env = "APISERVER_CONFIG")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    let loaded = match config::load(&args.config) {
        Ok(loaded) => loaded,
        Err(error) => {
            tracing::error!("{error}");
            return ExitCode::from(1);
        }
    };

    match serve(&args.config, loaded).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!("{error}");
            ExitCode::from(1)
        }
    }
}

async fn serve(config_path: &std::path::Path, loaded: config::Loaded) -> Result<(), String> {
    let fixed_server = resolver::FixedServer::from_loaded(&loaded)?;
    let config::Loaded { options, registry } = loaded;

    let server_addresses = registry
        .lookup_key(&options.public_key)
        .ok_or_else(|| "Peers API server record is missing from its own registry".to_string())?
        .addresses
        .clone();

    let state = AppState::new(registry);
    let shared_registry = state.registry();

    let (nic, stack) = SmolTcpNic::new(server_addresses.iter().copied());
    let listener = stack
        .listen(RPC_PORT, ACCEPT_BACKLOG)
        .map_err(|error| format!("cannot listen on virtual port {RPC_PORT}: {error}"))?;
    let mut runner = TunnelRunner::bind(
        TunnelConfig::new(options.private_key, &[]),
        rand::rngs::OsRng,
        nic,
        options.listen,
    )
    .await
    .map_err(|error| format!("cannot bind tunnel on {}: {error}", options.listen))?
    .with_observer(LearnedEndpointObserver {
        registry: shared_registry.clone(),
    });
    runner.enable_forwarding(options.relay_forwarding);
    if options.relay_forwarding {
        tracing::warn!("relay forwarding enabled");
    }

    let config_snapshot = shared_registry.config_snapshot();
    let peers = config_snapshot.peer_count();
    let routes = config_snapshot.route_count();

    tracing::info!(
        "serving {} as {} on virtual port {} at {} via UDP {}: {peers} peers, {routes} routes",
        config_path.display(),
        encode_key(&options.public_key),
        RPC_PORT,
        server_addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        options.listen,
    );

    let stop = Arc::new(Notify::new());
    let stack_task = tokio::spawn(stack.run());
    let tunnel_stop = Arc::clone(&stop);
    let (resolve_tx, resolve_requests) = mpsc::channel(RESOLVER_QUEUE_DEPTH);
    let (resolve_responses, resolve_rx) = mpsc::channel(RESOLVER_QUEUE_DEPTH);
    let resolver_task = tokio::spawn(resolver::task(
        config_path.to_path_buf(),
        fixed_server,
        shared_registry,
        resolve_requests,
        resolve_responses,
    ));
    let tunnel_task = tokio::spawn(async move {
        runner
            .run_with_resolver_task(resolve_tx, resolve_rx, resolver_task, async move {
                tunnel_stop.notified().await;
                Ok(())
            })
            .await
    });

    let server_task = tokio::spawn(accept_loop(listener, Arc::clone(&state), Arc::clone(&stop)));

    shutdown().await;
    stop.notify_waiters();
    let server_result = server_task
        .await
        .map_err(|error| format!("RPC task failed: {error}"))?;
    stack_task.abort();
    tunnel_task.abort();

    tracing::info!(
        "{} peers heard from, {} lookups refused, {} requests rate limited, {} connections limited",
        state.known_count(),
        state.refused(),
        state.rate_limited(),
        state.connection_limited(),
    );
    server_result
}

/// Accept virtual TCP connections until `stop` fires.
async fn accept_loop(
    listener: SmolTcpListener,
    state: Arc<AppState>,
    stop: Arc<Notify>,
) -> Result<(), String> {
    loop {
        let stream = tokio::select! {
            _ = stop.notified() => return Ok(()),
            accepted = listener.accept() => {
                accepted.map_err(|error| format!("virtual TCP accept failed: {error}"))?
            }
        };

        // Fail closed. A connection the stack could not attribute to a peer has
        // no identity for the RPC layer to admit on, so it is not served at
        // all rather than served as an anonymous caller.
        let Some(peer_key) = stream.remote_peer_key() else {
            tracing::warn!("dropping virtual TCP connection without authenticated peer metadata");
            continue;
        };
        tokio::spawn(serve_connection(stream, Arc::clone(&state), peer_key));
    }
}

/// Stop on Ctrl-C, and on `SIGTERM` where there is one.
async fn shutdown() {
    let interrupt = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    {
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut stream) => {
                    stream.recv().await;
                }
                Err(_) => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            _ = interrupt => {}
            _ = terminate => {}
        }
    }
    #[cfg(not(unix))]
    {
        interrupt.await;
    }

    tracing::info!("shutting down");
}
