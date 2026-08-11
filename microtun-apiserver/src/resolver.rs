//! Local peer resolver backed by the Peers API server configuration file.
//!
//! The tunnel core starts with no pinned peers. Whenever it needs to identify
//! an inbound public key or route an outbound tunnel address, this task answers
//! from the same published state used by the Peers API: validated
//! [`crate::registry::Registry`] data plus authenticated runtime endpoint
//! observations.
//!
//! The file is polled by content rather than metadata. Config files are small,
//! and comparing their text avoids missing an edit whose size and timestamp
//! happen to match the previous version. Invalid or runtime-incompatible
//! changes leave the last known-good registry in service.

use std::{
    collections::HashSet,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use microtun_core::{
    IpCidr, PeerUpdate, ResolveOutcome, ResolveQuery, ResolverCommand, ResolverEvent,
};
use tokio::sync::mpsc;

#[cfg(test)]
use crate::registry::Registry;
use crate::{
    config::{self, Loaded},
    registry::SharedRegistry,
};

/// How quickly a changed file becomes visible to resolver and RPC requests.
const RELOAD_INTERVAL: Duration = Duration::from_secs(1);

/// Server properties that cannot be changed without rebuilding the live
/// tunnel and virtual TCP stack.
pub struct FixedServer {
    public_key: [u8; 32],
    listen: SocketAddr,
    relay_forwarding: bool,
    addresses: Vec<IpCidr>,
}

impl FixedServer {
    pub fn from_loaded(loaded: &Loaded) -> Result<Self, String> {
        let addresses = server_addresses(loaded)?;
        Ok(Self {
            public_key: loaded.options.public_key,
            listen: loaded.options.listen,
            relay_forwarding: loaded.options.relay_forwarding,
            addresses,
        })
    }

    fn validate_reload(&self, loaded: &Loaded) -> Result<(), String> {
        if loaded.options.public_key != self.public_key {
            return Err("[Server] PrivateKey changed; restart to change tunnel identity".into());
        }
        if loaded.options.listen != self.listen {
            return Err(format!(
                "[Server] ListenPort changed from {} to {}; restart to rebind UDP",
                self.listen, loaded.options.listen
            ));
        }
        if loaded.options.relay_forwarding != self.relay_forwarding {
            return Err(
                "[Server] RelayForwarding changed; restart to change relay forwarding policy"
                    .into(),
            );
        }

        let addresses = server_addresses(loaded)?;
        if addresses.len() != self.addresses.len()
            || !addresses
                .iter()
                .all(|address| self.addresses.contains(address))
        {
            return Err(
                "[Server] Addresses changed; restart to rebuild the virtual TCP stack".into(),
            );
        }
        Ok(())
    }
}

fn server_addresses(loaded: &Loaded) -> Result<Vec<IpCidr>, String> {
    loaded
        .registry
        .lookup_key(&loaded.options.public_key)
        .map(|record| record.addresses.clone())
        .ok_or_else(|| "Peers API server record is missing from its own registry".to_string())
}

/// Run the published-state resolver until its request channel is closed.
///
/// A successful reload replaces the registry used by both this task and the
/// RPC handlers. Watched peers are refreshed immediately from the resulting
/// peer-level change stream; a lagged subscriber reconciles its complete watch
/// set from the latest registry snapshot.
pub async fn task(
    config_path: PathBuf,
    fixed: FixedServer,
    registry: SharedRegistry,
    mut commands: mpsc::Receiver<ResolverCommand>,
    events: mpsc::Sender<ResolverEvent>,
) {
    let mut last_observation: Option<Observation> = None;
    let mut interval = tokio::time::interval(RELOAD_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut changes = registry.subscribe();
    let mut watched = HashSet::new();

    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else {
                    return;
                };
                match command {
                    ResolverCommand::Resolve(request) => {
                        let query = request.query();
                        let outcome = resolve_shared(&registry, query, fixed.public_key);
                        // The core-facing resolver contract requires a positive
                        // answer to remain watched. This local resolver tracks
                        // that directly; remote clients use explicit v1.peer.watch.
                        if let ResolveOutcome::Found(peer) = &outcome {
                            watched.insert(peer.public_key);
                        }
                        let response = request.complete(outcome);
                        if events.send(ResolverEvent::Resolved(response)).await.is_err() {
                            return;
                        }
                    }
                    ResolverCommand::Unwatch(public_key) => {
                        watched.remove(&public_key);
                    }
                }
            }
            change = changes.recv() => {
                match change {
                    Ok(change) if watched.contains(&change.public_key) => {
                        if send_update(
                            &events,
                            &registry,
                            change.public_key,
                            fixed.public_key,
                        )
                        .await
                        .is_err()
                        {
                            return;
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        for public_key in watched.iter().copied().collect::<Vec<_>>() {
                            if send_update(
                                &events,
                                &registry,
                                public_key,
                                fixed.public_key,
                            )
                            .await
                            .is_err()
                            {
                                return;
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
            _ = interval.tick() => {
                reload_if_changed(
                    &config_path,
                    &fixed,
                    &registry,
                    &mut last_observation,
                );
            }
        }
    }
}

async fn send_update(
    events: &mpsc::Sender<ResolverEvent>,
    registry: &SharedRegistry,
    public_key: [u8; 32],
    local_public_key: [u8; 32],
) -> Result<(), ()> {
    let outcome = registry.read(|published| {
        published
            .lookup_key(&public_key)
            .map(|record| {
                ResolveOutcome::Found(resolve_record(
                    record,
                    published.effective_endpoint(record),
                    local_public_key,
                ))
            })
            .unwrap_or(ResolveOutcome::NotFound)
    });
    events
        .send(ResolverEvent::PeerUpdated(PeerUpdate::new(
            public_key, outcome,
        )))
        .await
        .map_err(|_| ())
}

fn resolve_shared(
    registry: &SharedRegistry,
    query: ResolveQuery,
    local_public_key: [u8; 32],
) -> ResolveOutcome {
    registry.read(|published| {
        let record = match query {
            ResolveQuery::ByPublicKey(public_key) => published.lookup_key(&public_key),
            ResolveQuery::ByDstAddress(address) => published.lookup_address(address),
        };

        record
            .map(|record| {
                ResolveOutcome::Found(resolve_record(
                    record,
                    published.effective_endpoint(record),
                    local_public_key,
                ))
            })
            .unwrap_or(ResolveOutcome::NotFound)
    })
}

#[cfg(test)]
fn resolve(registry: &Registry, query: ResolveQuery, local_public_key: [u8; 32]) -> ResolveOutcome {
    let record = match query {
        ResolveQuery::ByPublicKey(public_key) => registry.lookup_key(&public_key),
        ResolveQuery::ByDstAddress(address) => registry.lookup_address(address),
    };

    record
        .map(|record| {
            ResolveOutcome::Found(resolve_record(record, record.endpoint, local_public_key))
        })
        .unwrap_or(ResolveOutcome::NotFound)
}

/// Project a served registry record into the API server's own tunnel view.
///
/// `Relay = @server` is meaningful to remote clients: they should deliver
/// traffic for this peer through us. Locally, however, we *are* that relay, so
/// the peer must be treated as directly reachable. Its endpoint can then be
/// learned from authenticated inbound traffic, as required by the relay
/// forwarding path.
fn resolve_record(
    record: &crate::registry::PeerRecord,
    endpoint: Option<std::net::SocketAddr>,
    local_public_key: [u8; 32],
) -> microtun_core::ResolvedPeer {
    let mut peer = record.resolved_with_endpoint(endpoint);
    if peer.relay == Some(local_public_key) {
        peer.relay = None;
    }
    peer
}

#[derive(Clone, PartialEq, Eq)]
enum Observation {
    Contents(String),
    ReadError(String),
}

fn reload_if_changed(
    config_path: &Path,
    fixed: &FixedServer,
    registry: &SharedRegistry,
    last_observation: &mut Option<Observation>,
) {
    let observation = match fs::read_to_string(config_path) {
        Ok(contents) => Observation::Contents(contents),
        Err(error) => Observation::ReadError(error.to_string()),
    };

    if last_observation.as_ref() == Some(&observation) {
        return;
    }
    *last_observation = Some(observation.clone());

    let contents = match observation {
        Observation::Contents(contents) => contents,
        Observation::ReadError(error) => {
            tracing::warn!(
                "cannot refresh {}: {error}; keeping last known-good configuration",
                config_path.display()
            );
            return;
        }
    };

    let loaded = match config::parse(&contents, config_path) {
        Ok(loaded) => loaded,
        Err(error) => {
            tracing::warn!("{error}; keeping last known-good configuration");
            return;
        }
    };

    if let Err(error) = fixed.validate_reload(&loaded) {
        tracing::warn!(
            "cannot apply {}: {error}; keeping last known-good configuration",
            config_path.display()
        );
        return;
    }

    let peers = loaded.registry.peer_count();
    let routes = loaded.registry.route_count();
    registry.replace(loaded.registry);
    tracing::info!(
        "reloaded {}: {peers} peers, {routes} routes",
        config_path.display()
    );
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        net::SocketAddr,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use microtun_core::{ResolveOutcome, ResolveQuery};

    use super::{FixedServer, reload_if_changed, resolve, resolve_shared};
    use crate::{
        config::{
            self, Loaded,
            tests::{SERVER_PRIVATE, server_public},
        },
        registry::SharedRegistry,
    };

    const PEER_A: &str = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=";
    const PEER_B: &str = "u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s=";

    fn config_text(peer_key: &str, endpoint: &str, address: &str) -> String {
        format!(
            "[Server]\nPrivateKey = {SERVER_PRIVATE}\nAddresses = 10.0.0.1/32\n\n\
             [Peer.client]\nPublicKey = {peer_key}\nEndpoint = {endpoint}\nAddresses = {address}\n"
        )
    }

    fn loaded(text: &str) -> Loaded {
        config::parse(text, Path::new("test.conf")).expect("test config loads")
    }

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "microtun-apiserver-{label}-{}-{nonce}.conf",
            std::process::id()
        ))
    }

    #[test]
    fn answers_by_key_and_longest_prefix() {
        let text = format!(
            "[Server]\nPrivateKey = {SERVER_PRIVATE}\nAddresses = 10.0.0.1/32\n\n\
             [Peer.wide]\nPublicKey = {PEER_A}\nEndpoint = 198.51.100.1:51820\nAddresses = 10.2.0.0/16\n\n\
             [Peer.narrow]\nPublicKey = {PEER_B}\nEndpoint = 198.51.100.2:51820\nAddresses = 10.2.3.0/24\n"
        );
        let loaded = loaded(&text);

        let ResolveOutcome::Found(by_key) = resolve(
            &loaded.registry,
            ResolveQuery::ByPublicKey([0xAA; 32]),
            server_public(),
        ) else {
            panic!("peer should resolve by key");
        };
        assert_eq!(by_key.endpoint, Some("198.51.100.1:51820".parse().unwrap()));

        let ResolveOutcome::Found(by_address) = resolve(
            &loaded.registry,
            ResolveQuery::ByDstAddress("10.2.3.7".parse().unwrap()),
            server_public(),
        ) else {
            panic!("peer should resolve by address");
        };
        assert_eq!(by_address.public_key, [0xBB; 32]);

        assert!(matches!(
            resolve(
                &loaded.registry,
                ResolveQuery::ByPublicKey([0xCC; 32]),
                server_public(),
            ),
            ResolveOutcome::NotFound
        ));
    }

    #[test]
    fn published_resolver_prefers_learned_endpoint() {
        let configured: SocketAddr = "198.51.100.10:51820".parse().unwrap();
        let learned: SocketAddr = "203.0.113.10:42424".parse().unwrap();
        let first = loaded(&config_text(PEER_A, &configured.to_string(), "10.0.0.2/32"));
        let shared = SharedRegistry::new(first.registry);
        shared.observe_endpoint([0xAA; 32], learned);

        let ResolveOutcome::Found(by_key) = resolve_shared(
            &shared,
            ResolveQuery::ByPublicKey([0xAA; 32]),
            server_public(),
        ) else {
            panic!("peer should resolve by key");
        };
        assert_eq!(by_key.endpoint, Some(learned));

        let ResolveOutcome::Found(by_address) = resolve_shared(
            &shared,
            ResolveQuery::ByDstAddress("10.0.0.2".parse().unwrap()),
            server_public(),
        ) else {
            panic!("peer should resolve by address");
        };
        assert_eq!(by_address.endpoint, Some(learned));
    }

    #[test]
    fn server_local_resolver_strips_self_relay() {
        let text = format!(
            "[Server]\nPrivateKey = {SERVER_PRIVATE}\nAddresses = 10.0.0.1/32\n\n\
             [Peer.client]\nPublicKey = {PEER_A}\nAddresses = 10.0.0.2/32\nRelay = @server\n"
        );
        let loaded = loaded(&text);

        // The served registry must still tell remote clients to use this
        // server as the relay.
        assert_eq!(
            loaded.registry.lookup_key(&[0xAA; 32]).unwrap().relay,
            Some(server_public())
        );

        // The server's own tunnel is the relay, so its local view must be
        // direct. The authenticated initiation can then teach it the live
        // outer endpoint and the response goes straight back to that source.
        let ResolveOutcome::Found(peer) = resolve(
            &loaded.registry,
            ResolveQuery::ByPublicKey([0xAA; 32]),
            server_public(),
        ) else {
            panic!("peer should resolve by key");
        };
        assert_eq!(peer.relay, None);
        assert_eq!(peer.endpoint, None);
    }

    #[test]
    fn changed_valid_config_replaces_answers() {
        let first = loaded(&config_text(PEER_A, "198.51.100.10:51820", "10.0.0.2/32"));
        let fixed = FixedServer::from_loaded(&first).unwrap();
        let shared = SharedRegistry::new(first.registry);
        let mut observation = None;

        let path = temp_path("reload");
        fs::write(
            &path,
            config_text(PEER_B, "198.51.100.20:51820", "10.0.0.3/32"),
        )
        .unwrap();

        reload_if_changed(&path, &fixed, &shared, &mut observation);
        let snapshot = shared.config_snapshot();
        assert!(snapshot.lookup_key(&[0xAA; 32]).is_none());
        assert!(snapshot.lookup_key(&[0xBB; 32]).is_some());
        assert_eq!(
            snapshot
                .lookup_address("10.0.0.3".parse().unwrap())
                .unwrap()
                .public_key,
            [0xBB; 32]
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn relay_forwarding_change_requires_restart() {
        let first = loaded(&config_text(PEER_A, "198.51.100.10:51820", "10.0.0.2/32"));
        let fixed = FixedServer::from_loaded(&first).unwrap();
        let changed = loaded(
            &config_text(PEER_A, "198.51.100.10:51820", "10.0.0.2/32").replace(
                "Addresses = 10.0.0.1/32",
                "Addresses = 10.0.0.1/32\nRelayForwarding = true",
            ),
        );

        assert_eq!(
            fixed.validate_reload(&changed).unwrap_err(),
            "[Server] RelayForwarding changed; restart to change relay forwarding policy"
        );
    }

    #[test]
    fn invalid_or_runtime_incompatible_changes_keep_last_good_answers() {
        let first = loaded(&config_text(PEER_A, "198.51.100.10:51820", "10.0.0.2/32"));
        let fixed = FixedServer::from_loaded(&first).unwrap();
        let shared = SharedRegistry::new(first.registry);
        let mut observation = None;
        let path = temp_path("invalid-reload");

        fs::write(&path, "not a config").unwrap();
        reload_if_changed(&path, &fixed, &shared, &mut observation);
        assert!(shared.config_snapshot().lookup_key(&[0xAA; 32]).is_some());

        let changed_server = format!(
            "[Server]\nPrivateKey = {SERVER_PRIVATE}\nAddresses = 10.9.9.9/32\n\n\
             [Peer.client]\nPublicKey = {PEER_B}\nEndpoint = 198.51.100.20:51820\nAddresses = 10.0.0.3/32\n"
        );
        fs::write(&path, changed_server).unwrap();
        reload_if_changed(&path, &fixed, &shared, &mut observation);
        let snapshot = shared.config_snapshot();
        assert!(snapshot.lookup_key(&[0xAA; 32]).is_some());
        assert!(snapshot.lookup_key(&[0xBB; 32]).is_none());
        assert!(snapshot.lookup_key(&server_public()).is_some());

        let _ = fs::remove_file(path);
    }
}
