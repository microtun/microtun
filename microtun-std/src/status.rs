//! Read-only tunnel status shared with diagnostic tasks.
//!
//! The protocol engine remains single-owner inside [`crate::TunnelRunner`].
//! After each processed stimulus the runner copies the small, bounded peer
//! view published by `microtun-core` into this shared snapshot. Readers never
//! borrow or lock the live crypto engine.

use std::sync::{Arc, RwLock};

use microtun_core::PeerSnapshot;

use crate::MAX_PEERS;

/// Point-in-time operational view of the local tunnel interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelSnapshot {
    /// Local tunnel static public key.
    pub public_key: [u8; 32],
    /// UDP listen port used by the tunnel runner.
    pub listen_port: u16,
    /// Installed peers in peer-table order. Empty capacity remains `None`.
    pub peers: [Option<PeerSnapshot>; MAX_PEERS],
}

impl TunnelSnapshot {
    pub(crate) const fn empty() -> Self {
        Self {
            public_key: [0; 32],
            listen_port: 0,
            peers: [const { None }; MAX_PEERS],
        }
    }
}

/// Cheap cloneable handle for reading the latest tunnel snapshot.
///
/// Clone this before moving [`crate::TunnelRunner`] into its task, then call
/// [`snapshot`](Self::snapshot) from diagnostics, admin endpoints, or a CLI.
/// Snapshot reads never borrow the live protocol engine.
#[derive(Debug, Clone)]
pub struct TunnelStatus {
    snapshot: Arc<RwLock<TunnelSnapshot>>,
}

impl TunnelStatus {
    pub(crate) fn new() -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(TunnelSnapshot::empty())),
        }
    }

    /// Copy the latest complete snapshot.
    pub fn snapshot(&self) -> TunnelSnapshot {
        *self
            .snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn publish(&self, snapshot: TunnelSnapshot) {
        *self
            .snapshot
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = snapshot;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_observe_the_same_published_snapshot() {
        let status = TunnelStatus::new();
        let reader = status.clone();
        let mut snapshot = TunnelSnapshot::empty();
        snapshot.public_key = [7; 32];
        snapshot.listen_port = 51_820;

        status.publish(snapshot);

        assert_eq!(reader.snapshot(), snapshot);
    }
}
