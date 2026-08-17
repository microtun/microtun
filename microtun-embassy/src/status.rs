//! Read-only tunnel status shared with diagnostic tasks.
//!
//! The protocol engine remains single-owner inside [`crate::TunnelRunner`].
//! After each processed stimulus the runner copies the small, bounded peer
//! view published by `microtun-core` into this critical-section protected
//! snapshot. Readers therefore never borrow or lock the live crypto engine.

use core::cell::RefCell;

use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
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

/// Backing storage for [`TunnelStatus`].
///
/// This is embedded in [`crate::TunnelState`], so applications do not need a
/// second allocation just to enable diagnostics.
pub(crate) struct TunnelStatusState {
    snapshot: Mutex<CriticalSectionRawMutex, RefCell<TunnelSnapshot>>,
}

impl TunnelStatusState {
    pub(crate) const fn new() -> Self {
        Self {
            snapshot: Mutex::new(RefCell::new(TunnelSnapshot::empty())),
        }
    }
}

/// Cheap copyable handle for reading the latest tunnel snapshot.
#[derive(Clone, Copy)]
pub struct TunnelStatus<'a> {
    state: &'a TunnelStatusState,
}

impl<'a> TunnelStatus<'a> {
    pub(crate) const fn new(state: &'a TunnelStatusState) -> Self {
        Self { state }
    }

    /// Copy the latest complete snapshot.
    pub fn snapshot(&self) -> TunnelSnapshot {
        self.state.snapshot.lock(|snapshot| *snapshot.borrow())
    }

    pub(crate) fn publish(&self, snapshot: TunnelSnapshot) {
        self.state
            .snapshot
            .lock(|current| *current.borrow_mut() = snapshot);
    }
}
