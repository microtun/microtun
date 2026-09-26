//! Reply handles.
//!
//! Every request hands your device a reply object. Consuming it sends the
//! answer to the kernel. Reply objects are `Send + 'static`, so you may
//! answer immediately, park the reply in your device and answer later
//! (e.g. a blocking `read` that completes when data arrives), or move it to
//! another thread.
//!
//! If a reply is dropped without being used, `EIO` is sent automatically,
//! so a caller can never hang because of a forgotten reply.

use std::{
    collections::HashSet,
    marker::PhantomData,
    ptr,
    sync::{Arc, Mutex, PoisonError, RwLock, RwLockReadGuard},
};

use libc::c_int;

use crate::cuse::{
    Delivery, Errno, PollEvents, RequestId, ffi,
    ioctl::{Plain, UserBuf, bytes_of},
};

/// Tracks whether the libfuse session still exists. Replies sent after
/// teardown would touch freed memory inside libfuse, so every call that
/// talks to the kernel takes a read lock and checks this first; shutdown
/// takes the write lock and flips it.
pub(crate) struct Liveness(RwLock<bool>);

impl Liveness {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Liveness(RwLock::new(true)))
    }

    fn read(&self) -> RwLockReadGuard<'_, bool> {
        self.0.read().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn kill(&self) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = false;
    }
}

/// Owns a `fuse_req_t` until it's answered.
pub(crate) struct RawReply {
    req: ffi::fuse_req_t,
    id: RequestId,
    live: Arc<Liveness>,
}

// SAFETY: libfuse allows replying to a request from any thread; the request
// is used by exactly one owner (this struct) until it's answered.
unsafe impl Send for RawReply {}
unsafe impl Sync for RawReply {}

impl RawReply {
    pub(crate) fn new(req: ffi::fuse_req_t, id: RequestId, live: Arc<Liveness>) -> Self {
        RawReply { req, id, live }
    }

    fn send(mut self, f: impl FnOnce(ffi::fuse_req_t) -> c_int) -> Delivery {
        let req = std::mem::replace(&mut self.req, ptr::null_mut());
        let alive = self.live.read();
        if !*alive {
            return Delivery(Err(Errno::ENOTCONN));
        }
        Delivery(Errno::check(f(req)))
    }

    fn error(self, err: Errno) -> Delivery {
        self.send(|req| unsafe { ffi::fuse_reply_err(req, err.raw()) })
    }

    pub(crate) fn ack(self) -> Delivery {
        self.send(|req| unsafe { ffi::fuse_reply_err(req, 0) })
    }

    fn is_interrupted(&self) -> bool {
        let alive = self.live.read();
        !*alive || unsafe { ffi::fuse_req_interrupted(self.req) != 0 }
    }
}

impl Drop for RawReply {
    fn drop(&mut self) {
        if !self.req.is_null() {
            let req = std::mem::replace(&mut self.req, ptr::null_mut());
            let alive = self.live.read();
            if *alive {
                unsafe { ffi::fuse_reply_err(req, libc::EIO) };
            }
        }
    }
}

macro_rules! common_reply_methods {
    () => {
        /// The id of the request being answered. Compare it with the id
        /// passed to [`Device::interrupt`](crate::cuse::Device::interrupt).
        pub fn id(&self) -> RequestId {
            self.raw.id
        }

        /// Whether the caller has been interrupted by a signal (or the
        /// session is shutting down). A parked reply for which this returns
        /// `true` should usually be answered with [`Errno::EINTR`].
        pub fn is_interrupted(&self) -> bool {
            self.raw.is_interrupted()
        }

        /// Fails the request with `err`.
        pub fn error(self, err: Errno) -> Delivery {
            self.raw.error(err)
        }
    };
}

pub(crate) struct Slot<H> {
    pub(crate) handle: H,
    // Guarantees a non-zero-sized allocation so every open file gets a
    // distinct `fh`, even when `H` is `()`.
    _nonzero: u8,
}

pub(crate) type HandleRegistry = Arc<Mutex<HashSet<u64>>>;

/// Reply to [`Device::open`](crate::cuse::Device::open).
pub struct OpenReply<H> {
    raw: RawReply,
    handles: HandleRegistry,
    _handle: PhantomData<H>,
}

// `RawReply` and the registry are Send; the only thing that could make
// sending this unsound is moving an `H` across threads, hence the bound.
// (`PhantomData<H>` already gives exactly that auto-trait behavior.)

impl<H> OpenReply<H> {
    pub(crate) fn new(raw: RawReply, handles: HandleRegistry) -> Self {
        OpenReply {
            raw,
            handles,
            _handle: PhantomData,
        }
    }

    common_reply_methods!();

    /// Accepts the open. `handle` is your per-open-file state; it's passed
    /// back as `&mut H` to every subsequent operation on this file and
    /// given back to you by value in
    /// [`Device::release`](crate::cuse::Device::release).
    pub fn ok(self, handle: H) -> Delivery {
        let OpenReply { raw, handles, .. } = self;
        let fh = Box::into_raw(Box::new(Slot {
            handle,
            _nonzero: 0,
        })) as usize as u64;
        let drop_slot = || drop(unsafe { Box::from_raw(fh as usize as *mut Slot<H>) });

        // Register before replying: once the kernel has the reply, a
        // `release` for this fh may arrive on the session thread at any time.
        let alive_guard = raw.live.clone();
        let alive = alive_guard.read();
        if !*alive {
            drop(alive);
            drop_slot();
            return raw.send(|_| 0); // no-op, reports ENOTCONN
        }
        handles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(fh);
        drop(alive);

        let delivery = raw.send(|req| unsafe { ffi::cuse_shim_reply_open(req, fh) });
        if !delivery.is_delivered() {
            // The kernel never saw this fh, so no release will come for it.
            if handles
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&fh)
            {
                drop_slot();
            }
        }
        delivery
    }

    /// `Ok(handle)` → [`ok`](Self::ok), `Err(e)` → [`error`](Self::error).
    pub fn result(self, result: Result<H, Errno>) -> Delivery {
        match result {
            Ok(h) => self.ok(h),
            Err(e) => self.error(e),
        }
    }
}

/// Reply to [`Device::read`](crate::cuse::Device::read).
pub struct ReadReply {
    raw: RawReply,
    size: usize,
}

impl ReadReply {
    pub(crate) fn new(raw: RawReply, size: usize) -> Self {
        ReadReply { raw, size }
    }

    common_reply_methods!();

    /// Maximum number of bytes the caller asked for.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns `data` to the caller. Truncated to [`size`](Self::size) if
    /// longer. An empty slice means end-of-file to most programs.
    pub fn data(self, data: &[u8]) -> Delivery {
        let len = data.len().min(self.size);
        self.raw
            .send(|req| unsafe { ffi::fuse_reply_buf(req, data.as_ptr().cast(), len) })
    }

    /// `Ok(bytes)` → [`data`](Self::data), `Err(e)` → [`error`](Self::error).
    pub fn result<B: AsRef<[u8]>>(self, result: Result<B, Errno>) -> Delivery {
        match result {
            Ok(b) => self.data(b.as_ref()),
            Err(e) => self.error(e),
        }
    }
}

/// Reply to [`Device::write`](crate::cuse::Device::write).
pub struct WriteReply {
    raw: RawReply,
    size: usize,
}

impl WriteReply {
    pub(crate) fn new(raw: RawReply, size: usize) -> Self {
        WriteReply { raw, size }
    }

    common_reply_methods!();

    /// Number of bytes the caller tried to write.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Reports that `count` bytes were consumed (a short write if less
    /// than [`size`](Self::size)).
    pub fn written(self, count: usize) -> Delivery {
        let count = count.min(self.size);
        self.raw
            .send(|req| unsafe { ffi::fuse_reply_write(req, count) })
    }

    /// Reports that the whole buffer was consumed.
    pub fn all(self) -> Delivery {
        let n = self.size;
        self.written(n)
    }

    /// `Ok(count)` → [`written`](Self::written), `Err(e)` → [`error`](Self::error).
    pub fn result(self, result: Result<usize, Errno>) -> Delivery {
        match result {
            Ok(n) => self.written(n),
            Err(e) => self.error(e),
        }
    }
}

/// Reply to [`Device::ioctl`](crate::cuse::Device::ioctl).
pub struct IoctlReply {
    raw: RawReply,
}

impl IoctlReply {
    pub(crate) fn new(raw: RawReply) -> Self {
        IoctlReply { raw }
    }

    common_reply_methods!();

    /// Succeeds with `ioctl(2)` return value `result` and no output data.
    pub fn ok(self, result: i32) -> Delivery {
        self.ok_with(result, &[])
    }

    /// Succeeds with return value `result`, copying `out` back to the
    /// caller. `out` must not exceed [`Ioctl::out_size`](crate::cuse::Ioctl::out_size),
    /// or the caller gets `EIO`.
    pub fn ok_with(self, result: i32, out: &[u8]) -> Delivery {
        let buf = if out.is_empty() {
            ptr::null()
        } else {
            out.as_ptr().cast()
        };
        self.raw
            .send(|req| unsafe { ffi::fuse_reply_ioctl(req, result, buf, out.len()) })
    }

    /// Succeeds with return value `result`, copying `value` back to the
    /// caller. The typical reply for an `_IOR`/`_IOWR` command.
    pub fn ok_value<T: Plain>(self, result: i32, value: &T) -> Delivery {
        self.ok_with(result, bytes_of(value))
    }

    /// Unrestricted mode only: asks the kernel to call `ioctl` again with
    /// the contents of `input` (concatenated) as [`Ioctl::input`](crate::cuse::Ioctl::input),
    /// and to copy the reply data back into `output` (in order).
    pub fn retry(self, input: &[UserBuf], output: &[UserBuf]) -> Delivery {
        let iv: Vec<libc::iovec> = input.iter().map(|b| b.to_iovec()).collect();
        let ov: Vec<libc::iovec> = output.iter().map(|b| b.to_iovec()).collect();
        self.raw.send(|req| unsafe {
            ffi::fuse_reply_ioctl_retry(req, iv.as_ptr(), iv.len(), ov.as_ptr(), ov.len())
        })
    }
}

/// Reply to [`Device::poll`](crate::cuse::Device::poll).
pub struct PollReply {
    raw: RawReply,
}

impl PollReply {
    pub(crate) fn new(raw: RawReply) -> Self {
        PollReply { raw }
    }

    common_reply_methods!();

    /// Reports which events are ready *right now*.
    pub fn ready(self, events: PollEvents) -> Delivery {
        self.raw
            .send(|req| unsafe { ffi::fuse_reply_poll(req, events.bits()) })
    }
}

/// Wakes up a process sleeping in `poll`/`select`/`epoll` on this device.
///
/// Handed to [`Device::poll`](crate::cuse::Device::poll) when the caller intends
/// to wait. Keep it until readiness changes, then call
/// [`notify`](Self::notify); the kernel will call `poll` again to fetch the
/// new state. It is `Send`, so it can be notified from any thread.
pub struct PollNotifier {
    ph: *mut ffi::fuse_pollhandle,
    live: Arc<Liveness>,
}

// SAFETY: poll handles may be notified/destroyed from any thread.
unsafe impl Send for PollNotifier {}
unsafe impl Sync for PollNotifier {}

impl PollNotifier {
    pub(crate) fn new(ph: *mut ffi::fuse_pollhandle, live: Arc<Liveness>) -> Self {
        PollNotifier { ph, live }
    }

    /// Wakes the waiter(s).
    pub fn notify(self) -> Delivery {
        let alive = self.live.read();
        if !*alive {
            return Delivery(Err(Errno::ENOTCONN));
        }
        Delivery(Errno::check(unsafe {
            ffi::fuse_lowlevel_notify_poll(self.ph)
        }))
        // `self` drops here and frees the handle.
    }
}

impl Drop for PollNotifier {
    fn drop(&mut self) {
        // Just a free(); safe even after the session is gone.
        unsafe { ffi::fuse_pollhandle_destroy(self.ph) };
    }
}
