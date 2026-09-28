//! Glue between libfuse's C callbacks and the [`Device`] trait.
//!
//! libfuse's single-threaded loop invokes every callback on one session
//! thread (the caller for [`Cuse::run`](crate::commands::serial::cuse::Cuse::run), or the dedicated
//! thread for [`Cuse::start`](crate::commands::serial::cuse::Cuse::start)), so the device lives in a
//! `RefCell` and is never accessed concurrently. Only reply objects leave
//! that thread.

use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    panic::{AssertUnwindSafe, catch_unwind},
    slice,
    sync::{Arc, PoisonError},
};

use libc::{c_char, c_int, c_uint, c_void, size_t};

use super::{
    Device, PollEvents, Request, RequestId,
    ffi::{self, fuse_req_t},
    ioctl::Ioctl,
    reply::*,
};

pub(crate) struct Dispatcher<D: Device> {
    pub(crate) device: RefCell<D>,
    pub(crate) handles: HandleRegistry,
    pub(crate) live: Arc<Liveness>,
    next_id: Cell<u64>,
    /// Nesting depth of device calls. Interrupts that arrive while a
    /// handler is running (or before it has seen its request) are queued
    /// and delivered once it returns.
    depth: Cell<u32>,
    interrupts: RefCell<VecDeque<RequestId>>,
}

impl<D: Device> Dispatcher<D> {
    pub(crate) fn new(device: D, live: Arc<Liveness>) -> Self {
        Dispatcher {
            device: RefCell::new(device),
            handles: Default::default(),
            live,
            next_id: Cell::new(1),
            depth: Cell::new(0),
            interrupts: Default::default(),
        }
    }

    pub(crate) fn ops() -> ffi::ShimOps {
        ffi::ShimOps {
            init_done: init_done::<D>,
            open: open::<D>,
            read: read::<D>,
            write: write::<D>,
            release: release::<D>,
            ioctl: ioctl::<D>,
            poll: poll::<D>,
        }
    }

    /// Runs `f` against the device, with panic containment and interrupt
    /// bookkeeping.
    ///
    /// # Safety
    /// `req` must be the live request libfuse just handed to a callback.
    unsafe fn dispatch(
        &self,
        req: fuse_req_t,
        flags: c_int,
        interruptible: bool,
        f: impl FnOnce(&mut D, &Request, RawReply),
    ) {
        let id = RequestId(self.next_id.get());
        self.next_id.set(self.next_id.get().wrapping_add(1));
        // SAFETY: `req` is live (caller contract).
        let request = unsafe { Request::from_raw(req, id, flags) };
        let raw = RawReply::new(req, id, self.live.clone());

        self.depth.set(self.depth.get() + 1);
        if interruptible {
            // May call `on_interrupt` synchronously if the interrupt already
            // arrived; the depth counter makes that get queued.
            // SAFETY: `req` is live and not yet answered (`raw` still owns it).
            // The data pointer is just the request id, never dereferenced.
            unsafe {
                ffi::fuse_req_interrupt_func(
                    req,
                    Some(on_interrupt::<D>),
                    id.0 as usize as *mut c_void,
                )
            };
        }
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut device = self.device.borrow_mut();
            f(&mut device, &request, raw);
        }));
        self.depth.set(self.depth.get() - 1);

        if result.is_err() {
            // The reply was dropped during unwinding, which answered EIO.
            tracing::error!("CUSE device handler panicked; request failed with EIO");
        }
        self.drain_interrupts();
    }

    fn drain_interrupts(&self) {
        if self.depth.get() != 0 {
            return;
        }
        loop {
            let Some(id) = self.interrupts.borrow_mut().pop_front() else {
                break;
            };
            let result = catch_unwind(AssertUnwindSafe(|| {
                self.device.borrow_mut().interrupt(id);
            }));
            if result.is_err() {
                tracing::error!("CUSE Device::interrupt panicked");
            }
        }
    }
}

/// # Safety
/// `data` must be the `Dispatcher<D>` pointer registered by `Cuse`,
/// which outlives the session loop.
unsafe fn dispatcher<'a, D: Device>(data: *mut c_void) -> &'a Dispatcher<D> {
    // SAFETY: see function contract.
    unsafe { &*(data as *const Dispatcher<D>) }
}

/// # Safety
/// `fh` must be a handle produced by `OpenReply::ok` for this `D` that has
/// not been released yet, and no other reference to it may be alive. Both
/// hold because the kernel only sends an fh we handed out, never after its
/// release, and all callbacks run one at a time on the session thread.
unsafe fn handle<'a, D: Device>(fh: u64) -> &'a mut D::Handle {
    // SAFETY: see function contract.
    unsafe { &mut (*(fh as usize as *mut Slot<D::Handle>)).handle }
}

/// # Safety
/// If non-null, `ptr` must point to `len` readable bytes that stay valid
/// for `'a`.
unsafe fn bytes<'a>(ptr: *const c_void, len: size_t) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        // SAFETY: see function contract.
        unsafe { slice::from_raw_parts(ptr.cast(), len) }
    }
}

unsafe extern "C" fn on_interrupt<D: Device>(req: fuse_req_t, data: *mut c_void) {
    // SAFETY: libfuse only calls this for a live request of our session,
    // whose userdata is the `ShimUserdata` set up by `Cuse`.
    let d = unsafe {
        let ud = ffi::fuse_req_userdata(req) as *const ffi::ShimUserdata;
        dispatcher::<D>((*ud).data)
    };
    d.interrupts
        .borrow_mut()
        .push_back(RequestId(data as usize as u64));
    d.drain_interrupts();
}

unsafe extern "C" fn init_done<D: Device>(data: *mut c_void) {
    // SAFETY: the shim passes our dispatcher pointer.
    let d = unsafe { dispatcher::<D>(data) };
    if catch_unwind(AssertUnwindSafe(|| d.device.borrow_mut().ready())).is_err() {
        tracing::error!("CUSE Device::ready panicked");
    }
}

// In all trampolines below: the shim passes our dispatcher pointer as
// `data`, `req` is the live request of this callback, and `fh` is a handle
// we handed out (see `handle`'s contract).

unsafe extern "C" fn open<D: Device>(req: fuse_req_t, data: *mut c_void, flags: c_int) {
    // SAFETY: see comment above.
    unsafe {
        let d = dispatcher::<D>(data);
        d.dispatch(req, flags, true, |dev, r, raw| {
            dev.open(r, OpenReply::new(raw, d.handles.clone()));
        });
    }
}

unsafe extern "C" fn read<D: Device>(
    req: fuse_req_t,
    data: *mut c_void,
    size: size_t,
    fh: u64,
    flags: c_int,
) {
    // SAFETY: see comment above.
    unsafe {
        let d = dispatcher::<D>(data);
        let h = handle::<D>(fh);
        d.dispatch(req, flags, true, |dev, r, raw| {
            dev.read(r, h, ReadReply::new(raw, size));
        });
    }
}

unsafe extern "C" fn write<D: Device>(
    req: fuse_req_t,
    data: *mut c_void,
    buf: *const c_char,
    size: size_t,
    fh: u64,
    flags: c_int,
) {
    // SAFETY: see comment above; libfuse keeps `buf` valid for the callback.
    unsafe {
        let d = dispatcher::<D>(data);
        let h = handle::<D>(fh);
        let input = bytes(buf.cast(), size);
        d.dispatch(req, flags, true, |dev, r, raw| {
            dev.write(r, h, input, WriteReply::new(raw, size));
        });
    }
}

unsafe extern "C" fn release<D: Device>(req: fuse_req_t, data: *mut c_void, fh: u64, flags: c_int) {
    // SAFETY: see comment above; `fh` is removed from the registry before we
    // take ownership, so shutdown can't free it a second time.
    unsafe {
        let d = dispatcher::<D>(data);
        let owned = d
            .handles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&fh);
        let slot = owned.then(|| Box::from_raw(fh as usize as *mut Slot<D::Handle>));
        d.dispatch(req, flags, false, |dev, r, raw| {
            if let Some(slot) = slot {
                dev.release(r, slot.handle);
            }
            raw.ack(); // the kernel ignores errors from release
        });
    }
}

#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn ioctl<D: Device>(
    req: fuse_req_t,
    data: *mut c_void,
    cmd: c_int,
    arg: *mut c_void,
    fh: u64,
    file_flags: c_int,
    flags: c_uint,
    in_buf: *const c_void,
    in_bufsz: size_t,
    out_bufsz: size_t,
) {
    // SAFETY: see comment above; libfuse keeps `in_buf` valid for the callback.
    unsafe {
        let d = dispatcher::<D>(data);
        let h = handle::<D>(fh);
        let call = Ioctl {
            cmd: cmd as u32,
            arg: arg as usize as u64,
            flags,
            input: bytes(in_buf, in_bufsz),
            out_size: out_bufsz,
        };
        d.dispatch(req, file_flags, true, |dev, r, raw| {
            dev.ioctl(r, h, call, IoctlReply::new(raw));
        });
    }
}

unsafe extern "C" fn poll<D: Device>(
    req: fuse_req_t,
    data: *mut c_void,
    fh: u64,
    file_flags: c_int,
    requested: c_uint,
    ph: *mut ffi::fuse_pollhandle,
) {
    // SAFETY: see comment above; ownership of `ph` passes to the notifier.
    unsafe {
        let d = dispatcher::<D>(data);
        let h = handle::<D>(fh);
        let notifier = (!ph.is_null()).then(|| PollNotifier::new(ph, d.live.clone()));
        d.dispatch(req, file_flags, false, |dev, r, raw| {
            dev.poll(
                r,
                h,
                PollEvents::from_bits_retain(requested),
                notifier,
                PollReply::new(raw),
            );
        });
    }
}
