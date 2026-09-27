#![allow(dead_code)]

//! Write Linux character devices in safe Rust, served from userspace via
//! CUSE ("Character device in Userspace") and libfuse3.
//!
//! Implement [`Device`], then hand it to [`Cuse::run`]:
//!
//! ```no_run
//! use crate::cuse::{Cuse, Device, OpenReply, ReadReply, Request, WriteReply};
//!
//! /// `/dev/hello`: reads return a greeting, writes are swallowed.
//! struct Hello;
//!
//! impl Device for Hello {
//!     type Handle = ();
//!
//!     fn open(&mut self, _req: &Request, reply: OpenReply<()>) {
//!         reply.ok(());
//!     }
//!
//!     fn read(&mut self, _req: &Request, _h: &mut (), reply: ReadReply) {
//!         reply.data(b"hello from userspace\n");
//!     }
//!
//!     fn write(&mut self, _req: &Request, _h: &mut (), _data: &[u8], reply: WriteReply) {
//!         reply.all();
//!     }
//! }
//!
//! fn main() -> std::io::Result<()> {
//!     Cuse::new("hello").run(Hello)
//! }
//! ```
//!
//! # Design
//!
//! * **Per-open state.** [`Device::Handle`] is your state for one open
//!   file. You create it in `open`, get `&mut` access to it in every other
//!   operation, and receive it back by value in `release`. No integer file
//!   handles, no casts.
//! * **Replies are values.** Each operation gets a reply object that is
//!   `Send + 'static`. Answer immediately, or *park* it and answer later —
//!   that's how you implement blocking reads without blocking the device.
//!   Dropping a reply unanswered sends `EIO`, so callers never hang.
//! * **Interrupts.** When a caller blocked on your device gets a signal,
//!   [`Device::interrupt`] tells you which parked reply to cancel.
//! * **poll/select/epoll** via [`PollNotifier`].
//! * **ioctl** with const command-number helpers and typed input/output;
//!   see the [`ioctl`] module.
//!
//! # Threading
//!
//! All `Device` methods run one at a time. [`Cuse::run`] uses the calling
//! thread; [`Cuse::start`] uses a dedicated thread and therefore requires
//! the device and its per-open handles to be `Send`. For work that shouldn't
//! block other callers, move the reply to a worker thread and answer from
//! there.
//!
//! # Kernel semantics worth knowing
//!
//! * CUSE devices are always unbuffered and unseekable: offsets are always
//!   zero and are therefore not exposed.
//! * The kernel's CUSE frontend supports `open`, `read`, `write`, `ioctl`,
//!   `poll` and `release` only; there is no `mmap`, `fsync` or `flush`.
//! * Creating the device requires access to `/dev/cuse` (normally root)
//!   and the `cuse` kernel module (`modprobe cuse`).

mod dispatch;
mod ffi;
pub mod ioctl;
mod reply;
mod types;

use std::{
    ffi::CString,
    io,
    os::unix::thread::JoinHandleExt,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    sync::PoisonError,
    thread::{self, JoinHandle},
};

use dispatch::Dispatcher;
pub use ioctl::{Ioctl, UserBuf};
pub use reply::{IoctlReply, OpenReply, PollNotifier, PollReply, ReadReply, WriteReply};
use reply::{Liveness, Slot};
pub use types::{Delivery, Errno, PollEvents, Request, RequestId};

/// A character device implemented in userspace.
///
/// Only [`open`](Device::open) is required. The defaults of the other
/// methods behave like a kernel driver that doesn't implement them.
#[allow(unused_variables)]
pub trait Device {
    /// State kept for each open file description.
    ///
    /// Use `()` if you don't need any. If you want to answer `open` from
    /// another thread, this must be `Send`.
    type Handle;

    /// Called when a process opens the device. Answer with
    /// `reply.ok(handle)` or `reply.error(errno)`. The requested access mode
    /// and `O_NONBLOCK` are available through [`Request::flags`].
    fn open(&mut self, req: &Request, reply: OpenReply<Self::Handle>);

    /// Called for `read(2)`. Reply with at most [`ReadReply::size`] bytes.
    ///
    /// To block until data is available, store `reply` and answer it later;
    /// check `req.flags().is_nonblocking()` first and fail with
    /// [`Errno::EAGAIN`] instead if set.
    ///
    /// Default: `EINVAL`, like a kernel driver without a read method.
    fn read(&mut self, req: &Request, handle: &mut Self::Handle, reply: ReadReply) {
        reply.error(Errno::EINVAL);
    }

    /// Called for `write(2)`. `data` is only borrowed for the duration of
    /// the call; copy what you need if you defer the reply.
    ///
    /// Default: `EINVAL`.
    fn write(&mut self, req: &Request, handle: &mut Self::Handle, data: &[u8], reply: WriteReply) {
        reply.error(Errno::EINVAL);
    }

    /// Called for `ioctl(2)`. See the [`ioctl`] module.
    ///
    /// Default: `ENOTTY` ("inappropriate ioctl for device"), which is the
    /// conventional answer for unknown commands.
    fn ioctl(
        &mut self,
        req: &Request,
        handle: &mut Self::Handle,
        ioctl: Ioctl<'_>,
        reply: IoctlReply,
    ) {
        reply.error(Errno::ENOTTY);
    }

    /// Called for `poll(2)`/`select(2)`/`epoll`. Report current readiness
    /// with `reply.ready(..)`. `requested` contains the events the caller is
    /// interested in. If `notifier` is `Some`, keep it when a requested event
    /// is not currently ready and call [`PollNotifier::notify`] when readiness
    /// changes.
    ///
    /// Default: `ENOSYS`, which makes the kernel stop asking and treat the
    /// device as always readable and writable.
    fn poll(
        &mut self,
        req: &Request,
        handle: &mut Self::Handle,
        requested: PollEvents,
        notifier: Option<PollNotifier>,
        reply: PollReply,
    ) {
        reply.error(Errno::ENOSYS);
    }

    /// Called when the last file descriptor referring to an open file is
    /// closed. The handle is yours again; by default it's simply dropped.
    fn release(&mut self, req: &Request, handle: Self::Handle) {}

    /// The caller of request `id` received a signal. If you've parked the
    /// reply for that request, answer it now (usually with
    /// [`Errno::EINTR`]). Ids of requests you've already answered can show
    /// up here; ignore them.
    fn interrupt(&mut self, id: RequestId) {}

    /// Called once the device node has been registered with the kernel —
    /// a good place to adjust its permissions, e.g. with
    /// `std::fs::set_permissions("/dev/NAME", ...)`.
    fn ready(&mut self) {}
}

/// Configuration for a CUSE device; start here.
#[derive(Clone, Debug)]
pub struct Cuse {
    name: String,
    major: u32,
    minor: u32,
    unrestricted_ioctl: bool,
    debug: bool,
}

impl Cuse {
    /// A device that will appear as `/dev/<name>`.
    pub fn new(name: impl Into<String>) -> Self {
        Cuse {
            name: name.into(),
            major: 0,
            minor: 0,
            unrestricted_ioctl: false,
            debug: false,
        }
    }

    /// Requests a specific major number. The default (0) lets the kernel
    /// pick one.
    pub fn major(mut self, major: u32) -> Self {
        self.major = major;
        self
    }

    /// Requests a specific minor number. The default is 0.
    pub fn minor(mut self, minor: u32) -> Self {
        self.minor = minor;
        self
    }

    /// Use unrestricted ioctl mode; see the [`ioctl`] module.
    pub fn unrestricted_ioctl(mut self, enabled: bool) -> Self {
        self.unrestricted_ioctl = enabled;
        self
    }

    /// Let libfuse log every request to stderr.
    pub fn debug(mut self, enabled: bool) -> Self {
        self.debug = enabled;
        self
    }

    /// Creates the device and serves requests on the current thread until
    /// the process receives `SIGINT`, `SIGTERM` or `SIGHUP`.
    ///
    /// libfuse installs handlers for those signals, but only where the
    /// disposition is still the default, so handlers you install beforehand
    /// take precedence. Because a signal only interrupts the thread it's
    /// delivered to, prefer calling this from the main thread (or block
    /// these signals in your other threads).
    ///
    /// On shutdown, the device is dropped first (so parked replies are
    /// answered with `EIO`), then the handles of files that are still open
    /// are dropped, then the device node disappears. Replies still held by
    /// other threads become no-ops.
    pub fn run<D: Device>(self, device: D) -> io::Result<()> {
        if self.name.is_empty() || self.name.contains('/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "device name must be non-empty and must not contain '/'",
            ));
        }
        let invalid = |_| io::Error::new(io::ErrorKind::InvalidInput, "name contains a NUL byte");
        let dev_info = CString::new(format!("DEVNAME={}", self.name)).map_err(invalid)?;

        let mut args = vec![
            CString::new(self.name.clone()).map_err(invalid)?,
            cstr("-f"),
        ];
        if self.debug {
            args.push(cstr("-d"));
        }
        let mut argv: Vec<*mut libc::c_char> = args.iter().map(|a| a.as_ptr() as *mut _).collect();
        let argc = argv.len() as libc::c_int;
        argv.push(std::ptr::null_mut());

        let live = Liveness::new();
        let ops = Box::new(Dispatcher::<D>::ops());
        let dispatcher = Box::new(Dispatcher::new(device, live.clone()));
        let userdata = Box::new(ffi::ShimUserdata {
            ops: &*ops,
            data: &*dispatcher as *const Dispatcher<D> as *mut libc::c_void,
        });

        let se = unsafe {
            ffi::cuse_shim_setup(
                argc,
                argv.as_mut_ptr(),
                self.major,
                self.minor,
                dev_info.as_ptr(),
                self.unrestricted_ioctl as libc::c_int,
                &*userdata as *const ffi::ShimUserdata as *mut libc::c_void,
            )
        };
        if se.is_null() {
            return Err(io::Error::other(
                "CUSE setup failed (see stderr); is the `cuse` module loaded and \
                 /dev/cuse accessible (usually requires root)?",
            ));
        }

        let rc = unsafe { ffi::fuse_session_loop(se) };

        // Orderly shutdown. The loop has returned, so libfuse will not call
        // back into the dispatcher any more.
        let Dispatcher {
            device, handles, ..
        } = *dispatcher;
        let panic = catch_unwind(AssertUnwindSafe(|| drop(device.into_inner()))).err();
        live.kill();
        let leftover: Vec<u64> = handles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain()
            .collect();
        for fh in leftover {
            drop(unsafe { Box::from_raw(fh as usize as *mut Slot<D::Handle>) });
        }
        unsafe { ffi::cuse_lowlevel_teardown(se) };
        drop((userdata, ops));

        if let Some(p) = panic {
            resume_unwind(p);
        }
        // Negative: -errno. Positive: the signal that ended the loop.
        if rc < 0 {
            Err(io::Error::from_raw_os_error(-rc))
        } else {
            Ok(())
        }
    }

    /// Creates the device and serves it on a dedicated thread.
    ///
    /// This is useful when the device is one part of a larger event loop.
    /// Dropping the returned handle requests shutdown and joins the CUSE
    /// thread. [`RunningCuse::stop`] may be used to request shutdown earlier.
    pub fn start<D>(self, device: D) -> io::Result<RunningCuse<D>>
    where
        D: Device + Send + 'static,
        D::Handle: Send + 'static,
    {
        if self.name.is_empty() || self.name.contains('/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "device name must be non-empty and must not contain '/'",
            ));
        }
        let invalid = |_| io::Error::new(io::ErrorKind::InvalidInput, "name contains a NUL byte");
        let dev_info = CString::new(format!("DEVNAME={}", self.name)).map_err(invalid)?;
        let mut args = vec![
            CString::new(self.name.clone()).map_err(invalid)?,
            cstr("-f"),
        ];
        if self.debug {
            args.push(cstr("-d"));
        }
        let mut argv: Vec<*mut libc::c_char> = args.iter().map(|a| a.as_ptr() as *mut _).collect();
        let argc = argv.len() as libc::c_int;
        argv.push(std::ptr::null_mut());

        let live = Liveness::new();
        let ops = Box::new(Dispatcher::<D>::ops());
        let dispatcher = Box::new(Dispatcher::new(device, live.clone()));
        let userdata = Box::new(ffi::ShimUserdata {
            ops: &*ops,
            data: &*dispatcher as *const Dispatcher<D> as *mut libc::c_void,
        });
        // The legacy single-threaded libfuse loop can block in read(2) after
        // fuse_session_exit().  Install a temporary, non-restarting SIGPIPE
        // handler so stop() can wake that exact thread without affecting the
        // application's SIGINT/SIGTERM/SIGHUP handling.  Rust normally ignores
        // SIGPIPE, so relying on libfuse's SIGPIPE handler alone is not enough.
        let wake_signal_acquired = unsafe { ffi::cuse_shim_acquire_wakeup_signal() };
        if wake_signal_acquired == 0 {
            return Err(io::Error::other(
                "CUSE background mode cannot safely install its wake signal because SIGPIPE has a custom handler",
            ));
        }

        let se = unsafe {
            ffi::cuse_shim_setup(
                argc,
                argv.as_mut_ptr(),
                self.major,
                self.minor,
                dev_info.as_ptr(),
                self.unrestricted_ioctl as libc::c_int,
                &*userdata as *const ffi::ShimUserdata as *mut libc::c_void,
            )
        };
        if se.is_null() {
            unsafe { ffi::cuse_shim_release_wakeup_signal() };
            return Err(io::Error::other(
                "CUSE setup failed (see stderr); is the `cuse` module loaded and /dev/cuse accessible (usually requires root)?",
            ));
        }

        let session = SessionPtr(se);
        let loop_session = session;
        let thread = thread::Builder::new()
            .name(format!("cuse-{}", self.name))
            .spawn(move || loop_session.run_loop())
            .inspect_err(|_| unsafe {
                ffi::cuse_lowlevel_teardown(se);
                ffi::cuse_shim_release_wakeup_signal();
            })?;

        Ok(RunningCuse {
            session,
            live,
            ops: Some(ops),
            dispatcher: Some(dispatcher),
            userdata: Some(userdata),
            thread: Some(thread),
        })
    }
}

#[derive(Clone, Copy)]
struct SessionPtr(*mut ffi::fuse_session);

// SAFETY: ownership of the session stays with RunningCuse. The loop thread
// only serves it, while other threads may request exit; teardown happens only
// after the loop thread has been joined.
unsafe impl Send for SessionPtr {}
unsafe impl Sync for SessionPtr {}

impl SessionPtr {
    fn run_loop(self) -> libc::c_int {
        unsafe { ffi::fuse_session_loop(self.0) }
    }

    fn request_exit(self) {
        unsafe { ffi::fuse_session_exit(self.0) };
    }
}

/// A CUSE service running on a dedicated thread.
pub struct RunningCuse<D: Device> {
    session: SessionPtr,
    live: std::sync::Arc<Liveness>,
    ops: Option<Box<ffi::ShimOps>>,
    dispatcher: Option<Box<Dispatcher<D>>>,
    userdata: Option<Box<ffi::ShimUserdata>>,
    thread: Option<JoinHandle<libc::c_int>>,
}

impl<D: Device> RunningCuse<D> {
    /// Requests that the CUSE event loop exit. It is safe to call more than once.
    pub fn stop(&self) {
        self.session.request_exit();

        // fuse_session_loop() from the older libfuse ABI used by this crate
        // does not wake merely because the exit flag changed. Interrupt its
        // blocking read with the non-restarting SIGPIPE handler acquired by
        // Cuse::start(). This signal is directed only at the loop thread.
        if let Some(thread) = self.thread.as_ref()
            && !thread.is_finished() {
                unsafe {
                    let _ = libc::pthread_kill(thread.as_pthread_t(), libc::SIGPIPE);
                }
            }
    }

    fn finish(&mut self) -> io::Result<()> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        let loop_result = thread
            .join()
            .map_err(|_| io::Error::other("CUSE event-loop thread panicked"));

        let dispatcher = self
            .dispatcher
            .take()
            .expect("dispatcher present while thread runs");
        let Dispatcher {
            device, handles, ..
        } = *dispatcher;
        let panic = catch_unwind(AssertUnwindSafe(|| drop(device.into_inner()))).err();
        self.live.kill();
        let leftover: Vec<u64> = handles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain()
            .collect();
        for fh in leftover {
            drop(unsafe { Box::from_raw(fh as usize as *mut Slot<D::Handle>) });
        }
        unsafe {
            ffi::cuse_lowlevel_teardown(self.session.0);
            ffi::cuse_shim_release_wakeup_signal();
        }
        drop(self.userdata.take());
        drop(self.ops.take());

        if let Some(p) = panic {
            resume_unwind(p);
        }
        let rc = loop_result?;
        if rc < 0 {
            Err(io::Error::from_raw_os_error(-rc))
        } else {
            Ok(())
        }
    }

    /// Requests shutdown and waits for the service thread to finish.
    pub fn shutdown(mut self) -> io::Result<()> {
        self.stop();
        self.finish()
    }
}

impl<D: Device> Drop for RunningCuse<D> {
    fn drop(&mut self) {
        if self.thread.is_some() {
            self.stop();
            let _ = self.finish();
        }
    }
}

fn cstr(s: &str) -> CString {
    CString::new(s).expect("static string without NUL")
}
