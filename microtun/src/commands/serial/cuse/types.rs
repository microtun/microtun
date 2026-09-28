use std::{fmt, io};

use super::ffi;

/// A Linux error number, as returned to the process that made the syscall.
///
/// ```
/// use crate::commands::serial::cuse::Errno;
/// let e: Errno = std::io::Error::from(std::io::ErrorKind::NotFound).into();
/// assert_eq!(Errno::EAGAIN.raw(), libc::EAGAIN);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Errno(i32);

macro_rules! errnos {
    ($($name:ident),* $(,)?) => {
        impl Errno {
            $(
                #[doc = concat!("`", stringify!($name), "`")]
                pub const $name: Errno = Errno(libc::$name);
            )*
        }
    };
}

errnos!(
    EPERM, ENOENT, EINTR, EIO, ENXIO, E2BIG, EBADF, EAGAIN, ENOMEM, EACCES, EFAULT, EBUSY, EEXIST,
    ENODEV, EINVAL, ENFILE, EMFILE, ENOTTY, EFBIG, ENOSPC, ESPIPE, EROFS, EPIPE, ERANGE, ENOSYS,
    ENODATA, ETIME, EPROTO, EOVERFLOW, EBADMSG, ENOTSUP, ENOTCONN, ETIMEDOUT, ECANCELED,
);

impl Errno {
    /// `EWOULDBLOCK` (same value as `EAGAIN` on Linux).
    pub const EWOULDBLOCK: Errno = Errno::EAGAIN;

    /// Wraps a raw, positive errno value.
    pub const fn from_raw(errno: i32) -> Self {
        Errno(errno)
    }

    /// The raw, positive errno value.
    pub const fn raw(self) -> i32 {
        self.0
    }

    /// Converts libfuse's `0 / -errno` convention into a `Result`.
    pub(crate) fn check(rc: libc::c_int) -> Result<(), Errno> {
        if rc == 0 {
            Ok(())
        } else {
            Err(Errno(rc.saturating_abs()))
        }
    }
}

impl fmt::Debug for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Errno({}: {})",
            self.0,
            io::Error::from_raw_os_error(self.0)
        )
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&io::Error::from_raw_os_error(self.0), f)
    }
}

impl std::error::Error for Errno {}

impl From<io::Error> for Errno {
    fn from(e: io::Error) -> Self {
        Errno(e.raw_os_error().unwrap_or(libc::EIO))
    }
}

impl From<io::ErrorKind> for Errno {
    fn from(kind: io::ErrorKind) -> Self {
        io::Error::from(kind).into()
    }
}

impl From<Errno> for io::Error {
    fn from(e: Errno) -> Self {
        io::Error::from_raw_os_error(e.0)
    }
}

/// Identifies one in-flight request. Used to match
/// [`Device::interrupt`](crate::commands::serial::cuse::Device::interrupt) notifications against
/// replies you have parked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestId(pub(crate) u64);

/// Information about the process that issued a request.
#[derive(Clone, Debug)]
pub struct Request {
    pub(crate) id: RequestId,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) pid: i32,
    pub(crate) flags: OpenFlags,
}

impl Request {
    /// # Safety
    /// `req` must be a live, not yet answered request.
    pub(crate) unsafe fn from_raw(req: ffi::fuse_req_t, id: RequestId, flags: i32) -> Self {
        let (mut uid, mut gid, mut pid) = (0, 0, 0);
        // SAFETY: caller guarantees `req` is live; the out-pointers are valid locals.
        unsafe { ffi::cuse_shim_req_ctx(req, &mut uid, &mut gid, &mut pid) };
        Request {
            id,
            uid,
            gid,
            pid,
            flags: OpenFlags(flags),
        }
    }

    /// The id of this request (the same as the reply's `id()`).
    pub fn id(&self) -> RequestId {
        self.id
    }

    /// User id of the calling process.
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// Group id of the calling process.
    pub fn gid(&self) -> u32 {
        self.gid
    }

    /// Thread id of the calling process (as seen from the device's pid
    /// namespace; 0 if it isn't visible).
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// The file's status flags at the time of the request.
    ///
    /// Available for `open`, `read`, `write`, `ioctl`, `poll` and `release`. Because
    /// these are sent with every operation, changes made with
    /// `fcntl(F_SETFL, O_NONBLOCK)` after `open` are visible here.
    pub fn flags(&self) -> OpenFlags {
        self.flags
    }
}

/// File status flags (`O_*`) of an open file.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpenFlags(pub(crate) i32);

impl OpenFlags {
    /// Raw flag bits.
    pub fn bits(self) -> i32 {
        self.0
    }

    /// Whether the file was opened for reading (`O_RDONLY` or `O_RDWR`).
    pub fn readable(self) -> bool {
        matches!(self.0 & libc::O_ACCMODE, libc::O_RDONLY | libc::O_RDWR)
    }

    /// Whether the file was opened for writing (`O_WRONLY` or `O_RDWR`).
    pub fn writable(self) -> bool {
        matches!(self.0 & libc::O_ACCMODE, libc::O_WRONLY | libc::O_RDWR)
    }

    /// `O_NONBLOCK`: the caller wants `EAGAIN` instead of blocking.
    pub fn is_nonblocking(self) -> bool {
        self.contains(libc::O_NONBLOCK)
    }

    /// Whether all bits of `flag` (e.g. `libc::O_SYNC`) are set.
    pub fn contains(self, flag: i32) -> bool {
        self.0 & flag == flag
    }
}

impl fmt::Debug for OpenFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let access = match self.0 & libc::O_ACCMODE {
            libc::O_RDONLY => "O_RDONLY",
            libc::O_WRONLY => "O_WRONLY",
            _ => "O_RDWR",
        };
        write!(f, "OpenFlags({access}")?;
        if self.is_nonblocking() {
            f.write_str(" | O_NONBLOCK")?;
        }
        write!(f, ", {:#o})", self.0)
    }
}

bitflags::bitflags! {
    /// Readiness events for [`Device::poll`](crate::commands::serial::cuse::Device::poll).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct PollEvents: u32 {
        const IN = libc::POLLIN as u32;
        const PRI = libc::POLLPRI as u32;
        const OUT = libc::POLLOUT as u32;
        const ERR = libc::POLLERR as u32;
        const HUP = libc::POLLHUP as u32;
        const RDNORM = libc::POLLRDNORM as u32;
        const RDBAND = libc::POLLRDBAND as u32;
        const WRNORM = libc::POLLWRNORM as u32;
        const WRBAND = libc::POLLWRBAND as u32;
        const RDHUP = libc::POLLRDHUP as u32;
    }
}

/// Outcome of sending a reply to the kernel.
///
/// Deliberately *not* `#[must_use]`: most of the time you don't care. It
/// matters when a reply carries data you'd otherwise lose — if the calling
/// process was killed or interrupted in the meantime, the kernel rejects the
/// reply (typically with `ENOENT`) and you can keep the data for the next
/// reader:
///
/// ```ignore
/// if reply.data(&chunk).is_delivered() {
///     buffer.drain(..chunk.len());
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delivery(pub(crate) Result<(), Errno>);

impl Delivery {
    /// `true` if the kernel accepted the reply.
    pub fn is_delivered(self) -> bool {
        self.0.is_ok()
    }

    /// The underlying result. `Err(ENOTCONN)` means the session had already
    /// shut down.
    pub fn into_result(self) -> Result<(), Errno> {
        self.0
    }
}
