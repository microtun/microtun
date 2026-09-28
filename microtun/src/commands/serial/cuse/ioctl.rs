//! ioctl support: request decoding, command-number construction, and
//! plain-old-data conversion.
//!
//! # Command numbers
//!
//! The `io`/`ior`/`iow`/`iowr` functions are `const` equivalents of the C
//! `_IO`/`_IOR`/`_IOW`/`_IOWR` macros, so commands can be used directly as
//! `match` patterns:
//!
//! ```
//! use crate::commands::serial::cuse::ioctl::{io, ior, iow};
//!
//! const GET_COUNT: u32 = ior::<u64>(b'X', 1);
//! const RESET: u32 = io(b'X', 2);
//! const SET_MODE: u32 = iow::<u32>(b'X', 3);
//!
//! # fn f(cmd: u32) {
//! match cmd {
//!     GET_COUNT => { /* ... */ }
//!     RESET => { /* ... */ }
//!     _ => { /* ENOTTY */ }
//! }
//! # }
//! ```
//!
//! # Restricted vs. unrestricted mode
//!
//! By default CUSE runs ioctls in *restricted* mode: the kernel decodes the
//! direction and size from the command number, copies `_IOC_SIZE(cmd)`
//! bytes from the caller into [`Ioctl::input`] for `_IOW`/`_IOWR` commands,
//! and copies up to [`Ioctl::out_size`] bytes of your reply back for
//! `_IOR`/`_IOWR` commands. This covers the vast majority of drivers.
//!
//! With [`Cuse::unrestricted_ioctl`](crate::commands::serial::cuse::Cuse::unrestricted_ioctl) the
//! kernel copies nothing on its own; you get the raw [`Ioctl::arg`] pointer
//! and use [`IoctlReply::retry`](crate::commands::serial::cuse::IoctlReply::retry) to tell the
//! kernel which user memory to fetch/store. That's needed for commands
//! whose argument contains nested pointers or has a size not encoded in the
//! number.

use std::mem::size_of;

use super::{Errno, ffi};

#[cfg(any(
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "mips",
    target_arch = "mips64",
    target_arch = "sparc",
    target_arch = "sparc64"
))]
mod arch {
    pub const SIZEBITS: u32 = 13;
    pub const DIRBITS: u32 = 3;
    pub const NONE: u32 = 1;
    pub const READ: u32 = 2;
    pub const WRITE: u32 = 4;
}

#[cfg(not(any(
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "mips",
    target_arch = "mips64",
    target_arch = "sparc",
    target_arch = "sparc64"
)))]
mod arch {
    pub const SIZEBITS: u32 = 14;
    pub const DIRBITS: u32 = 2;
    pub const NONE: u32 = 0;
    pub const READ: u32 = 2;
    pub const WRITE: u32 = 1;
}

const NRBITS: u32 = 8;
const TYPEBITS: u32 = 8;
const NRSHIFT: u32 = 0;
const TYPESHIFT: u32 = NRSHIFT + NRBITS;
const SIZESHIFT: u32 = TYPESHIFT + TYPEBITS;
const DIRSHIFT: u32 = SIZESHIFT + arch::SIZEBITS;

/// Equivalent of the C `_IOC(dir, type, nr, size)` macro.
///
/// # Panics
/// At compile time (in const context) if `size` doesn't fit the size field.
pub const fn ioc(dir: u32, ty: u8, nr: u8, size: usize) -> u32 {
    assert!(
        size < (1 << arch::SIZEBITS),
        "ioctl argument type too large"
    );
    (dir << DIRSHIFT)
        | ((size as u32) << SIZESHIFT)
        | ((ty as u32) << TYPESHIFT)
        | ((nr as u32) << NRSHIFT)
}

/// `_IO(type, nr)`: a command without an argument payload.
pub const fn io(ty: u8, nr: u8) -> u32 {
    ioc(arch::NONE, ty, nr, 0)
}

/// `_IOR(type, nr, T)`: the device writes a `T` back to the caller.
pub const fn ior<T>(ty: u8, nr: u8) -> u32 {
    ioc(arch::READ, ty, nr, size_of::<T>())
}

/// `_IOW(type, nr, T)`: the caller passes a `T` to the device.
pub const fn iow<T>(ty: u8, nr: u8) -> u32 {
    ioc(arch::WRITE, ty, nr, size_of::<T>())
}

/// `_IOWR(type, nr, T)`: a `T` goes in and a `T` comes back.
pub const fn iowr<T>(ty: u8, nr: u8) -> u32 {
    ioc(arch::READ | arch::WRITE, ty, nr, size_of::<T>())
}

/// Data-transfer direction encoded in a command number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Direction {
    /// Caller → device (`_IOW`, `_IOWR`).
    pub write: bool,
    /// Device → caller (`_IOR`, `_IOWR`).
    pub read: bool,
}

/// Decodes the direction bits of `cmd` (`_IOC_DIR`).
pub const fn dir(cmd: u32) -> Direction {
    let d = (cmd >> DIRSHIFT) & ((1 << arch::DIRBITS) - 1);
    Direction {
        write: d & arch::WRITE != 0,
        read: d & arch::READ != 0,
    }
}

/// `_IOC_TYPE(cmd)`.
pub const fn ty(cmd: u32) -> u8 {
    (cmd >> TYPESHIFT) as u8
}

/// `_IOC_NR(cmd)`.
pub const fn nr(cmd: u32) -> u8 {
    (cmd >> NRSHIFT) as u8
}

/// `_IOC_SIZE(cmd)`.
pub const fn size(cmd: u32) -> usize {
    ((cmd >> SIZESHIFT) & ((1 << arch::SIZEBITS) - 1)) as usize
}

/// An incoming ioctl call.
#[derive(Clone, Copy, Debug)]
pub struct Ioctl<'a> {
    pub(crate) cmd: u32,
    pub(crate) arg: u64,
    pub(crate) flags: u32,
    pub(crate) input: &'a [u8],
    pub(crate) out_size: usize,
}

impl<'a> Ioctl<'a> {
    /// The command number.
    pub fn cmd(&self) -> u32 {
        self.cmd
    }

    /// The raw third argument of `ioctl(2)`: either an integer value or an
    /// address in the *caller's* address space. Never dereference it; in
    /// unrestricted mode, ask the kernel for its contents with
    /// [`IoctlReply::retry`](crate::commands::serial::cuse::IoctlReply::retry).
    pub fn arg(&self) -> u64 {
        self.arg
    }

    /// Data copied in from the caller.
    pub fn input(&self) -> &'a [u8] {
        self.input
    }

    /// Maximum number of bytes that may be returned with
    /// [`IoctlReply::ok_with`](crate::commands::serial::cuse::IoctlReply::ok_with).
    pub fn out_size(&self) -> usize {
        self.out_size
    }

    /// Raw `FUSE_IOCTL_*` flags.
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// The call came from a 32-bit process through the compat path.
    pub fn is_compat(&self) -> bool {
        self.flags & ffi::FUSE_IOCTL_COMPAT != 0
    }

    /// The caller is a 32-bit process.
    pub fn is_32bit(&self) -> bool {
        self.flags & ffi::FUSE_IOCTL_32BIT != 0
    }

    /// The device was set up with unrestricted ioctls.
    pub fn is_unrestricted(&self) -> bool {
        self.flags & ffi::FUSE_IOCTL_UNRESTRICTED != 0
    }

    /// Decodes the input as a `T`. Fails with `EINVAL` if too little input
    /// was supplied.
    pub fn input_as<T: Plain>(&self) -> Result<T, Errno> {
        from_bytes(self.input).ok_or(Errno::EINVAL)
    }
}

/// A region of the *caller's* memory, for
/// [`IoctlReply::retry`](crate::commands::serial::cuse::IoctlReply::retry).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserBuf {
    /// Address in the caller's address space.
    pub addr: u64,
    /// Length in bytes.
    pub len: usize,
}

impl UserBuf {
    /// A region of `len` bytes at `addr`.
    pub fn new(addr: u64, len: usize) -> Self {
        UserBuf { addr, len }
    }

    /// A region holding one `T` at `addr`.
    pub fn of<T>(addr: u64) -> Self {
        UserBuf {
            addr,
            len: size_of::<T>(),
        }
    }

    pub(crate) fn to_iovec(self) -> libc::iovec {
        libc::iovec {
            iov_base: self.addr as usize as *mut libc::c_void,
            iov_len: self.len,
        }
    }
}

/// Types that can be safely reinterpreted to and from raw bytes.
///
/// # Safety
///
/// Implementors must be `#[repr(C)]` (or `#[repr(transparent)]` / a
/// primitive), contain **no padding bytes**, and be valid for **every**
/// possible bit pattern. Structs of integers laid out without gaps
/// typically qualify; anything with `bool`, `char`, enums, references or
/// pointers does not.
///
/// ```
/// #[repr(C)]
/// #[derive(Clone, Copy)]
/// struct Geometry { width: u32, height: u32 }
/// unsafe impl crate::commands::serial::cuse::ioctl::Plain for Geometry {}
/// ```
pub unsafe trait Plain: Copy + 'static {}

macro_rules! plain {
    ($($t:ty),*) => { $(unsafe impl Plain for $t {})* };
}
plain!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, f32, f64
);
unsafe impl<T: Plain, const N: usize> Plain for [T; N] {}

/// Views a value as its raw bytes.
pub fn bytes_of<T: Plain>(value: &T) -> &[u8] {
    // SAFETY: `T: Plain` guarantees there are no (uninitialized) padding bytes.
    unsafe { std::slice::from_raw_parts(value as *const T as *const u8, size_of::<T>()) }
}

/// Reads a `T` from the start of `bytes` (unaligned). `None` if too short.
pub fn from_bytes<T: Plain>(bytes: &[u8]) -> Option<T> {
    if bytes.len() < size_of::<T>() {
        return None;
    }
    // SAFETY: length checked above; `T: Plain` means any bit pattern is valid.
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const T) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_linux_encoding() {
        // Values checked against the C macros on x86_64.
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            assert_eq!(io(b'T', 1), 0x5401);
            assert_eq!(ior::<u32>(b'E', 1), 0x8004_4501);
            assert_eq!(iow::<u64>(b'E', 2), 0x4008_4502);
            assert_eq!(iowr::<[u8; 16]>(b'E', 3), 0xC010_4503);
        }
        let c = iowr::<u32>(b'Z', 42);
        assert_eq!((ty(c), nr(c), size(c)), (b'Z', 42, 4));
        assert_eq!(
            dir(c),
            Direction {
                read: true,
                write: true
            }
        );
        assert_eq!(
            dir(io(b'Z', 1)),
            Direction {
                read: false,
                write: false
            }
        );
    }

    #[test]
    fn plain_roundtrip() {
        let v: u64 = 0x0102_0304_0506_0708;
        assert_eq!(from_bytes::<u64>(bytes_of(&v)), Some(v));
        assert_eq!(from_bytes::<u64>(&[1, 2, 3]), None);
    }
}
