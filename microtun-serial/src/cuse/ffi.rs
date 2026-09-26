//! Raw FFI surface. Private to the crate.
//!
//! Only *function signatures* of libfuse are declared here; no libfuse
//! struct layouts are mirrored. Everything layout-sensitive goes through
//! `csrc/shim.c`.

#![allow(non_camel_case_types)]

use libc::{c_char, c_int, c_uint, c_void, iovec, size_t};

/// Opaque `struct fuse_req`.
pub enum fuse_req {}
/// Opaque `struct fuse_session`.
pub enum fuse_session {}
/// Opaque `struct fuse_pollhandle`.
pub enum fuse_pollhandle {}

pub type fuse_req_t = *mut fuse_req;
pub type InterruptFn = unsafe extern "C" fn(req: fuse_req_t, data: *mut c_void);

/// Must match `struct cuse_shim_ops` in `csrc/shim.c`.
#[repr(C)]
pub struct ShimOps {
    pub init_done: unsafe extern "C" fn(data: *mut c_void),
    pub open: unsafe extern "C" fn(req: fuse_req_t, data: *mut c_void, flags: c_int),
    pub read: unsafe extern "C" fn(
        req: fuse_req_t,
        data: *mut c_void,
        size: size_t,
        fh: u64,
        flags: c_int,
    ),
    pub write: unsafe extern "C" fn(
        req: fuse_req_t,
        data: *mut c_void,
        buf: *const c_char,
        size: size_t,
        fh: u64,
        flags: c_int,
    ),
    pub release: unsafe extern "C" fn(req: fuse_req_t, data: *mut c_void, fh: u64, flags: c_int),
    pub ioctl: unsafe extern "C" fn(
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
    ),
    pub poll: unsafe extern "C" fn(
        req: fuse_req_t,
        data: *mut c_void,
        fh: u64,
        file_flags: c_int,
        requested: c_uint,
        ph: *mut fuse_pollhandle,
    ),
}

/// Must match `struct cuse_shim_userdata` in `csrc/shim.c`.
#[repr(C)]
pub struct ShimUserdata {
    pub ops: *const ShimOps,
    pub data: *mut c_void,
}

// ioctl flags passed by the kernel (include/uapi/linux/fuse.h).
pub const FUSE_IOCTL_COMPAT: u32 = 1 << 0;
pub const FUSE_IOCTL_UNRESTRICTED: u32 = 1 << 1;
pub const FUSE_IOCTL_32BIT: u32 = 1 << 3;

unsafe extern "C" {
    // --- csrc/shim.c ---
    pub fn cuse_shim_setup(
        argc: c_int,
        argv: *mut *mut c_char,
        major: c_uint,
        minor: c_uint,
        dev_info: *const c_char,
        unrestricted_ioctl: c_int,
        userdata: *mut c_void,
    ) -> *mut fuse_session;
    pub fn cuse_shim_reply_open(req: fuse_req_t, fh: u64) -> c_int;
    pub fn cuse_shim_req_ctx(req: fuse_req_t, uid: *mut u32, gid: *mut u32, pid: *mut i32);
    pub fn cuse_shim_acquire_wakeup_signal() -> c_int;
    pub fn cuse_shim_release_wakeup_signal();

    // --- libfuse3 ---
    pub fn cuse_lowlevel_teardown(se: *mut fuse_session);
    pub fn fuse_session_loop(se: *mut fuse_session) -> c_int;
    pub fn fuse_session_exit(se: *mut fuse_session);

    pub fn fuse_req_userdata(req: fuse_req_t) -> *mut c_void;
    pub fn fuse_req_interrupt_func(req: fuse_req_t, func: Option<InterruptFn>, data: *mut c_void);
    pub fn fuse_req_interrupted(req: fuse_req_t) -> c_int;

    pub fn fuse_reply_err(req: fuse_req_t, err: c_int) -> c_int;
    pub fn fuse_reply_buf(req: fuse_req_t, buf: *const c_char, size: size_t) -> c_int;
    pub fn fuse_reply_write(req: fuse_req_t, count: size_t) -> c_int;
    pub fn fuse_reply_ioctl(
        req: fuse_req_t,
        result: c_int,
        buf: *const c_void,
        size: size_t,
    ) -> c_int;
    pub fn fuse_reply_ioctl_retry(
        req: fuse_req_t,
        in_iov: *const iovec,
        in_count: size_t,
        out_iov: *const iovec,
        out_count: size_t,
    ) -> c_int;
    pub fn fuse_reply_poll(req: fuse_req_t, revents: c_uint) -> c_int;

    pub fn fuse_lowlevel_notify_poll(ph: *mut fuse_pollhandle) -> c_int;
    pub fn fuse_pollhandle_destroy(ph: *mut fuse_pollhandle);
}
