/*
 * Thin C shim between libfuse3's CUSE API and the Rust crate.
 *
 * Why this exists: struct fuse_file_info, struct cuse_info and
 * struct fuse_ctx are either full of bitfields or have changed across
 * libfuse 3.x releases. Rather than mirroring them by hand in Rust (and
 * silently breaking on the next libfuse update), we let the C compiler read
 * the real, installed headers and hand Rust only plain integers.
 *
 * The CUSE callbacks are forwarded to a table of Rust function pointers
 * (struct cuse_shim_ops). The Rust side monomorphizes one table per device
 * type, so there are no global #[no_mangle] symbols involved.
 */
#define FUSE_USE_VERSION 31

#include <cuse_lowlevel.h>
#include <fuse_lowlevel.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>

/* Must match `ShimOps` in ffi.rs exactly. */
struct cuse_shim_ops {
	void (*init_done)(void *data);
	void (*open)(fuse_req_t req, void *data, int flags);
	void (*read)(fuse_req_t req, void *data, size_t size, uint64_t fh,
		     int flags);
	void (*write)(fuse_req_t req, void *data, const char *buf, size_t size,
		      uint64_t fh, int flags);
	void (*release)(fuse_req_t req, void *data, uint64_t fh, int flags);
	void (*ioctl)(fuse_req_t req, void *data, int cmd, void *arg,
		      uint64_t fh, int file_flags, unsigned int flags, const void *in_buf,
		      size_t in_bufsz, size_t out_bufsz);
	void (*poll)(fuse_req_t req, void *data, uint64_t fh, int file_flags,
		     unsigned int requested, struct fuse_pollhandle *ph);
};

/* Must match `ShimUserdata` in ffi.rs exactly. */
struct cuse_shim_userdata {
	const struct cuse_shim_ops *ops;
	void *data;
};

/*
 * fuse_session_exit() only changes a flag in the legacy single-threaded
 * libfuse loop. If the loop is blocked in read(2), it must also be interrupted
 * before it can observe that flag. libfuse suggests SIGPIPE for this purpose,
 * but Rust programs normally start with SIGPIPE ignored; an ignored signal does
 * not interrupt read(2).
 *
 * For Cuse::start(), temporarily replace only the default/ignored SIGPIPE
 * disposition with a no-op handler without SA_RESTART. A small refcount makes
 * this safe for multiple background CUSE services in one process. If the
 * application owns SIGPIPE with a custom handler, leave it untouched and let
 * Rust report that background mode cannot guarantee a wakeable shutdown.
 */
static pthread_mutex_t wake_signal_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned int wake_signal_users;
static struct sigaction saved_sigpipe_action;

static void wake_signal_handler(int signo)
{
	(void)signo;
}

int cuse_shim_acquire_wakeup_signal(void)
{
	struct sigaction current;
	struct sigaction action;
	int ok = 0;

	if (pthread_mutex_lock(&wake_signal_lock) != 0)
		return 0;

	if (wake_signal_users != 0) {
		wake_signal_users++;
		ok = 1;
		goto out;
	}

	if (sigaction(SIGPIPE, NULL, &current) == -1)
		goto out;
	if (current.sa_handler != SIG_DFL && current.sa_handler != SIG_IGN)
		goto out;

	memset(&action, 0, sizeof(action));
	action.sa_handler = wake_signal_handler;
	sigemptyset(&action.sa_mask);
	/* Deliberately omit SA_RESTART: the signal must interrupt read(2). */
	if (sigaction(SIGPIPE, &action, &saved_sigpipe_action) == -1)
		goto out;

	wake_signal_users = 1;
	ok = 1;

out:
	pthread_mutex_unlock(&wake_signal_lock);
	return ok;
}

void cuse_shim_release_wakeup_signal(void)
{
	struct sigaction current;

	if (pthread_mutex_lock(&wake_signal_lock) != 0)
		return;
	if (wake_signal_users == 0)
		goto out;

	wake_signal_users--;
	if (wake_signal_users != 0)
		goto out;

	/* Do not overwrite a signal disposition the application changed later. */
	if (sigaction(SIGPIPE, NULL, &current) == 0 &&
	    current.sa_handler == wake_signal_handler)
		sigaction(SIGPIPE, &saved_sigpipe_action, NULL);

out:
	pthread_mutex_unlock(&wake_signal_lock);
}

static struct cuse_shim_userdata *ud_of(fuse_req_t req)
{
	return (struct cuse_shim_userdata *)fuse_req_userdata(req);
}

static void shim_init_done(void *userdata)
{
	struct cuse_shim_userdata *ud = userdata;
	ud->ops->init_done(ud->data);
}

static void shim_open(fuse_req_t req, struct fuse_file_info *fi)
{
	struct cuse_shim_userdata *ud = ud_of(req);
	ud->ops->open(req, ud->data, fi->flags);
}

static void shim_read(fuse_req_t req, size_t size, off_t off,
		      struct fuse_file_info *fi)
{
	struct cuse_shim_userdata *ud = ud_of(req);
	(void)off; /* the kernel's CUSE frontend always sends offset 0 */
	ud->ops->read(req, ud->data, size, fi->fh, fi->flags);
}

static void shim_write(fuse_req_t req, const char *buf, size_t size,
		       off_t off, struct fuse_file_info *fi)
{
	struct cuse_shim_userdata *ud = ud_of(req);
	(void)off;
	ud->ops->write(req, ud->data, buf, size, fi->fh, fi->flags);
}

static void shim_release(fuse_req_t req, struct fuse_file_info *fi)
{
	struct cuse_shim_userdata *ud = ud_of(req);
	ud->ops->release(req, ud->data, fi->fh, fi->flags);
}

static void shim_ioctl(fuse_req_t req, int cmd, void *arg,
		       struct fuse_file_info *fi, unsigned int flags,
		       const void *in_buf, size_t in_bufsz, size_t out_bufsz)
{
	struct cuse_shim_userdata *ud = ud_of(req);
	ud->ops->ioctl(req, ud->data, cmd, arg, fi->fh, fi->flags, flags, in_buf,
		       in_bufsz, out_bufsz);
}

static void shim_poll(fuse_req_t req, struct fuse_file_info *fi,
		      struct fuse_pollhandle *ph)
{
	struct cuse_shim_userdata *ud = ud_of(req);
	ud->ops->poll(req, ud->data, fi->fh, fi->flags, fi->poll_events, ph);
}

/*
 * The kernel's CUSE file_operations have no flush/fsync/mmap, so those
 * callbacks would never be invoked and are deliberately left out.
 */
static const struct cuse_lowlevel_ops shim_clop = {
	.init_done = shim_init_done,
	.open = shim_open,
	.read = shim_read,
	.write = shim_write,
	.release = shim_release,
	.ioctl = shim_ioctl,
	.poll = shim_poll,
};

struct fuse_session *cuse_shim_setup(int argc, char **argv,
				     unsigned int major, unsigned int minor,
				     const char *dev_info, int unrestricted_ioctl,
				     void *userdata)
{
	const char *dev_info_argv[] = { dev_info };
	struct cuse_info ci;
	int multithreaded; /* ignored: we always run the single-threaded loop */

	memset(&ci, 0, sizeof(ci));
	ci.dev_major = major;
	ci.dev_minor = minor;
	ci.dev_info_argc = 1;
	ci.dev_info_argv = dev_info_argv;
	ci.flags = unrestricted_ioctl ? CUSE_UNRESTRICTED_IOCTL : 0;

	/* cuse_lowlevel_new copies ci and clop, so stack storage is fine. */
	return cuse_lowlevel_setup(argc, argv, &ci, &shim_clop, &multithreaded,
				   userdata);
}

int cuse_shim_reply_open(fuse_req_t req, uint64_t fh)
{
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = fh;
	fi.direct_io = 1; /* CUSE is always direct I/O anyway */
	return fuse_reply_open(req, &fi);
}

void cuse_shim_req_ctx(fuse_req_t req, uint32_t *uid, uint32_t *gid,
		       int32_t *pid)
{
	const struct fuse_ctx *ctx = fuse_req_ctx(req);

	*uid = (uint32_t)ctx->uid;
	*gid = (uint32_t)ctx->gid;
	*pid = (int32_t)ctx->pid;
}
