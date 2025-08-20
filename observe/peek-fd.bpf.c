#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "Kcom.h"

// max support
#define MAX_VEC_SIZE 32 // vector max buffer count in iovec
#define MAX_MSG_CNT 8	// max message count in mmsghdr

#define LOG_SIZE_4K 4096
#define LOG_SIZE_1M 1048576

// flag bits
#define FD_READ 1  // Flag for read operation
#define FD_WRITE 2 // Flag for write operation

// Structure to define a rule for filtering
struct Rule
{
	pid_t pid; // Process ID
	int fd;	   // File descriptor
	int rw;	   // Read/Write flag
};

// Structure to log data
struct BpfData
{
	size_t sz;
	char buf[];
};

struct LogHdr
{
	size_t sz;
	struct BpfData *log;
};

struct Log4K
{
	const size_t sz;
	char buf[LOG_SIZE_4K];
};

struct Log1M
{
	const size_t sz;
	char buf[LOG_SIZE_1M];
};

struct Args
{
	long fd;
	union
	{
		struct // read/write
		{
			const char *buf;
			size_t count;
		};
		struct // for readv/writev
		{
			const struct iovec *vec;
			unsigned long vlen;
			// for pwritev/preadv
			unsigned long pos_l;
			unsigned long pos_h;
			// for pwritev2/preadv2
			rwf_t flags;
		};
		struct // for sendmmsg/recvmmsg
		{
			struct mmsghdr *msg;
			unsigned long mvlen;
		};
	};
	long ret;
};

// BPF map to store filtering rules
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct Rule);
	__uint(max_entries, 1);
} filter SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t);
	__type(value, struct Args);
	__uint(max_entries, 100);
} args_map SEC(".maps");

// BPF map to store logs
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct Log4K);
	__uint(max_entries, 1000);
} log_buf_4K SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct Log1M);
	__uint(max_entries, 10);
} log_buf_1M SEC(".maps");

// BPF map for ring buffer to output logs
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 10 * 1024 * 1024); // 10 M
} logs SEC(".maps");

static struct Log4K log_mirror_4K = {};
static struct Log1M log_mirror_1M = {};

// Context structure for read/write operations
struct RwCtx
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int __syscall_nr;
	int __algin8;
	long fd;		 // File descriptor
	const char *buf; // Buffer for data
	size_t count;	 // Size of data
};

struct SyscallExitCtx
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	int __syscall_nr;
	int align;
	long ret;
};

struct RwvCtx
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	int __syscall_nr;
	int align1;
	unsigned long fd;
	const struct iovec *vec;
	unsigned long vlen;
	// for pwritev/preadv
	unsigned long pos_l;
	unsigned long pos_h;
	// for pwritev2/preadv2
	rwf_t flags;
};

// Function to retrieve the filtering rule
static struct Rule *get_rule(void)
{
	struct Rule *rule;
	int key = 0; // Key for accessing the filter map
	rule = bpf_map_lookup_elem(&filter, &key); // Lookup rule
	return rule; // Return rule or NULL if not found
}

// Function to allocate and initialize a log entry
static struct LogHdr malloc_log(size_t sz)
{
	long ret;
	pid_t pid;
	struct BpfData *log;
	struct LogHdr loghdr = {};

	pid = bpf_get_current_pid_tgid(); // Get current PID
	void *log_buf = NULL;
	void *log_mirror = NULL;

	if (sz <= LOG_SIZE_4K)
	{
		log_buf = &log_buf_4K;
		log_mirror = &log_mirror_4K;
		sz = LOG_SIZE_4K;
	}
	else if (sz <= LOG_SIZE_1M)
	{
		log_buf = &log_buf_1M;
		log_mirror = &log_mirror_1M;
		sz = LOG_SIZE_1M;
	}
	else
	{
		bpf_err("requested log size too large: %lu", sz);
		return loghdr;
	}

	// Update log buffer with the mirror log
	ret = bpf_map_update_elem(log_buf, &pid, log_mirror, BPF_ANY);
	if (ret != 0)
	{
		bpf_printk("error: bpf_map_update_elem: %ld", ret);
		return loghdr; // Return NULL on error
	}

	// Retrieve the log entry for the current PID
	log = bpf_map_lookup_elem(log_buf, &pid);
	if (!log)
	{
		bpf_err("log entry not found: %d", pid);
		return loghdr;
	}

	loghdr.log = log;
	loghdr.sz = sz;
	return loghdr; // Return log entry or NULL if not found
}

// Function to free the allocated log entry
static void free_log(struct LogHdr loghdr)
{
	long ret;
	pid_t pid;
	void *log_buf = NULL;

	pid = bpf_get_current_pid_tgid(); // Get current PID

	if (loghdr.sz == LOG_SIZE_4K)
	{
		log_buf = &log_buf_4K;
	}
	else if (loghdr.sz == LOG_SIZE_1M)
	{
		log_buf = &log_buf_1M;
	}
	else
	{
		bpf_err("invalid log size: %lu", loghdr.sz);
		return;
	}

	// Delete the log entry from the log buffer
	ret = bpf_map_delete_elem(log_buf, &pid);
	if (ret != 0)
	{
		bpf_printk("error: bpf_map_delete_elem: %ld", ret);
	}
}

#ifdef USE_REMALLOC
static struct LogHdr remalloc_log(struct LogHdr loghdr, size_t new_sz)
{
	if (!loghdr.log)
	{
		return malloc_log(new_sz);
	}

	if (new_sz <= loghdr.sz)
	{
		return loghdr;
	}

	free_log(loghdr);
	return malloc_log(new_sz);
}
#endif

// Function to send log data to the ring buffer
static long send_log(struct BpfData *log, const char *buf, size_t sz)
{
	long ret;
	size_t send_sz;
	DEBUG(0, "LOG SENDED");

	ret = bpf_probe_read_user(log->buf, sz, buf); // Read user data
	if (ret != 0)
	{
		bpf_printk("error: bpf_probe_read_user: %ld", ret);
		return 0; // Return on error
	}

	// Set log size and adjust for write operations
	send_sz = sz + sizeof(log->sz);
	log->sz = sz;

	// Output log to the ring buffer
	ret = bpf_ringbuf_output(&logs, log, send_sz, 0);
	if (ret != 0)
	{
		bpf_printk("bpf_ringbuf_output: %d\n", ret);
	}

	return ret;
}

// Main function to watch file descriptor read/write operations
static int fd_rw_watch(struct Args *args)
{
	const char *buf = args->buf; // Get buffer from context
	size_t count = args->count;	 // Get count from context
	long ret = args->ret;		 // Get return value from context

	if (count > ret)
	{
		count = ret;
	}

	// Check if buffer is valid
	if (!buf || count == 0)
	{
		return 0;
	}

	struct LogHdr loghdr = malloc_log(count); // Allocate log entry
	if (!loghdr.log)
	{
		return 0; // Exit if allocation fails
	}
	send_log(loghdr.log, buf, count); // Send log data
	free_log(loghdr);				  // Free the log entry

	return 0; // Exit successfully
}

// Main function to watch file descriptor read/write operations
static int fd_rwv_watch(struct Args *args)
{
	const struct iovec *vec = args->vec;
	unsigned long vlen = args->vlen;

	// Check if buffer is valid
	if (vlen == 0 || !vec)
	{
		return 0;
	}

	struct LogHdr loghdr;
	loghdr = malloc_log(
#ifdef USE_REMALLOC
		LOG_SIZE_4K
#else
		LOG_SIZE_1M
#endif
	);
	if (!loghdr.log)
	{
		bpf_err("1M log buffer alloc failed");
		return 0;
	}

	struct iovec _vec;
	size_t iov_len;
	void *iov_base;
	// bytes successfully transferred
	long real_len = args->ret;

	if (vlen > MAX_VEC_SIZE)
	{
		vlen = MAX_VEC_SIZE;
	}

	for (u32 i = 0; i < vlen; i++)
	{
		if (real_len <= 0)
		{
			break;
		}

		bpf_read_umem_ret(&_vec, &vec[i], break);
		iov_len = _vec.iov_len;
		iov_base = _vec.iov_base;

		if (iov_len > real_len)
		{
			iov_len = real_len;
		}

		real_len -= iov_len;

		if (iov_len > LOG_SIZE_1M)
		{
			iov_len = LOG_SIZE_1M;
		}

#ifdef USE_REMALLOC
		loghdr = remalloc_log(loghdr, iov_len);
		if (!loghdr.log)
		{
			continue;
		}
#endif

		send_log(loghdr.log, iov_base, iov_len);
	}

	free_log(loghdr);

	return 0; // Exit successfully
}

static pid_t rule_filter(long fd, long rw)
{
	struct Rule *rule = get_rule();

	if (!rule)
	{
		DEBUG(0, "no rule specified");
		return 0;
	}

	pid_t pid;
	pid = bpf_get_current_pid_tgid();

	if (rule->pid && rule->pid != pid)
	{
		DEBUG(0, "filter by pid: %d vs %d", pid, rule->pid);
		return 0;
	}

	if (rw && !(rw & rule->rw))
	{
		DEBUG(0, "filter by rw: %ld vs %d", rw, rule->rw);
		return 0;
	}

	if ((rule->fd != -1 && rule->fd != fd))
	{
		DEBUG(0, "filter by fd: %ld vs %d", fd, rule->fd);
		return 0;
	}

	return pid;
}

static int save_rw_args(long fd, const char *buf, size_t count, long rw)
{
	long ret;
	pid_t pid;

	pid = rule_filter(fd, rw);

	if (!pid)
	{
		return 0;
	}

	struct Args args;
	args.fd = fd;
	args.buf = buf;
	args.count = count;
	ret = bpf_map_update_elem(&args_map, &pid, &args, BPF_ANY);
	if (ret)
	{
		bpf_err("bpf_map_update_elem: %ld", ret);
	}

	return 0;
}

static int
save_rwv_args(long fd, const struct iovec *vec, unsigned long vlen, long rw)
{
	long ret;
	pid_t pid;

	pid = rule_filter(fd, rw);

	if (!pid)
	{
		return 0;
	}

	struct Args args;
	args.fd = fd;
	DEBUG(0, "fd %ld", args.fd);
	args.vec = vec;
	args.vlen = vlen;
	ret = bpf_map_update_elem(&args_map, &pid, &args, BPF_ANY);
	if (ret)
	{
		bpf_err("bpf_map_update_elem: %ld", ret);
	}

	return 0;
}

static int get_args(long sys_ret, struct Args *args)
{
	long ret = -1;
	long bpf_ret;
	struct Args *_args;
	pid_t pid;
	pid = bpf_get_current_pid_tgid();
	_args = bpf_map_lookup_elem(&args_map, &pid);
	if (!_args)
	{
		DEBUG(0, "map lookup err: %ld", ret);
		return -1;
	}

	if (sys_ret < 0)
	{
		DEBUG(0, "sys ret: %ld", sys_ret);
		goto exit;
	}

	DEBUG(0, "fd: %ld", _args->fd);
	*args = *_args;
	args->ret = sys_ret;
	ret = 0;

exit:
	bpf_ret = bpf_map_delete_elem(&args_map, &pid);
	if (bpf_ret)
	{
		bpf_err("bpf_map_delete_elem: %ld", bpf_ret);
	}

	return ret;
}

// Tracepoint for syscalls on read operations
SEC("?tracepoint/syscalls/sys_enter_read")
int trace_sys_enter_read(struct RwCtx *ctx)
{
	filter_debug_proc(0, "test");
	return save_rw_args(ctx->fd, ctx->buf, ctx->count, FD_READ);
}

SEC("?tracepoint/syscalls/sys_exit_read")
int trace_sys_exit_read(struct SyscallExitCtx *ctx)
{
	filter_debug_proc(0, "test");
	struct Args args;
	if (get_args(ctx->ret, &args))
	{
		return 0;
	}

	fd_rw_watch(&args);

	return 0;
}

// Tracepoint for syscalls on write operations
SEC("?tracepoint/syscalls/sys_enter_write")
int trace_sys_enter_write(struct RwCtx *ctx)
{
	filter_debug_proc(0, "test");
	return save_rw_args(ctx->fd, ctx->buf, ctx->count, FD_WRITE);
}

SEC("?tracepoint/syscalls/sys_exit_write")
int trace_sys_exit_write(struct SyscallExitCtx *ctx)
{
	filter_debug_proc(0, "test");
	struct Args args;
	if (get_args(ctx->ret, &args))
	{
		return 0;
	}

	fd_rw_watch(&args);

	return 0;
}

SEC("?tracepoint/syscalls/sys_enter_readv")
int trace_sys_enter_readv(struct RwvCtx *ctx)
{
	filter_debug_proc(0, "test");
	return save_rwv_args(ctx->fd, ctx->vec, ctx->vlen, FD_READ);
}

SEC("?tracepoint/syscalls/sys_exit_readv")
int trace_sys_exit_readv(struct SyscallExitCtx *ctx)
{
	filter_debug_proc(0, "test");
	struct Args args;
	if (get_args(ctx->ret, &args))
	{
		return 0;
	}

	fd_rwv_watch(&args);
	return 0;
}

// Tracepoint for syscalls on write operations
SEC("?tracepoint/syscalls/sys_enter_writev")
int trace_sys_enter_writev(struct RwvCtx *ctx)
{
	filter_debug_proc(0, "test");
	DEBUG(0, "writev entry");
	return save_rwv_args(ctx->fd, ctx->vec, ctx->vlen, FD_WRITE);
}

// Tracepoint for syscalls on write operations
SEC("?tracepoint/syscalls/sys_exit_writev")
int trace_sys_exit_writev(struct SyscallExitCtx *ctx)
{
	filter_debug_proc(0, "test");
	struct Args args;
	if (get_args(ctx->ret, &args))
	{
		return 0;
	}
	DEBUG(0, "writev exit");
	fd_rwv_watch(&args);

	return 0;
}

SEC("?tracepoint/syscalls/sys_enter_preadv")
int trace_sys_enter_preadv(struct RwvCtx *ctx)
{
	filter_debug_proc(0, "test");
	DEBUG(0, "preadv entry");
	return save_rwv_args(ctx->fd, ctx->vec, ctx->vlen, FD_READ);
}

SEC("?tracepoint/syscalls/sys_exit_preadv")
int trace_sys_exit_preadv(struct SyscallExitCtx *ctx)
{
	filter_debug_proc(0, "test");
	struct Args args;
	if (get_args(ctx->ret, &args))
	{
		return 0;
	}
	DEBUG(0, "preadv exit");
	fd_rwv_watch(&args);

	return 0;
}

SEC("?tracepoint/syscalls/sys_enter_pwritev")
int trace_sys_enter_pwritev(struct RwvCtx *ctx)
{
	filter_debug_proc(0, "test");
	DEBUG(0, "pwritev entry");
	return save_rwv_args(ctx->fd, ctx->vec, ctx->vlen, FD_WRITE);
}

SEC("?tracepoint/syscalls/sys_exit_pwritev")
int trace_sys_exit_pwritev(struct SyscallExitCtx *ctx)
{
	filter_debug_proc(0, "test");
	struct Args args;
	if (get_args(ctx->ret, &args))
	{
		return 0;
	}
	DEBUG(0, "pwritev exit");
	fd_rwv_watch(&args);

	return 0;
}

SEC("?tracepoint/syscalls/sys_enter_preadv2")
int trace_sys_enter_preadv2(struct RwvCtx *ctx)
{
	filter_debug_proc(0, "test");
	DEBUG(0, "preadv2 entry");
	return save_rwv_args(ctx->fd, ctx->vec, ctx->vlen, FD_READ);
}

SEC("?tracepoint/syscalls/sys_exit_preadv2")
int trace_sys_exit_preadv2(struct SyscallExitCtx *ctx)
{
	filter_debug_proc(0, "test");
	struct Args args;
	if (get_args(ctx->ret, &args))
	{
		return 0;
	}
	DEBUG(0, "preadv2 exit");
	fd_rwv_watch(&args);

	return 0;
}

SEC("?tracepoint/syscalls/sys_enter_pwritev2")
int trace_sys_enter_pwritev2(struct RwvCtx *ctx)
{
	filter_debug_proc(0, "test");
	DEBUG(0, "pwritev2 entry");
	return save_rwv_args(ctx->fd, ctx->vec, ctx->vlen, FD_WRITE);
}

SEC("?tracepoint/syscalls/sys_exit_pwritev2")
int trace_sys_exit_pwritev2(struct SyscallExitCtx *ctx)
{
	filter_debug_proc(0, "test");
	struct Args args;
	if (get_args(ctx->ret, &args))
	{
		return 0;
	}
	DEBUG(0, "pwritev2 exit");
	fd_rwv_watch(&args);

	return 0;
}

// socket type fd
/**
 *
 *   struct SendCtx
 *   {
 *       unsigned short common_type;
 *       unsigned char common_flags;
 *       unsigned char common_preempt_count;
 *       int common_pid;
 *
 *       int __syscall_nr; int align1;
 *       long fd;
 *       void * buff;
 *       size_t len;
 *       unsigned int flags; int align2;
 *       struct sockaddr * addr;
 *       int addr_len;
 *   };
 *
 *   this is tracepoint context struct of syscalls/sys_enter_sendto,
 *   we only need fd, buff, len, whose memory layout is the same as 'struct
 * RwCtx', so we can reuse 'struct RwCtx' to parse the context.
 */

SEC("?tracepoint/syscalls/sys_enter_sendto")
int trace_sys_enter_sendto(struct RwCtx *ctx)
{
	filter_debug_proc(0, "test");
	DEBUG(0, "sendto entry");
	return save_rw_args(ctx->fd, ctx->buf, ctx->count, FD_WRITE);
}

SEC("?tracepoint/syscalls/sys_exit_sendto")
int trace_sys_exit_sendto(struct SyscallExitCtx *ctx)
{
	filter_debug_proc(0, "test");
	struct Args args;
	if (get_args(ctx->ret, &args))
	{
		return 0;
	}
	DEBUG(0, "sendto exit");
	fd_rw_watch(&args);

	return 0;
}

SEC("?tracepoint/syscalls/sys_enter_recvfrom")
int trace_sys_enter_recvfrom(struct RwCtx *ctx)
{
	filter_debug_proc(0, "test");
	DEBUG(0, "recvfrom entry");
	return save_rw_args(ctx->fd, ctx->buf, ctx->count, FD_READ);
}

SEC("?tracepoint/syscalls/sys_exit_recvfrom")
int trace_sys_exit_recvfrom(struct SyscallExitCtx *ctx)
{
	filter_debug_proc(0, "test");
	struct Args args;
	if (get_args(ctx->ret, &args))
	{
		return 0;
	}
	DEBUG(0, "recvfrom exit");
	fd_rw_watch(&args);

	return 0;
}

struct SendmsgCtx
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	int __syscall_nr;
	int align1;
	long fd;
	struct user_msghdr *msg;
	unsigned int flags;
};

SEC("?tracepoint/syscalls/sys_enter_sendmsg")
int trace_sys_enter_sendmsg(struct SendmsgCtx *ctx)
{
	filter_debug_proc(0, "test");
	DEBUG(0, "sendmsg entry");
	struct iovec *msg_iov;
	__kernel_size_t msg_iovlen;
	bpf_read_umem_ret(&msg_iov, &ctx->msg->msg_iov, return 0);
	DEBUG(0, "msg_iov: %p", msg_iov);
	bpf_read_umem_ret(&msg_iovlen, &ctx->msg->msg_iovlen, return 0);
	DEBUG(0, "msg_iovlen: %d", msg_iovlen);
	return save_rwv_args(ctx->fd, msg_iov, msg_iovlen, FD_WRITE);
}

SEC("?tracepoint/syscalls/sys_exit_sendmsg")
int trace_sys_exit_sendmsg(struct SyscallExitCtx *ctx)
{
	filter_debug_proc(0, "test");
	struct Args args;
	if (get_args(ctx->ret, &args))
	{
		return 0;
	}
	DEBUG(0, "sendmsg exit");
	fd_rwv_watch(&args);

	return 0;
}

SEC("?tracepoint/syscalls/sys_enter_recvmsg")
int trace_sys_enter_recvmsg(struct SendmsgCtx *ctx)
{
	filter_debug_proc(0, "test");
	DEBUG(0, "recvmsg entry");
	struct iovec *msg_iov;
	__kernel_size_t msg_iovlen;
	bpf_read_umem_ret(&msg_iov, &ctx->msg->msg_iov, return 0);
	DEBUG(0, "msg_iov: %p", msg_iov);
	bpf_read_umem_ret(&msg_iovlen, &ctx->msg->msg_iovlen, return 0);
	DEBUG(0, "msg_iovlen: %d", msg_iovlen);
	return save_rwv_args(ctx->fd, msg_iov, msg_iovlen, FD_READ);
}

SEC("?tracepoint/syscalls/sys_exit_recvmsg")
int trace_sys_exit_recvmsg(struct SyscallExitCtx *ctx)
{
	filter_debug_proc(0, "test");
	struct Args args;
	if (get_args(ctx->ret, &args))
	{
		return 0;
	}
	DEBUG(0, "recvmsg exit");
	fd_rwv_watch(&args);

	return 0;
}

struct SendmmsgCtx
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	int __syscall_nr;
	int align1;
	long fd;
	struct mmsghdr *msg;
	unsigned long vlen;
	unsigned int flags;
};

static int
save_mmsg_args(long fd, struct mmsghdr *msg, unsigned long vlen, long rw)
{
	long ret;
	pid_t pid;

	pid = rule_filter(fd, rw);

	if (!pid)
	{
		return 0;
	}

	struct Args args;
	args.fd = fd;
	args.msg = msg;
	args.vlen = vlen;
	ret = bpf_map_update_elem(&args_map, &pid, &args, BPF_ANY);
	if (ret)
	{
		bpf_err("bpf_map_update_elem: %ld", ret);
	}

	return 0;
}

static int fd_mmsg_watch(struct Args *args)
{
	long fd = args->fd; // Get file descriptor from context

	struct mmsghdr *msg;
	unsigned long mvlen;

	msg = args->msg;
	mvlen = args->mvlen;

	if (mvlen > args->ret)
	{
		mvlen = args->ret;
	}

	if (mvlen > MAX_MSG_CNT)
	{
		mvlen = MAX_MSG_CNT;
	}

	struct Args args_2;
	struct iovec *msg_iov;
	size_t msg_iovlen;
	size_t msg_len;
	args_2.fd = fd;

	for (u32 i = 0; i < mvlen; i++)
	{
		bpf_read_umem_ret(&msg_iov, &msg[i].msg_hdr.msg_iov, break);

		bpf_read_umem_ret(&msg_iovlen, &msg[i].msg_hdr.msg_iovlen, break);

		bpf_read_umem_ret(&msg_len, &msg[i].msg_len, break);
		args_2.vec = msg_iov;
		args_2.vlen = msg_iovlen;
		args_2.ret = msg_len;
		fd_rwv_watch(&args_2);
	}
	return 0;
}

SEC("?tracepoint/syscalls/sys_enter_sendmmsg")
int trace_sys_enter_sendmmsg(struct SendmmsgCtx *ctx)
{
	filter_debug_proc(0, "test");
	DEBUG(0, "sendmmsg entry");
	save_mmsg_args(ctx->fd, ctx->msg, ctx->vlen, FD_WRITE);
	return 0;
}

SEC("?tracepoint/syscalls/sys_exit_sendmmsg")
int trace_sys_exit_sendmmsg(struct SyscallExitCtx *ctx)
{
	filter_debug_proc(0, "test");
	struct Args args;
	if (get_args(ctx->ret, &args))
	{
		return 0;
	}
	DEBUG(0, "sendmmsg exit");
	fd_mmsg_watch(&args);

	return 0;
}

SEC("?tracepoint/syscalls/sys_enter_recvmmsg")
int trace_sys_enter_recvmmsg(struct SendmmsgCtx *ctx)
{
	filter_debug_proc(0, "test");
	DEBUG(0, "recvmmsg entry");
	save_mmsg_args(ctx->fd, ctx->msg, ctx->vlen, FD_READ);
	return 0;
}

SEC("?tracepoint/syscalls/sys_exit_recvmmsg")
int trace_sys_exit_recvmmsg(struct SyscallExitCtx *ctx)
{
	filter_debug_proc(0, "test");
	struct Args args;
	if (get_args(ctx->ret, &args))
	{
		return 0;
	}
	DEBUG(0, "recvmmsg exit");
	fd_mmsg_watch(&args);

	return 0;
}

// License declaration for BPF program
char _license[] SEC("license") = "GPL";