/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * mountsnoop  Trace mount and umount[2] syscalls
 *
 * Copyright (c) 2021 Hengqi Chen
 * 30-May-2021   Hengqi Chen   Created this.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <thread>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "mountsnoop.skel.h"
#include "Ucom.h"
#include "dkapture.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

/* https://www.gnu.org/software/gnulib/manual/html_node/strerrorname_005fnp.html */
#if !defined(__GLIBC__) || __GLIBC__ < 2 || \
	(__GLIBC__ == 2 && __GLIBC_MINOR__ < 32)
const char *strerrorname_np(int errnum)
{
	return NULL;
}
#endif

static struct ring_buffer *rb = NULL;
static struct mountsnoop_bpf *obj = nullptr;
static bool exit_flag = false;
static std::thread *rb_thread;
static char filter_path[PATH_MAX] = {};
static bool verbose = false;

#ifndef BUILTIN
static const char *flag_names[] = {
	[0] = "MS_RDONLY",	 [1] = "MS_NOSUID",
	[2] = "MS_NODEV",	 [3] = "MS_NOEXEC",
	[4] = "MS_SYNCHRONOUS",	 [5] = "MS_REMOUNT",
	[6] = "MS_MANDLOCK",	 [7] = "MS_DIRSYNC",
	[8] = "MS_NOSYMFOLLOW",	 [9] = "MS_NOATIME",
	[10] = "MS_NODIRATIME",	 [11] = "MS_BIND",
	[12] = "MS_MOVE",	 [13] = "MS_REC",
	[14] = "MS_VERBOSE",	 [15] = "MS_SILENT",
	[16] = "MS_POSIXACL",	 [17] = "MS_UNBINDABLE",
	[18] = "MS_PRIVATE",	 [19] = "MS_SLAVE",
	[20] = "MS_SHARED",	 [21] = "MS_RELATIME",
	[22] = "MS_KERNMOUNT",	 [23] = "MS_I_VERSION",
	[24] = "MS_STRICTATIME", [25] = "MS_LAZYTIME",
	[26] = "MS_SUBMOUNT",	 [27] = "MS_NOREMOTELOCK",
	[28] = "MS_NOSEC",	 [29] = "MS_BORN",
	[30] = "MS_ACTIVE",	 [31] = "MS_NOUSER",
};
static const int flag_count = sizeof(flag_names) / sizeof(flag_names[0]);
const char *argp_program_version = "mountsnoop 0.1";
#endif

const char argp_program_doc[] =
	"Trace mount and umount syscalls.\n"
	"\n"
	"USAGE: mountsnoop [-h] [-t] [-p PID] [-v]\n"
	"\n"
	"EXAMPLES:\n"
	"    mountsnoop         # trace mount and umount syscalls\n"
	"    mountsnoop -d      # detailed output (one line per column value)\n"
	"    mountsnoop -p 1216 # only trace PID 1216\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key)
	{
	case 'p':
		memset(filter_path, 0, PATH_MAX);
		if (strlen(arg) >= PATH_MAX)
			return -1;
		strncpy(filter_path, arg, PATH_MAX);
		break;
	case 'v':
		verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

#ifndef BUILTIN
static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exit_flag = true;
}

static const char *strflags(__u64 flags)
{
	static char str[512];
	int i;

	if (!flags)
		return "0x0";

	str[0] = '\0';
	for (i = 0; i < flag_count; i++)
	{
		if (!((1 << i) & flags))
			continue;
		if (str[0])
			strcat(str, " | ");
		strcat(str, flag_names[i]);
	}
	return str;
}

static const char *strerrno(int errnum)
{
	const char *errstr;
	static char ret[32] = {};

	if (!errnum)
		return "0";

	ret[0] = '\0';
	errstr = strerrorname_np(-errnum);
	if (!errstr)
	{
		snprintf(ret, sizeof(ret), "%d", errnum);
		return ret;
	}

	snprintf(ret, sizeof(ret), "-%s", errstr);
	return ret;
}

static char g_call_buf[40960];

static const char *gen_mount_call(const struct mount_args *e)
{
	snprintf(g_call_buf, sizeof(g_call_buf),
		 "mount(\"%s\", \"%s\", \"%s\", %s, \"%s\") = `%s", e->source,
		 e->target, e->filesystemtype, strflags(e->flags), e->data,
		 strerrno(e->ret));
	return g_call_buf;
}

static const char *gen_umount_call(const struct umount_args *e)
{
	snprintf(g_call_buf, sizeof(g_call_buf), "umount(\"%s\", %s) = %s",
		 e->target, strflags(e->flags), strerrno(e->ret));
	return g_call_buf;
}

static const char *gen_fsopen_call(const struct fsopen_args *e)
{
	snprintf(g_call_buf, sizeof(g_call_buf), "fsopen(\"%s\", %u) = %d",
		 e->fsname, e->flags, e->ret);
	return g_call_buf;
}

static const char *gen_fsconfig_call(const struct fsconfig_args *e)
{
	snprintf(g_call_buf, sizeof(g_call_buf),
		 "fsconfig(%d, %u, \"%s\", \"%s\", %d) = %d", e->fd, e->cmd,
		 e->key, e->value, e->aux, e->ret);
	return g_call_buf;
}

static const char *gen_fsmount_call(const struct fsmount_args *e)
{
	snprintf(g_call_buf, sizeof(g_call_buf), "fsmount(%d, %u, %u) = %d",
		 e->fs_fd, e->flags, e->attr_flags, e->ret);
	return g_call_buf;
}

static const char *gen_fsmovemount_call(const struct move_mount_args *e)
{
	snprintf(g_call_buf, sizeof(g_call_buf),
		 "move_mount(%d, \"%s\", %d, \"%s\", %u) = %d", e->from_dfd,
		 e->from_pathname, e->to_dfd, e->to_pathname, e->flags, e->ret);
	return g_call_buf;
}
static const char *gen_fspick_call(const struct fspick_args *e)
{
	snprintf(g_call_buf, sizeof(g_call_buf), "fspick(%d, \"%s\", %u) = %d",
		 e->dfd, (const char *)e->path, e->flags, e->ret);
	return g_call_buf;
}

static const char *gen_mount_setattr_call(const struct mount_setattr_args *e)
{
	snprintf(g_call_buf, sizeof(g_call_buf),
		 "mount_setattr(%d, \"%s\", %u, "
		 "{attr_set=0x%llx, attr_clr=0x%llx, "
		 "propagation=0x%llx, userns_fd=%llu}, %zu) = %d",
		 e->dfd, e->path, e->flags,
		 (unsigned long long)e->uattr.attr_set,
		 (unsigned long long)e->uattr.attr_clr,
		 (unsigned long long)e->uattr.propagation,
		 (unsigned long long)e->uattr.userns_fd, e->usize, e->ret);
	return g_call_buf;
}

static const char *gen_open_tree_call(const struct open_tree_args *e)
{
	snprintf(g_call_buf, sizeof(g_call_buf),
		 "open_tree(%d, \"%s\", %u) = %d", e->dfd, e->filename,
		 e->flags, e->ret);
	return g_call_buf;
}

static int handle_event(void *ctx, void *data, size_t len)
{
	switch (len)
	{
	case sizeof(mount_args): {
		const struct mount_args *e = (typeof(e))data;
		printf("%-16s %-7d %-7d %-11u %s\n", e->comm, e->pid, e->tid,
		       e->mnt_ns, gen_mount_call(e));
		break;
	}
	case sizeof(umount_args): {
		const struct umount_args *e = (typeof(e))data;
		printf("%-16s %-7d %-7d %-11u %s\n", e->comm, e->pid, e->tid,
		       e->mnt_ns, gen_umount_call(e));
		break;
	}
	case sizeof(fsopen_args): {
		const struct fsopen_args *e = (const struct fsopen_args *)data;
		printf("%-16s %-7d %-7d %-11u %s\n", e->comm, e->pid, e->tid,
		       e->mnt_ns, gen_fsopen_call(e));
		break;
	}
	case sizeof(fsconfig_args): {
		const struct fsconfig_args *e =
			(const struct fsconfig_args *)data;
		printf("%-16s %-7d %-7d %-11u %s\n", e->comm, e->pid, e->tid,
		       e->mnt_ns, gen_fsconfig_call(e));
		break;
	}
	case sizeof(fsmount_args): {
		const struct fsmount_args *e =
			(const struct fsmount_args *)data;
		printf("%-16s %-7d %-7d %-11u %s\n", e->comm, e->pid, e->tid,
		       e->mnt_ns, gen_fsmount_call(e));
		break;
	}
	case sizeof(move_mount_args): {
		const struct move_mount_args *e =
			(const struct move_mount_args *)data;
		printf("%-16s %-7d %-7d %-11u %s\n", e->comm, e->pid, e->tid,
		       e->mnt_ns, gen_fsmovemount_call(e));
		break;
	}
	case sizeof(fspick_args): {
		const struct fspick_args *e = (const struct fspick_args *)data;
		printf("%-16s %-7d %-7d %-11u %s\n", e->comm, e->pid, e->tid,
		       e->mnt_ns, gen_fspick_call(e));
		break;
	}
	case sizeof(mount_setattr_args): {
		const struct mount_setattr_args *e =
			(const struct mount_setattr_args *)data;
		printf("%-16s %-7d %-7d %-11u %s\n", e->comm, e->pid, e->tid,
		       e->mnt_ns, gen_mount_setattr_call(e));
		break;
	}
	case sizeof(open_tree_args): {
		const struct open_tree_args *e =
			(const struct open_tree_args *)data;
		printf("%-16s %-7d %-7d %-11u %s\n", e->comm, e->pid, e->tid,
		       e->mnt_ns, gen_open_tree_call(e));
		break;
	}
	default:
		printf("Unknown event size: %zu\n", len);
		break;
	}

	return 0;
}
#endif

static void ringbuf_worker(void)
{
	while (!exit_flag)
	{
		int err = ring_buffer__poll(rb, 1000 /* timeout in ms */);
		// Check for errors during polling
		if (err < 0 && err != -EINTR)
		{
			pr_error("Error polling ring buffer: %d\n", err);
			sleep(5); // Sleep before retrying
		}
	}
}

int mountsnoop_deinit(void)
{
	exit_flag = true;
	if (rb_thread)
	{
		rb_thread->join();
		delete rb_thread;
		rb_thread = nullptr;
	}
	if (rb)
	{
		ring_buffer__free(rb);
		rb = nullptr;
	}
	if (obj)
	{
		mountsnoop_bpf__destroy(obj);
		obj = nullptr;
	}
	return 0;
}

#ifdef BUILTIN
int mountsnoop_init(int argc, char **argv, DKapture::DKCallback callback,
		    void *ctx)
#else
int main(int argc, char **argv)
#endif
{
	int err, key = 0;
	int event_map_fd;
	int filter_map_fd;
	exit_flag = false;

	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

#ifndef BUILTIN
	Log::set_level(Log::DEBUG);
	libbpf_set_print(libbpf_print_fn);
	if (signal(SIGINT, sig_int) == SIG_ERR)
	{
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto err_out;
	}
#endif

	obj = mountsnoop_bpf__open();
	if (!obj)
	{
		warn("failed to open BPF object\n");
		return 1;
	}

	err = mountsnoop_bpf__load(obj);
	if (err)
	{
		warn("failed to load BPF object: %d\n", err);
		goto err_out;
	}

	err = mountsnoop_bpf__attach(obj);
	if (err)
	{
		warn("failed to attach BPF programs: %d\n", err);
		goto err_out;
	}

	event_map_fd = bpf_get_map_fd(obj->obj, "events", goto err_out);
	filter_map_fd = bpf_get_map_fd(obj->obj, "filter", goto err_out);
	DEBUG(0, "filter path: %s", filter_path);
	bpf_map_update_elem(filter_map_fd, &key, filter_path, BPF_ANY);

#ifndef BUILTIN
	rb = ring_buffer__new(event_map_fd, handle_event, NULL, NULL);
#else
	rb = ring_buffer__new(event_map_fd, (ring_buffer_sample_fn)callback,
			      ctx, NULL);
#endif
	if (!rb)
		goto err_out;

	rb_thread = new (std::nothrow) std::thread(ringbuf_worker);
	if (!rb_thread)
		goto err_out;

#ifdef BUILTIN
	return 0;
#else

	printf("%-16s %-7s %-7s %-11s %s\n", "COMM", "PID", "TID", "MNT_NS",
	       "CALL");

	while (!exit_flag)
		sleep(10);
#endif

err_out:
	mountsnoop_deinit();

	return err != 0;
}
