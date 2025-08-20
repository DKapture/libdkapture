/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2021 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "Kcom.h"
#include "Kstr-utils.h"
#include "dkapture.h"

#define MAX_ENTRIES 1000

#define MAX_EVENT_SIZE 10240
#define RINGBUF_SIZE (1024 * 256)

static const union
{
	struct fsconfig_args fsconfig_args;
	struct mount_args mount_args;
	struct move_mount_args move_mount_args;
	struct fspick_args fspick_args;
	struct mount_setattr_args mount_setattr_args;
	struct open_tree_args open_tree_args;
	struct umount_args umount_args;
} zero_map_item = {};

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, char[4096]);
} filter SEC(".maps");

static bool filter_path(const char *path, int n)
{
	int key = 0;
	char *rule_path;
	rule_path = bpf_map_lookup_elem(&filter, &key);
	if (!rule_path || rule_path[0] == '\0')
	{
		return true;
	}

	if (!path)
	{
		return false;
	}

	return strncmp(path, rule_path, n) == 0;
}

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	__type(key, pid_t);
	__type(value, struct fsopen_args);
} fsopen_map SEC(".maps");

static void save_fsopen_args(struct syscall_trace_enter *ctx)
{
	const char __user *fsname = (typeof(fsname))ctx->args[0];
	unsigned int flags = (typeof(flags))ctx->args[1];
	struct fsopen_args args;
	args.flags = flags;
	bpf_read_ustr(args.fsname, 32, fsname);
	long ret = 0;
	pid_t pid = bpf_get_current_pid_tgid();
	ret = bpf_map_update_elem(&fsopen_map, &pid, &args, BPF_ANY);
	if (ret)
	{
		bpf_printk("Error saving args for pid %d: %ld\n", pid, ret);
	}
}

static void save_fsopen_ret(int ret)
{
	struct fsopen_args *args;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t pid = pid_tgid;
	pid_t tgid = pid_tgid >> 32;
	args = bpf_map_lookup_elem(&fsopen_map, &pid);
	if (!args)
	{
		bpf_warn("Error: args not found for pid %d\n", pid);
		return;
	}
	args->ret = ret;
	args->pid = tgid;
	args->tid = pid;
	struct task_struct *task;
	task = (struct task_struct *)bpf_get_current_task();
	args->mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	bpf_get_current_comm(args->comm, sizeof(args->comm));
	bpf_ringbuf_output(&events, args, sizeof(*args), 0);
	bpf_map_delete_elem(&fsopen_map, &pid);
}

SEC("tracepoint/syscalls/sys_enter_fsopen")
int fsopen_entry(struct syscall_trace_enter *ctx)
{
	save_fsopen_args(ctx);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_fsopen")
int fsopen_exit(struct syscall_trace_exit *ctx)
{
	save_fsopen_ret(ctx->ret);
	return 0;
}

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	__type(key, pid_t);
	__type(value, struct fsconfig_args);
} fsconfig_map SEC(".maps");

static void save_fsconfig_args(struct syscall_trace_enter *ctx)
{
	long ret;
	int fd = (int)ctx->args[0];
	unsigned int cmd = (unsigned int)ctx->args[1];
	const char __user *key = (const char *)ctx->args[2];
	const void __user *value = (void *)ctx->args[3];
	int aux = (int)ctx->args[4];
	pid_t pid = bpf_get_current_pid_tgid();
	ret = bpf_map_update_elem(&fsconfig_map, &pid, &zero_map_item, BPF_ANY);
	if (ret)
	{
		bpf_err("bpf_map_update_elem fail: %ld", ret);
		return;
	}

	struct fsconfig_args *args;
	args = bpf_map_lookup_elem(&fsconfig_map, &pid);
	if (!args)
	{
		bpf_err("bpf_map_update_elem fail: %ld", ret);
		return;
	}
	args->aux = aux;
	args->fd = fd;
	args->cmd = cmd;
	bpf_read_ustr(args->key, sizeof(args->key), key);
	switch (cmd)
	{
	case FSCONFIG_SET_BINARY:
		if (aux > sizeof(args->value))
		{
			aux = sizeof(args->value);
		}
		bpf_probe_read_user(&args->value, aux, value);
		break;
	case FSCONFIG_SET_STRING:
	case FSCONFIG_SET_PATH_EMPTY:
	case FSCONFIG_SET_PATH:
		bpf_read_ustr(&args->value, sizeof(args->value), value);
		break;
	default:
		break;
	}
}

static void save_fsconfig_ret(int ret)
{
	struct fsconfig_args *args;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t pid = pid_tgid;
	pid_t tgid = pid_tgid >> 32;
	args = bpf_map_lookup_elem(&fsconfig_map, &pid);
	if (!args)
	{
		bpf_warn("Error: args not found for pid %d\n", pid);
		return;
	}
	args->ret = ret;
	args->pid = tgid;
	args->tid = pid;
	struct task_struct *task;
	task = (struct task_struct *)bpf_get_current_task();
	args->mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	bpf_get_current_comm(args->comm, sizeof(args->comm));
	bpf_ringbuf_output(&events, args, sizeof(*args), 0);
	bpf_map_delete_elem(&fsconfig_map, &pid);
}

SEC("tracepoint/syscalls/sys_enter_fsconfig")
int fsconfig_entry(struct syscall_trace_enter *ctx)
{
	save_fsconfig_args(ctx);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_fsconfig")
int fsconfig_exit(struct syscall_trace_exit *ctx)
{
	save_fsconfig_ret(ctx->ret);
	return 0;
}

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	__type(key, pid_t);
	__type(value, struct fsmount_args);
} fsmount_map SEC(".maps");

static void save_fsmount_args(struct syscall_trace_enter *ctx)
{
	int fs_fd;
	unsigned int flags;
	unsigned int attr_flags;
	fs_fd = (int)ctx->args[0];
	flags = (unsigned int)ctx->args[1];
	attr_flags = (unsigned int)ctx->args[2];
	struct fsmount_args args;
	args.fs_fd = fs_fd;
	args.flags = flags;
	args.attr_flags = attr_flags;
	long ret = 0;
	pid_t pid = bpf_get_current_pid_tgid();
	ret = bpf_map_update_elem(&fsmount_map, &pid, &args, BPF_ANY);
	if (ret)
	{
		bpf_err("Error saving args for pid %d: %ld\n", pid, ret);
	}
}

static void save_fsmount_ret(int ret)
{
	struct fsmount_args *args;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t pid = pid_tgid;
	pid_t tgid = pid_tgid >> 32;
	args = bpf_map_lookup_elem(&fsmount_map, &pid);
	if (!args)
	{
		bpf_warn("Error: args not found for pid %d\n", pid);
		return;
	}
	args->ret = ret;
	args->pid = tgid;
	args->tid = pid;
	struct task_struct *task;
	task = (struct task_struct *)bpf_get_current_task();
	args->mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	bpf_get_current_comm(args->comm, sizeof(args->comm));
	bpf_ringbuf_output(&events, args, sizeof(*args), 0);
	bpf_map_delete_elem(&fsmount_map, &pid);
}

SEC("tracepoint/syscalls/sys_enter_fsmount")
int fsmount_entry(struct syscall_trace_enter *ctx)
{
	save_fsmount_args(ctx);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_fsmount")
int fsmount_exit(struct syscall_trace_exit *ctx)
{
	save_fsmount_ret(ctx->ret);
	return 0;
}

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	__type(key, pid_t);
	__type(value, struct mount_args);
} mount_map SEC(".maps");

static void save_mount_args(struct syscall_trace_enter *ctx)
{
	long ret;
	char __user *source = (char *)ctx->args[0];
	char __user *target = (char *)ctx->args[1];
	char __user *filesystemtype = (char *)ctx->args[2];
	unsigned long flags = (__u64)ctx->args[3];
	void __user *data = (void *)ctx->args[4];

	pid_t pid = bpf_get_current_pid_tgid();
	ret = bpf_map_update_elem(&mount_map, &pid, &zero_map_item, BPF_ANY);
	if (ret)
	{
		bpf_err("bpf_map_update_elem fail: %ld", ret);
		return;
	}

	struct mount_args *args;
	args = bpf_map_lookup_elem(&mount_map, &pid);
	if (!args)
	{
		bpf_err("bpf_map_update_elem fail: %ld", ret);
		return;
	}
	bpf_read_ustr(args->source, sizeof(args->source), source);
	bpf_read_ustr(args->target, sizeof(args->target), target);
	bpf_read_ustr(
		args->filesystemtype,
		sizeof(args->filesystemtype),
		filesystemtype
	);
	args->flags = flags;
	bpf_read_umem(&args->data, data);
}

static void save_mount_ret(int ret)
{
	struct mount_args *args;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t pid = pid_tgid;
	pid_t tgid = pid_tgid >> 32;
	args = bpf_map_lookup_elem(&mount_map, &pid);
	if (!args)
	{
		bpf_err("Error: args not found for pid %d\n", pid);
		return;
	}
	args->ret = ret;
	args->pid = tgid;
	args->tid = pid;
	struct task_struct *task;
	task = (struct task_struct *)bpf_get_current_task();
	args->mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	bpf_get_current_comm(args->comm, sizeof(args->comm));
	if (filter_path(args->source, sizeof(args->source)) ||
		filter_path(args->target, sizeof(args->target)))
	{
		bpf_ringbuf_output(&events, args, sizeof(*args), 0);
	}
	bpf_map_delete_elem(&mount_map, &pid);
}

SEC("tracepoint/syscalls/sys_enter_mount")
int mount_entry(struct syscall_trace_enter *ctx)
{
	save_mount_args(ctx);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_mount")
int mount_exit(struct syscall_trace_exit *ctx)
{
	save_mount_ret(ctx->ret);
	return 0;
}

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	__type(key, pid_t);
	__type(value, struct move_mount_args);
} move_mount_map SEC(".maps");

static void save_move_mount_args(struct syscall_trace_enter *ctx)
{
	long ret;
	int from_dfd;
	const char __user *from_pathname;
	int to_dfd;
	const char __user *to_pathname;
	unsigned int flags;
	from_dfd = (int)ctx->args[0];
	from_pathname = (const char *)ctx->args[1];
	to_dfd = (int)ctx->args[2];
	to_pathname = (const char *)ctx->args[3];
	flags = (unsigned int)ctx->args[4];
	pid_t pid = bpf_get_current_pid_tgid();
	ret = bpf_map_update_elem(&move_mount_map, &pid, &zero_map_item, BPF_ANY);
	if (ret)
	{
		bpf_err("bpf_map_update_elem fail: %ld", ret);
		return;
	}

	struct move_mount_args *args;
	args = bpf_map_lookup_elem(&move_mount_map, &pid);
	if (!args)
	{
		bpf_err("bpf_map_update_elem fail: %ld", ret);
		return;
	}
	args->flags = flags;
	args->from_dfd = from_dfd;
	args->to_dfd = to_dfd;
	bpf_read_ustr(
		args->from_pathname,
		sizeof(args->from_pathname),
		from_pathname
	);
	bpf_read_ustr(args->to_pathname, sizeof(args->to_pathname), to_pathname);
}

static void save_move_mount_ret(int ret)
{
	struct move_mount_args *args;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t pid = pid_tgid;
	pid_t tgid = pid_tgid >> 32;
	args = bpf_map_lookup_elem(&move_mount_map, &pid);
	if (!args)
	{
		bpf_err("bpf_map_update_elem fail: %ld", ret);
		return;
	}
	args->ret = ret;
	args->pid = tgid;
	args->tid = pid;
	struct task_struct *task;
	task = (struct task_struct *)bpf_get_current_task();
	args->mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	bpf_get_current_comm(args->comm, sizeof(args->comm));
	bpf_ringbuf_output(&events, args, sizeof(*args), 0);
	bpf_map_delete_elem(&move_mount_map, &pid);
}

SEC("tracepoint/syscalls/sys_enter_move_mount")
int move_mount_entry(struct syscall_trace_enter *ctx)
{
	save_move_mount_args(ctx);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_move_mount")
int move_mount_exit(struct syscall_trace_exit *ctx)
{
	save_move_mount_ret(ctx->ret);
	return 0;
}

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	__type(key, pid_t);
	__type(value, struct fspick_args);
} fspick_map SEC(".maps");

static void save_fspick_args(struct syscall_trace_enter *ctx)
{
	long ret;
	int dfd;
	const char __user *path;
	unsigned int flags;
	dfd = (int)ctx->args[0];
	path = (const char *)ctx->args[1];
	flags = (unsigned int)ctx->args[2];

	pid_t pid = bpf_get_current_pid_tgid();
	ret = bpf_map_update_elem(&fspick_map, &pid, &zero_map_item, BPF_ANY);
	if (ret)
	{
		bpf_err("bpf_map_update_elem fail: %ld", ret);
		return;
	}

	struct fspick_args *args;
	args = bpf_map_lookup_elem(&fspick_map, &pid);
	if (!args)
	{
		bpf_err("bpf_map_update_elem fail: %ld", ret);
		return;
	}
	args->dfd = dfd;
	args->flags = flags;
	bpf_read_ustr(args->path, sizeof(args->path), path);
}

static void save_fspick_ret(int ret)
{
	struct fspick_args *args;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t pid = pid_tgid;
	pid_t tgid = pid_tgid >> 32;
	args = bpf_map_lookup_elem(&fspick_map, &pid);
	if (!args)
	{
		bpf_err("bpf_map_update_elem fail: %ld", ret);
		return;
	}
	args->ret = ret;
	args->pid = tgid;
	args->tid = pid;
	struct task_struct *task;
	task = (struct task_struct *)bpf_get_current_task();
	args->mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	bpf_get_current_comm(args->comm, sizeof(args->comm));
	bpf_ringbuf_output(&events, args, sizeof(*args), 0);
	bpf_map_delete_elem(&fspick_map, &pid);
}

SEC("tracepoint/syscalls/sys_enter_fspick")
int fspick_entry(struct syscall_trace_enter *ctx)
{
	save_fspick_args(ctx);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_fspick")
int fspick_exit(struct syscall_trace_exit *ctx)
{
	save_fspick_ret(ctx->ret);
	return 0;
}

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	__type(key, pid_t);
	__type(value, struct mount_setattr_args);
} mount_setattr_map SEC(".maps");

static void save_mount_setattr_args(struct syscall_trace_enter *ctx)
{
	long ret;
	int dfd;
	const char __user *path;
	unsigned int flags;
	struct mount_attr __user *uattr;
	size_t usize;

	dfd = (int)ctx->args[0];
	path = (const char *)ctx->args[1];
	flags = (unsigned int)ctx->args[2];
	uattr = (struct mount_attr *)ctx->args[3];
	usize = (size_t)ctx->args[4];

	pid_t pid = bpf_get_current_pid_tgid();
	ret =
		bpf_map_update_elem(&mount_setattr_map, &pid, &zero_map_item, BPF_ANY);
	if (ret)
	{
		bpf_err("bpf_map_update_elem fail: %ld", ret);
		return;
	}

	struct mount_setattr_args *args;
	args = bpf_map_lookup_elem(&mount_setattr_map, &pid);
	if (!args)
	{
		bpf_err("bpf_map_update_elem fail: %ld", ret);
		return;
	}
	args->dfd = dfd;
	bpf_read_ustr(args->path, sizeof(args->path), path);
	args->flags = flags;
	bpf_read_umem(&args->uattr, uattr);
	args->usize = usize;
}

static void save_mount_setattr_ret(int ret)
{
	struct mount_setattr_args *args;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t pid = pid_tgid;
	pid_t tgid = pid_tgid >> 32;
	args = bpf_map_lookup_elem(&mount_setattr_map, &pid);
	if (!args)
	{
		bpf_err("bpf_map_update_elem fail: %ld", ret);
		return;
	}
	args->ret = ret;
	args->pid = tgid;
	args->tid = pid;
	struct task_struct *task;
	task = (struct task_struct *)bpf_get_current_task();
	args->mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	bpf_get_current_comm(args->comm, sizeof(args->comm));
	bpf_ringbuf_output(&events, args, sizeof(*args), 0);
	bpf_map_delete_elem(&mount_setattr_map, &pid);
}

SEC("tracepoint/syscalls/sys_enter_mount_setattr")
int mount_setattr_entry(struct syscall_trace_enter *ctx)
{
	save_mount_setattr_args(ctx);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_mount_setattr")
int mount_setattr_exit(struct syscall_trace_exit *ctx)
{
	save_mount_setattr_ret(ctx->ret);
	return 0;
}

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	__type(key, pid_t);
	__type(value, struct open_tree_args);
} open_tree_map SEC(".maps");

static void save_open_tree_args(struct syscall_trace_enter *ctx)
{
	long ret;
	int dfd;
	const char __user *filename;
	unsigned int flags;

	dfd = (int)ctx->args[0];
	filename = (const char *)ctx->args[1];
	flags = (unsigned int)ctx->args[2];

	pid_t pid = bpf_get_current_pid_tgid();
	ret = bpf_map_update_elem(&open_tree_map, &pid, &zero_map_item, BPF_ANY);
	if (ret)
	{
		bpf_err("bpf_map_update_elem fail: %ld", ret);
		return;
	}

	struct open_tree_args *args;
	args = bpf_map_lookup_elem(&open_tree_map, &pid);
	if (!args)
	{
		bpf_err("bpf_map_update_elem fail: %ld", ret);
		return;
	}
	args->dfd = dfd;
	bpf_read_ustr(args->filename, sizeof(args->filename), filename);
	args->flags = flags;
}

static void save_open_tree_ret(int ret)
{
	struct open_tree_args *args;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t pid = pid_tgid;
	pid_t tgid = pid_tgid >> 32;
	args = bpf_map_lookup_elem(&open_tree_map, &pid);
	if (!args)
	{
		bpf_err("bpf_map_update_elem fail: %ld", ret);
		return;
	}
	args->ret = ret;
	args->pid = tgid;
	args->tid = pid;
	struct task_struct *task;
	task = (struct task_struct *)bpf_get_current_task();
	args->mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	bpf_get_current_comm(args->comm, sizeof(args->comm));
	bpf_ringbuf_output(&events, args, sizeof(*args), 0);
	bpf_map_delete_elem(&open_tree_map, &pid);
}

SEC("tracepoint/syscalls/sys_enter_open_tree")
int open_tree_entry(struct syscall_trace_enter *ctx)
{
	save_open_tree_args(ctx);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_open_tree")
int open_tree_exit(struct syscall_trace_exit *ctx)
{
	save_open_tree_ret(ctx->ret);
	return 0;
}

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	__type(key, pid_t);
	__type(value, struct umount_args);
} umount_map SEC(".maps");

static void save_umount_args(struct syscall_trace_enter *ctx)
{
	long ret;
	const char __user *target;
	unsigned int flags = 0;

	target = (const char *)ctx->args[0];
	if (ctx->nr == 2)
	{
		flags = (unsigned int)ctx->args[1];
	}

	pid_t pid = bpf_get_current_pid_tgid();
	ret = bpf_map_update_elem(&umount_map, &pid, &zero_map_item, BPF_ANY);
	if (ret)
	{
		bpf_err("bpf_map_update_elem fail: %ld", ret);
		return;
	}

	struct umount_args *args;
	args = bpf_map_lookup_elem(&umount_map, &pid);
	if (!args)
	{
		bpf_err("bpf_map_update_elem fail: %ld", ret);
		return;
	}
	bpf_read_ustr(args->target, sizeof(args->target), target);
	args->flags = flags;
}

static void save_umount_ret(int ret)
{
	struct umount_args *args;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t pid = pid_tgid;
	pid_t tgid = pid_tgid >> 32;
	args = bpf_map_lookup_elem(&umount_map, &pid);
	if (!args)
	{
		bpf_err("bpf_map_update_elem fail: %ld", ret);
		return;
	}
	args->ret = ret;
	args->pid = tgid;
	args->tid = pid;
	struct task_struct *task;
	task = (struct task_struct *)bpf_get_current_task();
	args->mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	bpf_get_current_comm(args->comm, sizeof(args->comm));
	if (filter_path(args->target, sizeof(args->target)))
	{
		bpf_ringbuf_output(&events, args, sizeof(*args), 0);
	}
	bpf_map_delete_elem(&umount_map, &pid);
}

SEC("tracepoint/syscalls/sys_enter_umount")
int umount_entry(struct syscall_trace_enter *ctx)
{
	save_umount_args(ctx);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_umount")
int umount_exit(struct syscall_trace_exit *ctx)
{
	save_umount_ret(ctx->ret);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
