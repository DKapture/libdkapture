#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "Ktask.h"
#include "Kmem.h"
#include "Kstr-utils.h"
#include <errno.h>
#include "jhash.h"

char _license[] SEC("license") = "GPL";

#define PROT_EXEC 0x4
#define MAP_PRIVATE 0x02
#define MAJOR(dev) (u32)((dev & 0xfff00000) >> 20)
#define MINOR(dev) (u32)(dev & 0xfffff)

struct Target
{
	dev_t dev;
	ino_t ino;
};

struct Rule
{
	union
	{
		struct Target target;
		struct
		{
			int not_uid;
			uid_t uid;
		};
	};
};

struct BpfData
{
	uid_t uid;
	pid_t pid;
	int is_binary;
	struct Target target;
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct Rule);
	__uint(max_entries, 400000);
} whitelist SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024); // 1 MB
} logs SEC(".maps");

static void audit_log(uid_t uid, pid_t pid, int is_binary,
		      struct Target *target)
{
	struct BpfData log;
	log.uid = uid;
	log.pid = pid;
	log.is_binary = is_binary;
	log.target = *target;
	long ret = bpf_ringbuf_output(&logs, &log, sizeof(log), 0);
	if (ret)
	{
		bpf_printk("error: bpf_perf_event_output: %ld", ret);
	}
}

struct Event
{
	bool allow;
	uid_t uid;
	struct Target *target;
};

static long match_callback(struct bpf_map *map, const void *key, void *value,
			   void *ctx)
{
	struct Event *event = ctx;
	struct Rule *rule = value;

	if (!rule->not_uid && rule->uid == event->uid)
	{
		event->allow = true;
		return 1;
	}
	if (rule->target.dev == event->target->dev &&
	    rule->target.ino == event->target->ino)
	{
		event->allow = true;
		return 1;
	}
	return 0;
}

static bool rules_filter(struct Target *target, uid_t uid)
{
	struct Event event = {
		.allow = false,
		.target = target,
		.uid = uid,
	};
	bpf_for_each_map_elem(&whitelist, match_callback, &event, 0);
	return event.allow;
}

static int check_permission(const struct dentry *d, int is_binary)
{
	struct Target target = {
		.dev = d->d_sb->s_dev,
		.ino = d->d_inode->i_ino,
	};
	struct Target parent_target = {
		.dev = d->d_parent->d_sb->s_dev,
		.ino = d->d_parent->d_inode->i_ino,
	};
	uid_t uid = bpf_get_current_uid_gid() & 0xffffffff;
	pid_t pid = bpf_get_current_pid_tgid() & 0xffffffff;

	if (rules_filter(&target, uid))
		return 0;
	if (rules_filter(&parent_target, uid))
		return 0;

	audit_log(uid, pid, is_binary, &target);
	return -EACCES;
}

SEC("lsm/mmap_file")
int BPF_PROG(mmap_file, struct file *file, unsigned long reqprot,
	     unsigned long prot, unsigned long flags, int ret)
{
	if (ret)
		return ret;
	if (file && (prot & PROT_EXEC) && (flags & MAP_PRIVATE))
		return check_permission(file->f_path.dentry, 1);
	else
		return 0;
}

SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(bprm_creds_for_exec, struct linux_binprm *bprm, int ret)
{
	if (ret)
		return ret;
	if (bprm && bprm->file)
		return check_permission(bprm->file->f_path.dentry, 0);
	else
		return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm *bprm, int ret)
{
	if (ret)
		return ret;
	if (bprm && bprm->file)
		return check_permission(bprm->file->f_path.dentry, 0);
	else
		return 0;
}
