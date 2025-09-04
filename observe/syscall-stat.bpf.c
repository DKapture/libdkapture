/**
 * system call statistic
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "jhash.h"
#include "Kstr-utils.h"
#include "Kmem.h"
#include "Kcom.h"

typedef u32 pHash;

#define __NR_syscalls 453

extern int
bpf_get_fsverity_digest(struct file *file, struct bpf_dynptr *digest_p) __ksym;

extern int bpf_verify_pkcs7_signature(
	struct bpf_dynptr *data_p,
	struct bpf_dynptr *sig_p,
	struct bpf_key *trusted_keyring
) __ksym;

char _license[] SEC("license") = "GPL";

struct Rule
{
	pid_t pid;
	pHash pathhash;
	char comm[16];
};

struct info
{
	u64 cnt;
	u64 time;
	long ret;
};

struct shoot
{
	u32 nr;
	u64 time;
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pHash);
	__type(value, struct Rule);
	__uint(max_entries, 1);
} filter SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct info);
	__uint(max_entries, __NR_syscalls);
} syscall_stat SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct shoot);
	__uint(max_entries, 10000);
} shoot_cache SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, pid_t);
	__type(value, pHash);
	__uint(max_entries, 1024);
} pid2pathhash SEC(".maps");

// Function to retrieve the filtering rule
static struct Rule *get_rule(void)
{
	struct Rule *rule;
	int key = 0;
	rule = bpf_map_lookup_elem(&filter, &key); // Lookup rule
	return rule; // Return rule or NULL if not found
}
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024); // 1 MB
} logs SEC(".maps");

// SEC("fentry/x64_sys_call")
SEC("tp_btf/sys_enter")
int BPF_PROG(enter_sys_call, const struct pt_regs *regs, unsigned int nr)
{
	struct Rule *rule;
	struct shoot shoot;
	pid_t pid;
	long ret = 0;

	rule = get_rule();
	if (!rule)
	{
		return 0;
	}

	pid = bpf_get_current_pid_tgid();
	if (rule->pid > 0 && rule->pid != pid)
	{
		return 0;
	}

	if (rule->pathhash)
	{
		u32 *pathhash;
		pathhash = bpf_map_lookup_elem(&pid2pathhash, &pid);
		if (!pathhash)
		{
			return 0;
		}

		if (rule->pathhash != *pathhash)
		{
			return 0;
		}
	}

	if (rule->comm[0])
	{
		char comm[16];
		ret = bpf_get_current_comm(comm, sizeof(comm));
		if (ret)
		{
			bpf_printk("fail to get current comm: %d", ret);
			return 0;
		}

		if (strncmp(comm, rule->comm, sizeof(comm)))
		{
			return 0;
		}
	}

	shoot.time = bpf_ktime_get_ns();
	shoot.nr = nr;
	bpf_map_update_elem(&shoot_cache, &regs, &shoot, BPF_ANY);

	return 0;
}

// SEC("fexit/x64_sys_call")
SEC("tp_btf/sys_exit")
int BPF_PROG(exit_sys_call, const struct pt_regs *regs, long ret)
{
	filter_debug_proc(0, "test");
	struct info *snr;
	struct shoot *shoot;
	shoot = (struct shoot *)bpf_map_lookup_elem(&shoot_cache, &regs);
	if (!shoot)
	{
		DEBUG(0, "shoot_cache map lookup fail");
		return 0;
	}
	snr = bpf_map_lookup_elem(&syscall_stat, &shoot->nr);
	if (!snr)
	{
		bpf_err("fail to lookup syscall info: %d", shoot->nr);
		return 0;
	}

	u64 d_time = bpf_ktime_get_ns() - shoot->time;
	__sync_fetch_and_add(&snr->time, d_time);
	__sync_fetch_and_add(&snr->cnt, 1);
	if (ret < 0)
	{
		__sync_fetch_and_add(&snr->ret, 1);
	}
	return 0;
}

SEC("fexit/bprm_execve")
int BPF_PROG(
	bprm_execve,
	struct linux_binprm *bprm,
	int fd,
	struct filename *filename,
	int flags
)
{ // used for creating map from pid to pathhash
	long ret = 0;
	pid_t pid;
	struct Rule *rule;
	u32 *buf;

	rule = get_rule();
	if (!rule)
	{
		DEBUG(0, "no filter rule specified");
		return 0;
	}

	if (rule->pid > 0)
	{ // pid used first, pathhash ignored
		DEBUG(0, "pid used first, pathhash ignored");
		return 0;
	}

	if (rule->pathhash == 0)
	{
		DEBUG(0, "pathhash not set in rule");
		return 0;
	}

	char *path = malloc_page(0);
	if (!path)
	{
		bpf_printk("path buffer full");
		return 0;
	}

	ret = bpf_probe_read_kernel_str(path, 4096, &filename->iname);
	if (ret <= 0)
	{
		bpf_printk("fail to read kernel space string: %ld", ret);
		goto exit;
	}

	pHash pathhash = jhash(path, 4096, 0);
	if (pathhash != rule->pathhash)
	{
		DEBUG(
			0,
			"%d filter by pathhash: %d vs %d",
			pid,
			pathhash,
			rule->pathhash
		);
		goto exit;
	}

	pid = bpf_get_current_pid_tgid();
	ret = bpf_map_update_elem(&pid2pathhash, &pid, path, BPF_ANY);
	if (ret)
	{
		bpf_printk("fail to update map pid2pathhash: %ld", ret);
		goto exit;
	}

	buf = bpf_map_lookup_elem(&pid2pathhash, &pid);
	if (!buf)
	{
		bpf_printk("fail to lookup pathhash for pid: %d", pid);
		goto exit;
	}

	*buf = pathhash;

exit:
	free_page(0);
	if (ret)
	{
		bpf_map_delete_elem(&pid2pathhash, &pid);
	}

	return 0;
}

SEC("fentry/exit_thread")
int BPF_PROG(exit_thread, struct task_struct *tsk)
{
	long ret;
	pid_t pid;
	struct Rule *rule;
	pHash *pathhash;

	rule = get_rule();
	if (!rule)
	{
		DEBUG(0, "no filter rule specified");
		return 0;
	}

	if (rule->pid > 0)
	{ // pid used first, pathhash ignored
		DEBUG(0, "PID used first");
		return 0;
	}

	if (rule->pathhash == 0)
	{
		DEBUG(0, "path not set");
		return 0;
	}

	pid = bpf_get_current_pid_tgid();
	pathhash = bpf_map_lookup_elem(&pid2pathhash, &pid);
	if (!pathhash)
	{
		DEBUG(0, "no pid to path hash for %d", pid);
		return 0;
	}

	if (*pathhash != rule->pathhash)
	{
		DEBUG(
			0,
			"%d filter by pathhash: %d vs %d",
			pid,
			pathhash,
			rule->pathhash
		);
		return 0;
	}

	ret = bpf_probe_read_kernel(&pid, sizeof(pid), &tsk->pid);
	if (ret)
	{
		bpf_printk("fail to read pid: %d", ret);
		return 0;
	}

	ret = bpf_map_delete_elem(&pid2pathhash, &pid);
	if (ret)
	{
		bpf_printk("fail to delete pid2pathhash: %d", ret);
	}

	return 0;
}
