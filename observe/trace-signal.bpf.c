#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "Kstr-utils.h"
#include "jhash.h"
#include "Kmem.h"
#include "Kcom.h"

char _license[] SEC("license") = "GPL";

struct Rule
{
	pid_t sender_pid; // Process ID
	u32 sender_phash;
	pid_t recv_pid;
	u32 recv_phash;
	int sig;
};

// Structure to log data
struct BpfData
{
	pid_t sender_pid;
	char sender_comm[16];
	pid_t recv_pid;
	char recv_comm[16];
	int sig;
	int res; // Result of the signal sending
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
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); // 256 KB
} logs SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, pid_t);
	__type(value, u32);
	__uint(max_entries, 10000);
} pid2pathhash SEC(".maps");

static struct Rule *get_rule(void)
{
	struct Rule *rule;
	int key = 0; // Key for accessing the filter map
	rule = bpf_map_lookup_elem(&filter, &key); // Lookup rule
	return rule; // Return rule or NULL if not found
}

static int rule_filter(struct Rule *rule, struct BpfData *log)
{
	u32 *pathhash;
	if (rule->sender_pid > 0 && rule->sender_pid != log->sender_pid)
	{
		return 0;
	}

	if (rule->recv_pid > 0 && rule->recv_pid != log->recv_pid)
	{
		return 0;
	}

	if (rule->sender_phash)
	{
		DEBUG(0, "check send pid: %u", log->sender_pid);
		pathhash = bpf_map_lookup_elem(&pid2pathhash, &log->sender_pid);
		if (!pathhash)
		{
			return 0;
		}

		if (rule->sender_phash != *pathhash)
		{
			return 0;
		}
		DEBUG(0, "send phash match: %u", *pathhash);
	}

	if (rule->recv_phash)
	{
		DEBUG(0, "check recv pid: %u", log->recv_pid);
		pathhash = bpf_map_lookup_elem(&pid2pathhash, &log->recv_pid);
		if (!pathhash)
		{
			return 0;
		}

		if (rule->recv_phash != *pathhash)
		{
			return 0;
		}
		DEBUG(0, "recv phash match: %u", *pathhash);
	}

	if (rule->sig && rule->sig != log->sig)
	{
		return 0;
	}
	DEBUG(0, "signal match: %u", log->sig);

	return 1;
}

struct TpEnterKill
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	int __syscall_nr;
	int not_used;
	long pid;
	long sig;
};

struct TpExitKill
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	int __syscall_nr;
	int not_used;
	long ret;
};

static u32 lkey = __LINE__;
SEC("tracepoint/syscalls/sys_enter_kill")
int sys_enter_kill(struct TpEnterKill *ctx)
{
	long ret;
	filter_debug_proc(0, "kill");
	struct BpfData *log = (typeof(log))malloc_page(lkey);
	if (!log)
	{
		return 0;
	}
	log->sender_pid = bpf_get_current_pid_tgid();
	log->recv_pid = ctx->pid;
	log->sig = ctx->sig;
	ret = bpf_get_current_comm(log->sender_comm, sizeof(log->sender_comm));
	if (ret)
	{
		bpf_err("fail to get current comm: %d", ret);
		goto exit;
	}

	return 0;

exit:
	if (log)
	{
		free_page(lkey);
	}
	return 0;
}

SEC("lsm/task_kill")
int BPF_PROG(
	task_kill,
	struct task_struct *p,
	struct kernel_siginfo *info,
	int sig,
	const struct cred *cred,
	int ret
)
{
	if (ret)
	{
		return ret;
	}

	struct BpfData *log = (typeof(log))lookup_page(lkey);
	if (!log)
	{
		return 0;
	}

	ret =
		bpf_probe_read_kernel(&log->recv_comm, sizeof(log->recv_comm), p->comm);
	if (ret)
	{
		bpf_err("fail to read comm: %d", ret);
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_kill")
int sys_exit_kill(struct TpExitKill *ctx)
{
	long ret;
	struct Rule *rule;
	struct BpfData *log = (typeof(log))lookup_page(lkey);
	if (!log)
	{
		return 0;
	}
	log->res = ctx->ret;

	rule = get_rule();
	if (!rule)
	{
		return 0;
	}
	if (!rule_filter(rule, log))
	{
		goto exit;
	}

	ret = bpf_ringbuf_output(&logs, log, sizeof(*log), 0);
	if (ret)
	{
		bpf_err("bpf_ringbuf_output: %d\n", ret);
	}

exit:
	free_page(lkey);
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

	rule = get_rule();
	if (!rule)
	{
		return 0;
	}

	if (rule->sender_phash == 0 && rule->recv_phash == 0)
	{
		return 0;
	}

	u32 pkey = __LINE__;
	char *path = malloc_page(pkey);
	if (!path)
	{
		bpf_err("path buffer full");
		return 0;
	}

	ret = bpf_probe_read_kernel_str(path, 4096, &filename->iname);
	if (ret <= 0)
	{
		bpf_err("fail to read kernel space string: %ld", ret);
		goto exit;
	}

	u32 pathhash = jhash2((u32 *)path, 1024, 0);

	if (pathhash != rule->sender_phash && pathhash != rule->recv_phash)
	{
		goto exit;
	}

	pid = bpf_get_current_pid_tgid();
	ret = bpf_map_update_elem(&pid2pathhash, &pid, &pathhash, BPF_ANY);
	if (ret)
	{
		bpf_err("fail to update map pid2pathhash: %ld", ret);
		goto exit;
	}

exit:
	if (path)
	{
		free_page(pkey);
	}

	return 0;
}

SEC("fentry/exit_thread")
int BPF_PROG(exit_thread, struct task_struct *tsk)
{
	long ret;
	pid_t pid;
	struct Rule *rule;
	u32 *pathhash;

	rule = get_rule();
	if (!rule)
	{
		return 0;
	}

	if (rule->sender_phash == 0 && rule->recv_phash == 0)
	{
		return 0;
	}

	pid = bpf_get_current_pid_tgid();
	pathhash = bpf_map_lookup_elem(&pid2pathhash, &pid);
	if (!pathhash)
	{
		return 0;
	}

	if (*pathhash != rule->sender_phash && *pathhash != rule->recv_phash)
	{
		return 0;
	}

	ret = bpf_probe_read_kernel(&pid, sizeof(pid), &tsk->pid);
	if (ret)
	{
		bpf_err("fail to read pid: %d", ret);
		return 0;
	}

	ret = bpf_map_delete_elem(&pid2pathhash, &pid);
	if (ret)
	{
		bpf_err("fail to delete pid2pathhash: %d", ret);
	}

	return 0;
}

SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
	struct task_struct *task;
	struct file *file;
	struct mm_struct *mm;

	task = ctx->task;
	if (!task)
	{
		return 0;
	}

	// if (task->pid != task->tgid)    // Only dump the main thread
	//     return 0;

	mm = task->mm;
	if (!mm)
	{
		return 0;
	}
	file = mm->exe_file;
	if (!file)
	{
		return 0;
	}

	long ret = 0;
	pid_t pid;
	struct Rule *rule;

	rule = get_rule();
	if (!rule)
	{
		return 0;
	}

	if (rule->sender_phash == 0 && rule->recv_phash == 0)
	{
		return 0;
	}

	u32 pkey = __LINE__;
	char *path = malloc_page(pkey);
	if (!path)
	{
		bpf_err("path buffer full");
		return 0;
	}

	ret = bpf_d_path(&file->f_path, path, PAGE_SIZE);
	if (ret < 0)
	{
		bpf_err("fail to read kernel space string: %ld", ret);
		goto exit;
	}

	if (ret >= PAGE_SIZE)
	{
		bpf_err("path too long: %ld", ret);
		goto exit;
	}

	zero_str_tail(path, PAGE_SIZE);

	u32 pathhash = jhash2((u32 *)path, PAGE_SIZE / 4, 0);
	DEBUG(0, "path: %s PHASH: %u", path, pathhash);

	if (pathhash != rule->sender_phash && pathhash != rule->recv_phash)
	{
		goto exit;
	}

	DEBUG(0, "path: %s PHASH: %u", path, pathhash);
	pid = task->pid;
	ret = bpf_map_update_elem(&pid2pathhash, &pid, &pathhash, BPF_ANY);
	if (ret)
	{
		bpf_err("fail to update map pid2pathhash: %ld", ret);
		goto exit;
	}

exit:
	if (path)
	{
		free_page(pkey);
	}

	return 0;
}