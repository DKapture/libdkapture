/**
 * 通过使用 trace point
 * 在sched_wakeup函数的入口和退出处放置钩子，实现对该系统调用的跟踪
 */
#include "vmlinux.h"
#include "wakeup_count.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <asm-generic/errno.h>

#define MAX_ENTRIES 10240
#define TASK_RUNNING 0

const volatile bool filter_cg = false;
const volatile bool targ_per_process = false;
const volatile bool targ_per_thread = false;
const volatile bool targ_per_pidns = false;
const volatile bool targ_ms = false;
const volatile pid_t targ_tgid = 0;

struct
{
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

static struct hist zero;

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct hkey);
	__type(value, struct hist);
} hists SEC(".maps");

static __always_inline void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *init)
{
	void *val;
	/* bpf helper functions like bpf_map_update_elem() below normally return
	 * long, but using int instead of long to store the result is a workaround
	 * to avoid incorrectly evaluating err in cases where the following criteria
	 * is met:
	 *     the architecture is 64-bit
	 *     the helper function return type is long
	 *     the helper function returns the value of a call to a bpf_map_ops func
	 *     the bpf_map_ops function return type is int
	 *     the compiler inlines the helper function
	 *     the compiler does not sign extend the result of the bpf_map_ops func
	 *
	 * if this criteria is met, at best an error can only be checked as zero or
	 * non-zero. it will not be possible to check for a negative value or a
	 * specific error value. this is because the sign bit would have been stuck
	 * at the 32nd bit of a 64-bit long int.
	 */
	int err;

	val = bpf_map_lookup_elem(map, key);
	if (val)
	{
		return val;
	}

	err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
	if (err && err != -EEXIST)
	{
		return 0;
	}

	return bpf_map_lookup_elem(map, key);
}

static int trace_enqueue(struct task_struct *p)
{
	struct hist *histp;
	struct hkey hkey;
	u32 pid, tgid;

	pid = BPF_CORE_READ(p, pid);
	tgid = BPF_CORE_READ(p, tgid);

	if (!pid)
	{
		return 0;
	}
	if (targ_tgid && targ_tgid != tgid)
	{
		return 0;
	}

	hkey.pid = pid;
	histp = bpf_map_lookup_or_try_init(&hists, &hkey, &zero);
	if (!histp)
	{
		return 0;
	}

	if (!histp->comm[0])
	{
		bpf_printk("histp->comm null 0x%x", histp->comm[0]);
		bpf_probe_read_kernel_str(&histp->comm, sizeof(histp->comm), p->comm);
		bpf_printk("histp->comm %s", histp->comm);
	}

	__sync_fetch_and_add(&histp->wakeup_count, 1);

	bpf_printk(
		"trace_enqueue tgid=%u pid=%u comm=%s wakeup_count=%llu \n",
		tgid,
		pid,
		histp->comm,
		histp->wakeup_count
	);

	return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
	{
		return 0;
	}

	bpf_printk("sched_wakeup tgid=%u pid=%u comm=%s", p->tgid, p->pid, p->comm);

	return trace_enqueue(p);
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(sched_wakeup_new, struct task_struct *p)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
	{
		return 0;
	}

	bpf_printk(
		"sched_wakeup_new tgid=%u pid=%u comm=%s",
		p->tgid,
		p->pid,
		p->comm
	);

	return trace_enqueue(p);
}

char LICENSE[] SEC("license") = "GPL";