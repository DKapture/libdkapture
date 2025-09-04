#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "jhash.h"
#include "Kstr-utils.h"
#include "Kmem.h"

#ifdef CONFIG_THREAD_INFO_IN_TASK
#define CURRENT_CPU(t) (t->thread_info.cpu)
#else
#define CURRENT_CPU(t) (t->recent_used_cpu)
#endif

char _license[] SEC("license") = "GPL";

struct Rule
{
	struct
	{
		pid_t min;
		pid_t max;
	} pid;
	struct
	{
		pid_t min;
		pid_t max;
	} tgid;
	u32 on_rq : 2;
	u32 on_cpu : 2;
	struct
	{
		u64 min;
		u64 max;
	} utime;
	struct
	{
		u64 min;
		u64 max;
	} stime;
	struct
	{
		u64 min;
		u64 max;
	} start_time;

	struct
	{
		int min;
		int max;
	} priority;
	char comm[16];
};

// Structure to log data
struct BpfData
{
	pid_t pid;
	pid_t tgid;
	u32 cpu;
	u32 on_rq : 1;
	u32 on_cpu : 1;
	u64 utime;
	u64 stime;
	u64 start_time;

	int priority;
	char comm[16];
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

static int rule_filter(struct task_struct *task)
{
	u32 rkey = 0;
	u32 debug = 0;
	struct Rule *rule = bpf_map_lookup_elem(&filter, &rkey);
	if (!rule)
	{
		bpf_printk("error: fail to get rule");
		return 0;
	}

	if (rule->comm[0])
	{
		if (strncmp(rule->comm, task->comm, 16))
		{
			return 0;
		}
		else
		{
			debug = 1;
		}
	}

	if (task->pid < rule->pid.min || task->pid > rule->pid.max)
	{
		DEBUG(0, "filtered by pid: %d", task->pid);
		return 0;
	}

	if (task->tgid < rule->tgid.min || task->tgid > rule->tgid.max)
	{
		DEBUG(0, "filtered by tgid: %d", task->tgid);
		return 0;
	}

	if (task->stime < rule->stime.min || task->stime > rule->stime.max)
	{
		DEBUG(0, "filtered by stime: %lu", task->stime);
		return 0;
	}

	if (task->utime < rule->utime.min || task->utime > rule->utime.max)
	{
		DEBUG(0, "filtered by utime: %lu", task->utime);
		return 0;
	}

	if (task->start_time < rule->start_time.min ||
		task->start_time > rule->start_time.max)
	{
		DEBUG(0, "filtered by start_time: %lu", task->start_time);
		return 0;
	}

	if (rule->on_cpu != 2 && task->on_cpu != rule->on_cpu)
	{
		// bpf_printk("on_cpu: %d", rule->on_cpu);
		DEBUG(0, "filtered by on_cpu: %d", task->on_cpu);
		return 0;
	}

	if (rule->on_rq != 2 && task->on_rq != rule->on_rq)
	{
		// bpf_printk("on_rq: %d", rule->on_rq);
		DEBUG(0, "filtered by on_rq: %d", task->on_rq);
		return 0;
	}

	if (task->prio < rule->priority.min || task->prio > rule->priority.max)
	{
		DEBUG(0, "filtered by priority: %d", task->prio);
		return 0;
	}

	return 1;
}

static void parse_log(struct task_struct *task, struct BpfData *log)
{
	log->on_cpu = task->on_cpu;
	log->on_rq = task->on_rq;
	log->pid = task->pid;
	log->tgid = task->tgid;
	log->start_time = task->start_time;
	log->stime = task->stime;
	log->utime = task->utime;
	log->cpu = CURRENT_CPU(task);
	log->priority = task->prio;
	__builtin_memmove(log->comm, task->comm, 16);
}

static void send_log(struct BpfData *log)
{
	long ret;
	ret = bpf_ringbuf_output(&logs, log, sizeof(*log), 0);
	if (ret)
	{
		bpf_printk("error: bpf_ringbuf_output: %ld", ret);
	}
}

static void print_log(struct seq_file *seq, const struct BpfData *log)
{
	BPF_SEQ_PRINTF(
		seq,
		"%d %d %d %d %lu %lu %lu %u %d\n",
		log->on_cpu,
		log->on_rq,
		log->pid,
		log->tgid,
		log->start_time,
		log->stime,
		log->utime,
		log->cpu,
		log->priority
	);
}

SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	// __u64 seq_num = ctx->meta->seq_num;
	struct task_struct *task = ctx->task;

	if (!task)
	{
		return 0;
	}

	if (!rule_filter(task))
	{
		return 0;
	}

	struct BpfData log;
	parse_log(task, &log);
	print_log(seq, &log);
	send_log(&log);
	return 0;
}