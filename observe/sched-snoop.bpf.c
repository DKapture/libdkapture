#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "Kstr-utils.h"

#define TASK_COMM_LEN 16

// Event types
enum sched_event_type
{
	SCHED_SWITCH = 1,
	SCHED_WAKEUP = 2,
	SCHED_MIGRATE = 3,
	SCHED_FORK = 4,
	SCHED_EXIT = 5,
	SCHED_EXEC = 6,
	SCHED_STAT_RUNTIME = 7,
	SCHED_STAT_WAIT = 8,
	SCHED_STAT_SLEEP = 9,
	SCHED_STAT_BLOCKED = 10,
	SCHED_STAT_IOWAIT = 11,
	SCHED_WAKEUP_NEW = 12,
};

// Filter configuration
struct Rule
{
	u32 target_pid; // 0 means no filter
	int target_cpu; // -1 means no filter
	char target_comm[TASK_COMM_LEN];
	u32 event_mask; // Bitmask of events to trace
};

// Common event data structure
struct BpfData
{
	u64 timestamp;
	u32 cpu;
	u32 event_type;

	// Common fields for all events
	char comm[TASK_COMM_LEN];
	u32 pid;
	u32 prio;

	// Event-specific data (union to save space)
	union
	{
		// For SCHED_SWITCH
		struct
		{
			char prev_comm[TASK_COMM_LEN];
			u32 prev_pid;
			u32 prev_prio;
			u64 prev_state;
			char next_comm[TASK_COMM_LEN];
			u32 next_pid;
			u32 next_prio;
		} switch_data;

		// For SCHED_WAKEUP
		struct
		{
			u32 target_cpu;
		} wakeup_data;

		// For SCHED_MIGRATE
		struct
		{
			u32 orig_cpu;
			u32 dest_cpu;
		} migrate_data;

		// For SCHED_FORK
		struct
		{
			char parent_comm[TASK_COMM_LEN];
			u32 parent_pid;
			char child_comm[TASK_COMM_LEN];
			u32 child_pid;
		} fork_data;

		// For SCHED_STAT_* events
		struct
		{
			u64 delay;	 // delay time in nanoseconds
			u64 runtime; // runtime in nanoseconds
		} stat_data;

		// For SCHED_EXIT and SCHED_EXEC - use common fields only
	};
};

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
	__uint(max_entries, 256 * 1024);
} logs SEC(".maps");

static int rule_filter(struct Rule *rule, u32 pid, int cpu, u32 event_type)
{
	// Check event type filter
	if (rule->event_mask && !(rule->event_mask & (1 << event_type)))
	{
		return 0;
	}

	if (rule->target_pid && rule->target_pid != pid)
	{
		return 0;
	}

	if (rule->target_cpu >= 0 && rule->target_cpu != cpu)
	{
		return 0;
	}

	return 1;
}

static int
send_event(u32 event_type, struct task_struct *task, void *extra_data)
{
	u32 key = 0;
	struct Rule *rule = bpf_map_lookup_elem(&filter, &key);
	if (!rule)
	{
		return 0;
	}

	u32 cpu = bpf_get_smp_processor_id();
	u32 pid = BPF_CORE_READ(task, pid);

	// Apply basic filters
	if (!rule_filter(rule, pid, cpu, event_type))
	{
		return 0;
	}

	struct BpfData *log = bpf_ringbuf_reserve(&logs, sizeof(*log), 0);
	if (!log)
	{
		return 0;
	}

	log->timestamp = bpf_ktime_get_ns();
	log->cpu = cpu;
	log->event_type = event_type;
	log->pid = pid;
	log->prio = BPF_CORE_READ(task, prio);
	BPF_CORE_READ_STR_INTO(&log->comm, task, comm);

	// Copy event-specific data
	if (extra_data)
	{
		switch (event_type)
		{
		case SCHED_WAKEUP:
			__builtin_memcpy(
				&log->wakeup_data,
				extra_data,
				sizeof(log->wakeup_data)
			);
			break;
		case SCHED_MIGRATE:
			__builtin_memcpy(
				&log->migrate_data,
				extra_data,
				sizeof(log->migrate_data)
			);
			break;
		case SCHED_FORK:
			__builtin_memcpy(
				&log->fork_data,
				extra_data,
				sizeof(log->fork_data)
			);
			break;
		case SCHED_STAT_RUNTIME:
		case SCHED_STAT_WAIT:
		case SCHED_STAT_SLEEP:
		case SCHED_STAT_BLOCKED:
		case SCHED_STAT_IOWAIT:
			__builtin_memcpy(
				&log->stat_data,
				extra_data,
				sizeof(log->stat_data)
			);
			break;
		}
	}

	bpf_ringbuf_submit(log, 0);
	return 0;
}

SEC("tp/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
	u32 key = 0;
	struct Rule *rule = bpf_map_lookup_elem(&filter, &key);
	if (!rule)
	{
		return 0;
	}

	u32 cpu = bpf_get_smp_processor_id();
	u32 prev_pid = ctx->prev_pid;
	u32 next_pid = ctx->next_pid;

	// Check if we should trace this event
	if (!rule_filter(rule, prev_pid, cpu, SCHED_SWITCH) &&
		!rule_filter(rule, next_pid, cpu, SCHED_SWITCH))
	{
		return 0;
	}

	struct BpfData *log = bpf_ringbuf_reserve(&logs, sizeof(*log), 0);
	if (!log)
	{
		return 0;
	}

	log->timestamp = bpf_ktime_get_ns();
	log->cpu = cpu;
	log->event_type = SCHED_SWITCH;

	// For switch events, we'll use prev as the main task
	log->pid = prev_pid;
	log->prio = ctx->prev_prio;
	bpf_probe_read_kernel_str(log->comm, TASK_COMM_LEN, ctx->prev_comm);

	// Fill switch-specific data
	bpf_probe_read_kernel_str(
		log->switch_data.prev_comm,
		TASK_COMM_LEN,
		ctx->prev_comm
	);
	log->switch_data.prev_pid = prev_pid;
	log->switch_data.prev_prio = ctx->prev_prio;
	log->switch_data.prev_state = ctx->prev_state;

	bpf_probe_read_kernel_str(
		log->switch_data.next_comm,
		TASK_COMM_LEN,
		ctx->next_comm
	);
	log->switch_data.next_pid = next_pid;
	log->switch_data.next_prio = ctx->next_prio;

	bpf_ringbuf_submit(log, 0);
	return 0;
}

SEC("tp/sched/sched_wakeup")
int handle_sched_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
	u32 key = 0;
	struct Rule *rule = bpf_map_lookup_elem(&filter, &key);
	if (!rule)
	{
		return 0;
	}

	u32 cpu = bpf_get_smp_processor_id();
	u32 pid = ctx->pid;

	if (!rule_filter(rule, pid, cpu, SCHED_WAKEUP))
	{
		return 0;
	}

	struct BpfData *log = bpf_ringbuf_reserve(&logs, sizeof(*log), 0);
	if (!log)
	{
		return 0;
	}

	log->timestamp = bpf_ktime_get_ns();
	log->cpu = cpu;
	log->event_type = SCHED_WAKEUP;
	log->pid = pid;
	log->prio = ctx->prio;
	bpf_probe_read_kernel_str(log->comm, TASK_COMM_LEN, ctx->comm);

	log->wakeup_data.target_cpu = ctx->target_cpu;

	bpf_ringbuf_submit(log, 0);
	return 0;
}

SEC("tp/sched/sched_wakeup_new")
int handle_sched_wakeup_new(struct trace_event_raw_sched_wakeup_template *ctx)
{
	u32 key = 0;
	struct Rule *rule = bpf_map_lookup_elem(&filter, &key);
	if (!rule)
	{
		return 0;
	}

	u32 cpu = bpf_get_smp_processor_id();
	u32 pid = ctx->pid;

	if (!rule_filter(rule, pid, cpu, SCHED_WAKEUP_NEW))
	{
		return 0;
	}

	struct BpfData *log = bpf_ringbuf_reserve(&logs, sizeof(*log), 0);
	if (!log)
	{
		return 0;
	}

	log->timestamp = bpf_ktime_get_ns();
	log->cpu = cpu;
	log->event_type = SCHED_WAKEUP_NEW;
	log->pid = pid;
	log->prio = ctx->prio;
	bpf_probe_read_kernel_str(log->comm, TASK_COMM_LEN, ctx->comm);

	log->wakeup_data.target_cpu = ctx->target_cpu;

	bpf_ringbuf_submit(log, 0);
	return 0;
}

SEC("tp/sched/sched_migrate_task")
int handle_sched_migrate(struct trace_event_raw_sched_migrate_task *ctx)
{
	u32 key = 0;
	struct Rule *rule = bpf_map_lookup_elem(&filter, &key);
	if (!rule)
	{
		return 0;
	}

	u32 cpu = bpf_get_smp_processor_id();
	u32 pid = ctx->pid;

	if (!rule_filter(rule, pid, cpu, SCHED_MIGRATE))
	{
		return 0;
	}

	struct BpfData *log = bpf_ringbuf_reserve(&logs, sizeof(*log), 0);
	if (!log)
	{
		return 0;
	}

	log->timestamp = bpf_ktime_get_ns();
	log->cpu = cpu;
	log->event_type = SCHED_MIGRATE;
	log->pid = pid;
	log->prio = ctx->prio;
	bpf_probe_read_kernel_str(log->comm, TASK_COMM_LEN, ctx->comm);

	log->migrate_data.orig_cpu = ctx->orig_cpu;
	log->migrate_data.dest_cpu = ctx->dest_cpu;

	bpf_ringbuf_submit(log, 0);
	return 0;
}

SEC("tp/sched/sched_process_fork")
int handle_sched_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	u32 key = 0;
	struct Rule *rule = bpf_map_lookup_elem(&filter, &key);
	if (!rule)
	{
		return 0;
	}

	u32 cpu = bpf_get_smp_processor_id();
	u32 parent_pid = ctx->parent_pid;

	if (!rule_filter(rule, parent_pid, cpu, SCHED_FORK))
	{
		return 0;
	}

	struct BpfData *log = bpf_ringbuf_reserve(&logs, sizeof(*log), 0);
	if (!log)
	{
		return 0;
	}

	log->timestamp = bpf_ktime_get_ns();
	log->cpu = cpu;
	log->event_type = SCHED_FORK;
	log->pid = parent_pid;
	log->prio = 120; // Default priority
	bpf_probe_read_kernel_str(log->comm, TASK_COMM_LEN, ctx->parent_comm);

	bpf_probe_read_kernel_str(
		log->fork_data.parent_comm,
		TASK_COMM_LEN,
		ctx->parent_comm
	);
	log->fork_data.parent_pid = parent_pid;
	bpf_probe_read_kernel_str(
		log->fork_data.child_comm,
		TASK_COMM_LEN,
		ctx->child_comm
	);
	log->fork_data.child_pid = ctx->child_pid;

	bpf_ringbuf_submit(log, 0);
	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_sched_exit(struct trace_event_raw_sched_process_template *ctx)
{
	u32 key = 0;
	struct Rule *rule = bpf_map_lookup_elem(&filter, &key);
	if (!rule)
	{
		return 0;
	}

	u32 cpu = bpf_get_smp_processor_id();
	u32 pid = ctx->pid;

	if (!rule_filter(rule, pid, cpu, SCHED_EXIT))
	{
		return 0;
	}

	struct BpfData *log = bpf_ringbuf_reserve(&logs, sizeof(*log), 0);
	if (!log)
	{
		return 0;
	}

	log->timestamp = bpf_ktime_get_ns();
	log->cpu = cpu;
	log->event_type = SCHED_EXIT;
	log->pid = pid;
	log->prio = ctx->prio;
	bpf_probe_read_kernel_str(log->comm, TASK_COMM_LEN, ctx->comm);

	bpf_ringbuf_submit(log, 0);
	return 0;
}

SEC("tp/sched/sched_process_exec")
int handle_sched_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	u32 key = 0;
	struct Rule *rule = bpf_map_lookup_elem(&filter, &key);
	if (!rule)
	{
		return 0;
	}

	u32 cpu = bpf_get_smp_processor_id();
	u32 pid = ctx->pid;

	if (!rule_filter(rule, pid, cpu, SCHED_EXEC))
	{
		return 0;
	}

	struct BpfData *log = bpf_ringbuf_reserve(&logs, sizeof(*log), 0);
	if (!log)
	{
		return 0;
	}

	log->timestamp = bpf_ktime_get_ns();
	log->cpu = cpu;
	log->event_type = SCHED_EXEC;
	log->pid = pid;
	log->prio = 120; // Default priority

	// For exec events, copy the filename as comm
	__builtin_memset(log->comm, 0, sizeof(log->comm));
	// Handle __data_loc field: filename is at offset specified in the field
	void *filename_ptr = (void *)ctx + (ctx->__data_loc_filename & 0xffff);
	bpf_probe_read_kernel_str(log->comm, sizeof(log->comm), filename_ptr);

	bpf_ringbuf_submit(log, 0);
	return 0;
}

SEC("tp/sched/sched_stat_runtime")
int handle_sched_stat_runtime(struct trace_event_raw_sched_stat_runtime *ctx)
{
	u32 key = 0;
	struct Rule *rule = bpf_map_lookup_elem(&filter, &key);
	if (!rule)
	{
		return 0;
	}

	u32 cpu = bpf_get_smp_processor_id();
	u32 pid = ctx->pid;

	if (!rule_filter(rule, pid, cpu, SCHED_STAT_RUNTIME))
	{
		return 0;
	}

	struct BpfData *log = bpf_ringbuf_reserve(&logs, sizeof(*log), 0);
	if (!log)
	{
		return 0;
	}

	log->timestamp = bpf_ktime_get_ns();
	log->cpu = cpu;
	log->event_type = SCHED_STAT_RUNTIME;
	log->pid = pid;
	log->prio = 120; // Default priority
	bpf_probe_read_kernel_str(log->comm, TASK_COMM_LEN, ctx->comm);

	log->stat_data.runtime = ctx->runtime;
	log->stat_data.delay = 0; // Not applicable for runtime

	bpf_ringbuf_submit(log, 0);
	return 0;
}

SEC("tp/sched/sched_stat_wait")
int handle_sched_stat_wait(struct trace_event_raw_sched_stat_template *ctx)
{
	u32 key = 0;
	struct Rule *rule = bpf_map_lookup_elem(&filter, &key);
	if (!rule)
	{
		return 0;
	}

	u32 cpu = bpf_get_smp_processor_id();
	u32 pid = ctx->pid;

	if (!rule_filter(rule, pid, cpu, SCHED_STAT_WAIT))
	{
		return 0;
	}

	struct BpfData *log = bpf_ringbuf_reserve(&logs, sizeof(*log), 0);
	if (!log)
	{
		return 0;
	}

	log->timestamp = bpf_ktime_get_ns();
	log->cpu = cpu;
	log->event_type = SCHED_STAT_WAIT;
	log->pid = pid;
	log->prio = 120; // Default priority
	bpf_probe_read_kernel_str(log->comm, TASK_COMM_LEN, ctx->comm);

	log->stat_data.delay = ctx->delay;
	log->stat_data.runtime = 0; // Not applicable for wait

	bpf_ringbuf_submit(log, 0);
	return 0;
}

SEC("tp/sched/sched_stat_sleep")
int handle_sched_stat_sleep(struct trace_event_raw_sched_stat_template *ctx)
{
	u32 key = 0;
	struct Rule *rule = bpf_map_lookup_elem(&filter, &key);
	if (!rule)
	{
		return 0;
	}

	u32 cpu = bpf_get_smp_processor_id();
	u32 pid = ctx->pid;

	if (!rule_filter(rule, pid, cpu, SCHED_STAT_SLEEP))
	{
		return 0;
	}

	struct BpfData *log = bpf_ringbuf_reserve(&logs, sizeof(*log), 0);
	if (!log)
	{
		return 0;
	}

	log->timestamp = bpf_ktime_get_ns();
	log->cpu = cpu;
	log->event_type = SCHED_STAT_SLEEP;
	log->pid = pid;
	log->prio = 120; // Default priority
	bpf_probe_read_kernel_str(log->comm, TASK_COMM_LEN, ctx->comm);

	log->stat_data.delay = ctx->delay;
	log->stat_data.runtime = 0; // Not applicable for sleep

	bpf_ringbuf_submit(log, 0);
	return 0;
}

SEC("tp/sched/sched_stat_blocked")
int handle_sched_stat_blocked(struct trace_event_raw_sched_stat_template *ctx)
{
	u32 key = 0;
	struct Rule *rule = bpf_map_lookup_elem(&filter, &key);
	if (!rule)
	{
		return 0;
	}

	u32 cpu = bpf_get_smp_processor_id();
	u32 pid = ctx->pid;

	if (!rule_filter(rule, pid, cpu, SCHED_STAT_BLOCKED))
	{
		return 0;
	}

	struct BpfData *log = bpf_ringbuf_reserve(&logs, sizeof(*log), 0);
	if (!log)
	{
		return 0;
	}

	log->timestamp = bpf_ktime_get_ns();
	log->cpu = cpu;
	log->event_type = SCHED_STAT_BLOCKED;
	log->pid = pid;
	log->prio = 120; // Default priority
	bpf_probe_read_kernel_str(log->comm, TASK_COMM_LEN, ctx->comm);

	log->stat_data.delay = ctx->delay;
	log->stat_data.runtime = 0; // Not applicable for blocked

	bpf_ringbuf_submit(log, 0);
	return 0;
}

SEC("tp/sched/sched_stat_iowait")
int handle_sched_stat_iowait(struct trace_event_raw_sched_stat_template *ctx)
{
	u32 key = 0;
	struct Rule *rule = bpf_map_lookup_elem(&filter, &key);
	if (!rule)
	{
		return 0;
	}

	u32 cpu = bpf_get_smp_processor_id();
	u32 pid = ctx->pid;

	if (!rule_filter(rule, pid, cpu, SCHED_STAT_IOWAIT))
	{
		return 0;
	}

	struct BpfData *log = bpf_ringbuf_reserve(&logs, sizeof(*log), 0);
	if (!log)
	{
		return 0;
	}

	log->timestamp = bpf_ktime_get_ns();
	log->cpu = cpu;
	log->event_type = SCHED_STAT_IOWAIT;
	log->pid = pid;
	log->prio = 120; // Default priority
	bpf_probe_read_kernel_str(log->comm, TASK_COMM_LEN, ctx->comm);

	log->stat_data.delay = ctx->delay;
	log->stat_data.runtime = 0; // Not applicable for iowait

	bpf_ringbuf_submit(log, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";